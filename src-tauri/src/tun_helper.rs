#[cfg(windows)]
mod windows {
    use std::{
        ffi::{OsStr, OsString},
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        mem::size_of,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Path, PathBuf},
        ptr,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS,
            ERROR_BUFFER_OVERFLOW, ERROR_CANCELLED, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
            GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        NetworkManagement::IpHelper::{
            FreeMibTable, GetAdaptersAddresses, GetBestRoute2, GetIfEntry2, GetIpForwardTable2,
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GAA_FLAG_SKIP_UNICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP,
            IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2,
        },
        NetworkManagement::Ndis::TUNNEL_TYPE_NONE,
        Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN_ADDR, SOCKADDR_IN, SOCKADDR_IN6,
            SOCKADDR_INET,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_NAME_NORMALIZED, FILE_SHARE_READ, OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX, VOLUME_NAME_DOS,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                GetNamedPipeServerProcessId, SetNamedPipeHandleState, WaitNamedPipeW, PIPE_NOWAIT,
                PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
                PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
                QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_DUP_HANDLE,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
        UI::Shell::{
            ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW,
        },
    };

    use crate::{
        engine_runtime::{
            random_hex, DiagnosticBuffer, EngineLauncher, ManagedChild, RuntimeError,
            SessionConfig, TunCaptureSnapshot, VerifiedEngineLauncher,
        },
        redaction::Redactor,
        tun_helper_protocol::{
            pipe_suffix, read_frame, session_id, write_frame, CleanupState, Frame,
            HelperFailureCode, HelperPhase, ServerState, TunInterfaceState, UpstreamChoice,
            MAX_CONFIG_BYTES, PROTOCOL_VERSION,
        },
    };

    const HELPER_FILE_NAME: &str = "routedeck-tun-helper.exe";
    const GUI_FILE_NAME: &str = "routedeck.exe";
    const PIPE_PREFIX: &str = r"\\.\pipe\RouteDeck.Tun.";
    const PIPE_BUFFER_BYTES: u32 = 32 * 1024;
    const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
    const HELPER_STOP_TIMEOUT: Duration = Duration::from_secs(8);
    const TUN_INTERFACE_NAME: &str = "RouteDeck";
    const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;

    pub(crate) struct TunHelperLauncher {
        validator: VerifiedEngineLauncher,
        expected_helper_sha256: Option<&'static str>,
        prepared: Mutex<Option<PreparedTransfer>>,
    }

    struct PreparedTransfer {
        config_guard: File,
        config_len: u64,
        config_sha256: String,
    }

    impl TunHelperLauncher {
        pub(crate) fn resolve(
            expected_helper_sha256: Option<&'static str>,
        ) -> Result<Self, RuntimeError> {
            Ok(Self {
                validator: VerifiedEngineLauncher::resolve()?,
                expected_helper_sha256,
                prepared: Mutex::new(None),
            })
        }
    }

    impl EngineLauncher for TunHelperLauncher {
        fn check(
            &self,
            config: &SessionConfig,
            redactor: Redactor,
            diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<String, RuntimeError> {
            let version = self.validator.check(config, redactor, diagnostics)?;
            let mut guard = config.revalidate_for_launch()?;
            let (config_len, config_sha256) = hash_config(&mut guard)?;
            *self
                .prepared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PreparedTransfer {
                config_guard: guard,
                config_len,
                config_sha256,
            });
            Ok(version)
        }

        fn start(
            &self,
            _config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<Box<dyn ManagedChild>, RuntimeError> {
            let prepared = self
                .prepared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or_else(|| {
                    RuntimeError::new(
                        "start_engine",
                        "TUN helper launch was not prepared by the matching configuration check",
                    )
                })?;
            launch_helper(prepared, self.expected_helper_sha256)
                .map(|child| Box::new(child) as Box<dyn ManagedChild>)
        }
    }

    fn hash_config(file: &mut File) -> Result<(u64, String), RuntimeError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
        let mut hasher = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
            if count == 0 {
                break;
            }
            length = length.saturating_add(count as u64);
            if length > MAX_CONFIG_BYTES {
                return Err(RuntimeError::new(
                    "session_storage",
                    "generated TUN configuration exceeds the helper limit",
                ));
            }
            hasher.update(&buffer[..count]);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
        if length == 0 {
            return Err(RuntimeError::new(
                "session_storage",
                "generated TUN configuration is empty",
            ));
        }
        Ok((length, format!("{:x}", hasher.finalize())))
    }

    fn launch_helper(
        prepared: PreparedTransfer,
        expected_helper_sha256: Option<&str>,
    ) -> Result<TunHelperChild, RuntimeError> {
        let route_context = preflight_route_context()?;
        let helper_path = fixed_helper_path()?;
        let _helper_guard = verify_helper_for_launch(&helper_path, expected_helper_sha256)?;
        let session = random_hex(16)?;
        let suffix = random_hex(16)?;
        let mut pipe = create_server_pipe(&suffix)?;
        let parent_pid = unsafe { GetCurrentProcessId() };
        let parent_created = process_creation_time(unsafe { GetCurrentProcess() })?;
        let arguments = helper_arguments(&session, &suffix, parent_pid, parent_created)?;
        let helper_process = shell_execute_runas(&helper_path, &arguments)?;
        connect_helper(&pipe, &helper_process)?;
        let helper_pid = pipe_client_pid(&pipe)?;
        let actual_helper_created = process_creation_time(helper_process.raw())?;

        let hello = read_frame(&mut pipe).map_err(protocol_runtime_error)?;
        let (hello_nonce, claimed_pid, claimed_created) = match hello {
            Frame::HelperHello {
                protocol_version: _,
                session: claimed_session,
                helper_pid,
                helper_created,
                nonce,
            } if claimed_session == session => (nonce, helper_pid, helper_created),
            _ => {
                return Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN helper identity message was rejected",
                ))
            }
        };
        if helper_pid != claimed_pid || actual_helper_created != claimed_created {
            return Err(RuntimeError::new(
                "tun_helper_protocol",
                "TUN helper process identity changed during activation",
            ));
        }

        let challenge = random_hex(32)?;
        let expires_at = unix_seconds()?.saturating_add(30);
        write_frame(
            &mut pipe,
            &Frame::GuiChallenge {
                protocol_version: PROTOCOL_VERSION,
                session: session.clone(),
                request_id: 1,
                challenge: challenge.clone(),
                expires_at,
            },
        )
        .map_err(protocol_runtime_error)?;
        let preflight_sha256 = preflight_digest(&prepared.config_sha256, &route_context);
        write_frame(
            &mut pipe,
            &Frame::StartTun {
                protocol_version: PROTOCOL_VERSION,
                session: session.clone(),
                request_id: 2,
                challenge,
                hello_nonce,
                config_handle_id: prepared.config_guard.as_raw_handle() as usize as u64,
                config_len: prepared.config_len,
                config_sha256: prepared.config_sha256,
                preflight_sha256,
                upstream_choice: UpstreamChoice::CurrentPath,
            },
        )
        .map_err(protocol_runtime_error)?;
        let response = read_frame(&mut pipe).map_err(protocol_runtime_error)?;
        match response {
            Frame::Started {
                request_id: 2,
                engine_pid,
                engine_created,
            } => Ok(TunHelperChild {
                pipe: Some(pipe),
                helper_process: Some(helper_process),
                helper_pid,
                engine_pid,
                engine_created,
                session,
                request_id: 2,
                stopped: false,
            }),
            Frame::Failure {
                request_id: 2,
                code,
                safe_detail,
            } => Err(RuntimeError::new(
                match code {
                    HelperFailureCode::PreflightConflict => "tun_preflight",
                    HelperFailureCode::CaptureInvalid => "tun_capture",
                    _ => "start_engine",
                },
                safe_detail.unwrap_or_else(|| "elevated TUN helper rejected startup".into()),
            )),
            _ => Err(RuntimeError::new(
                "tun_helper_protocol",
                "TUN helper returned an unexpected startup response",
            )),
        }
    }

    fn preflight_digest(config_sha256: &str, route_context: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"RouteDeck TUN current-path launch context v2\0");
        hasher.update(config_sha256.as_bytes());
        hasher.update(route_context.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    struct TunHelperChild {
        pipe: Option<File>,
        helper_process: Option<OwnedHandle>,
        helper_pid: u32,
        engine_pid: u32,
        engine_created: u64,
        session: String,
        request_id: u64,
        stopped: bool,
    }

    impl TunHelperChild {
        fn next_request(&mut self) -> Result<u64, RuntimeError> {
            self.request_id = self.request_id.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN helper request counter exhausted",
                )
            })?;
            Ok(self.request_id)
        }

        fn helper_running(&self) -> Result<bool, RuntimeError> {
            if self
                .pipe
                .as_ref()
                .is_some_and(|pipe| pipe_client_pid(pipe).ok() != Some(self.helper_pid))
            {
                return Err(RuntimeError::new(
                    "engine_process",
                    "TUN helper pipe ownership changed",
                ));
            }
            let process = self.helper_process.as_ref().ok_or_else(|| {
                RuntimeError::new("engine_process", "TUN helper process handle is missing")
            })?;
            match unsafe { WaitForSingleObject(process.raw(), 0) } {
                WAIT_TIMEOUT => Ok(true),
                WAIT_OBJECT_0 => Ok(false),
                _ => Err(last_error(
                    "engine_process",
                    "could not inspect the TUN helper process",
                )),
            }
        }

        fn query_running_state(&mut self) -> Result<Option<TunCaptureSnapshot>, RuntimeError> {
            if self.stopped || !self.helper_running()? {
                return Ok(None);
            }
            let request_id = self.next_request()?;
            let pipe = self.pipe.as_mut().ok_or_else(|| {
                RuntimeError::new("engine_process", "TUN helper channel is closed")
            })?;
            write_frame(
                pipe,
                &Frame::Status {
                    protocol_version: PROTOCOL_VERSION,
                    session: self.session.clone(),
                    request_id,
                },
            )
            .map_err(protocol_runtime_error)?;
            match read_frame(pipe).map_err(protocol_runtime_error)? {
                Frame::State {
                    request_id: response_id,
                    phase: HelperPhase::Running,
                    engine_pid: Some(pid),
                    cleanup: CleanupState::NotRequired,
                    capture: Some(capture),
                } if response_id == request_id && pid == self.engine_pid => {
                    let engine = unsafe {
                        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self.engine_pid)
                    };
                    let engine = OwnedHandle::new(
                        engine,
                        "engine_process",
                        "could not reopen the helper-owned sing-box process",
                    )?;
                    if process_creation_time(engine.raw())? != self.engine_created {
                        return Ok(None);
                    }
                    Ok(Some(TunCaptureSnapshot {
                        interface_luid: capture.interface_luid,
                        in_octets: capture.in_octets,
                        out_octets: capture.out_octets,
                    }))
                }
                Frame::State {
                    request_id: response_id,
                    phase: HelperPhase::Stopped | HelperPhase::Failed,
                    ..
                } if response_id == request_id => Ok(None),
                Frame::Failure {
                    request_id: response_id,
                    safe_detail,
                    code,
                } if response_id == request_id => Err(RuntimeError::new(
                    match code {
                        HelperFailureCode::PreflightConflict => "tun_preflight",
                        _ => "tun_capture",
                    },
                    safe_detail.unwrap_or_else(|| {
                        "owned TUN adapter or capture routes changed unexpectedly".into()
                    }),
                )),
                _ => Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN helper returned an unexpected status response",
                )),
            }
        }
    }

    impl ManagedChild for TunHelperChild {
        fn pid(&self) -> u32 {
            self.engine_pid
        }

        fn is_alive(&mut self) -> Result<bool, RuntimeError> {
            self.query_running_state().map(|state| state.is_some())
        }

        fn stop(&mut self) -> Result<(), RuntimeError> {
            if self.stopped {
                return Ok(());
            }
            let request_id = self.next_request()?;
            let pipe = self
                .pipe
                .as_mut()
                .ok_or_else(|| RuntimeError::new("stop_engine", "TUN helper channel is closed"))?;
            write_frame(
                pipe,
                &Frame::StopTun {
                    protocol_version: PROTOCOL_VERSION,
                    session: self.session.clone(),
                    request_id,
                },
            )
            .map_err(|_| RuntimeError::new("stop_engine", "could not request TUN shutdown"))?;
            let cleanup = match read_frame(pipe) {
                Ok(Frame::Stopped {
                    request_id: response_id,
                    cleanup,
                }) if response_id == request_id => cleanup,
                _ => {
                    return Err(RuntimeError::new(
                        "stop_engine",
                        "TUN helper did not confirm shutdown",
                    ))
                }
            };
            if cleanup != CleanupState::Complete {
                return Err(RuntimeError::new(
                    "stop_engine",
                    "TUN cleanup could not be verified and requires review",
                ));
            }
            self.stopped = true;
            self.pipe.take();
            if let Some(process) = self.helper_process.as_ref() {
                if unsafe {
                    WaitForSingleObject(process.raw(), HELPER_STOP_TIMEOUT.as_millis() as u32)
                } != WAIT_OBJECT_0
                {
                    return Err(RuntimeError::new(
                        "stop_engine",
                        "TUN helper did not exit after verified cleanup",
                    ));
                }
            }
            self.helper_process.take();
            Ok(())
        }

        fn tun_capture_snapshot(&mut self) -> Result<TunCaptureSnapshot, RuntimeError> {
            self.query_running_state()?.ok_or_else(|| {
                RuntimeError::new("tun_capture", "the helper-owned TUN engine is not running")
            })
        }
    }

    impl Drop for TunHelperChild {
        fn drop(&mut self) {
            if !self.stopped {
                let _ = self.stop();
                self.pipe.take();
                self.helper_process.take();
            }
        }
    }

    pub fn helper_main() -> Result<(), String> {
        helper_main_inner().map_err(|error| error.stage().to_string())
    }

    fn helper_main_inner() -> Result<(), RuntimeError> {
        if !crate::windows_process::current_process_is_elevated()? {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "TUN helper is not elevated",
            ));
        }
        let invocation = HelperInvocation::parse(std::env::args_os())?;
        let mut pipe = connect_parent_pipe(&invocation.pipe_suffix)?;
        authenticate_parent(&pipe, &invocation)?;
        let helper_pid = unsafe { GetCurrentProcessId() };
        let helper_created = process_creation_time(unsafe { GetCurrentProcess() })?;
        let hello_nonce = random_hex(32)?;
        write_frame(
            &mut pipe,
            &Frame::HelperHello {
                protocol_version: PROTOCOL_VERSION,
                session: invocation.session.clone(),
                helper_pid,
                helper_created,
                nonce: hello_nonce.clone(),
            },
        )
        .map_err(protocol_runtime_error)?;

        let challenge_frame = read_frame(&mut pipe).map_err(protocol_runtime_error)?;
        let mut state = ServerState::AwaitingChallenge;
        state
            .accept(&challenge_frame)
            .map_err(protocol_runtime_error)?;
        let (challenge, expires_at) = match challenge_frame {
            Frame::GuiChallenge {
                session,
                challenge,
                expires_at,
                ..
            } if session == invocation.session => (challenge, expires_at),
            _ => {
                return Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "GUI challenge identity was rejected",
                ))
            }
        };
        if unix_seconds()? > expires_at {
            return Err(RuntimeError::new(
                "tun_helper_protocol",
                "GUI challenge expired before TUN startup",
            ));
        }

        let start_frame = read_frame(&mut pipe).map_err(protocol_runtime_error)?;
        state.accept(&start_frame).map_err(protocol_runtime_error)?;
        let start = match start_frame {
            Frame::StartTun {
                session,
                request_id,
                challenge: received_challenge,
                hello_nonce: received_nonce,
                config_handle_id,
                config_len,
                config_sha256,
                preflight_sha256,
                upstream_choice: UpstreamChoice::CurrentPath,
                ..
            } if session == invocation.session
                && received_challenge == challenge
                && received_nonce == hello_nonce =>
            {
                StartRequest {
                    request_id,
                    config_handle_id,
                    config_len,
                    config_sha256,
                    preflight_sha256,
                }
            }
            _ => {
                return Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN start challenge was rejected",
                ))
            }
        };

        match start_engine_session(&invocation, &start) {
            Ok(mut running) => {
                let child = &mut running.child;
                let journal = &mut running.journal;
                let engine_created = running.engine_created;
                let owned_luid = running.owned_luid;
                let engine_pid = child.pid();
                write_frame(
                    &mut pipe,
                    &Frame::Started {
                        request_id: start.request_id,
                        engine_pid,
                        engine_created,
                    },
                )
                .map_err(protocol_runtime_error)?;
                serve_running(
                    &mut pipe,
                    &invocation,
                    &mut state,
                    child.as_mut(),
                    journal,
                    owned_luid,
                )
            }
            Err(error) => {
                let _ = write_frame(
                    &mut pipe,
                    &Frame::Failure {
                        request_id: start.request_id,
                        code: helper_failure_code(error.stage()),
                        safe_detail: Some(safe_helper_detail(error.stage()).into()),
                    },
                );
                Err(error)
            }
        }
    }

    struct StartRequest {
        request_id: u64,
        config_handle_id: u64,
        config_len: u64,
        config_sha256: String,
        preflight_sha256: String,
    }

    struct RunningSession {
        child: Box<dyn ManagedChild>,
        journal: TunJournal,
        engine_created: u64,
        owned_luid: Option<u64>,
    }

    fn start_engine_session(
        invocation: &HelperInvocation,
        request: &StartRequest,
    ) -> Result<RunningSession, RuntimeError> {
        let route_context = preflight_route_context()?;
        if request.preflight_sha256 != preflight_digest(&request.config_sha256, &route_context) {
            return Err(RuntimeError::new(
                "tun_preflight",
                "network routes changed while TUN permission was being granted; retry the connection",
            ));
        }
        if !find_tun_adapter_luids()?.is_empty() {
            return Err(RuntimeError::new(
                "tun_preflight",
                "a RouteDeck TUN adapter already exists",
            ));
        }
        let parent = open_verified_parent(invocation)?;
        let config = duplicate_config(parent.raw(), request)?;
        let config_directory = protected_config_directory(&config)?;
        let contents = read_verified_config(config, request)?;
        validate_tun_config(&contents)?;

        let session = SessionConfig::create(&config_directory, &contents)?;
        let diagnostics = Arc::new(Mutex::new(DiagnosticBuffer::default()));
        let redactor = Redactor::default().with_secret(&contents);
        let launcher = VerifiedEngineLauncher::resolve()?;
        let _version = launcher.check(&session, redactor.clone(), diagnostics.clone())?;
        let mut journal = TunJournal::create(
            &config_directory,
            &invocation.session,
            &request.config_sha256,
        )?;
        let mut child = launcher.start(&session, redactor, diagnostics)?;
        let engine_created = process_creation_time_for_pid(child.pid())?;
        journal.mark_running(child.pid(), engine_created)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        let owned_luid = loop {
            let found = match find_tun_adapter_luids() {
                Ok(found) => found,
                Err(error) => {
                    rollback_failed_start(child.as_mut(), &mut journal, None)?;
                    return Err(error);
                }
            };
            if found.len() > 1 {
                rollback_failed_start(child.as_mut(), &mut journal, None)?;
                return Err(RuntimeError::new(
                    "tun_preflight",
                    "multiple RouteDeck TUN adapters appeared",
                ));
            }
            if let Some(luid) = found.into_iter().next() {
                break luid;
            }
            if Instant::now() >= deadline {
                rollback_failed_start(child.as_mut(), &mut journal, None)?;
                return Err(RuntimeError::new(
                    "tun_preflight",
                    "the owned RouteDeck TUN adapter did not appear",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        };
        let route_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if inspect_owned_capture(owned_luid).is_ok() {
                break;
            }
            if Instant::now() >= route_deadline {
                rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
                return Err(RuntimeError::new(
                    "tun_capture",
                    "RouteDeck TUN adapter appeared, but its IPv4/IPv6 capture routes did not become effective",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        if let Err(error) = journal.mark_capture(child.pid(), engine_created, owned_luid) {
            rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
            return Err(error);
        }
        if let Err(error) = inspect_owned_capture(owned_luid) {
            rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
            return Err(error);
        }
        Ok(RunningSession {
            child: Box::new(HelperEngineChild {
                child,
                _config: session,
            }),
            journal,
            engine_created,
            owned_luid: Some(owned_luid),
        })
    }

    fn rollback_failed_start(
        child: &mut dyn ManagedChild,
        journal: &mut TunJournal,
        owned_luid: Option<u64>,
    ) -> Result<(), RuntimeError> {
        let stopped = child.stop();
        let cleanup = wait_for_cleanup(owned_luid, Duration::from_secs(3));
        if stopped.is_ok() && cleanup == CleanupState::Complete {
            journal.complete()
        } else {
            journal.mark_conflict()?;
            Err(RuntimeError::new(
                "session_recovery",
                "failed TUN startup could not be rolled back safely",
            ))
        }
    }

    struct HelperEngineChild {
        child: Box<dyn ManagedChild>,
        _config: SessionConfig,
    }

    impl ManagedChild for HelperEngineChild {
        fn pid(&self) -> u32 {
            self.child.pid()
        }

        fn is_alive(&mut self) -> Result<bool, RuntimeError> {
            self.child.is_alive()
        }

        fn stop(&mut self) -> Result<(), RuntimeError> {
            self.child.stop()
        }
    }

    fn serve_running(
        pipe: &mut File,
        invocation: &HelperInvocation,
        state: &mut ServerState,
        child: &mut dyn ManagedChild,
        journal: &mut TunJournal,
        owned_luid: Option<u64>,
    ) -> Result<(), RuntimeError> {
        loop {
            let frame = match read_frame(pipe) {
                Ok(frame) => frame,
                Err(_) => {
                    let stop = child.stop();
                    let cleanup = wait_for_cleanup(owned_luid, Duration::from_secs(3));
                    if stop.is_ok() && cleanup == CleanupState::Complete {
                        journal.complete()?;
                        return Ok(());
                    }
                    journal.mark_conflict()?;
                    return Err(RuntimeError::new(
                        "stop_engine",
                        "GUI disconnected and TUN cleanup could not be verified",
                    ));
                }
            };
            if frame_session(&frame).is_some_and(|session| session != invocation.session) {
                return Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN helper session changed",
                ));
            }
            state.accept(&frame).map_err(protocol_runtime_error)?;
            match frame {
                Frame::Status { request_id, .. } => {
                    let alive = child.is_alive()?;
                    if alive {
                        match owned_luid.and_then(|luid| inspect_owned_capture(luid).ok()) {
                            Some(capture) => write_frame(
                                pipe,
                                &Frame::State {
                                    request_id,
                                    phase: HelperPhase::Running,
                                    engine_pid: Some(child.pid()),
                                    cleanup: CleanupState::NotRequired,
                                    capture: Some(capture),
                                },
                            )
                            .map_err(protocol_runtime_error)?,
                            None => write_frame(
                                pipe,
                                &Frame::Failure {
                                    request_id,
                                    code: HelperFailureCode::CaptureInvalid,
                                    safe_detail: Some(
                                        "RouteDeck TUN capture routes are missing or no longer own the system path"
                                            .into(),
                                    ),
                                },
                            )
                            .map_err(protocol_runtime_error)?,
                        }
                    } else {
                        write_frame(
                            pipe,
                            &Frame::State {
                                request_id,
                                phase: HelperPhase::Failed,
                                engine_pid: None,
                                cleanup: CleanupState::NotRequired,
                                capture: None,
                            },
                        )
                        .map_err(protocol_runtime_error)?;
                    }
                }
                Frame::StopTun { request_id, .. } => {
                    let stop = child.stop();
                    let cleanup = wait_for_cleanup(owned_luid, Duration::from_secs(3));
                    if stop.is_ok() && cleanup == CleanupState::Complete {
                        journal.complete()?;
                    } else {
                        journal.mark_conflict()?;
                    }
                    write_frame(
                        pipe,
                        &Frame::Stopped {
                            request_id,
                            cleanup,
                        },
                    )
                    .map_err(protocol_runtime_error)?;
                    return if stop.is_ok() && cleanup == CleanupState::Complete {
                        Ok(())
                    } else {
                        Err(RuntimeError::new(
                            "stop_engine",
                            "TUN helper cleanup requires review",
                        ))
                    };
                }
                _ => {
                    return Err(RuntimeError::new(
                        "tun_helper_protocol",
                        "TUN helper received an unexpected running request",
                    ))
                }
            }
        }
    }

    fn frame_session(frame: &Frame) -> Option<&str> {
        match frame {
            Frame::StopTun { session, .. } | Frame::Status { session, .. } => Some(session),
            _ => None,
        }
    }

    fn duplicate_config(parent: HANDLE, request: &StartRequest) -> Result<File, RuntimeError> {
        let source = request.config_handle_id as usize as HANDLE;
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "TUN config handle is invalid",
            ));
        }
        let mut duplicated = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                parent,
                source,
                GetCurrentProcess(),
                &mut duplicated,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(last_error(
                "tun_helper_config",
                "could not duplicate the protected TUN config handle",
            ));
        }
        Ok(unsafe { File::from_raw_handle(duplicated) })
    }

    fn read_verified_config(
        mut config: File,
        request: &StartRequest,
    ) -> Result<String, RuntimeError> {
        config
            .seek(SeekFrom::Start(0))
            .map_err(|error| RuntimeError::new("tun_helper_config", error.to_string()))?;
        let mut bytes = Vec::with_capacity(request.config_len as usize);
        config
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| RuntimeError::new("tun_helper_config", error.to_string()))?;
        if bytes.len() as u64 != request.config_len || bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN config length changed",
            ));
        }
        let actual = format!("{:x}", Sha256::digest(&bytes));
        if !constant_time_eq(actual.as_bytes(), request.config_sha256.as_bytes()) {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN config hash changed",
            ));
        }
        String::from_utf8(bytes).map_err(|_| {
            RuntimeError::new("tun_helper_config", "protected TUN config is not UTF-8")
        })
    }

    fn protected_config_directory(config: &File) -> Result<PathBuf, RuntimeError> {
        let path = final_path(config)?;
        if path.file_name() != Some(OsStr::new("config.json")) {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN config file name is invalid",
            ));
        }
        let directory = path.parent().ok_or_else(|| {
            RuntimeError::new(
                "tun_helper_config",
                "protected TUN config directory is missing",
            )
        })?;
        let session_name = directory
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix("session-"))
            .ok_or_else(|| {
                RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN session identity is invalid",
                )
            })?;
        session_id(session_name).map_err(protocol_runtime_error)?;
        if directory
            .parent()
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            != Some("sessions")
        {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN session root is invalid",
            ));
        }
        for checked in [
            directory,
            directory.parent().expect("session root checked above"),
        ] {
            let metadata = fs::symlink_metadata(checked).map_err(|_| {
                RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN session directory could not be inspected",
                )
            })?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN session directory identity was rejected",
                ));
            }
        }
        Ok(directory.to_owned())
    }

    fn final_path(file: &File) -> Result<PathBuf, RuntimeError> {
        let mut buffer = vec![0_u16; 1024];
        loop {
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if length == 0 {
                return Err(last_error(
                    "tun_helper_config",
                    "could not resolve the protected TUN config handle",
                ));
            }
            if length < buffer.len() as u32 {
                buffer.truncate(length as usize);
                let path = OsString::from_wide(&buffer);
                let text = path.to_string_lossy();
                let normalized = text.strip_prefix(r"\\?\").unwrap_or(&text);
                return Ok(PathBuf::from(normalized));
            }
            if length > 32_767 {
                return Err(RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN config path exceeds the Windows limit",
                ));
            }
            buffer.resize(length as usize + 1, 0);
        }
    }

    fn validate_tun_config(contents: &str) -> Result<(), RuntimeError> {
        let root: serde_json::Value = serde_json::from_str(contents).map_err(|_| {
            RuntimeError::new(
                "tun_helper_config",
                "protected TUN config is not valid JSON",
            )
        })?;
        let object = root.as_object().ok_or_else(|| {
            RuntimeError::new("tun_helper_config", "protected TUN config root is invalid")
        })?;
        let allowed = ["log", "dns", "inbounds", "outbounds", "route"];
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN config contains an unsupported root field",
            ));
        }
        let inbounds = object
            .get("inbounds")
            .and_then(serde_json::Value::as_array)
            .filter(|items| !items.is_empty() && items.len() <= 8)
            .ok_or_else(|| {
                RuntimeError::new("tun_helper_config", "protected TUN inbounds are invalid")
            })?;
        let mut tun_count = 0;
        for inbound in inbounds {
            let inbound = inbound.as_object().ok_or_else(|| {
                RuntimeError::new("tun_helper_config", "protected TUN inbound is invalid")
            })?;
            if inbound.get("type").and_then(serde_json::Value::as_str) == Some("tun") {
                tun_count += 1;
                if inbound.get("tag").and_then(serde_json::Value::as_str) != Some("tun-in")
                    || inbound
                        .get("interface_name")
                        .and_then(serde_json::Value::as_str)
                        != Some(TUN_INTERFACE_NAME)
                    || inbound
                        .get("auto_route")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                    || inbound
                        .get("strict_route")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                    || inbound.get("stack").and_then(serde_json::Value::as_str) != Some("system")
                {
                    return Err(RuntimeError::new(
                        "tun_helper_config",
                        "protected TUN inbound policy is invalid",
                    ));
                }
            } else if inbound.get("listen").and_then(serde_json::Value::as_str) != Some("127.0.0.1")
            {
                return Err(RuntimeError::new(
                    "tun_helper_config",
                    "protected local inbound is not loopback-only",
                ));
            }
        }
        if tun_count != 1
            || object
                .get("route")
                .and_then(serde_json::Value::as_object)
                .and_then(|route| route.get("auto_detect_interface"))
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN route policy is invalid",
            ));
        }
        Ok(())
    }

    struct HelperInvocation {
        session: String,
        pipe_suffix: String,
        parent_pid: u32,
        parent_created: u64,
    }

    impl HelperInvocation {
        fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, RuntimeError> {
            let args = args.into_iter().collect::<Vec<_>>();
            if args.len() != 9
                || args[1] != "--session"
                || args[3] != "--pipe-suffix"
                || args[5] != "--parent-pid"
                || args[7] != "--parent-created"
            {
                return Err(RuntimeError::new(
                    "tun_helper_arguments",
                    "TUN helper arguments are invalid",
                ));
            }
            let session = strict_unicode(&args[2])?;
            let suffix = strict_unicode(&args[4])?;
            session_id(&session).map_err(protocol_runtime_error)?;
            pipe_suffix(&suffix).map_err(protocol_runtime_error)?;
            let parent_pid = strict_decimal(&args[6])?
                .parse::<u32>()
                .map_err(|_| RuntimeError::new("tun_helper_arguments", "parent PID is invalid"))?;
            let parent_created = strict_decimal(&args[8])?.parse::<u64>().map_err(|_| {
                RuntimeError::new("tun_helper_arguments", "parent creation time is invalid")
            })?;
            if parent_pid == 0 || parent_created == 0 {
                return Err(RuntimeError::new(
                    "tun_helper_arguments",
                    "parent identity is invalid",
                ));
            }
            Ok(Self {
                session,
                pipe_suffix: suffix,
                parent_pid,
                parent_created,
            })
        }
    }

    fn strict_unicode(value: &OsStr) -> Result<String, RuntimeError> {
        value.to_str().map(str::to_owned).ok_or_else(|| {
            RuntimeError::new("tun_helper_arguments", "helper argument is not Unicode")
        })
    }

    fn strict_decimal(value: &OsStr) -> Result<String, RuntimeError> {
        let value = strict_unicode(value)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RuntimeError::new(
                "tun_helper_arguments",
                "helper numeric argument is invalid",
            ));
        }
        Ok(value)
    }

    fn helper_arguments(
        session: &str,
        suffix: &str,
        parent_pid: u32,
        parent_created: u64,
    ) -> Result<String, RuntimeError> {
        session_id(session).map_err(protocol_runtime_error)?;
        pipe_suffix(suffix).map_err(protocol_runtime_error)?;
        let value = format!(
            "--session {session} --pipe-suffix {suffix} --parent-pid {parent_pid} --parent-created {parent_created}"
        );
        if value.len() > 512
            || value
                .bytes()
                .any(|byte| matches!(byte, b'"' | b'\'' | b'/' | b'\\' | b'&' | b'|' | b';'))
        {
            return Err(RuntimeError::new(
                "tun_helper_arguments",
                "fixed helper arguments are invalid",
            ));
        }
        Ok(value)
    }

    fn create_server_pipe(suffix: &str) -> Result<File, RuntimeError> {
        pipe_suffix(suffix).map_err(protocol_runtime_error)?;
        let name = pipe_name(suffix);
        let wide = wide(&name)?;
        let descriptor = SecurityDescriptor::pipe()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.raw(),
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1.min(PIPE_UNLIMITED_INSTANCES),
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &attributes,
            )
        };
        let handle = OwnedHandle::new(
            handle,
            "tun_helper_pipe",
            "could not create the private TUN helper pipe",
        )?;
        Ok(unsafe { File::from_raw_handle(handle.into_raw()) })
    }

    fn connect_helper(pipe: &File, helper: &OwnedHandle) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + HELPER_CONNECT_TIMEOUT;
        loop {
            let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) };
            if connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                let mode = PIPE_READMODE_BYTE | PIPE_WAIT;
                if unsafe {
                    SetNamedPipeHandleState(pipe.as_raw_handle(), &mode, ptr::null(), ptr::null())
                } == 0
                {
                    return Err(last_error(
                        "tun_helper_pipe",
                        "could not switch the helper pipe to blocking mode",
                    ));
                }
                return Ok(());
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_LISTENING {
                return Err(last_error(
                    "tun_helper_pipe",
                    "could not accept the elevated TUN helper",
                ));
            }
            if unsafe { WaitForSingleObject(helper.raw(), 0) } == WAIT_OBJECT_0 {
                return Err(RuntimeError::new(
                    "tun_helper_pipe",
                    "elevated TUN helper exited before authentication",
                ));
            }
            if Instant::now() >= deadline {
                return Err(RuntimeError::new(
                    "tun_helper_pipe",
                    "elevated TUN helper authentication timed out",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn connect_parent_pipe(suffix: &str) -> Result<File, RuntimeError> {
        pipe_suffix(suffix).map_err(protocol_runtime_error)?;
        let wide = wide(pipe_name(suffix))?;
        let deadline = Instant::now() + HELPER_CONNECT_TIMEOUT;
        loop {
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                return Ok(unsafe { File::from_raw_handle(handle) });
            }
            if Instant::now() >= deadline {
                return Err(last_error(
                    "tun_helper_pipe",
                    "could not connect to the RouteDeck helper pipe",
                ));
            }
            unsafe { WaitNamedPipeW(wide.as_ptr(), 100) };
        }
    }

    fn pipe_name(suffix: &str) -> String {
        format!("{PIPE_PREFIX}{suffix}")
    }

    fn pipe_client_pid(pipe: &File) -> Result<u32, RuntimeError> {
        let mut pid = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } == 0 || pid == 0 {
            return Err(last_error(
                "tun_helper_pipe",
                "could not authenticate the TUN helper pipe client",
            ));
        }
        Ok(pid)
    }

    fn authenticate_parent(pipe: &File, invocation: &HelperInvocation) -> Result<(), RuntimeError> {
        let mut server_pid = 0;
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server_pid) } == 0
            || server_pid != invocation.parent_pid
        {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "TUN helper pipe server identity was rejected",
            ));
        }
        let parent = open_verified_parent(invocation)?;
        let image = process_image(parent.raw())?;
        let helper = std::env::current_exe()
            .map_err(|error| RuntimeError::new("tun_helper_identity", error.to_string()))?;
        if image.file_name() != Some(OsStr::new(GUI_FILE_NAME)) || image.parent() != helper.parent()
        {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "TUN helper parent image was rejected",
            ));
        }
        Ok(())
    }

    fn open_verified_parent(invocation: &HelperInvocation) -> Result<OwnedHandle, RuntimeError> {
        let parent = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_SYNCHRONIZE,
                0,
                invocation.parent_pid,
            )
        };
        let parent = OwnedHandle::new(
            parent,
            "tun_helper_identity",
            "could not open the RouteDeck parent process",
        )?;
        if process_creation_time(parent.raw())? != invocation.parent_created {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "RouteDeck parent creation time changed",
            ));
        }
        Ok(parent)
    }

    fn fixed_helper_path() -> Result<PathBuf, RuntimeError> {
        let current = std::env::current_exe()
            .map_err(|error| RuntimeError::new("tun_helper_identity", error.to_string()))?;
        let parent = current.parent().ok_or_else(|| {
            RuntimeError::new("tun_helper_identity", "RouteDeck executable has no parent")
        })?;
        let helper = parent.join(HELPER_FILE_NAME);
        let metadata = fs::symlink_metadata(&helper).map_err(|_| {
            RuntimeError::new(
                "tun_helper_identity",
                "TUN helper is missing from the RouteDeck directory",
            )
        })?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "TUN helper file identity was rejected",
            ));
        }
        Ok(helper)
    }

    fn verify_helper_for_launch(
        path: &Path,
        expected_helper_sha256: Option<&str>,
    ) -> Result<File, RuntimeError> {
        let (guard, actual) = open_and_hash_helper(path)?;
        verify_helper_digest(
            &actual,
            expected_helper_sha256,
            cfg!(debug_assertions)
                && std::env::var_os("ROUTEDECK_ALLOW_UNPINNED_TUN_HELPER").as_deref()
                    == Some(OsStr::new("1")),
        )?;
        Ok(guard)
    }

    fn verify_helper_digest(
        actual: &str,
        expected: Option<&str>,
        allow_unpinned_debug: bool,
    ) -> Result<(), RuntimeError> {
        if allow_unpinned_debug {
            return Ok(());
        }
        let expected = expected.ok_or_else(|| {
            RuntimeError::new(
                "tun_helper_identity",
                "TUN helper hash is not embedded in this RouteDeck build",
            )
        })?;
        if expected.len() != 64
            || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
            || actual.len() != 64
            || !actual.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !constant_time_eq(actual.as_bytes(), expected.to_ascii_lowercase().as_bytes())
        {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "TUN helper hash does not match this RouteDeck build",
            ));
        }
        Ok(())
    }

    fn open_and_hash_helper(path: &Path) -> Result<(File, String), RuntimeError> {
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|_| {
                RuntimeError::new("tun_helper_identity", "could not hold the TUN helper file")
            })?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file.read(&mut buffer).map_err(|_| {
                RuntimeError::new("tun_helper_identity", "could not hash the TUN helper file")
            })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok((file, format!("{:x}", hasher.finalize())))
    }

    fn shell_execute_runas(path: &Path, arguments: &str) -> Result<OwnedHandle, RuntimeError> {
        let verb = wide("runas")?;
        let file = wide(path.as_os_str())?;
        let parameters = wide(arguments)?;
        let directory = path.parent().ok_or_else(|| {
            RuntimeError::new("tun_helper_identity", "TUN helper directory is invalid")
        })?;
        let directory = wide(directory.as_os_str())?;
        let mut information = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            hwnd: ptr::null_mut(),
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: parameters.as_ptr(),
            lpDirectory: directory.as_ptr(),
            nShow: 0,
            hInstApp: ptr::null_mut(),
            lpIDList: ptr::null_mut(),
            lpClass: ptr::null(),
            hkeyClass: ptr::null_mut(),
            dwHotKey: 0,
            Anonymous: Default::default(),
            hProcess: ptr::null_mut(),
        };
        if unsafe { ShellExecuteExW(&mut information) } == 0 {
            return Err(shell_launch_error(unsafe { GetLastError() }));
        }
        OwnedHandle::new(
            information.hProcess,
            "tun_helper_launch",
            "Windows did not return the TUN helper process handle",
        )
    }

    fn shell_launch_error(code: u32) -> RuntimeError {
        if code == ERROR_CANCELLED {
            RuntimeError::new("tun_uac_cancelled", "TUN permission request was cancelled")
        } else {
            RuntimeError::new(
                "tun_helper_launch",
                format!("could not start the elevated TUN helper (Windows error {code})"),
            )
        }
    }

    fn process_creation_time_for_pid(pid: u32) -> Result<u64, RuntimeError> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        let process = OwnedHandle::new(
            process,
            "engine_process",
            "could not open the helper-owned engine process",
        )?;
        process_creation_time(process.raw())
    }

    fn process_creation_time(process: HANDLE) -> Result<u64, RuntimeError> {
        let mut creation = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = windows_sys::Win32::Foundation::FILETIME::default();
        let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
        let mut user = windows_sys::Win32::Foundation::FILETIME::default();
        if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(last_error(
                "tun_helper_identity",
                "could not read process creation time",
            ));
        }
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }

    fn process_image(process: HANDLE) -> Result<PathBuf, RuntimeError> {
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0
            || length == 0
        {
            return Err(last_error(
                "tun_helper_identity",
                "could not read the RouteDeck parent image",
            ));
        }
        buffer.truncate(length as usize);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AdapterState {
        luid: u64,
        friendly_name: String,
        description: String,
        if_type: u32,
        tunnel_type: i32,
        physical_address_length: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RouteState {
        luid: u64,
        family: u16,
        prefix: [u8; 16],
        prefix_len: u8,
        metric: u32,
    }

    fn adapter_states() -> Result<Vec<AdapterState>, RuntimeError> {
        let flags = GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER
            | GAA_FLAG_SKIP_UNICAST;
        let mut size = 16 * 1024_u32;
        for _ in 0..3 {
            let mut buffer = vec![0_u8; size as usize];
            let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let status = unsafe {
                GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), first, &mut size)
            };
            if status == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if status != 0 {
                return Err(RuntimeError::new(
                    "tun_preflight",
                    format!("could not enumerate adapters (Windows error {status})"),
                ));
            }
            let mut output = Vec::new();
            let mut current = first;
            while !current.is_null() {
                let adapter = unsafe { &*current };
                output.push(AdapterState {
                    luid: unsafe { adapter.Luid.Value },
                    friendly_name: wide_ptr_string(adapter.FriendlyName).unwrap_or_default(),
                    description: wide_ptr_string(adapter.Description).unwrap_or_default(),
                    if_type: adapter.IfType,
                    tunnel_type: adapter.TunnelType,
                    physical_address_length: adapter.PhysicalAddressLength,
                });
                current = adapter.Next;
            }
            output.sort_by_key(|adapter| adapter.luid);
            output.dedup_by_key(|adapter| adapter.luid);
            return Ok(output);
        }
        Err(RuntimeError::new(
            "tun_preflight",
            "adapter enumeration changed repeatedly",
        ))
    }

    fn find_tun_adapter_luids() -> Result<Vec<u64>, RuntimeError> {
        Ok(adapter_states()?
            .into_iter()
            .filter(|adapter| adapter.friendly_name == TUN_INTERFACE_NAME)
            .map(|adapter| adapter.luid)
            .collect())
    }

    fn route_states() -> Result<Vec<RouteState>, RuntimeError> {
        let mut table = ptr::null_mut::<MIB_IPFORWARD_TABLE2>();
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
        if status != 0 || table.is_null() {
            return Err(RuntimeError::new(
                "tun_preflight",
                "Windows routing table could not be inspected",
            ));
        }
        let count = unsafe { (*table).NumEntries as usize };
        if count > 1_000_000 {
            unsafe { FreeMibTable(table.cast()) };
            return Err(RuntimeError::new(
                "tun_preflight",
                "Windows routing table returned an invalid size",
            ));
        }
        let first = unsafe { ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>() };
        let rows = unsafe { std::slice::from_raw_parts(first, count) };
        let mut output = Vec::with_capacity(count);
        for row in rows {
            let family = unsafe { row.DestinationPrefix.Prefix.si_family };
            let mut prefix = [0_u8; 16];
            if family == AF_INET {
                prefix[..4].copy_from_slice(
                    &unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr }
                        .to_ne_bytes(),
                );
            } else if family == AF_INET6 {
                prefix = unsafe { row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte };
            } else {
                continue;
            }
            output.push(RouteState {
                luid: unsafe { row.InterfaceLuid.Value },
                family,
                prefix,
                prefix_len: row.DestinationPrefix.PrefixLength,
                metric: row.Metric,
            });
        }
        unsafe { FreeMibTable(table.cast()) };
        Ok(output)
    }

    fn looks_like_foreign_tunnel(adapter: &AdapterState) -> bool {
        let signal = format!("{} {}", adapter.friendly_name, adapter.description).to_lowercase();
        adapter.tunnel_type != TUNNEL_TYPE_NONE
            || matches!(adapter.if_type, IF_TYPE_TUNNEL | IF_TYPE_PPP)
            || (adapter.physical_address_length == 0
                && !matches!(adapter.if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211))
            || [
                "vpn",
                "tun",
                "wintun",
                "wireguard",
                "tailscale",
                "zerotier",
                "xray",
                "kwik",
            ]
            .iter()
            .any(|marker| signal.contains(marker))
    }

    fn foreign_full_tunnel<'a>(
        adapters: &'a [AdapterState],
        routes: &[RouteState],
    ) -> Option<&'a AdapterState> {
        let v4_left = [1_u8, 1, 1, 1];
        let v4_right = [200_u8, 1, 1, 1];
        let v6_left = [0x20_u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let v6_right = [0xa0_u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        adapters.iter().find(|adapter| {
            if adapter.friendly_name == TUN_INTERFACE_NAME || !looks_like_foreign_tunnel(adapter) {
                return false;
            }
            let covers = |family, address: &[u8]| {
                routes.iter().any(|route| {
                    route.luid == adapter.luid && address_is_covered(route, family, address)
                })
            };
            (covers(AF_INET, &v4_left) && covers(AF_INET, &v4_right))
                || (covers(AF_INET6, &v6_left) && covers(AF_INET6, &v6_right))
        })
    }

    fn preflight_route_context() -> Result<String, RuntimeError> {
        let adapters = adapter_states()?;
        let mut routes = route_states()?;
        if foreign_full_tunnel(&adapters, &routes).is_some() {
            return Err(RuntimeError::new(
                "tun_preflight",
                "another full-tunnel VPN is active; turn it off before starting RouteDeck TUN",
            ));
        }
        routes.retain(|route| route.prefix_len <= 1);
        routes.sort_by_key(|route| {
            (
                route.family,
                route.luid,
                route.prefix_len,
                route.prefix,
                route.metric,
            )
        });
        let mut hasher = Sha256::new();
        hasher.update(b"RouteDeck Windows route preflight v1\0");
        for route in routes {
            hasher.update(route.family.to_le_bytes());
            hasher.update(route.luid.to_le_bytes());
            hasher.update([route.prefix_len]);
            hasher.update(route.prefix);
            hasher.update(route.metric.to_le_bytes());
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn address_is_covered(route: &RouteState, family: u16, address: &[u8]) -> bool {
        if route.family != family || route.prefix_len as usize > address.len() * 8 {
            return false;
        }
        let whole = route.prefix_len as usize / 8;
        let remaining = route.prefix_len as usize % 8;
        if route.prefix[..whole] != address[..whole] {
            return false;
        }
        remaining == 0
            || (route.prefix[whole] & (0xff << (8 - remaining)))
                == (address[whole] & (0xff << (8 - remaining)))
    }

    fn best_route_luid_v4(address: [u8; 4]) -> Result<u64, RuntimeError> {
        let destination = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address),
                    },
                },
                sin_zero: [0; 8],
            },
        };
        best_route_luid(&destination)
    }

    fn best_route_luid_v6(address: [u8; 16]) -> Result<u64, RuntimeError> {
        let destination = SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: address },
                },
                Anonymous: Default::default(),
            },
        };
        best_route_luid(&destination)
    }

    fn best_route_luid(destination: &SOCKADDR_INET) -> Result<u64, RuntimeError> {
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        let status = unsafe {
            GetBestRoute2(
                ptr::null(),
                0,
                ptr::null(),
                destination,
                0,
                &mut route,
                &mut source,
            )
        };
        if status != 0 {
            return Err(RuntimeError::new(
                "tun_capture",
                "Windows could not resolve the effective TUN capture route",
            ));
        }
        Ok(unsafe { route.InterfaceLuid.Value })
    }

    fn inspect_owned_capture(luid: u64) -> Result<TunInterfaceState, RuntimeError> {
        let adapters = adapter_states()?;
        if adapters
            .iter()
            .filter(|adapter| adapter.friendly_name == TUN_INTERFACE_NAME)
            .map(|adapter| adapter.luid)
            .collect::<Vec<_>>()
            != [luid]
        {
            return Err(RuntimeError::new(
                "tun_capture",
                "the exact helper-owned RouteDeck TUN adapter is missing or ambiguous",
            ));
        }
        let routes = route_states()?;
        if foreign_full_tunnel(&adapters, &routes).is_some() {
            return Err(RuntimeError::new(
                "tun_capture",
                "another full-tunnel VPN became active during the RouteDeck TUN session",
            ));
        }
        let v4 = [1_u8, 1, 1, 1];
        let v6 = [
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ];
        let owns_v4 = routes
            .iter()
            .any(|route| route.luid == luid && address_is_covered(route, AF_INET, &v4));
        let owns_v6 = routes
            .iter()
            .any(|route| route.luid == luid && address_is_covered(route, AF_INET6, &v6));
        if !owns_v4
            || !owns_v6
            || best_route_luid_v4(v4)? != luid
            || best_route_luid_v6(v6)? != luid
        {
            return Err(RuntimeError::new(
                "tun_capture",
                "RouteDeck does not own the effective IPv4 and IPv6 capture routes",
            ));
        }
        let mut row = MIB_IF_ROW2::default();
        row.InterfaceLuid.Value = luid;
        if unsafe { GetIfEntry2(&mut row) } != 0 {
            return Err(RuntimeError::new(
                "tun_capture",
                "RouteDeck TUN adapter counters could not be inspected",
            ));
        }
        Ok(TunInterfaceState {
            interface_luid: luid,
            in_octets: row.InOctets,
            out_octets: row.OutOctets,
        })
    }

    fn wide_ptr_string(pointer: *const u16) -> Option<String> {
        if pointer.is_null() {
            return None;
        }
        let mut length = 0_usize;
        while length < 1024 && unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        (length < 1024).then(|| {
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
        })
    }

    fn verify_cleanup(owned_luid: Option<u64>) -> CleanupState {
        match find_tun_adapter_luids() {
            Ok(current) => match owned_luid {
                Some(luid) if current.contains(&luid) => CleanupState::Conflict,
                _ if current.is_empty() => CleanupState::Complete,
                _ => CleanupState::Conflict,
            },
            Err(_) => CleanupState::Conflict,
        }
    }

    fn wait_for_cleanup(owned_luid: Option<u64>, timeout: Duration) -> CleanupState {
        let deadline = Instant::now() + timeout;
        loop {
            let cleanup = verify_cleanup(owned_luid);
            if cleanup == CleanupState::Complete || Instant::now() >= deadline {
                return cleanup;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    struct TunJournal {
        path: PathBuf,
        file: Option<File>,
        session: String,
        config_sha256: String,
    }

    impl TunJournal {
        fn create(
            session_directory: &Path,
            session: &str,
            config_sha256: &str,
        ) -> Result<Self, RuntimeError> {
            let path = session_directory.join("tun-journal.json");
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ);
            let mut file = options
                .open(&path)
                .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
            write_journal(
                &mut file,
                serde_json::json!({
                    "schemaVersion": 1,
                    "session": session,
                    "phase": "starting",
                    "configSha256": config_sha256,
                }),
            )?;
            Ok(Self {
                path,
                file: Some(file),
                session: session.to_owned(),
                config_sha256: config_sha256.to_owned(),
            })
        }

        fn mark_running(
            &mut self,
            engine_pid: u32,
            engine_created: u64,
        ) -> Result<(), RuntimeError> {
            self.write(serde_json::json!({
                "schemaVersion": 1,
                "session": self.session,
                "phase": "running",
                "configSha256": self.config_sha256,
                "enginePid": engine_pid,
                "engineCreated": engine_created,
            }))
        }

        fn mark_conflict(&mut self) -> Result<(), RuntimeError> {
            self.write(serde_json::json!({
                "schemaVersion": 1,
                "session": self.session,
                "phase": "conflict",
                "configSha256": self.config_sha256,
            }))
        }

        fn mark_capture(
            &mut self,
            engine_pid: u32,
            engine_created: u64,
            owned_luid: u64,
        ) -> Result<(), RuntimeError> {
            let routes = route_states()?
                .into_iter()
                .filter(|route| route.luid == owned_luid)
                .map(|route| {
                    serde_json::json!({
                        "family": route.family,
                        "prefix": route.prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                        "prefixLength": route.prefix_len,
                        "metric": route.metric,
                    })
                })
                .collect::<Vec<_>>();
            self.write(serde_json::json!({
                "schemaVersion": 2,
                "session": self.session,
                "phase": "capture_verified",
                "configSha256": self.config_sha256,
                "enginePid": engine_pid,
                "engineCreated": engine_created,
                "ownedInterfaceLuid": owned_luid,
                "ownedRoutes": routes,
            }))
        }

        fn write(&mut self, value: serde_json::Value) -> Result<(), RuntimeError> {
            let file = self.file.as_mut().ok_or_else(|| {
                RuntimeError::new("session_storage", "TUN journal handle is closed")
            })?;
            write_journal(file, value)
        }

        fn complete(&mut self) -> Result<(), RuntimeError> {
            self.file.take();
            fs::remove_file(&self.path)
                .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
            Ok(())
        }
    }

    fn write_journal(file: &mut File, value: serde_json::Value) -> Result<(), RuntimeError> {
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| RuntimeError::new("session_storage", "could not encode TUN journal"))?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.set_len(0))
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.sync_all())
            .map_err(|error| RuntimeError::new("session_storage", error.to_string()))
    }

    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        fn pipe() -> Result<Self, RuntimeError> {
            let text = wide("D:P(A;;GA;;;OW)(A;;GA;;;BA)(A;;GA;;;SY)")?;
            let mut descriptor = ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(last_error(
                    "tun_helper_pipe",
                    "could not create the TUN helper pipe ACL",
                ));
            }
            Ok(Self(descriptor))
        }

        fn raw(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
        }
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(
            handle: HANDLE,
            stage: &'static str,
            message: &'static str,
        ) -> Result<Self, RuntimeError> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                Err(last_error(stage, message))
            } else {
                Ok(Self(handle))
            }
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn into_raw(mut self) -> HANDLE {
            let handle = self.0;
            self.0 = ptr::null_mut();
            handle
        }
    }

    unsafe impl Send for OwnedHandle {}

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn unix_seconds() -> Result<u64, RuntimeError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| RuntimeError::new("tun_helper_protocol", "system clock is invalid"))
    }

    fn safe_helper_detail(stage: &str) -> &'static str {
        match stage {
            "tun_preflight" => "TUN could not start because the adapter state is not ready",
            "tun_capture" => {
                "TUN started but did not obtain effective IPv4 and IPv6 capture routes"
            }
            "tun_helper_config" | "config_check" => "The generated TUN configuration was rejected",
            "engine_integrity" | "engine_layout" => {
                "The reviewed sing-box component could not be verified"
            }
            "session_recovery" => "Previous TUN cleanup requires review",
            _ => "The elevated TUN helper could not start sing-box",
        }
    }

    fn helper_failure_code(stage: &str) -> HelperFailureCode {
        match stage {
            "tun_preflight" => HelperFailureCode::PreflightConflict,
            "tun_capture" => HelperFailureCode::CaptureInvalid,
            _ => HelperFailureCode::StartFailed,
        }
    }

    fn protocol_runtime_error(error: impl std::fmt::Display) -> RuntimeError {
        let _ = error;
        RuntimeError::new("tun_helper_protocol", "TUN helper protocol was rejected")
    }

    fn last_error(stage: &'static str, message: &'static str) -> RuntimeError {
        RuntimeError::new(
            stage,
            format!("{message} (Windows error {})", unsafe { GetLastError() }),
        )
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
                == 0
    }

    fn wide(value: impl AsRef<OsStr>) -> Result<Vec<u16>, RuntimeError> {
        let mut value = value.as_ref().encode_wide().collect::<Vec<_>>();
        if value.contains(&0) {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "Windows helper value contains an invalid NUL",
            ));
        }
        value.push(0);
        Ok(value)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn helper_arguments_have_one_fixed_pathless_shape() {
            let session = "01".repeat(16);
            let suffix = "02".repeat(16);
            let arguments = helper_arguments(&session, &suffix, 123, 456).unwrap();
            assert_eq!(
                arguments,
                format!(
                    "--session {session} --pipe-suffix {suffix} --parent-pid 123 --parent-created 456"
                )
            );
            assert!(!arguments.contains(['"', '\'', '/', '\\', '&', '|', ';']));
        }

        #[test]
        fn helper_argument_parser_rejects_extra_flags_paths_and_noncanonical_ids() {
            let good = vec![
                OsString::from("helper.exe"),
                OsString::from("--session"),
                OsString::from("01".repeat(16)),
                OsString::from("--pipe-suffix"),
                OsString::from("02".repeat(16)),
                OsString::from("--parent-pid"),
                OsString::from("123"),
                OsString::from("--parent-created"),
                OsString::from("456"),
            ];
            assert!(HelperInvocation::parse(good.clone()).is_ok());
            let mut extra = good.clone();
            extra.push(OsString::from("--command"));
            assert!(HelperInvocation::parse(extra).is_err());
            let mut path = good.clone();
            path[2] = OsString::from(r"C:\config.json");
            assert!(HelperInvocation::parse(path).is_err());
            let mut uppercase = good;
            uppercase[4] = OsString::from("AA".repeat(16));
            assert!(HelperInvocation::parse(uppercase).is_err());
        }

        #[test]
        fn strict_tun_config_rejects_non_tun_and_non_loopback_inputs() {
            let valid = serde_json::json!({
                "log": {},
                "dns": {},
                "inbounds": [
                    {"type":"http","listen":"127.0.0.1"},
                    {"type":"tun","tag":"tun-in","interface_name":"RouteDeck","auto_route":true,"strict_route":true,"stack":"system"}
                ],
                "outbounds": [],
                "route": {"auto_detect_interface":true}
            });
            assert!(validate_tun_config(&valid.to_string()).is_ok());
            let mut foreign = valid.clone();
            foreign["inbounds"][0]["listen"] = serde_json::json!("0.0.0.0");
            assert!(validate_tun_config(&foreign.to_string()).is_err());
            let mut no_tun = valid;
            no_tun["inbounds"].as_array_mut().unwrap().pop();
            assert!(validate_tun_config(&no_tun.to_string()).is_err());
        }

        #[test]
        fn duplicated_config_path_must_resolve_to_a_generated_session() {
            let root = std::env::temp_dir().join(format!(
                "routedeck-helper-path-test-{}",
                random_hex(8).unwrap()
            ));
            let sessions = root.join("sessions");
            let config = SessionConfig::create(&sessions, "{}").unwrap();
            let guard = config.revalidate_for_launch().unwrap();
            assert_eq!(
                protected_config_directory(&guard).unwrap(),
                config.path().parent().unwrap()
            );
            let mut journal = TunJournal::create(
                config.path().parent().unwrap(),
                &"01".repeat(16),
                &"02".repeat(32),
            )
            .unwrap();
            assert!(config
                .path()
                .parent()
                .unwrap()
                .join("tun-journal.json")
                .is_file());
            journal.complete().unwrap();
            drop(guard);
            drop(config);
            fs::remove_dir(sessions).unwrap();
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn held_helper_file_cannot_be_modified_or_replaced_before_launch() {
            let root = std::env::temp_dir().join(format!(
                "routedeck-helper-guard-test-{}",
                random_hex(8).unwrap()
            ));
            fs::create_dir(&root).unwrap();
            let helper = root.join(HELPER_FILE_NAME);
            fs::write(&helper, b"reviewed helper fixture").unwrap();
            let (guard, digest) = open_and_hash_helper(&helper).unwrap();
            assert_eq!(digest.len(), 64);
            assert!(OpenOptions::new().write(true).open(&helper).is_err());
            assert!(fs::rename(&helper, root.join("replaced.exe")).is_err());
            drop(guard);
            fs::remove_file(helper).unwrap();
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn exact_embedded_hash_accepts_an_unsigned_local_helper() {
            let root = std::env::temp_dir().join(format!(
                "routedeck-helper-pin-test-{}",
                random_hex(8).unwrap()
            ));
            fs::create_dir(&root).unwrap();
            let helper = root.join(HELPER_FILE_NAME);
            fs::write(&helper, b"unsigned portable helper fixture").unwrap();
            let (guard, digest) = open_and_hash_helper(&helper).unwrap();

            verify_helper_digest(&digest, Some(&digest), false).unwrap();

            drop(guard);
            fs::remove_file(helper).unwrap();
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn missing_or_mismatched_embedded_helper_hash_is_rejected() {
            let actual = "01".repeat(32);
            let other = "02".repeat(32);

            assert!(verify_helper_digest(&actual, None, false).is_err());
            assert!(verify_helper_digest(&actual, Some(&other), false).is_err());
            assert!(verify_helper_digest(&actual, Some("not-a-digest"), false).is_err());
            assert!(verify_helper_digest(&actual, None, true).is_ok());
        }

        #[test]
        fn cancellation_is_distinct_and_precedes_any_session_or_journal_creation() {
            let error = shell_launch_error(ERROR_CANCELLED);
            assert_eq!(error.stage(), "tun_uac_cancelled");
            assert_eq!(shell_launch_error(5).stage(), "tun_helper_launch");
        }

        fn adapter(luid: u64, name: &str, if_type: u32, physical: u32) -> AdapterState {
            AdapterState {
                luid,
                friendly_name: name.into(),
                description: name.into(),
                if_type,
                tunnel_type: TUNNEL_TYPE_NONE,
                physical_address_length: physical,
            }
        }

        fn default_route(luid: u64, family: u16, metric: u32) -> RouteState {
            RouteState {
                luid,
                family,
                prefix: [0; 16],
                prefix_len: 0,
                metric,
            }
        }

        #[test]
        fn foreign_metric_zero_tunnel_blocks_preflight_but_physical_default_does_not() {
            let physical = adapter(1, "Ethernet", IF_TYPE_ETHERNET_CSMACD, 6);
            let xray = adapter(2, "xray_tun", 53, 0);
            let routes = [default_route(1, AF_INET, 25), default_route(2, AF_INET, 0)];
            let adapters = [physical.clone(), xray];
            assert_eq!(foreign_full_tunnel(&adapters, &routes).unwrap().luid, 2);
            assert!(foreign_full_tunnel(&[physical], &routes[..1]).is_none());

            let mut lower_half = default_route(2, AF_INET, 0);
            lower_half.prefix_len = 1;
            let mut upper_half = lower_half;
            upper_half.prefix[0] = 128;
            assert_eq!(
                foreign_full_tunnel(&adapters, &[lower_half, upper_half])
                    .unwrap()
                    .luid,
                2
            );

            let mut host_only = default_route(2, AF_INET, 0);
            host_only.prefix = [172, 30, 205, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            host_only.prefix_len = 32;
            assert!(foreign_full_tunnel(&adapters, &[host_only]).is_none());
        }

        #[test]
        fn capture_route_matching_is_family_and_prefix_exact() {
            let mut route = default_route(7, AF_INET, 0);
            assert!(address_is_covered(&route, AF_INET, &[1, 1, 1, 1]));
            route.prefix = [128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            route.prefix_len = 1;
            assert!(!address_is_covered(&route, AF_INET, &[1, 1, 1, 1]));
            assert!(address_is_covered(&route, AF_INET, &[200, 1, 1, 1]));
            assert!(!address_is_covered(&route, AF_INET6, &[0; 16]));
        }

        #[test]
        fn preflight_digest_binds_config_and_route_snapshot() {
            let base = preflight_digest(&"01".repeat(32), &"02".repeat(32));
            assert_ne!(base, preflight_digest(&"03".repeat(32), &"02".repeat(32)));
            assert_ne!(base, preflight_digest(&"01".repeat(32), &"04".repeat(32)));
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::TunHelperLauncher;

#[cfg(windows)]
pub fn helper_main() -> Result<(), String> {
    windows::helper_main()
}

#[cfg(not(windows))]
pub fn helper_main() -> Result<(), String> {
    Err("TUN helper is available only on Windows".into())
}
