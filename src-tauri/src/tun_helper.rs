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
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::AF_UNSPEC,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_FIRST_PIPE_INSTANCE,
            FILE_SHARE_READ, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
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
            random_hex, reconcile_stale_sessions, DiagnosticBuffer, EngineLauncher, ManagedChild,
            RuntimeError, SessionConfig, VerifiedEngineLauncher,
        },
        redaction::Redactor,
        tun_helper_protocol::{
            pipe_suffix, read_frame, session_id, write_frame, CleanupState, Frame,
            HelperFailureCode, HelperPhase, ServerState, UpstreamChoice, MAX_CONFIG_BYTES,
            PROTOCOL_VERSION,
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
        prepared: Mutex<Option<PreparedTransfer>>,
    }

    struct PreparedTransfer {
        config_guard: File,
        config_len: u64,
        config_sha256: String,
    }

    impl TunHelperLauncher {
        pub(crate) fn resolve() -> Result<Self, RuntimeError> {
            Ok(Self {
                validator: VerifiedEngineLauncher::resolve()?,
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
            launch_helper(prepared).map(|child| Box::new(child) as Box<dyn ManagedChild>)
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

    fn launch_helper(prepared: PreparedTransfer) -> Result<TunHelperChild, RuntimeError> {
        let helper_path = fixed_helper_path()?;
        let _helper_guard = verify_helper_for_launch(&helper_path)?;
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
        let preflight_sha256 = preflight_digest(&prepared.config_sha256);
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
                code: _,
                safe_detail,
            } => Err(RuntimeError::new(
                "start_engine",
                safe_detail.unwrap_or_else(|| "elevated TUN helper rejected startup".into()),
            )),
            _ => Err(RuntimeError::new(
                "tun_helper_protocol",
                "TUN helper returned an unexpected startup response",
            )),
        }
    }

    fn preflight_digest(config_sha256: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"RouteDeck TUN current-path launch context v1\0");
        hasher.update(config_sha256.as_bytes());
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
    }

    impl ManagedChild for TunHelperChild {
        fn pid(&self) -> u32 {
            self.engine_pid
        }

        fn is_alive(&mut self) -> Result<bool, RuntimeError> {
            if self.stopped || !self.helper_running()? {
                return Ok(false);
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
                } if response_id == request_id && pid == self.engine_pid => {
                    let engine = unsafe {
                        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, self.engine_pid)
                    };
                    let engine = OwnedHandle::new(
                        engine,
                        "engine_process",
                        "could not reopen the helper-owned sing-box process",
                    )?;
                    Ok(process_creation_time(engine.raw())? == self.engine_created)
                }
                Frame::State {
                    request_id: response_id,
                    phase: HelperPhase::Stopped | HelperPhase::Failed,
                    ..
                } if response_id == request_id => Ok(false),
                _ => Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN helper returned an unexpected status response",
                )),
            }
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
                && received_nonce == hello_nonce
                && preflight_sha256 == preflight_digest(&config_sha256) =>
            {
                StartRequest {
                    request_id,
                    config_handle_id,
                    config_len,
                    config_sha256,
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
                        code: HelperFailureCode::StartFailed,
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
        if !find_tun_adapter_luids()?.is_empty() {
            return Err(RuntimeError::new(
                "tun_preflight",
                "a RouteDeck TUN adapter already exists",
            ));
        }
        let parent = open_verified_parent(invocation)?;
        let config = duplicate_config(parent.raw(), request)?;
        let contents = read_verified_config(config, request)?;
        validate_tun_config(&contents)?;

        let root = helper_session_root();
        reconcile_stale_sessions(&root)?;
        let session = SessionConfig::create(&root, &contents)?;
        let diagnostics = Arc::new(Mutex::new(DiagnosticBuffer::default()));
        let redactor = Redactor::default().with_secret(&contents);
        let launcher = VerifiedEngineLauncher::resolve()?;
        let _version = launcher.check(&session, redactor.clone(), diagnostics.clone())?;
        let mut journal = TunJournal::create(&invocation.session, &request.config_sha256)?;
        let child = launcher.start(&session, redactor, diagnostics)?;
        let engine_created = process_creation_time_for_pid(child.pid())?;
        journal.mark_running(child.pid(), engine_created)?;

        let deadline = Instant::now() + Duration::from_secs(5);
        let owned_luid = loop {
            let found = find_tun_adapter_luids()?;
            if found.len() > 1 {
                let mut child = child;
                let _ = child.stop();
                return Err(RuntimeError::new(
                    "tun_preflight",
                    "multiple RouteDeck TUN adapters appeared",
                ));
            }
            if let Some(luid) = found.into_iter().next() {
                break Some(luid);
            }
            if Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(50));
        };
        Ok(RunningSession {
            child: Box::new(HelperEngineChild {
                child,
                _config: session,
            }),
            journal,
            engine_created,
            owned_luid,
        })
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
                    let cleanup = verify_cleanup(owned_luid);
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
                    write_frame(
                        pipe,
                        &Frame::State {
                            request_id,
                            phase: if alive {
                                HelperPhase::Running
                            } else {
                                HelperPhase::Failed
                            },
                            engine_pid: alive.then(|| child.pid()),
                            cleanup: CleanupState::NotRequired,
                        },
                    )
                    .map_err(protocol_runtime_error)?;
                }
                Frame::StopTun { request_id, .. } => {
                    let stop = child.stop();
                    let cleanup = verify_cleanup(owned_luid);
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

    fn verify_helper_for_launch(path: &Path) -> Result<File, RuntimeError> {
        let (guard, actual) = open_and_hash_helper(path)?;
        if cfg!(debug_assertions) {
            if std::env::var_os("ROUTEDECK_ALLOW_UNTRUSTED_TUN_HELPER").as_deref()
                != Some(OsStr::new("1"))
            {
                return Err(RuntimeError::new(
                    "tun_helper_identity",
                    "development TUN helper is disabled outside the reviewed VM",
                ));
            }
            return Ok(guard);
        }
        let expected = option_env!("ROUTEDECK_TUN_HELPER_SHA256").ok_or_else(|| {
            RuntimeError::new(
                "tun_helper_identity",
                "release TUN helper manifest hash is not embedded",
            )
        })?;
        if expected.len() != 64
            || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !constant_time_eq(actual.as_bytes(), expected.to_ascii_lowercase().as_bytes())
        {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "release TUN helper hash was rejected",
            ));
        }
        verify_authenticode(path, &guard)?;
        Ok(guard)
    }

    fn verify_authenticode(path: &Path, guard: &File) -> Result<(), RuntimeError> {
        use windows_sys::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
            WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
            WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };

        let path = wide(path.as_os_str())?;
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: guard.as_raw_handle(),
            pgKnownSubject: ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: ptr::null_mut(),
            pwszURLReference: ptr::null_mut(),
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dwUIContext: 0,
            pSignatureSettings: ptr::null_mut(),
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        if status != 0 {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "release TUN helper Authenticode signature was rejected",
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

    fn find_tun_adapter_luids() -> Result<Vec<u64>, RuntimeError> {
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
                if wide_ptr_string(adapter.FriendlyName).as_deref() == Some(TUN_INTERFACE_NAME) {
                    output.push(unsafe { adapter.Luid.Value });
                }
                current = adapter.Next;
            }
            output.sort_unstable();
            output.dedup();
            return Ok(output);
        }
        Err(RuntimeError::new(
            "tun_preflight",
            "adapter enumeration changed repeatedly",
        ))
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

    struct TunJournal {
        path: PathBuf,
        file: Option<File>,
    }

    impl TunJournal {
        fn create(session: &str, config_sha256: &str) -> Result<Self, RuntimeError> {
            let root = helper_journal_root();
            fs::create_dir_all(&root)
                .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
            if fs::read_dir(&root)
                .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?
                .next()
                .transpose()
                .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?
                .is_some()
            {
                return Err(RuntimeError::new(
                    "session_recovery",
                    "a preserved TUN helper journal requires review",
                ));
            }
            let path = root.join(format!("tun-{session}.json"));
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
            })
        }

        fn mark_running(
            &mut self,
            engine_pid: u32,
            engine_created: u64,
        ) -> Result<(), RuntimeError> {
            self.write(serde_json::json!({
                "schemaVersion": 1,
                "phase": "running",
                "enginePid": engine_pid,
                "engineCreated": engine_created,
            }))
        }

        fn mark_conflict(&mut self) -> Result<(), RuntimeError> {
            self.write(serde_json::json!({
                "schemaVersion": 1,
                "phase": "conflict",
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
            if let Some(root) = self.path.parent() {
                let _ = fs::remove_dir(root);
            }
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

    fn helper_session_root() -> PathBuf {
        std::env::temp_dir()
            .join("RouteDeckTunHelper")
            .join("sessions")
    }

    fn helper_journal_root() -> PathBuf {
        std::env::temp_dir()
            .join("RouteDeckTunHelper")
            .join("journals")
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
            "tun_helper_config" | "config_check" => "The generated TUN configuration was rejected",
            "engine_integrity" | "engine_layout" => {
                "The reviewed sing-box component could not be verified"
            }
            "session_recovery" => "Previous TUN cleanup requires review",
            _ => "The elevated TUN helper could not start sing-box",
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
        fn cancellation_is_distinct_and_precedes_any_session_or_journal_creation() {
            let error = shell_launch_error(ERROR_CANCELLED);
            assert_eq!(error.stage(), "tun_uac_cancelled");
            assert_eq!(shell_launch_error(5).stage(), "tun_helper_launch");
            assert!(!helper_session_root().join("session-fixture").exists());
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
