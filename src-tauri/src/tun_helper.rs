#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TunUpstreamIdentity {
    pub(crate) interface_luid: u64,
    pub(crate) interface_index: u32,
    pub(crate) interface_alias: String,
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::{OsStr, OsString},
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        mem::size_of,
        net::IpAddr,
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

    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS,
            ERROR_BUFFER_OVERFLOW, ERROR_CANCELLED, ERROR_INVALID_PARAMETER, GENERIC_READ,
            GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        NetworkManagement::IpHelper::{
            FreeMibTable, GetAdaptersAddresses, GetBestRoute2, GetIfEntry2, GetIpForwardTable2,
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GAA_FLAG_SKIP_UNICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP,
            IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2,
        },
        NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH, TUNNEL_TYPE_NONE},
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
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_NAME_NORMALIZED,
            FILE_SHARE_READ, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, VOLUME_NAME_DOS,
        },
        System::{
            Pipes::{
                CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
                PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId,
                GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
                PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
        UI::Shell::{
            ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW,
        },
    };

    use super::TunUpstreamIdentity;
    use crate::{
        engine_runtime::{
            random_hex, DiagnosticBuffer, EngineLauncher, ManagedChild, RuntimeError,
            SessionConfig, TunCaptureSnapshot, VerifiedEngineLauncher,
        },
        redaction::Redactor,
        tun_helper_protocol::{
            exact_hex, pipe_suffix, session_id, CleanupState, Frame, HelperFailureCode,
            HelperPhase, ServerState, TunInterfaceState, UpstreamChoice, MAX_CONFIG_BYTES,
            PROTOCOL_VERSION,
        },
        tun_helper_transport::{read_frame, write_frame, PipeTransport, TransportError},
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
        upstream: TunUpstreamIdentity,
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
            upstream: TunUpstreamIdentity,
        ) -> Result<Self, RuntimeError> {
            Ok(Self {
                validator: VerifiedEngineLauncher::resolve()?,
                expected_helper_sha256,
                upstream,
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
            launch_helper(prepared, self.expected_helper_sha256, &self.upstream)
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
        upstream: &TunUpstreamIdentity,
    ) -> Result<TunHelperChild, RuntimeError> {
        let route_context = preflight_route_context(upstream)?;
        let helper_path = fixed_helper_path()?;
        let _helper_guard = verify_helper_for_launch(&helper_path, expected_helper_sha256)?;
        let session = random_hex(16)?;
        let suffix = random_hex(16)?;
        let mut pipe = create_server_pipe(&suffix)?;
        let parent_pid = unsafe { GetCurrentProcessId() };
        let parent_created = process_creation_time(unsafe { GetCurrentProcess() })?;
        let arguments = helper_arguments(&session, &suffix, parent_pid, parent_created)?;
        let helper_process = shell_execute_runas(&helper_path, &arguments)?;
        connect_helper(&mut pipe, &helper_process)?;
        let helper_pid =
            pipe_client_pid(&pipe).map_err(|error| helper_exit_or(&helper_process, error))?;
        verify_launched_peer_pid(helper_pid, unsafe { GetProcessId(helper_process.raw()) })?;
        let actual_helper_created = process_creation_time(helper_process.raw())?;

        let hello =
            read_frame(&mut pipe).map_err(|error| helper_exit_or(&helper_process, error.into()))?;
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
        let upstream_choice = upstream_choice(upstream);
        let preflight_sha256 =
            preflight_digest(&prepared.config_sha256, &route_context, &upstream_choice);
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
                upstream_choice,
            },
        )
        .map_err(protocol_runtime_error)?;
        let response =
            read_frame(&mut pipe).map_err(|error| helper_exit_or(&helper_process, error.into()))?;
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
                    _ => "tun_helper_start",
                },
                safe_detail.unwrap_or_else(|| "elevated TUN helper rejected startup".into()),
            )),
            _ => Err(RuntimeError::new(
                "tun_helper_protocol",
                "TUN helper returned an unexpected startup response",
            )),
        }
    }

    // Explicit GUI-only control-plane diagnostic. It deliberately sends no challenge
    // or StartTun frame and never reads configuration, subscription, adapter or routes.
    pub fn diagnose_helper_handshake(expected_helper_sha256: Option<&str>) -> Result<(), String> {
        diagnose_helper_handshake_inner(expected_helper_sha256).map_err(|error| {
            match error.stage() {
                "tun_helper_exit" | "tun_helper_pipe" | "tun_helper_launch" => {
                    format!("stage={} cause={}", error.stage(), error.message())
                }
                "tun_helper_protocol" => {
                    "stage=tun_helper_protocol cause=helper authentication frame rejected".into()
                }
                "tun_helper_identity" => {
                    "stage=tun_helper_identity cause=helper image or process identity rejected"
                        .into()
                }
                _ => "stage=tun_helper_start cause=control-plane diagnostic could not start".into(),
            }
        })
    }

    fn diagnose_helper_handshake_inner(
        expected_helper_sha256: Option<&str>,
    ) -> Result<(), RuntimeError> {
        let helper_path = fixed_helper_path()?;
        let _helper_guard = verify_helper_for_launch(&helper_path, expected_helper_sha256)?;
        let session = random_hex(16)?;
        let suffix = random_hex(16)?;
        let mut pipe = create_server_pipe(&suffix)?;
        let parent_pid = unsafe { GetCurrentProcessId() };
        let parent_created = process_creation_time(unsafe { GetCurrentProcess() })?;
        let arguments = helper_arguments(&session, &suffix, parent_pid, parent_created)?;
        let helper = shell_execute_runas(&helper_path, &arguments)?;
        let result = (|| {
            connect_helper(&mut pipe, &helper)?;
            let peer_pid =
                pipe_client_pid(&pipe).map_err(|error| helper_exit_or(&helper, error))?;
            verify_launched_peer_pid(peer_pid, unsafe { GetProcessId(helper.raw()) })?;
            let actual_created = process_creation_time(helper.raw())?;
            let hello =
                read_frame(&mut pipe).map_err(|error| helper_exit_or(&helper, error.into()))?;
            match hello {
                Frame::HelperHello {
                    session: claimed_session,
                    helper_pid,
                    helper_created,
                    ..
                } if claimed_session == session
                    && helper_pid == peer_pid
                    && helper_created == actual_created =>
                {
                    Ok(())
                }
                _ => Err(RuntimeError::new(
                    "tun_helper_protocol",
                    "TUN helper identity message was rejected",
                )),
            }
        })();
        // Closing the channel makes the existing helper stop before it can receive
        // a StartTun frame. Keep its exact process handle until bounded exit proof.
        drop(pipe);
        if unsafe { WaitForSingleObject(helper.raw(), HELPER_STOP_TIMEOUT.as_millis() as u32) }
            != WAIT_OBJECT_0
        {
            if let Err(error) = result {
                return Err(RuntimeError::new(
                    error.stage(),
                    format!(
                        "{}; helper exit after pipe closure was not confirmed",
                        error.message()
                    ),
                ));
            }
            return Err(RuntimeError::new(
                "tun_helper_pipe",
                "handshake-only helper did not exit after its pipe closed",
            ));
        }
        result
    }

    fn verify_launched_peer_pid(peer_pid: u32, launched_pid: u32) -> Result<(), RuntimeError> {
        if launched_pid == 0 || peer_pid != launched_pid {
            return Err(RuntimeError::new(
                "tun_helper_identity",
                "TUN pipe peer is not the launched helper process",
            ));
        }
        Ok(())
    }

    fn upstream_choice(upstream: &TunUpstreamIdentity) -> UpstreamChoice {
        UpstreamChoice::Physical {
            interface_luid: upstream.interface_luid,
            interface_index: upstream.interface_index,
            interface_alias: upstream.interface_alias.clone(),
        }
    }

    fn upstream_identity(choice: &UpstreamChoice) -> TunUpstreamIdentity {
        match choice {
            UpstreamChoice::Physical {
                interface_luid,
                interface_index,
                interface_alias,
            } => TunUpstreamIdentity {
                interface_luid: *interface_luid,
                interface_index: *interface_index,
                interface_alias: interface_alias.clone(),
            },
        }
    }

    fn preflight_digest(
        config_sha256: &str,
        route_context: &str,
        upstream: &UpstreamChoice,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"RouteDeck TUN physical-upstream launch context v3\0");
        hasher.update(config_sha256.as_bytes());
        hasher.update(route_context.as_bytes());
        match upstream {
            UpstreamChoice::Physical {
                interface_luid,
                interface_index,
                interface_alias,
            } => {
                hasher.update(interface_luid.to_le_bytes());
                hasher.update(interface_index.to_le_bytes());
                hasher.update((interface_alias.len() as u64).to_le_bytes());
                hasher.update(interface_alias.as_bytes());
            }
        }
        format!("{:x}", hasher.finalize())
    }

    struct TunHelperChild {
        pipe: Option<PipeTransport>,
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
            self.query_running_state_inner()
                .map_err(running_state_error)
        }

        fn query_running_state_inner(
            &mut self,
        ) -> Result<Option<TunCaptureSnapshot>, RuntimeError> {
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

    pub fn helper_main() -> Result<(), i32> {
        helper_main_inner().map_err(|error| helper_exit_code(error.stage()))
    }

    fn helper_main_inner() -> Result<(), RuntimeError> {
        if !crate::windows_process::current_process_is_elevated().map_err(|_| {
            RuntimeError::new("helper_elevation_query", "helper elevation query failed")
        })? {
            return Err(RuntimeError::new(
                "helper_not_elevated",
                "TUN helper is not elevated",
            ));
        }
        let invocation = HelperInvocation::parse(std::env::args_os())?;
        let mut pipe = connect_parent_pipe(&invocation.pipe_suffix)?;
        authenticate_parent(&pipe, &invocation)?;
        let helper_pid = unsafe { GetCurrentProcessId() };
        let helper_created =
            process_creation_time(unsafe { GetCurrentProcess() }).map_err(|_| {
                RuntimeError::new(
                    "helper_self_identity",
                    "helper process identity query failed",
                )
            })?;
        let hello_nonce = random_hex(32).map_err(|_| {
            RuntimeError::new("helper_nonce", "helper challenge random source failed")
        })?;
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
        .map_err(|_| {
            RuntimeError::new("helper_hello_write", "helper hello could not be written")
        })?;

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
                upstream_choice,
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
                    upstream: upstream_identity(&upstream_choice),
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
                let capture = &running.capture;
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
                    capture,
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
        upstream: TunUpstreamIdentity,
    }

    struct RunningSession {
        child: Box<dyn ManagedChild>,
        journal: TunJournal,
        engine_created: u64,
        capture: CaptureExpectation,
    }

    struct CaptureExpectation {
        owned_luid: Option<u64>,
        expected_families: ExpectedFamilies,
        upstream: TunUpstreamIdentity,
    }

    fn start_engine_session(
        invocation: &HelperInvocation,
        request: &StartRequest,
    ) -> Result<RunningSession, RuntimeError> {
        let route_context = preflight_route_context(&request.upstream)?;
        let choice = upstream_choice(&request.upstream);
        if request.preflight_sha256
            != preflight_digest(&request.config_sha256, &route_context, &choice)
        {
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
        let expected_families = validate_tun_config(&contents, &request.upstream.interface_alias)?;

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
        if let Err(error) = journal.mark_adapter(child.pid(), engine_created, owned_luid) {
            rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
            return Err(error);
        }
        loop {
            if inspect_owned_capture(owned_luid, expected_families).is_ok() {
                break;
            }
            if Instant::now() >= route_deadline {
                rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
                return Err(RuntimeError::new(
                    "tun_capture",
                    "RouteDeck TUN adapter appeared, but its enabled address-family capture routes did not become effective",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        if let Err(error) = journal.mark_capture(child.pid(), engine_created, owned_luid) {
            rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
            return Err(error);
        }
        if let Err(error) = inspect_owned_capture(owned_luid, expected_families) {
            rollback_failed_start(child.as_mut(), &mut journal, Some(owned_luid))?;
            return Err(error);
        }
        if let Err(error) = validate_physical_upstream_after_start(&request.upstream) {
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
            capture: CaptureExpectation {
                owned_luid: Some(owned_luid),
                expected_families,
                upstream: request.upstream.clone(),
            },
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
        pipe: &mut PipeTransport,
        invocation: &HelperInvocation,
        state: &mut ServerState,
        child: &mut dyn ManagedChild,
        journal: &mut TunJournal,
        capture: &CaptureExpectation,
    ) -> Result<(), RuntimeError> {
        let parent = open_verified_parent(invocation)?;
        loop {
            let frame = match pipe.read_frame_from_peer(parent.raw()) {
                Ok(frame) => frame,
                Err(_) => {
                    let stop = child.stop();
                    let cleanup = wait_for_cleanup(capture.owned_luid, Duration::from_secs(3));
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
                        let verified = capture.owned_luid.map_or_else(
                            || {
                                Err(RuntimeError::new(
                                    "tun_capture",
                                    "the helper-owned TUN adapter identity is unavailable",
                                ))
                            },
                            |luid| {
                                validate_physical_upstream_after_start(&capture.upstream).and_then(
                                    |_| inspect_owned_capture(luid, capture.expected_families),
                                )
                            },
                        );
                        match verified {
                            Ok(capture) => write_frame(
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
                            Err(error) => write_frame(
                                pipe,
                                &Frame::Failure {
                                    request_id,
                                    code: HelperFailureCode::CaptureInvalid,
                                    safe_detail: Some(safe_helper_detail(error.stage()).into()),
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
                    let cleanup = wait_for_cleanup(capture.owned_luid, Duration::from_secs(3));
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ExpectedFamilies {
        ipv4: bool,
        ipv6: bool,
    }

    fn validate_tun_config(
        contents: &str,
        upstream_alias: &str,
    ) -> Result<ExpectedFamilies, RuntimeError> {
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
        let mut expected_families = ExpectedFamilies {
            ipv4: false,
            ipv6: false,
        };
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
                let addresses = inbound
                    .get("address")
                    .and_then(serde_json::Value::as_array)
                    .filter(|addresses| !addresses.is_empty() && addresses.len() <= 2)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            "tun_helper_config",
                            "protected TUN address families are invalid",
                        )
                    })?;
                for address in addresses {
                    let address = address
                        .as_str()
                        .and_then(|address| address.split('/').next())
                        .and_then(|address| address.parse::<IpAddr>().ok())
                        .ok_or_else(|| {
                            RuntimeError::new(
                                "tun_helper_config",
                                "protected TUN address is invalid",
                            )
                        })?;
                    match address {
                        IpAddr::V4(_) => expected_families.ipv4 = true,
                        IpAddr::V6(_) => expected_families.ipv6 = true,
                    }
                }
            } else if inbound.get("listen").and_then(serde_json::Value::as_str) != Some("127.0.0.1")
            {
                return Err(RuntimeError::new(
                    "tun_helper_config",
                    "protected local inbound is not loopback-only",
                ));
            }
        }
        let route = object
            .get("route")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                RuntimeError::new("tun_helper_config", "protected TUN route policy is invalid")
            })?;
        let outbounds = object
            .get("outbounds")
            .and_then(serde_json::Value::as_array)
            .filter(|outbounds| outbounds.len() == 2)
            .ok_or_else(|| {
                RuntimeError::new("tun_helper_config", "protected TUN outbounds are invalid")
            })?;
        let selected = outbounds
            .iter()
            .find(|outbound| {
                outbound.get("tag").and_then(serde_json::Value::as_str) == Some("selected")
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN selected outbound is invalid",
                )
            })?;
        let direct = outbounds
            .iter()
            .find(|outbound| {
                outbound.get("tag").and_then(serde_json::Value::as_str) == Some("direct")
            })
            .filter(|outbound| {
                outbound.get("type").and_then(serde_json::Value::as_str) == Some("direct")
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN direct outbound is invalid",
                )
            })?;
        let bootstrap = root
            .pointer("/dns/servers")
            .and_then(serde_json::Value::as_array)
            .and_then(|servers| {
                servers.iter().find(|server| {
                    server.get("tag").and_then(serde_json::Value::as_str) == Some("bootstrap")
                })
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    "tun_helper_config",
                    "protected TUN bootstrap DNS server is invalid",
                )
            })?;
        let selected_is_bridge =
            selected.get("type").and_then(serde_json::Value::as_str) == Some("socks");
        let upstream_binding_valid = if selected_is_bridge {
            route.get("default_interface").is_none()
                && selected.get("server").and_then(serde_json::Value::as_str) == Some("127.0.0.1")
                && selected.get("bind_interface").is_none()
                && direct
                    .get("bind_interface")
                    .and_then(serde_json::Value::as_str)
                    == Some(upstream_alias)
                && bootstrap
                    .get("bind_interface")
                    .and_then(serde_json::Value::as_str)
                    == Some(upstream_alias)
        } else {
            route
                .get("default_interface")
                .and_then(serde_json::Value::as_str)
                == Some(upstream_alias)
                && selected.get("bind_interface").is_none()
                && direct.get("bind_interface").is_none()
                && bootstrap.get("bind_interface").is_none()
        };
        if tun_count != 1 || route.get("auto_detect_interface").is_some() || !upstream_binding_valid
        {
            return Err(RuntimeError::new(
                "tun_helper_config",
                "protected TUN physical upstream binding is invalid",
            ));
        }
        crate::config::validate_tun_dns_hijack(&root).map_err(|_| {
            RuntimeError::new(
                "tun_helper_config",
                "protected TUN DNS port hijack is missing or ambiguous",
            )
        })?;
        Ok(expected_families)
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

    fn create_server_pipe(suffix: &str) -> Result<PipeTransport, RuntimeError> {
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
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
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
        Ok(PipeTransport::new(unsafe {
            File::from_raw_handle(handle.into_raw())
        }))
    }

    fn connect_helper(pipe: &mut PipeTransport, helper: &OwnedHandle) -> Result<(), RuntimeError> {
        pipe.connect(HELPER_CONNECT_TIMEOUT)
            .map_err(|error| helper_exit_or(helper, error.into()))
    }

    fn connect_parent_pipe(suffix: &str) -> Result<PipeTransport, RuntimeError> {
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
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                return Ok(PipeTransport::new(unsafe { File::from_raw_handle(handle) }));
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

    fn pipe_client_pid(pipe: &PipeTransport) -> Result<u32, RuntimeError> {
        let mut pid = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } == 0 || pid == 0 {
            return Err(last_error(
                "tun_helper_pipe",
                "could not authenticate the TUN helper pipe client",
            ));
        }
        Ok(pid)
    }

    fn authenticate_parent(
        pipe: &PipeTransport,
        invocation: &HelperInvocation,
    ) -> Result<(), RuntimeError> {
        let mut server_pid = 0;
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server_pid) } == 0
            || server_pid != invocation.parent_pid
        {
            return Err(RuntimeError::new(
                "helper_parent_pipe_pid",
                "TUN helper pipe server identity was rejected",
            ));
        }
        let parent = open_verified_parent(invocation)?;
        let image = process_image(parent.raw()).map_err(|_| {
            RuntimeError::new(
                "helper_parent_image_query",
                "helper parent image query failed",
            )
        })?;
        let helper = std::env::current_exe().map_err(|_| {
            RuntimeError::new("helper_self_image_query", "helper image query failed")
        })?;
        if image.file_name() != Some(OsStr::new(GUI_FILE_NAME)) {
            return Err(RuntimeError::new(
                "helper_parent_image_name",
                "TUN helper parent image was rejected",
            ));
        }
        if image.parent() != helper.parent() {
            return Err(RuntimeError::new(
                "helper_parent_image_directory",
                "TUN helper parent directory was rejected",
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
            "helper_parent_open",
            "could not open the RouteDeck parent process",
        )?;
        if process_creation_time(parent.raw()).map_err(|_| {
            RuntimeError::new(
                "helper_parent_creation_query",
                "helper parent creation time query failed",
            )
        })? != invocation.parent_created
        {
            return Err(RuntimeError::new(
                "helper_parent_creation_mismatch",
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
        if_index: u32,
        friendly_name: String,
        description: String,
        if_type: u32,
        tunnel_type: i32,
        physical_address_length: u32,
        oper_status: i32,
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
                    if_index: unsafe { adapter.Anonymous1.Anonymous.IfIndex },
                    friendly_name: wide_ptr_string(adapter.FriendlyName).unwrap_or_default(),
                    description: wide_ptr_string(adapter.Description).unwrap_or_default(),
                    if_type: adapter.IfType,
                    tunnel_type: adapter.TunnelType,
                    physical_address_length: adapter.PhysicalAddressLength,
                    oper_status: adapter.OperStatus,
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
                "tap",
                "openvpn",
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

    pub(crate) fn select_physical_upstream() -> Result<TunUpstreamIdentity, RuntimeError> {
        let adapters = adapter_states()?;
        let routes = route_states()?;
        if foreign_full_tunnel(&adapters, &routes).is_some() {
            return Err(RuntimeError::new(
                "tun_preflight",
                "another full-tunnel VPN is active; turn it off before starting RouteDeck TUN",
            ));
        }
        let best_luid = best_route_luid_v4([1, 1, 1, 1])?;
        physical_upstream_from(&adapters, best_luid).ok_or_else(|| {
            RuntimeError::new(
                "tun_preflight",
                "the current IPv4 path is not an active physical Ethernet or Wi-Fi adapter",
            )
        })
    }

    fn physical_upstream_from(
        adapters: &[AdapterState],
        best_luid: u64,
    ) -> Option<TunUpstreamIdentity> {
        let adapter = adapters.iter().find(|adapter| {
            adapter.luid == best_luid
                && adapter.if_index != 0
                && adapter.oper_status == IfOperStatusUp
                && adapter.tunnel_type == TUNNEL_TYPE_NONE
                && adapter.physical_address_length > 0
                && matches!(adapter.if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
                && !adapter.friendly_name.is_empty()
                && adapter.friendly_name.trim() == adapter.friendly_name
                && adapter.friendly_name.encode_utf16().count() <= 256
                && !adapter.friendly_name.chars().any(char::is_control)
                && !adapter
                    .friendly_name
                    .eq_ignore_ascii_case(TUN_INTERFACE_NAME)
        })?;
        Some(TunUpstreamIdentity {
            interface_luid: adapter.luid,
            interface_index: adapter.if_index,
            interface_alias: adapter.friendly_name.clone(),
        })
    }

    fn exact_upstream_adapter<'a>(
        adapters: &'a [AdapterState],
        expected: &TunUpstreamIdentity,
    ) -> Option<&'a AdapterState> {
        if physical_upstream_from(adapters, expected.interface_luid).as_ref() != Some(expected) {
            return None;
        }
        adapters.iter().find(|adapter| {
            adapter.luid == expected.interface_luid
                && adapter.if_index == expected.interface_index
                && adapter.friendly_name == expected.interface_alias
                && adapter.oper_status == IfOperStatusUp
                && adapter.tunnel_type == TUNNEL_TYPE_NONE
                && adapter.physical_address_length > 0
                && matches!(adapter.if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
        })
    }

    fn preflight_route_context(upstream: &TunUpstreamIdentity) -> Result<String, RuntimeError> {
        let adapters = adapter_states()?;
        let mut routes = route_states()?;
        if foreign_full_tunnel(&adapters, &routes).is_some() {
            return Err(RuntimeError::new(
                "tun_preflight",
                "another full-tunnel VPN is active; turn it off before starting RouteDeck TUN",
            ));
        }
        if exact_upstream_adapter(&adapters, upstream).is_none()
            || best_route_luid_v4([1, 1, 1, 1])? != upstream.interface_luid
        {
            return Err(RuntimeError::new(
                "tun_preflight",
                "the selected physical upstream changed before TUN startup",
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

    fn validate_physical_upstream_after_start(
        upstream: &TunUpstreamIdentity,
    ) -> Result<(), RuntimeError> {
        let adapters = adapter_states()?;
        if exact_upstream_adapter(&adapters, upstream).is_none()
            || best_route_luid_v4_on_interface([1, 1, 1, 1], upstream.interface_luid)?
                != upstream.interface_luid
        {
            return Err(RuntimeError::new(
                "tun_upstream",
                "the sealed physical upstream is unavailable or changed identity",
            ));
        }
        Ok(())
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

    fn enabled_capture_is_valid(expected: ExpectedFamilies, ipv4: bool, ipv6: bool) -> bool {
        (!expected.ipv4 || ipv4) && (!expected.ipv6 || ipv6)
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
        best_route_luid(&destination, None)
    }

    fn best_route_luid_v4_on_interface(
        address: [u8; 4],
        interface_luid: u64,
    ) -> Result<u64, RuntimeError> {
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
        best_route_luid(&destination, Some(interface_luid))
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
        best_route_luid(&destination, None)
    }

    fn best_route_luid(
        destination: &SOCKADDR_INET,
        interface_luid: Option<u64>,
    ) -> Result<u64, RuntimeError> {
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        let luid = interface_luid.map(|luid| NET_LUID_LH { Value: luid });
        let status = unsafe {
            GetBestRoute2(
                luid.as_ref().map_or(ptr::null(), ptr::from_ref),
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

    fn inspect_owned_capture(
        luid: u64,
        expected: ExpectedFamilies,
    ) -> Result<TunInterfaceState, RuntimeError> {
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
        let ipv4_valid = !expected.ipv4 || (owns_v4 && best_route_luid_v4(v4)? == luid);
        let ipv6_valid = !expected.ipv6 || (owns_v6 && best_route_luid_v6(v6)? == luid);
        if !enabled_capture_is_valid(expected, ipv4_valid, ipv6_valid) {
            return Err(RuntimeError::new(
                "tun_capture",
                "RouteDeck does not own every enabled TUN address-family capture route",
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
        match (find_tun_adapter_luids(), route_states()) {
            (Ok(current), Ok(routes)) => cleanup_state_from(
                &current,
                &routes.iter().map(|route| route.luid).collect::<Vec<_>>(),
                owned_luid,
            ),
            _ => CleanupState::Conflict,
        }
    }

    fn cleanup_state_from(
        same_name_luids: &[u64],
        route_luids: &[u64],
        owned_luid: Option<u64>,
    ) -> CleanupState {
        if !same_name_luids.is_empty() {
            return CleanupState::Conflict;
        }
        if owned_luid.is_some_and(|luid| route_luids.contains(&luid)) {
            return CleanupState::Conflict;
        }
        CleanupState::Complete
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

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct StoredTunJournal {
        schema_version: u32,
        session: String,
        phase: String,
        config_sha256: String,
        #[serde(default)]
        engine_pid: Option<u32>,
        #[serde(default)]
        engine_created: Option<u64>,
        #[serde(default)]
        owned_interface_luid: Option<u64>,
        #[serde(default)]
        owned_routes: Vec<StoredRouteKey>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct StoredRouteKey {
        family: u16,
        prefix: String,
        prefix_length: u8,
        metric: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StaleProcessIdentity {
        Absent,
        Matching,
        Mismatched,
        Unknown,
    }

    #[derive(Debug)]
    struct StaleTunCandidate {
        directory: PathBuf,
        nested_directories: Vec<PathBuf>,
        outer_config: Option<PathBuf>,
        journal_path: PathBuf,
        journal: StoredTunJournal,
    }

    pub(crate) fn reconcile_stale_tun_sessions(root: &Path) -> Result<(), RuntimeError> {
        fs::create_dir_all(root).map_err(|error| recovery_error(error.to_string()))?;
        reject_reparse_directory(root)?;

        let same_name_luids = find_tun_adapter_luids()
            .map_err(|_| recovery_error("could not inspect RouteDeck adapter ownership"))?;
        if !same_name_luids.is_empty() {
            return Err(recovery_error(
                "an existing RouteDeck adapter has no live session owner",
            ));
        }

        let mut candidates = Vec::new();
        for entry in fs::read_dir(root).map_err(|error| recovery_error(error.to_string()))? {
            let entry = entry.map_err(|error| recovery_error(error.to_string()))?;
            candidates.push(inspect_stale_tun_candidate(entry.path())?);
        }

        let route_luids = if candidates
            .iter()
            .any(|candidate| candidate.journal.owned_interface_luid.is_some())
        {
            route_states()
                .map_err(|_| recovery_error("could not inspect stale RouteDeck route ownership"))?
                .into_iter()
                .map(|route| route.luid)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        for candidate in &candidates {
            let process = stale_process_identity(
                candidate.journal.engine_pid,
                candidate.journal.engine_created,
            );
            if !stale_recovery_is_safe(
                true,
                &same_name_luids,
                &route_luids,
                candidate.journal.owned_interface_luid,
                process,
            ) {
                return Err(recovery_error(
                    "stale TUN state is still active or its identity is ambiguous",
                ));
            }
        }

        for candidate in candidates {
            remove_stale_tun_candidate(candidate)?;
        }
        Ok(())
    }

    fn inspect_stale_tun_candidate(directory: PathBuf) -> Result<StaleTunCandidate, RuntimeError> {
        reject_reparse_directory(&directory)?;
        let name = directory
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix("session-"))
            .ok_or_else(|| recovery_error("session directory identity is invalid"))?;
        session_id(name).map_err(|_| recovery_error("session directory identity is invalid"))?;

        let mut outer_config = None;
        let mut journal_path = None;
        let mut nested_directories = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|error| recovery_error(error.to_string()))? {
            let entry = entry.map_err(|error| recovery_error(error.to_string()))?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| recovery_error(error.to_string()))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(recovery_error("stale TUN session contains a reparse point"));
            }
            match entry.file_name().to_str() {
                Some("config.json") if metadata.is_file() && outer_config.is_none() => {
                    outer_config = Some(path);
                }
                Some("tun-journal.json") if metadata.is_file() && journal_path.is_none() => {
                    journal_path = Some(path);
                }
                Some(name) if metadata.is_dir() && valid_session_directory_name(name) => {
                    inspect_nested_session_directory(&path)?;
                    nested_directories.push(path);
                }
                _ => {
                    return Err(recovery_error(
                        "stale TUN session contains an unrecognized entry",
                    ));
                }
            }
        }
        if nested_directories.len() > 1 {
            return Err(recovery_error(
                "stale TUN session contains multiple helper sessions",
            ));
        }
        let journal_path = journal_path.ok_or_else(|| {
            recovery_error("session has no exact TUN ownership journal; preserved for review")
        })?;
        let journal = read_stored_tun_journal(&journal_path)?;
        validate_stored_tun_journal(&journal)?;
        if let Some(path) = outer_config.as_ref() {
            verify_stale_config_digest(path, &journal.config_sha256)?;
        }
        for nested in &nested_directories {
            let path = nested.join("config.json");
            if path.exists() {
                verify_stale_config_digest(&path, &journal.config_sha256)?;
            }
        }
        Ok(StaleTunCandidate {
            directory,
            nested_directories,
            outer_config,
            journal_path,
            journal,
        })
    }

    fn valid_session_directory_name(name: &str) -> bool {
        name.strip_prefix("session-")
            .is_some_and(|value| session_id(value).is_ok())
    }

    fn inspect_nested_session_directory(directory: &Path) -> Result<(), RuntimeError> {
        reject_reparse_directory(directory)?;
        for entry in fs::read_dir(directory).map_err(|error| recovery_error(error.to_string()))? {
            let entry = entry.map_err(|error| recovery_error(error.to_string()))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| recovery_error(error.to_string()))?;
            if !metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || entry.file_name() != OsStr::new("config.json")
            {
                return Err(recovery_error(
                    "stale helper session contains an unrecognized entry",
                ));
            }
        }
        Ok(())
    }

    fn reject_reparse_directory(path: &Path) -> Result<(), RuntimeError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| recovery_error(error.to_string()))?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(recovery_error("stale TUN directory identity was rejected"));
        }
        Ok(())
    }

    fn read_stored_tun_journal(path: &Path) -> Result<StoredTunJournal, RuntimeError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| recovery_error(error.to_string()))?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > 64 * 1024
        {
            return Err(recovery_error("stale TUN journal identity was rejected"));
        }
        let bytes = fs::read(path).map_err(|error| recovery_error(error.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| recovery_error("stale TUN journal schema was rejected"))
    }

    fn validate_stored_tun_journal(journal: &StoredTunJournal) -> Result<(), RuntimeError> {
        if journal.schema_version != 2
            || session_id(&journal.session).is_err()
            || exact_hex(&journal.config_sha256, 64).is_err()
            || journal.engine_pid == Some(0)
            || journal.engine_created == Some(0)
            || journal.owned_interface_luid == Some(0)
            || journal.engine_pid.is_some() != journal.engine_created.is_some()
            || (!journal.owned_routes.is_empty() && journal.owned_interface_luid.is_none())
            || journal
                .owned_routes
                .iter()
                .any(|route| !stored_route_is_valid(route))
        {
            return Err(recovery_error("stale TUN journal metadata was rejected"));
        }
        let valid_phase = match journal.phase.as_str() {
            "starting" => {
                journal.engine_pid.is_none()
                    && journal.owned_interface_luid.is_none()
                    && journal.owned_routes.is_empty()
            }
            "running" => {
                journal.engine_pid.is_some()
                    && journal.owned_interface_luid.is_none()
                    && journal.owned_routes.is_empty()
            }
            "adapter_observed" => {
                journal.engine_pid.is_some() && journal.owned_interface_luid.is_some()
            }
            "capture_verified" => {
                journal.engine_pid.is_some()
                    && journal.owned_interface_luid.is_some()
                    && !journal.owned_routes.is_empty()
            }
            "conflict" => true,
            _ => false,
        };
        if !valid_phase {
            return Err(recovery_error("stale TUN journal phase was rejected"));
        }
        Ok(())
    }

    fn stored_route_is_valid(route: &StoredRouteKey) -> bool {
        let prefix_length_valid = match route.family {
            family if family == AF_INET => route.prefix_length <= 32,
            family if family == AF_INET6 => route.prefix_length <= 128,
            _ => false,
        };
        let _ = route.metric;
        prefix_length_valid && exact_hex(&route.prefix, 32).is_ok()
    }

    fn verify_stale_config_digest(path: &Path, expected: &str) -> Result<(), RuntimeError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| recovery_error(error.to_string()))?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(recovery_error("stale TUN config identity was rejected"));
        }
        let mut file = File::open(path).map_err(|error| recovery_error(error.to_string()))?;
        let (_, actual) = hash_config(&mut file)
            .map_err(|_| recovery_error("stale TUN config could not be hashed"))?;
        if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
            return Err(recovery_error(
                "stale TUN config digest did not match its journal",
            ));
        }
        Ok(())
    }

    fn stale_process_identity(pid: Option<u32>, created: Option<u64>) -> StaleProcessIdentity {
        let (Some(pid), Some(created)) = (pid, created) else {
            return StaleProcessIdentity::Absent;
        };
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
                StaleProcessIdentity::Absent
            } else {
                StaleProcessIdentity::Unknown
            };
        }
        let process = match OwnedHandle::new(
            process,
            "session_recovery",
            "could not inspect the stale TUN engine process",
        ) {
            Ok(process) => process,
            Err(_) => return StaleProcessIdentity::Unknown,
        };
        match process_creation_time(process.raw()) {
            Ok(actual) if actual == created => StaleProcessIdentity::Matching,
            Ok(_) => StaleProcessIdentity::Mismatched,
            Err(_) => StaleProcessIdentity::Unknown,
        }
    }

    fn stale_recovery_is_safe(
        has_journal: bool,
        same_name_luids: &[u64],
        route_luids: &[u64],
        owned_luid: Option<u64>,
        process: StaleProcessIdentity,
    ) -> bool {
        has_journal
            && same_name_luids.is_empty()
            && !owned_luid.is_some_and(|luid| route_luids.contains(&luid))
            && process == StaleProcessIdentity::Absent
    }

    fn remove_stale_tun_candidate(candidate: StaleTunCandidate) -> Result<(), RuntimeError> {
        for nested in candidate.nested_directories {
            let config = nested.join("config.json");
            if config.exists() {
                fs::remove_file(&config).map_err(|error| recovery_error(error.to_string()))?;
            }
            fs::remove_dir(&nested).map_err(|error| recovery_error(error.to_string()))?;
        }
        if let Some(config) = candidate.outer_config {
            fs::remove_file(config).map_err(|error| recovery_error(error.to_string()))?;
        }
        fs::remove_file(candidate.journal_path)
            .map_err(|error| recovery_error(error.to_string()))?;
        fs::remove_dir(candidate.directory).map_err(|error| recovery_error(error.to_string()))
    }

    fn recovery_error(message: impl Into<String>) -> RuntimeError {
        let _ = message.into();
        RuntimeError::new(
            "session_recovery",
            "stale TUN session requires review; preserved ambiguous state",
        )
    }

    struct TunJournal {
        path: PathBuf,
        file: Option<File>,
        session: String,
        config_sha256: String,
        engine_pid: Option<u32>,
        engine_created: Option<u64>,
        owned_luid: Option<u64>,
        owned_routes: Vec<RouteState>,
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
                    "schemaVersion": 2,
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
                engine_pid: None,
                engine_created: None,
                owned_luid: None,
                owned_routes: Vec::new(),
            })
        }

        fn mark_running(
            &mut self,
            engine_pid: u32,
            engine_created: u64,
        ) -> Result<(), RuntimeError> {
            self.engine_pid = Some(engine_pid);
            self.engine_created = Some(engine_created);
            let value = self.value("running");
            self.write(value)
        }

        fn mark_conflict(&mut self) -> Result<(), RuntimeError> {
            if let Some(owned_luid) = self.owned_luid {
                if let Ok(routes) = route_states() {
                    for route in routes.into_iter().filter(|route| route.luid == owned_luid) {
                        if !self.owned_routes.contains(&route) {
                            self.owned_routes.push(route);
                        }
                    }
                }
            }
            let value = self.value("conflict");
            self.write(value)
        }

        fn mark_adapter(
            &mut self,
            engine_pid: u32,
            engine_created: u64,
            owned_luid: u64,
        ) -> Result<(), RuntimeError> {
            self.engine_pid = Some(engine_pid);
            self.engine_created = Some(engine_created);
            self.owned_luid = Some(owned_luid);
            self.owned_routes = route_states()?
                .into_iter()
                .filter(|route| route.luid == owned_luid)
                .collect();
            let value = self.value("adapter_observed");
            self.write(value)
        }

        fn mark_capture(
            &mut self,
            engine_pid: u32,
            engine_created: u64,
            owned_luid: u64,
        ) -> Result<(), RuntimeError> {
            self.engine_pid = Some(engine_pid);
            self.engine_created = Some(engine_created);
            self.owned_luid = Some(owned_luid);
            self.owned_routes = route_states()?
                .into_iter()
                .filter(|route| route.luid == owned_luid)
                .collect::<Vec<_>>();
            let value = self.value("capture_verified");
            self.write(value)
        }

        fn value(&self, phase: &str) -> serde_json::Value {
            let routes = self
                .owned_routes
                .iter()
                .map(|route| {
                    serde_json::json!({
                        "family": route.family,
                        "prefix": route.prefix.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                        "prefixLength": route.prefix_len,
                        "metric": route.metric,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "schemaVersion": 2,
                "session": self.session,
                "phase": phase,
                "configSha256": self.config_sha256,
                "enginePid": self.engine_pid,
                "engineCreated": self.engine_created,
                "ownedInterfaceLuid": self.owned_luid,
                "ownedRoutes": routes,
            })
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
                "TUN started but did not obtain every enabled address-family capture route"
            }
            "tun_upstream" => "The sealed physical network adapter changed or became unavailable",
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
            "tun_capture" | "tun_upstream" => HelperFailureCode::CaptureInvalid,
            _ => HelperFailureCode::StartFailed,
        }
    }

    impl From<crate::tun_helper_protocol::ProtocolError> for RuntimeError {
        fn from(_: crate::tun_helper_protocol::ProtocolError) -> Self {
            Self::new("tun_helper_protocol", "TUN helper protocol was rejected")
        }
    }

    impl From<TransportError> for RuntimeError {
        fn from(error: TransportError) -> Self {
            Self::new(
                if error == TransportError::Protocol {
                    "tun_helper_protocol"
                } else {
                    "tun_helper_pipe"
                },
                error.to_string(),
            )
        }
    }

    fn protocol_runtime_error(error: impl Into<RuntimeError>) -> RuntimeError {
        error.into()
    }

    fn running_state_error(error: RuntimeError) -> RuntimeError {
        if matches!(error.stage(), "tun_helper_pipe" | "tun_helper_protocol") {
            RuntimeError::new("engine_process", error.message())
        } else {
            error
        }
    }

    // The helper's process handle was returned by ShellExecuteExW and its image hash
    // held before launch. Early exit reasons travel only as finite process codes;
    // no unauthenticated pipe frame or arbitrary stderr is trusted as diagnostics.
    fn helper_exit_or(helper: &OwnedHandle, fallback: RuntimeError) -> RuntimeError {
        if unsafe { WaitForSingleObject(helper.raw(), 250) } != WAIT_OBJECT_0 {
            return fallback;
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(helper.raw(), &mut code) } == 0 {
            return fallback;
        }
        RuntimeError::new(
            "tun_helper_exit",
            format!("{} (helper exit {code})", helper_exit_description(code)),
        )
    }

    fn helper_exit_code(stage: &str) -> i32 {
        match stage {
            "helper_elevation_query" => 80,
            "helper_not_elevated" => 81,
            "tun_helper_arguments" => 82,
            "tun_helper_pipe" => 83,
            "helper_parent_pipe_pid" => 84,
            "helper_parent_open" => 85,
            "helper_parent_creation_query" => 86,
            "helper_parent_creation_mismatch" => 87,
            "helper_parent_image_query" => 88,
            "helper_self_image_query" => 89,
            "helper_parent_image_name" => 90,
            "helper_parent_image_directory" => 91,
            "helper_self_identity" => 92,
            "helper_nonce" => 93,
            "helper_hello_write" => 94,
            "tun_helper_protocol" => 95,
            "tun_helper_config" | "config_check" => 96,
            "session_recovery" => 97,
            "engine_integrity" | "engine_layout" => 98,
            _ => 99,
        }
    }

    fn helper_exit_description(code: u32) -> &'static str {
        match code {
            80 => "Windows could not report the helper elevation state",
            81 => "Windows started the helper without required elevation",
            82 => "The helper rejected its fixed startup arguments",
            83 => "The helper could not complete its pipe transaction",
            84 => "The helper rejected the pipe server process identity",
            85 => "The helper could not open the exact GUI process with required rights",
            86 => "The helper could not read the GUI process creation time",
            87 => "The helper found a changed GUI process creation time",
            88 => "The helper could not query the GUI executable identity",
            89 => "The helper could not query its own executable identity",
            90 => "The helper rejected the GUI executable file name",
            91 => "The helper and GUI executable directory identities did not match",
            92 => "The helper could not read its own process creation time",
            93 => "The helper could not create a fresh authentication nonce",
            94 => "The helper could not send its authentication hello",
            95 => "The helper rejected the authentication or session protocol",
            96 => "The helper rejected the protected generated configuration",
            97 => "The helper preserved an incomplete cleanup for recovery",
            98 => "The helper could not verify the pinned engine component",
            _ => "The helper exited before completing the requested operation",
        }
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
        #[test]
        fn pipe_peer_must_be_the_process_returned_by_helper_launch() {
            assert!(super::verify_launched_peer_pid(42, 42).is_ok());
            for (peer, launched) in [(42, 43), (42, 0), (0, 0)] {
                assert_eq!(
                    super::verify_launched_peer_pid(peer, launched)
                        .unwrap_err()
                        .stage(),
                    "tun_helper_identity"
                );
            }
        }

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
        fn early_helper_exit_codes_distinguish_authentication_subcauses_without_paths() {
            let stages = [
                "helper_elevation_query",
                "helper_not_elevated",
                "tun_helper_arguments",
                "tun_helper_pipe",
                "helper_parent_pipe_pid",
                "helper_parent_open",
                "helper_parent_creation_query",
                "helper_parent_creation_mismatch",
                "helper_parent_image_query",
                "helper_self_image_query",
                "helper_parent_image_name",
                "helper_parent_image_directory",
                "helper_self_identity",
                "helper_nonce",
                "helper_hello_write",
                "tun_helper_protocol",
                "tun_helper_config",
                "session_recovery",
                "engine_integrity",
            ];
            for (index, stage) in stages.into_iter().enumerate() {
                let code = helper_exit_code(stage);
                assert_eq!(code, 80 + index as i32);
                let message = helper_exit_description(code as u32);
                assert!(!message.contains("\\") && !message.contains("/") && message.len() < 128);
            }
            assert_eq!(helper_exit_code("unclassified"), 99);
            assert_eq!(
                helper_exit_description(u32::MAX),
                helper_exit_description(99)
            );
        }

        #[test]
        fn running_pipe_failure_preserves_finite_cause_but_is_not_startup_failure() {
            let raw = TransportError::Io {
                operation: "read",
                code: 232,
            };
            let bootstrap: RuntimeError = raw.into();
            assert_eq!(bootstrap.stage(), "tun_helper_pipe");
            let running = running_state_error(bootstrap);
            assert_eq!(running.stage(), "engine_process");
            assert!(running.message().contains("232"));
            let capture =
                running_state_error(RuntimeError::new("tun_capture", "fixture capture mismatch"));
            assert_eq!(capture.stage(), "tun_capture");
        }

        #[test]
        fn strict_tun_config_rejects_non_tun_and_non_loopback_inputs() {
            let valid = serde_json::json!({
                "log": {},
                "dns": {"servers":[{"tag":"bootstrap"}]},
                "inbounds": [
                    {"type":"http","listen":"127.0.0.1"},
                    {"type":"tun","tag":"tun-in","interface_name":"RouteDeck","address":["172.19.0.1/30"],"auto_route":true,"strict_route":true,"stack":"system"}
                ],
                "outbounds": [
                    {"type":"hysteria2","tag":"selected"},
                    {"type":"direct","tag":"direct"}
                ],
                "route": {"default_interface":"Ethernet","rules":[
                    {"inbound":["health-in"],"action":"route","outbound":"selected"},
                    {"inbound":["tun-in"],"network":["tcp","udp"],"port":53,"action":"hijack-dns"}
                ]}
            });
            assert_eq!(
                validate_tun_config(&valid.to_string(), "Ethernet").unwrap(),
                ExpectedFamilies {
                    ipv4: true,
                    ipv6: false,
                }
            );
            let mut dual = valid.clone();
            let mut legacy_dns = valid.clone();
            legacy_dns["route"]["rules"][1] =
                serde_json::json!({"inbound":["tun-in"],"protocol":"dns","action":"hijack-dns"});
            assert!(validate_tun_config(&legacy_dns.to_string(), "Ethernet").is_err());
            let mut narrowed_dns = valid.clone();
            narrowed_dns["route"]["rules"][1]["protocol"] = serde_json::json!("dns");
            assert!(validate_tun_config(&narrowed_dns.to_string(), "Ethernet").is_err());
            let mut reordered_dns = valid.clone();
            reordered_dns["route"]["rules"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
            assert!(validate_tun_config(&reordered_dns.to_string(), "Ethernet").is_err());
            dual["inbounds"][1]["address"] =
                serde_json::json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
            assert_eq!(
                validate_tun_config(&dual.to_string(), "Ethernet").unwrap(),
                ExpectedFamilies {
                    ipv4: true,
                    ipv6: true,
                }
            );
            assert!(validate_tun_config(&dual.to_string(), "Wi-Fi").is_err());
            let mut automatic = dual.clone();
            automatic["route"]["auto_detect_interface"] = serde_json::json!(true);
            assert!(validate_tun_config(&automatic.to_string(), "Ethernet").is_err());
            let mut native_selected_override = valid.clone();
            native_selected_override["outbounds"][0]["bind_interface"] = serde_json::json!("Wi-Fi");
            assert!(
                validate_tun_config(&native_selected_override.to_string(), "Ethernet").is_err()
            );
            let mut native_direct_override = valid.clone();
            native_direct_override["outbounds"][1]["bind_interface"] =
                serde_json::json!("Ethernet");
            assert!(validate_tun_config(&native_direct_override.to_string(), "Ethernet").is_err());
            let mut native_dns_override = valid.clone();
            native_dns_override["dns"] = serde_json::json!({
                "servers": [{"tag":"bootstrap", "bind_interface":"Ethernet"}]
            });
            assert!(validate_tun_config(&native_dns_override.to_string(), "Ethernet").is_err());
            let bridge = serde_json::json!({
                "log": {},
                "dns": {"servers":[{"tag":"bootstrap","bind_interface":"Ethernet"}]},
                "inbounds": [
                    {"type":"http","listen":"127.0.0.1"},
                    {"type":"tun","tag":"tun-in","interface_name":"RouteDeck","address":["172.19.0.1/30"],"auto_route":true,"strict_route":true,"stack":"system"}
                ],
                "outbounds": [
                    {"type":"socks","tag":"selected","server":"127.0.0.1","server_port":19090},
                    {"type":"direct","tag":"direct","bind_interface":"Ethernet"}
                ],
                "route": {"rules":[
                    {"inbound":["health-in"],"action":"route","outbound":"selected"},
                    {"inbound":["tun-in"],"network":["tcp","udp"],"port":53,"action":"hijack-dns"}
                ]}
            });
            assert!(validate_tun_config(&bridge.to_string(), "Ethernet").is_ok());
            let mut remote_bridge = bridge.clone();
            remote_bridge["outbounds"][0]["server"] = serde_json::json!("192.0.2.1");
            assert!(validate_tun_config(&remote_bridge.to_string(), "Ethernet").is_err());
            let mut bound_bridge = bridge.clone();
            bound_bridge["outbounds"][0]["bind_interface"] = serde_json::json!("Ethernet");
            assert!(validate_tun_config(&bound_bridge.to_string(), "Ethernet").is_err());
            let mut fake_direct = bridge.clone();
            fake_direct["outbounds"][1]["type"] = serde_json::json!("socks");
            assert!(validate_tun_config(&fake_direct.to_string(), "Ethernet").is_err());
            let mut wrong_direct_tag = bridge.clone();
            wrong_direct_tag["outbounds"][1]["tag"] = serde_json::json!("other");
            assert!(validate_tun_config(&wrong_direct_tag.to_string(), "Ethernet").is_err());
            let mut wrong_bootstrap = bridge;
            wrong_bootstrap["dns"]["servers"][0]["tag"] = serde_json::json!("other");
            assert!(validate_tun_config(&wrong_bootstrap.to_string(), "Ethernet").is_err());
            let mut foreign = valid.clone();
            foreign["inbounds"][0]["listen"] = serde_json::json!("0.0.0.0");
            assert!(validate_tun_config(&foreign.to_string(), "Ethernet").is_err());
            let mut no_tun = valid;
            no_tun["inbounds"].as_array_mut().unwrap().pop();
            assert!(validate_tun_config(&no_tun.to_string(), "Ethernet").is_err());
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
                if_index: luid as u32,
                friendly_name: name.into(),
                description: name.into(),
                if_type,
                tunnel_type: TUNNEL_TYPE_NONE,
                physical_address_length: physical,
                oper_status: IfOperStatusUp,
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

            let tap = adapter(3, "TAP-Windows Adapter", IF_TYPE_ETHERNET_CSMACD, 6);
            assert_eq!(
                foreign_full_tunnel(&[tap], &[default_route(3, AF_INET, 25)])
                    .unwrap()
                    .luid,
                3
            );
        }

        #[test]
        fn physical_upstream_requires_the_exact_active_hardware_default() {
            let ethernet = adapter(7, "Ethernet", IF_TYPE_ETHERNET_CSMACD, 6);
            assert_eq!(
                physical_upstream_from(std::slice::from_ref(&ethernet), 7),
                Some(TunUpstreamIdentity {
                    interface_luid: 7,
                    interface_index: 7,
                    interface_alias: "Ethernet".into(),
                })
            );
            assert!(physical_upstream_from(std::slice::from_ref(&ethernet), 8).is_none());

            let mut down = ethernet.clone();
            down.oper_status = 2;
            assert!(physical_upstream_from(&[down], 7).is_none());
            let tunnel = adapter(9, "xray_tun", IF_TYPE_TUNNEL, 0);
            assert!(physical_upstream_from(&[tunnel], 9).is_none());
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

            assert!(enabled_capture_is_valid(
                ExpectedFamilies {
                    ipv4: true,
                    ipv6: false,
                },
                true,
                false,
            ));
            assert!(!enabled_capture_is_valid(
                ExpectedFamilies {
                    ipv4: true,
                    ipv6: true,
                },
                true,
                false,
            ));
        }

        #[test]
        fn cleanup_requires_the_exact_owned_adapter_and_routes_to_be_gone() {
            assert_eq!(
                cleanup_state_from(&[7], &[], Some(7)),
                CleanupState::Conflict
            );
            assert_eq!(
                cleanup_state_from(&[], &[7], Some(7)),
                CleanupState::Conflict
            );
            assert_eq!(
                cleanup_state_from(&[], &[99], Some(7)),
                CleanupState::Complete
            );
            assert_eq!(
                cleanup_state_from(&[], &[], Some(7)),
                CleanupState::Complete
            );
        }

        #[test]
        fn stale_recovery_fails_closed_for_foreign_or_ambiguous_identity() {
            assert!(stale_recovery_is_safe(
                true,
                &[],
                &[],
                Some(7),
                StaleProcessIdentity::Absent,
            ));
            assert!(!stale_recovery_is_safe(
                false,
                &[],
                &[],
                Some(7),
                StaleProcessIdentity::Absent,
            ));
            assert!(!stale_recovery_is_safe(
                true,
                &[99],
                &[],
                Some(7),
                StaleProcessIdentity::Absent,
            ));
            assert!(!stale_recovery_is_safe(
                true,
                &[],
                &[7],
                Some(7),
                StaleProcessIdentity::Absent,
            ));
            for identity in [
                StaleProcessIdentity::Matching,
                StaleProcessIdentity::Mismatched,
                StaleProcessIdentity::Unknown,
            ] {
                assert!(!stale_recovery_is_safe(true, &[], &[], Some(7), identity));
            }
        }

        #[test]
        fn conflict_journal_preserves_process_adapter_and_route_ownership() {
            let root = std::env::temp_dir().join(format!(
                "routedeck-journal-preserve-test-{}",
                random_hex(8).unwrap()
            ));
            fs::create_dir(&root).unwrap();
            let mut journal =
                TunJournal::create(&root, &"01".repeat(16), &"02".repeat(32)).unwrap();
            journal.engine_pid = Some(123);
            journal.engine_created = Some(456);
            journal.owned_luid = Some(7);
            journal.owned_routes = vec![default_route(7, AF_INET, 0)];
            journal.mark_conflict().unwrap();

            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&journal.path).unwrap()).unwrap();
            assert_eq!(value["phase"], "conflict");
            assert_eq!(value["enginePid"], 123);
            assert_eq!(value["engineCreated"], 456);
            assert_eq!(value["ownedInterfaceLuid"], 7);
            assert_eq!(value["ownedRoutes"].as_array().unwrap().len(), 1);
            validate_stored_tun_journal(&read_stored_tun_journal(&journal.path).unwrap()).unwrap();

            journal.complete().unwrap();
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn exact_stale_journal_shape_can_be_removed_without_recursive_cleanup() {
            let root = std::env::temp_dir().join(format!(
                "routedeck-stale-shape-test-{}",
                random_hex(8).unwrap()
            ));
            fs::create_dir(&root).unwrap();
            let directory = root.join(format!("session-{}", "01".repeat(16)));
            fs::create_dir(&directory).unwrap();
            let config = br#"{"inbounds":[]}"#;
            fs::write(directory.join("config.json"), config).unwrap();
            let config_sha256 = format!("{:x}", Sha256::digest(config));
            fs::write(
                directory.join("tun-journal.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 2,
                    "session": "02".repeat(16),
                    "phase": "starting",
                    "configSha256": config_sha256,
                }))
                .unwrap(),
            )
            .unwrap();

            let candidate = inspect_stale_tun_candidate(directory.clone()).unwrap();
            remove_stale_tun_candidate(candidate).unwrap();
            assert!(!directory.exists());
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn journal_without_exact_identity_metadata_is_preserved() {
            let root = std::env::temp_dir().join(format!(
                "routedeck-stale-invalid-test-{}",
                random_hex(8).unwrap()
            ));
            fs::create_dir(&root).unwrap();
            let directory = root.join(format!("session-{}", "01".repeat(16)));
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("config.json"), b"{}").unwrap();
            fs::write(
                directory.join("tun-journal.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 2,
                    "session": "02".repeat(16),
                    "phase": "running",
                    "configSha256": format!("{:x}", Sha256::digest(b"{}")),
                    "enginePid": 123,
                    "engineCreated": null,
                }))
                .unwrap(),
            )
            .unwrap();

            assert!(inspect_stale_tun_candidate(directory.clone()).is_err());
            assert!(directory.join("tun-journal.json").exists());
            fs::remove_file(directory.join("tun-journal.json")).unwrap();
            fs::remove_file(directory.join("config.json")).unwrap();
            fs::remove_dir(directory).unwrap();
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn preflight_digest_binds_config_and_route_snapshot() {
            let upstream = UpstreamChoice::Physical {
                interface_luid: 7,
                interface_index: 9,
                interface_alias: "Ethernet".into(),
            };
            let base = preflight_digest(&"01".repeat(32), &"02".repeat(32), &upstream);
            assert_ne!(
                base,
                preflight_digest(&"03".repeat(32), &"02".repeat(32), &upstream)
            );
            assert_ne!(
                base,
                preflight_digest(&"01".repeat(32), &"04".repeat(32), &upstream)
            );
            assert_ne!(
                base,
                preflight_digest(
                    &"01".repeat(32),
                    &"02".repeat(32),
                    &UpstreamChoice::Physical {
                        interface_luid: 8,
                        interface_index: 9,
                        interface_alias: "Ethernet".into(),
                    },
                )
            );
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::TunHelperLauncher;

#[cfg(windows)]
pub(crate) fn select_physical_upstream(
) -> Result<TunUpstreamIdentity, crate::engine_runtime::RuntimeError> {
    windows::select_physical_upstream()
}

#[cfg(not(windows))]
pub(crate) fn select_physical_upstream(
) -> Result<TunUpstreamIdentity, crate::engine_runtime::RuntimeError> {
    Err(crate::engine_runtime::RuntimeError::new(
        "tun_preflight",
        "physical TUN upstream selection is available only on Windows",
    ))
}

#[cfg(windows)]
pub(crate) fn reconcile_stale_tun_sessions(
    root: &std::path::Path,
) -> Result<(), crate::engine_runtime::RuntimeError> {
    windows::reconcile_stale_tun_sessions(root)
}

#[cfg(not(windows))]
pub(crate) fn reconcile_stale_tun_sessions(
    _root: &std::path::Path,
) -> Result<(), crate::engine_runtime::RuntimeError> {
    Ok(())
}

#[cfg(windows)]
pub fn helper_main() -> Result<(), i32> {
    windows::helper_main()
}

#[cfg(windows)]
pub fn diagnose_helper_handshake(expected_helper_sha256: Option<&str>) -> Result<(), String> {
    windows::diagnose_helper_handshake(expected_helper_sha256)
}

#[cfg(not(windows))]
pub fn diagnose_helper_handshake(_expected_helper_sha256: Option<&str>) -> Result<(), String> {
    Err("stage=tun_helper_start cause=Windows is required".into())
}

#[cfg(not(windows))]
pub fn helper_main() -> Result<(), i32> {
    Err(99)
}
