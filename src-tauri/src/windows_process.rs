#![cfg(windows)]

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::FromRawHandle,
    },
    path::Path,
    ptr,
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::CreatePipe,
        SystemInformation::GetWindowsDirectoryW,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
    },
};

use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::engine_runtime::RuntimeError;

const PROCESS_ABORT_CODE: u32 = 0x5254_444b;
const MAX_COMMAND_LINE_UNITS: usize = 32_767;

pub(crate) fn current_process_is_elevated() -> Result<bool, RuntimeError> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(win32_error(
            "tun_privilege",
            "could not inspect the RouteDeck process token",
        ));
    }
    let token = OwnedHandle::new(
        token,
        "tun_privilege",
        "the RouteDeck process token was invalid",
    )?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    let read = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if read == 0 || returned != size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(win32_error(
            "tun_privilege",
            "could not read the RouteDeck elevation state",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineCommand {
    SingBoxCheck,
    SingBoxRun,
    XrayCheck,
    XrayRun,
}

impl EngineCommand {
    fn captures_stdout(self) -> bool {
        // Xray writes its useful runtime diagnostics to stdout. Keep checks quiet and avoid
        // changing sing-box capture semantics; only the long-lived Xray sidecar needs it.
        matches!(self, Self::XrayRun)
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
            Err(win32_error(stage, message))
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
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct AttributeList {
    storage: Vec<usize>,
    initialized: bool,
}

impl AttributeList {
    fn with_handles(handles: &mut [HANDLE; 3]) -> Result<Self, RuntimeError> {
        let mut bytes = 0_usize;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(win32_error(
                "start_engine",
                "could not size the child handle allow-list",
            ));
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut list = Self {
            storage: vec![0_usize; words],
            initialized: false,
        };
        let pointer = list.pointer();
        let initialized = unsafe { InitializeProcThreadAttributeList(pointer, 1, 0, &mut bytes) };
        if initialized == 0 {
            return Err(win32_error(
                "start_engine",
                "could not initialize the child handle allow-list",
            ));
        }
        list.initialized = true;
        let updated = unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                size_of::<HANDLE>() * handles.len(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            return Err(win32_error(
                "start_engine",
                "could not restrict inherited child handles",
            ));
        }
        Ok(list)
    }

    fn pointer(&mut self) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

struct KillOnCloseJob(OwnedHandle);

impl KillOnCloseJob {
    fn create() -> Result<Self, RuntimeError> {
        let handle = OwnedHandle::new(
            unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
            "start_engine",
            "could not create the engine Job Object",
        )?;
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectExtendedLimitInformation,
                (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(win32_error(
                "start_engine",
                "could not configure the engine Job Object",
            ));
        }
        Ok(Self(handle))
    }

    fn assign(&self, process: HANDLE) -> Result<(), RuntimeError> {
        if unsafe { AssignProcessToJobObject(self.0.raw(), process) } == 0 {
            Err(win32_error(
                "start_engine",
                "could not assign the suspended engine to its Job Object",
            ))
        } else {
            Ok(())
        }
    }

    fn terminate(&self) -> Result<(), RuntimeError> {
        if unsafe { TerminateJobObject(self.0.raw(), PROCESS_ABORT_CODE) } == 0 {
            Err(win32_error(
                "stop_engine",
                "could not terminate the contained engine Job Object",
            ))
        } else {
            Ok(())
        }
    }
}

pub(crate) struct SuspendedProcess {
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    job: Option<KillOnCloseJob>,
    stderr: Option<File>,
    pid: u32,
    armed: bool,
}

impl SuspendedProcess {
    pub(crate) fn take_stderr(&mut self) -> Result<File, RuntimeError> {
        self.stderr
            .take()
            .ok_or_else(|| RuntimeError::new("start_engine", "engine stderr pipe was unavailable"))
    }

    pub(crate) fn resume(mut self) -> Result<PlatformProcess, RuntimeError> {
        let thread = self.thread.as_ref().ok_or_else(|| {
            RuntimeError::new("start_engine", "suspended engine thread was unavailable")
        })?;
        let previous_count = unsafe { ResumeThread(thread.raw()) };
        if previous_count != 1 {
            return Err(win32_error(
                "start_engine",
                "could not safely resume the contained engine process",
            ));
        }
        self.thread.take();
        self.armed = false;
        Ok(PlatformProcess {
            process: self
                .process
                .take()
                .expect("suspended process handle missing"),
            job: self.job.take(),
            pid: self.pid,
        })
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if self.armed {
            if let Some(process) = &self.process {
                unsafe {
                    TerminateProcess(process.raw(), PROCESS_ABORT_CODE);
                    WaitForSingleObject(process.raw(), 1_000);
                }
            }
            self.job.take();
        }
    }
}

pub(crate) struct PlatformProcess {
    process: OwnedHandle,
    job: Option<KillOnCloseJob>,
    pid: u32,
}

unsafe impl Send for PlatformProcess {}

impl PlatformProcess {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn try_wait(&self) -> Result<Option<u32>, RuntimeError> {
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } == 0 {
                    Err(win32_error(
                        "engine_process",
                        "could not read the engine exit code",
                    ))
                } else {
                    Ok(Some(code))
                }
            }
            _ => Err(win32_error(
                "engine_process",
                "could not query the engine process",
            )),
        }
    }

    pub(crate) fn terminate_tree(&mut self, timeout: Duration) -> Result<(), RuntimeError> {
        if self.try_wait()?.is_none() {
            if let Some(job) = &self.job {
                job.terminate()?;
            } else if unsafe { TerminateProcess(self.process.raw(), PROCESS_ABORT_CODE) } == 0 {
                return Err(win32_error(
                    "stop_engine",
                    "could not terminate the engine process",
                ));
            }
        }
        let milliseconds = timeout.as_millis().min(u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(self.process.raw(), milliseconds) } {
            WAIT_OBJECT_0 => {
                self.job.take();
                Ok(())
            }
            WAIT_TIMEOUT => Err(RuntimeError::new(
                "stop_engine",
                "engine did not exit within the shutdown deadline",
            )),
            _ => Err(win32_error(
                "stop_engine",
                "could not wait for the engine process",
            )),
        }
    }
}

impl Drop for PlatformProcess {
    fn drop(&mut self) {
        let _ = self.terminate_tree(Duration::from_secs(1));
    }
}

pub(crate) fn create_suspended_engine<T>(
    executable: &Path,
    engine_dir: &Path,
    command: EngineCommand,
    config_path: &Path,
    preflight: impl FnOnce() -> Result<T, RuntimeError>,
) -> Result<(SuspendedProcess, T), RuntimeError> {
    let application = nul_terminated(executable.as_os_str(), "engine executable path")?;
    let current_directory = nul_terminated(engine_dir.as_os_str(), "engine directory path")?;
    let mut command_line = command_line(executable.as_os_str(), command, config_path.as_os_str())?;
    let environment = environment_block()?;

    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut pipe_read = ptr::null_mut();
    let mut pipe_write = ptr::null_mut();
    if unsafe { CreatePipe(&mut pipe_read, &mut pipe_write, &security, 0) } == 0 {
        return Err(win32_error(
            "start_engine",
            "could not create the engine stderr pipe",
        ));
    }
    let pipe_read = OwnedHandle::new(pipe_read, "start_engine", "stderr pipe was invalid")?;
    let pipe_write = OwnedHandle::new(pipe_write, "start_engine", "stderr pipe was invalid")?;
    if unsafe { SetHandleInformation(pipe_read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(win32_error(
            "start_engine",
            "could not protect the parent stderr handle",
        ));
    }
    let null_input = open_null(FILE_GENERIC_READ, &security)?;
    let null_output = open_null(FILE_GENERIC_WRITE, &security)?;
    let mut inherited = [null_input.raw(), null_output.raw(), pipe_write.raw()];
    let mut attributes = AttributeList::with_handles(&mut inherited)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_input.raw();
    startup.StartupInfo.hStdOutput = if command.captures_stdout() {
        pipe_write.raw()
    } else {
        null_output.raw()
    };
    startup.StartupInfo.hStdError = pipe_write.raw();
    startup.lpAttributeList = attributes.pointer();

    let job = KillOnCloseJob::create()?;
    let mut information = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | CREATE_NO_WINDOW
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT;
    // Keep the exact namespace/ACL/file-ID revalidation adjacent to CreateProcessW. All
    // fallible pipe, environment, attribute-list and Job setup is complete before this point.
    let preflight = preflight()?;
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            flags,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            &startup.StartupInfo as *const _,
            &mut information,
        )
    };
    if created == 0 {
        return Err(win32_error(
            "start_engine",
            "could not create the suspended engine process",
        ));
    }
    let process = match OwnedHandle::new(
        information.hProcess,
        "start_engine",
        "engine process handle was invalid",
    ) {
        Ok(process) => process,
        Err(error) => {
            if !information.hThread.is_null() && information.hThread != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(information.hThread) };
            }
            return Err(error);
        }
    };
    let thread = match OwnedHandle::new(
        information.hThread,
        "start_engine",
        "engine thread handle was invalid",
    ) {
        Ok(thread) => thread,
        Err(error) => {
            unsafe {
                TerminateProcess(process.raw(), PROCESS_ABORT_CODE);
                WaitForSingleObject(process.raw(), 1_000);
            }
            return Err(error);
        }
    };
    drop(pipe_write);
    drop(null_input);
    drop(null_output);
    job.assign(process.raw()).inspect_err(|_| unsafe {
        TerminateProcess(process.raw(), PROCESS_ABORT_CODE);
        WaitForSingleObject(process.raw(), 1_000);
    })?;
    let stderr = unsafe { File::from_raw_handle(pipe_read.into_raw()) };
    Ok((
        SuspendedProcess {
            process: Some(process),
            thread: Some(thread),
            job: Some(job),
            stderr: Some(stderr),
            pid: information.dwProcessId,
            armed: true,
        },
        preflight,
    ))
}

fn open_null(access: u32, security: &SECURITY_ATTRIBUTES) -> Result<OwnedHandle, RuntimeError> {
    let name = [b'N' as u16, b'U' as u16, b'L' as u16, 0];
    OwnedHandle::new(
        unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                security,
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        },
        "start_engine",
        "could not open the null device for the engine",
    )
}

fn command_line(
    executable: &OsStr,
    command: EngineCommand,
    config_path: &OsStr,
) -> Result<Vec<u16>, RuntimeError> {
    let mut output = Vec::new();
    let arguments: &[&OsStr] = match command {
        EngineCommand::SingBoxCheck => &[OsStr::new("check"), OsStr::new("-c"), config_path],
        EngineCommand::SingBoxRun => &[OsStr::new("run"), OsStr::new("-c"), config_path],
        EngineCommand::XrayCheck => &[
            OsStr::new("run"),
            OsStr::new("-test"),
            OsStr::new("-config"),
            config_path,
        ],
        EngineCommand::XrayRun => &[OsStr::new("run"), OsStr::new("-config"), config_path],
    };
    for (index, argument) in std::iter::once(executable)
        .chain(arguments.iter().copied())
        .enumerate()
    {
        if index != 0 {
            output.push(b' ' as u16);
        }
        output.extend(quote_argument(argument)?);
    }
    output.push(0);
    if output.len() > MAX_COMMAND_LINE_UNITS {
        return Err(RuntimeError::new(
            "start_engine",
            "engine command line exceeds the Windows limit",
        ));
    }
    Ok(output)
}

fn quote_argument(argument: &OsStr) -> Result<Vec<u16>, RuntimeError> {
    let units = argument.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(RuntimeError::new(
            "start_engine",
            "engine argument contains an invalid NUL",
        ));
    }
    let mut output = vec![b'"' as u16];
    let mut backslashes = 0_usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(unit);
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(unit);
        }
        backslashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(output)
}

fn environment_block() -> Result<Vec<u16>, RuntimeError> {
    let windows = trusted_windows_directory()?;
    let mut entries = vec![
        ("SystemRoot".to_owned(), windows.clone()),
        ("WINDIR".to_owned(), windows),
    ];
    for key in ["TEMP", "TMP", "LOCALAPPDATA"] {
        if let Some(value) = std::env::var_os(key) {
            entries.push((key.to_owned(), value));
        }
    }
    encode_environment(entries)
}

fn trusted_windows_directory() -> Result<OsString, RuntimeError> {
    let mut buffer = vec![0_u16; 260];
    loop {
        let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(win32_error(
                "start_engine",
                "could not resolve the Windows directory",
            ));
        }
        if length < buffer.len() as u32 {
            buffer.truncate(length as usize);
            return Ok(OsString::from_wide(&buffer));
        }
        buffer.resize(length as usize + 1, 0);
    }
}

fn encode_environment(mut entries: Vec<(String, OsString)>) -> Result<Vec<u16>, RuntimeError> {
    entries.sort_by_key(|(key, _)| key.to_ascii_lowercase());
    entries.dedup_by(|left, right| left.0.eq_ignore_ascii_case(&right.0));
    let mut block = Vec::new();
    for (key, value) in entries {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(RuntimeError::new(
                "start_engine",
                "engine environment contains an invalid name",
            ));
        }
        block.extend(key.encode_utf16());
        block.push(b'=' as u16);
        let value = value.encode_wide().collect::<Vec<_>>();
        if value.contains(&0) {
            return Err(RuntimeError::new(
                "start_engine",
                "engine environment contains an invalid value",
            ));
        }
        block.extend(value);
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

fn nul_terminated(value: &OsStr, label: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut units = value.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(RuntimeError::new(
            "start_engine",
            format!("{label} contains an invalid NUL"),
        ));
    }
    units.push(0);
    Ok(units)
}

fn win32_error(stage: &'static str, message: &'static str) -> RuntimeError {
    RuntimeError::new(
        stage,
        format!("{message} (Windows error {})", unsafe { GetLastError() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_quotes_spaces_quotes_and_trailing_backslashes() {
        let quoted = quote_argument(OsStr::new(r#"C:\Program Files\x\"quoted"\"#)).unwrap();
        let text = String::from_utf16(&quoted).unwrap();
        assert!(text.starts_with('"') && text.ends_with('"'));
        assert!(text.contains(r#"\"quoted\""#));
        assert!(text.ends_with(r#"\\""#));
    }

    #[test]
    fn engine_commands_use_only_the_pinned_cli_shapes() {
        let cases = [
            (
                EngineCommand::SingBoxCheck,
                r#""engine.exe" "check" "-c" "config.json""#,
            ),
            (
                EngineCommand::SingBoxRun,
                r#""engine.exe" "run" "-c" "config.json""#,
            ),
            (
                EngineCommand::XrayCheck,
                r#""engine.exe" "run" "-test" "-config" "config.json""#,
            ),
            (
                EngineCommand::XrayRun,
                r#""engine.exe" "run" "-config" "config.json""#,
            ),
        ];
        for (command, expected) in cases {
            let encoded =
                command_line(OsStr::new("engine.exe"), command, OsStr::new("config.json")).unwrap();
            let actual = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn only_running_xray_joins_stdout_to_the_diagnostic_pipe() {
        assert!(!EngineCommand::SingBoxCheck.captures_stdout());
        assert!(!EngineCommand::SingBoxRun.captures_stdout());
        assert!(!EngineCommand::XrayCheck.captures_stdout());
        assert!(EngineCommand::XrayRun.captures_stdout());
    }

    #[test]
    fn environment_is_sorted_deduplicated_double_nul_and_has_no_path() {
        let block = encode_environment(vec![
            ("TEMP".into(), OsString::from("one")),
            ("windir".into(), OsString::from("windows")),
            ("WINDIR".into(), OsString::from("duplicate")),
        ])
        .unwrap();
        assert!(block.ends_with(&[0, 0]));
        let text = String::from_utf16_lossy(&block);
        assert!(text.starts_with("TEMP=one\0windir=windows\0"));
        assert_eq!(text.to_ascii_lowercase().matches("windir=").count(), 1);
        assert!(!text.to_ascii_lowercase().contains("path="));
    }
}
