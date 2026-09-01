use std::{
    collections::{BTreeSet, VecDeque},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use getrandom::fill as fill_random;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{config::LocalPorts, redaction::Redactor};

const EMBEDDED_ENGINE_LOCK: &str = include_str!("../../engine/sing-box.lock.json");
const ENGINE_DIRECTORY: &str = "engine";
const ENGINE_EXE: &str = "sing-box.exe";
const CRONET_DLL: &str = "libcronet.dll";
const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_CHECK_STDERR: usize = 64 * 1024;
const MAX_DIAGNOSTIC_LINES: usize = 128;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    stage: &'static str,
    message: String,
}

impl RuntimeError {
    pub fn new(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }

    pub fn stage(&self) -> &'static str {
        self.stage
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.message)
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EngineLock {
    schema_version: u32,
    engine: String,
    version: String,
    runtime_files: Vec<LockedFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockedFile {
    path: String,
    kind: String,
    size: u64,
    sha256: String,
}

#[derive(Debug)]
pub(crate) struct FixedEngineLayout {
    engine_dir: PathBuf,
    executable: PathBuf,
}

impl FixedEngineLayout {
    pub(crate) fn resolve() -> Result<Self, RuntimeError> {
        let executable = std::env::current_exe()
            .map_err(|error| RuntimeError::new("engine_layout", error.to_string()))?;
        let package_root = executable.parent().ok_or_else(|| {
            RuntimeError::new("engine_layout", "application directory is unavailable")
        })?;
        Self::from_package_root(package_root)
    }

    fn from_package_root(package_root: &Path) -> Result<Self, RuntimeError> {
        reject_reparse(package_root)?;
        let engine_dir = package_root.join(ENGINE_DIRECTORY);
        reject_reparse(&engine_dir)?;
        let canonical_root = fs::canonicalize(package_root)
            .map_err(|error| RuntimeError::new("engine_layout", error.to_string()))?;
        let canonical_engine = fs::canonicalize(&engine_dir)
            .map_err(|error| RuntimeError::new("engine_layout", error.to_string()))?;
        if canonical_engine.parent() != Some(canonical_root.as_path()) {
            return Err(RuntimeError::new(
                "engine_layout",
                "engine directory is outside the application package",
            ));
        }
        Ok(Self {
            executable: canonical_engine.join(ENGINE_EXE),
            engine_dir: canonical_engine,
        })
    }
}

struct VerifiedFiles {
    _executable: File,
    _cronet: File,
}

impl FixedEngineLayout {
    fn verify(&self) -> Result<(VerifiedFiles, String), RuntimeError> {
        let lock: EngineLock = serde_json::from_str(EMBEDDED_ENGINE_LOCK)
            .map_err(|_| RuntimeError::new("engine_integrity", "embedded lock is invalid"))?;
        self.verify_lock(&lock)
    }

    fn verify_lock(&self, lock: &EngineLock) -> Result<(VerifiedFiles, String), RuntimeError> {
        if lock.schema_version != 1 || lock.engine != "sing-box" || lock.version != "1.13.19" {
            return Err(RuntimeError::new(
                "engine_integrity",
                "embedded engine identity is unsupported",
            ));
        }
        reject_unlocked_binaries(&self.engine_dir, &lock.runtime_files)?;
        let mut held_executable = None;
        let mut held_cronet = None;
        for locked in &lock.runtime_files {
            if Path::new(&locked.path).file_name() != Some(OsStr::new(&locked.path)) {
                return Err(RuntimeError::new(
                    "engine_integrity",
                    "engine lock contains a nested runtime path",
                ));
            }
            let path = self.engine_dir.join(&locked.path);
            reject_reparse(&path)?;
            let mut file = open_verified_file(&path)?;
            let metadata = file
                .metadata()
                .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
            if !metadata.is_file() || metadata.len() != locked.size {
                return Err(RuntimeError::new(
                    "engine_integrity",
                    format!("{} has an unexpected size", locked.path),
                ));
            }
            let digest = sha256_reader(&mut file)?;
            if !constant_time_ascii_eq(&digest, &locked.sha256) {
                return Err(RuntimeError::new(
                    "engine_integrity",
                    format!("{} failed SHA-256 verification", locked.path),
                ));
            }
            match locked.path.as_str() {
                ENGINE_EXE if locked.kind == "executable" => held_executable = Some(file),
                CRONET_DLL if locked.kind == "library" => held_cronet = Some(file),
                _ => {}
            }
        }
        let files = VerifiedFiles {
            _executable: held_executable.ok_or_else(|| {
                RuntimeError::new("engine_integrity", "locked executable is missing")
            })?,
            _cronet: held_cronet.ok_or_else(|| {
                RuntimeError::new("engine_integrity", "locked libcronet is missing")
            })?,
        };
        Ok((files, lock.version.clone()))
    }
}

fn reject_unlocked_binaries(
    engine_dir: &Path,
    locked_files: &[LockedFile],
) -> Result<(), RuntimeError> {
    let allowed: BTreeSet<String> = locked_files
        .iter()
        .map(|entry| entry.path.to_ascii_lowercase())
        .collect();
    if allowed.len() != locked_files.len() {
        return Err(RuntimeError::new(
            "engine_integrity",
            "engine lock contains duplicate runtime paths",
        ));
    }
    for entry in fs::read_dir(engine_dir)
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?
    {
        let entry =
            entry.map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
        reject_reparse(&entry.path())?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if !entry
            .file_type()
            .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?
            .is_file()
            || !allowed.contains(&name)
        {
            return Err(RuntimeError::new(
                "engine_integrity",
                "engine directory contains an unlocked file or directory",
            ));
        }
    }
    Ok(())
}

fn reject_reparse(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
    if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return Err(RuntimeError::new(
            "engine_integrity",
            "reparse points are forbidden in the engine layout",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn open_verified_file(path: &Path) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
        .open(path)
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))
}

fn sha256_reader(reader: &mut File) -> Result<String, RuntimeError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn constant_time_ascii_eq(actual: &str, expected: &str) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(crate) struct PortReservations {
    listeners: Vec<TcpListener>,
    ports: LocalPorts,
}

impl PortReservations {
    pub(crate) fn reserve() -> Result<Self, RuntimeError> {
        let mut listeners = Vec::with_capacity(3);
        let mut ports = Vec::with_capacity(3);
        for _ in 0..3 {
            let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .map_err(|error| RuntimeError::new("reserve_ports", error.to_string()))?;
            let port = listener
                .local_addr()
                .map_err(|error| RuntimeError::new("reserve_ports", error.to_string()))?
                .port();
            if ports.contains(&port) {
                return Err(RuntimeError::new(
                    "reserve_ports",
                    "operating system returned duplicate listener ports",
                ));
            }
            ports.push(port);
            listeners.push(listener);
        }
        Ok(Self {
            listeners,
            ports: LocalPorts {
                http: ports[0],
                socks: ports[1],
                health: ports[2],
            },
        })
    }

    pub(crate) fn ports(&self) -> LocalPorts {
        self.ports
    }

    pub(crate) fn release(self) {
        drop(self.listeners);
    }
}

pub(crate) struct SessionConfig {
    directory: PathBuf,
    config_path: PathBuf,
    guard: Option<File>,
}

impl SessionConfig {
    pub(crate) fn create(root: &Path, contents: &str) -> Result<Self, RuntimeError> {
        fs::create_dir_all(root)
            .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
        reject_reparse(root)?;
        let session_id = random_hex(16)?;
        let directory = root.join(format!("session-{session_id}"));
        create_private_directory(&directory)?;
        let result = create_session_config(&directory, contents);
        match result {
            Ok((config_path, guard)) => Ok(Self {
                directory,
                config_path,
                guard: Some(guard),
            }),
            Err(error) => {
                let cleanup = cleanup_session_directory(&directory);
                if cleanup.is_err() {
                    return Err(RuntimeError::new(
                        "session_storage",
                        "session configuration failed and partial secret cleanup was incomplete",
                    ));
                }
                Err(error)
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.config_path
    }
}

fn create_session_config(
    directory: &Path,
    contents: &str,
) -> Result<(PathBuf, File), RuntimeError> {
    let temporary = directory.join("config.tmp");
    let config_path = directory.join("config.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    file.write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    drop(file);
    fs::rename(&temporary, &config_path)
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    reject_reparse(&config_path)
        .map_err(|error| RuntimeError::new("session_storage", error.message))?;
    let mut guard_options = OpenOptions::new();
    guard_options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        guard_options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let guard = guard_options
        .open(&config_path)
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    Ok((config_path, guard))
}

pub(crate) fn reconcile_stale_sessions(root: &Path) -> Result<(), RuntimeError> {
    fs::create_dir_all(root)
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
    reject_reparse(root).map_err(|error| RuntimeError::new("session_recovery", error.message))?;
    let mut entries = fs::read_dir(root)
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?
        .is_some()
    {
        return Err(RuntimeError::new(
            "session_recovery",
            "session recovery requires explicit user review; preserved existing session data",
        ));
    }
    Ok(())
}

fn cleanup_session_directory(directory: &Path) -> Result<(), RuntimeError> {
    for entry in fs::read_dir(directory)
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?
    {
        let entry =
            entry.map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
        reject_reparse(&entry.path())
            .map_err(|error| RuntimeError::new("session_recovery", error.message))?;
        let name = entry.file_name();
        if !entry
            .file_type()
            .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?
            .is_file()
            || (name != OsStr::new("config.tmp") && name != OsStr::new("config.json"))
        {
            return Err(RuntimeError::new(
                "session_recovery",
                "session directory contains an unrecognized entry",
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
    }
    fs::remove_dir(directory)
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))
}

impl Drop for SessionConfig {
    fn drop(&mut self) {
        self.guard.take();
        let _ = fs::remove_file(&self.config_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> Result<(), RuntimeError> {
    use std::{mem::size_of, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
    };

    let descriptor_text: Vec<u16> = OsStr::new("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(RuntimeError::new(
            "session_storage",
            "could not construct private directory ACL",
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) };
    let error = unsafe { GetLastError() };
    unsafe {
        LocalFree(descriptor as *mut _);
    }
    if created == 0 {
        let message = if error == ERROR_ALREADY_EXISTS {
            "private session directory already exists"
        } else {
            "could not create private session directory"
        };
        return Err(RuntimeError::new("session_storage", message));
    }
    Ok(())
}

#[cfg(not(windows))]
fn create_private_directory(path: &Path) -> Result<(), RuntimeError> {
    fs::create_dir(path).map_err(|error| RuntimeError::new("session_storage", error.to_string()))
}

pub(crate) fn random_hex(byte_count: usize) -> Result<String, RuntimeError> {
    let mut bytes = vec![0_u8; byte_count];
    fill_random(&mut bytes)
        .map_err(|_| RuntimeError::new("random", "operating system random source failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Default)]
pub(crate) struct DiagnosticBuffer {
    lines: VecDeque<String>,
    bytes: usize,
}

impl DiagnosticBuffer {
    pub(crate) fn push(&mut self, line: String) {
        let line = if line.len() > 4 * 1024 {
            "[REDACTED: diagnostic line omitted]".to_owned()
        } else {
            line
        };
        self.bytes += line.len();
        self.lines.push_back(line);
        while self.lines.len() > MAX_DIAGNOSTIC_LINES || self.bytes > MAX_DIAGNOSTIC_BYTES {
            if let Some(removed) = self.lines.pop_front() {
                self.bytes = self.bytes.saturating_sub(removed.len());
            }
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

pub(crate) trait ManagedChild: Send {
    fn pid(&self) -> u32;
    fn is_alive(&mut self) -> Result<bool, RuntimeError>;
    fn stop(&mut self) -> Result<(), RuntimeError>;
}

pub(crate) trait EngineLauncher: Send + Sync {
    fn check(
        &self,
        config: &Path,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<String, RuntimeError>;

    fn start(
        &self,
        config: &Path,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<Box<dyn ManagedChild>, RuntimeError>;
}

pub(crate) struct VerifiedEngineLauncher {
    layout: FixedEngineLayout,
}

impl VerifiedEngineLauncher {
    pub(crate) fn resolve() -> Result<Self, RuntimeError> {
        Ok(Self {
            layout: FixedEngineLayout::resolve()?,
        })
    }
}

impl EngineLauncher for VerifiedEngineLauncher {
    fn check(
        &self,
        config: &Path,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<String, RuntimeError> {
        let (_check_guards, version) = self.layout.verify()?;
        let mut check = fixed_command(
            &self.layout,
            &[OsStr::new("check"), OsStr::new("-c"), config.as_os_str()],
        );
        let mut child = check
            .spawn()
            .map_err(|error| RuntimeError::new("config_check", error.to_string()))?;
        let _check_job = KillOnDropJob::assign(&mut child)?;
        let stderr = child.stderr.take().ok_or_else(|| {
            RuntimeError::new("config_check", "engine check stderr was unavailable")
        })?;
        let reader = thread::spawn(move || read_bounded(stderr, MAX_CHECK_STDERR));
        let deadline = Instant::now() + CHECK_TIMEOUT;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| RuntimeError::new("config_check", error.to_string()))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RuntimeError::new("config_check", "engine check timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        };
        let raw = reader
            .join()
            .unwrap_or_else(|_| "stderr reader failed".into());
        let sanitized = redactor.redact(&raw);
        if !sanitized.trim().is_empty() {
            diagnostics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(sanitized.clone());
        }
        if !status.success() {
            return Err(RuntimeError::new(
                "config_check",
                if sanitized.trim().is_empty() {
                    "sing-box rejected the generated configuration".into()
                } else {
                    sanitized
                },
            ));
        }

        Ok(version)
    }

    fn start(
        &self,
        config: &Path,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<Box<dyn ManagedChild>, RuntimeError> {
        let (launch_guards, _launch_version) = self.layout.verify()?;
        let mut command = fixed_command(
            &self.layout,
            &[OsStr::new("run"), OsStr::new("-c"), config.as_os_str()],
        );
        let mut child = command
            .spawn()
            .map_err(|error| RuntimeError::new("start_engine", error.to_string()))?;
        let job = KillOnDropJob::assign(&mut child)?;
        let stderr = child.stderr.take().ok_or_else(|| {
            let _ = child.kill();
            RuntimeError::new("start_engine", "engine stderr was unavailable")
        })?;
        let diagnostic_target = diagnostics.clone();
        let stderr_redactor = redactor.clone();
        let stderr_thread = thread::spawn(move || {
            capture_stderr(stderr, &stderr_redactor, &diagnostic_target);
        });
        Ok(Box::new(RealManagedChild {
            child,
            job: Some(job),
            stderr_thread: Some(stderr_thread),
            _verified_files: launch_guards,
        }))
    }
}

fn fixed_command(layout: &FixedEngineLayout, arguments: &[&OsStr]) -> Command {
    let mut command = Command::new(&layout.executable);
    command
        .args(arguments)
        .current_dir(&layout.engine_dir)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for name in ["SystemRoot", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn read_bounded(reader: impl Read, limit: usize) -> String {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let _ = reader.take((limit + 1) as u64).read_to_end(&mut bytes);
    if bytes.len() > limit {
        "[REDACTED: engine diagnostic exceeded limit]".into()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn capture_stderr(
    mut reader: impl Read,
    redactor: &Redactor,
    diagnostics: &Arc<Mutex<DiagnosticBuffer>>,
) {
    const MAX_PENDING_LINE: usize = 4 * 1024;
    let mut chunk = [0_u8; 2 * 1024];
    let mut pending = Vec::new();
    let mut discard_until_newline = false;
    loop {
        let count = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        for byte in &chunk[..count] {
            if discard_until_newline {
                if *byte == b'\n' {
                    discard_until_newline = false;
                }
                continue;
            }
            if *byte == b'\n' {
                push_redacted_bytes(&pending, redactor, diagnostics);
                pending.clear();
                continue;
            }
            pending.push(*byte);
            if pending.len() > MAX_PENDING_LINE {
                diagnostics
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push("[REDACTED: engine diagnostic line exceeded limit]".into());
                pending.clear();
                discard_until_newline = true;
            }
        }
    }
    if !pending.is_empty() {
        push_redacted_bytes(&pending, redactor, diagnostics);
    }
}

fn push_redacted_bytes(
    bytes: &[u8],
    redactor: &Redactor,
    diagnostics: &Arc<Mutex<DiagnosticBuffer>>,
) {
    let text = String::from_utf8_lossy(bytes);
    diagnostics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(redactor.redact(text.trim_end()));
}

struct RealManagedChild {
    child: Child,
    job: Option<KillOnDropJob>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    _verified_files: VerifiedFiles,
}

impl ManagedChild for RealManagedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn is_alive(&mut self) -> Result<bool, RuntimeError> {
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|error| RuntimeError::new("engine_process", error.to_string()))
    }

    fn stop(&mut self) -> Result<(), RuntimeError> {
        if self
            .child
            .try_wait()
            .map_err(|error| RuntimeError::new("stop_engine", error.to_string()))?
            .is_none()
        {
            if let Err(error) = self.child.kill() {
                if self
                    .child
                    .try_wait()
                    .map_err(|wait_error| RuntimeError::new("stop_engine", wait_error.to_string()))?
                    .is_none()
                {
                    return Err(RuntimeError::new("stop_engine", error.to_string()));
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut exited = loop {
            if self
                .child
                .try_wait()
                .map_err(|error| RuntimeError::new("stop_engine", error.to_string()))?
                .is_some()
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(20));
        };
        self.job.take();
        if !exited {
            let job_deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if self
                    .child
                    .try_wait()
                    .map_err(|error| RuntimeError::new("stop_engine", error.to_string()))?
                    .is_some()
                {
                    exited = true;
                    break;
                }
                if Instant::now() >= job_deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        if exited {
            if let Some(reader) = self.stderr_thread.take() {
                let _ = reader.join();
            }
            Ok(())
        } else {
            self.stderr_thread.take();
            Err(RuntimeError::new(
                "stop_engine",
                "engine did not exit within the shutdown deadline",
            ))
        }
    }
}

impl Drop for RealManagedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(windows)]
struct KillOnDropJob(windows_sys::Win32::Foundation::HANDLE);

// A Job Object HANDLE has no thread affinity. This wrapper owns the handle and
// closes it exactly once, so transferring ownership with the managed child is safe.
#[cfg(windows)]
unsafe impl Send for KillOnDropJob {}

#[cfg(windows)]
impl KillOnDropJob {
    fn assign(child: &mut Child) -> Result<Self, RuntimeError> {
        use std::{mem::size_of, os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            let _ = child.kill();
            return Err(RuntimeError::new(
                "start_engine",
                "could not create engine Job Object",
            ));
        }
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &information as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        let assigned = if configured != 0 {
            unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as _) }
        } else {
            0
        };
        if assigned == 0 {
            let _ = child.kill();
            unsafe { CloseHandle(handle) };
            return Err(RuntimeError::new(
                "start_engine",
                "could not assign engine to kill-on-close Job Object",
            ));
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for KillOnDropJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(not(windows))]
struct KillOnDropJob;

#[cfg(not(windows))]
impl KillOnDropJob {
    fn assign(_child: &mut Child) -> Result<Self, RuntimeError> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    struct FixtureLayout {
        root: PathBuf,
        layout: FixedEngineLayout,
        lock: EngineLock,
    }

    impl FixtureLayout {
        fn create() -> Self {
            let root = std::env::temp_dir().join(format!(
                "routedeck-engine-fixture-{}",
                random_hex(8).unwrap()
            ));
            let engine = root.join(ENGINE_DIRECTORY);
            fs::create_dir_all(&engine).unwrap();
            let executable = b"fixture executable";
            let cronet = b"fixture cronet";
            let license = b"fixture license";
            fs::write(engine.join(ENGINE_EXE), executable).unwrap();
            fs::write(engine.join(CRONET_DLL), cronet).unwrap();
            fs::write(engine.join("LICENSE"), license).unwrap();
            let layout = FixedEngineLayout::from_package_root(&root).unwrap();
            let lock = EngineLock {
                schema_version: 1,
                engine: "sing-box".into(),
                version: "1.13.19".into(),
                runtime_files: vec![
                    LockedFile {
                        path: ENGINE_EXE.into(),
                        kind: "executable".into(),
                        size: executable.len() as u64,
                        sha256: digest(executable),
                    },
                    LockedFile {
                        path: CRONET_DLL.into(),
                        kind: "library".into(),
                        size: cronet.len() as u64,
                        sha256: digest(cronet),
                    },
                    LockedFile {
                        path: "LICENSE".into(),
                        kind: "license".into(),
                        size: license.len() as u64,
                        sha256: digest(license),
                    },
                ],
            };
            Self { root, layout, lock }
        }
    }

    impl Drop for FixtureLayout {
        fn drop(&mut self) {
            let canonical_temp = fs::canonicalize(std::env::temp_dir()).ok();
            let canonical_root = fs::canonicalize(&self.root).ok();
            if canonical_root
                .as_ref()
                .zip(canonical_temp.as_ref())
                .is_some_and(|(root, temp)| root.starts_with(temp) && root != temp)
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    #[test]
    fn fixture_engine_requires_exact_hash_size_and_file_set() {
        let fixture = FixtureLayout::create();
        fixture.layout.verify_lock(&fixture.lock).unwrap();
        fs::write(fixture.layout.engine_dir.join("extra.exe"), b"foreign").unwrap();
        let error = match fixture.layout.verify_lock(&fixture.lock) {
            Ok(_) => panic!("unexpected extra executable was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.stage(), "engine_integrity");
        fs::remove_file(fixture.layout.engine_dir.join("extra.exe")).unwrap();
        fs::write(&fixture.layout.executable, b"wrong size").unwrap();
        assert!(fixture.layout.verify_lock(&fixture.lock).is_err());
    }

    #[test]
    fn reservations_are_distinct_and_occupy_loopback_ports() {
        let reservations = PortReservations::reserve().unwrap();
        let ports = reservations.ports();
        assert_ne!(ports.http, ports.socks);
        assert_ne!(ports.http, ports.health);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, ports.http)).is_err());
    }

    #[test]
    fn diagnostic_buffer_is_bounded() {
        let mut buffer = DiagnosticBuffer::default();
        for index in 0..300 {
            buffer.push(format!("line-{index}"));
        }
        assert_eq!(buffer.snapshot().len(), MAX_DIAGNOSTIC_LINES);
    }

    #[test]
    fn streaming_stderr_is_bounded_and_redacted_before_storage() {
        let diagnostics = Arc::new(Mutex::new(DiagnosticBuffer::default()));
        let secret = "fixture-runtime-password";
        let input = format!("password={secret}\n{}", "x".repeat(5 * 1024));
        capture_stderr(
            std::io::Cursor::new(input),
            &Redactor::default().with_secret(secret),
            &diagnostics,
        );
        let lines = diagnostics.lock().unwrap().snapshot();
        assert!(lines.iter().all(|line| !line.contains(secret)));
        assert!(lines.iter().any(|line| line.contains("exceeded limit")));
    }

    #[test]
    fn oversized_stderr_discards_the_entire_line_across_secret_boundary() {
        let diagnostics = Arc::new(Mutex::new(DiagnosticBuffer::default()));
        let secret = "boundary-secret-value";
        let input = format!("{}{}\nnext-safe-line\n", "x".repeat(4090), secret);
        capture_stderr(
            std::io::Cursor::new(input),
            &Redactor::default().with_secret(secret),
            &diagnostics,
        );
        let lines = diagnostics.lock().unwrap().snapshot();
        assert!(lines.iter().all(|line| !line.contains("secret-value")));
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("exceeded limit"))
                .count(),
            1
        );
        assert!(lines.iter().any(|line| line == "next-safe-line"));
    }

    #[test]
    fn random_values_are_distinct_and_fixed_length() {
        let first = random_hex(16).unwrap();
        let second = random_hex(16).unwrap();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
    }

    #[cfg(windows)]
    #[test]
    fn session_config_is_private_atomic_and_locked_against_mutation() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-session-fixture-{}",
            random_hex(8).unwrap()
        ));
        let session = SessionConfig::create(&root, "{\"secret\":true}").unwrap();
        assert_eq!(
            fs::read_to_string(session.path()).unwrap(),
            "{\"secret\":true}"
        );
        assert!(OpenOptions::new().write(true).open(session.path()).is_err());
        assert!(fs::remove_file(session.path()).is_err());
        let path = session.path().to_owned();
        drop(session);
        assert!(!path.exists());
        let canonical_temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        assert!(canonical_root.starts_with(&canonical_temp) && canonical_root != canonical_temp);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn stale_session_recovery_preserves_data_without_proven_ownership() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-recovery-fixture-{}",
            random_hex(8).unwrap()
        ));
        let stale = root.join("session-0123456789abcdef0123456789abcdef");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("config.tmp"), b"fixture-secret").unwrap();
        assert!(reconcile_stale_sessions(&root).is_err());
        assert_eq!(
            fs::read(stale.join("config.tmp")).unwrap(),
            b"fixture-secret"
        );
        fs::remove_file(stale.join("config.tmp")).unwrap();
        fs::remove_dir(stale).unwrap();
        reconcile_stale_sessions(&root).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
