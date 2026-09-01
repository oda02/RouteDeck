use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use getrandom::fill as fill_random;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[cfg(windows)]
use crate::windows_process::{create_suspended_engine, EngineCommand, PlatformProcess};
use crate::{config::LocalPorts, redaction::Redactor};

const EMBEDDED_SING_BOX_LOCK: &str = include_str!("../../engine/sing-box.lock.json");
const EMBEDDED_XRAY_LOCK: &str = include_str!("../../engine/xray-core.lock.json");
const SING_BOX_DIRECTORY: &str = "engine";
const SING_BOX_EXE: &str = "sing-box.exe";
const XRAY_DIRECTORY: &str = "xray";
const XRAY_EXE: &str = "xray.exe";
const CRONET_DLL: &str = "libcronet.dll";
const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
const CHECK_READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CHECK_STDERR: usize = 64 * 1024;
const MAX_DIAGNOSTIC_LINES: usize = 128;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Xray is staged here and consumed by the dual-engine application milestone.
pub(crate) enum EngineKind {
    SingBox,
    Xray,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Descriptor metadata is intentionally exposed before dual-engine wiring.
pub(crate) struct EngineDescriptor {
    kind: EngineKind,
    directory_name: &'static str,
    executable_name: &'static str,
    lock_json: &'static str,
    lock_engine: &'static str,
    version: &'static str,
    execution_files: &'static [(&'static str, &'static str)],
    check_command: EngineCommand,
    run_command: EngineCommand,
    display_name: &'static str,
}

const SING_BOX_EXECUTION_FILES: &[(&str, &str)] =
    &[(SING_BOX_EXE, "executable"), (CRONET_DLL, "library")];
const XRAY_EXECUTION_FILES: &[(&str, &str)] = &[(XRAY_EXE, "executable")];

#[allow(dead_code)]
impl EngineDescriptor {
    pub(crate) const fn for_kind(kind: EngineKind) -> Self {
        match kind {
            EngineKind::SingBox => Self {
                kind,
                directory_name: SING_BOX_DIRECTORY,
                executable_name: SING_BOX_EXE,
                lock_json: EMBEDDED_SING_BOX_LOCK,
                lock_engine: "sing-box",
                version: "1.13.19",
                execution_files: SING_BOX_EXECUTION_FILES,
                check_command: EngineCommand::SingBoxCheck,
                run_command: EngineCommand::SingBoxRun,
                display_name: "sing-box",
            },
            EngineKind::Xray => Self {
                kind,
                directory_name: XRAY_DIRECTORY,
                executable_name: XRAY_EXE,
                lock_json: EMBEDDED_XRAY_LOCK,
                lock_engine: "xray-core",
                version: "26.3.27",
                execution_files: XRAY_EXECUTION_FILES,
                check_command: EngineCommand::XrayCheck,
                run_command: EngineCommand::XrayRun,
                display_name: "Xray",
            },
        }
    }

    pub(crate) const fn kind(self) -> EngineKind {
        self.kind
    }

    pub(crate) const fn directory_name(self) -> &'static str {
        self.directory_name
    }

    pub(crate) const fn executable_name(self) -> &'static str {
        self.executable_name
    }
}

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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EngineLock {
    schema_version: u32,
    engine: String,
    version: String,
    runtime_files: Vec<LockedFile>,
}

#[derive(Debug, Clone, Deserialize)]
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
    descriptor: EngineDescriptor,
}

impl FixedEngineLayout {
    fn resolve(descriptor: EngineDescriptor) -> Result<Self, RuntimeError> {
        let executable = std::env::current_exe()
            .map_err(|error| RuntimeError::new("engine_layout", error.to_string()))?;
        let package_root = executable.parent().ok_or_else(|| {
            RuntimeError::new("engine_layout", "application directory is unavailable")
        })?;
        Self::from_package_root(package_root, descriptor)
    }

    fn from_package_root(
        package_root: &Path,
        descriptor: EngineDescriptor,
    ) -> Result<Self, RuntimeError> {
        reject_reparse(package_root)?;
        let engine_dir = package_root.join(descriptor.directory_name);
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
            engine_dir: canonical_engine,
            descriptor,
        })
    }
}

struct VerifiedFiles {
    _directory: File,
    files: BTreeMap<String, File>,
}

impl FixedEngineLayout {
    fn verify(&self) -> Result<(VerifiedFiles, String), RuntimeError> {
        let lock = embedded_engine_lock(self.descriptor)?;
        self.verify_lock(&lock)
    }

    fn verify_lock(&self, lock: &EngineLock) -> Result<(VerifiedFiles, String), RuntimeError> {
        if lock.schema_version != 1
            || lock.engine != self.descriptor.lock_engine
            || lock.version != self.descriptor.version
        {
            return Err(RuntimeError::new(
                "engine_integrity",
                "embedded engine identity is unsupported",
            ));
        }
        let files = verify_runtime_directory(&self.engine_dir, lock, self.descriptor)?;
        Ok((files, lock.version.clone()))
    }
}

fn embedded_engine_lock(descriptor: EngineDescriptor) -> Result<EngineLock, RuntimeError> {
    serde_json::from_str(descriptor.lock_json)
        .map_err(|_| RuntimeError::new("engine_integrity", "embedded lock is invalid"))
}

fn verify_runtime_directory(
    engine_dir: &Path,
    lock: &EngineLock,
    descriptor: EngineDescriptor,
) -> Result<VerifiedFiles, RuntimeError> {
    let held_directory = open_engine_directory_guard(engine_dir)?;
    reject_unlocked_binaries(engine_dir, &lock.runtime_files)?;
    let mut held_files = BTreeMap::new();
    let mut execution_files = BTreeSet::new();
    for locked in &lock.runtime_files {
        if Path::new(&locked.path).file_name() != Some(OsStr::new(&locked.path)) {
            return Err(RuntimeError::new(
                "engine_integrity",
                "engine lock contains a nested runtime path",
            ));
        }
        let path = engine_dir.join(&locked.path);
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
        if descriptor
            .execution_files
            .contains(&(locked.path.as_str(), locked.kind.as_str()))
        {
            execution_files.insert((locked.path.clone(), locked.kind.clone()));
        }
        held_files.insert(locked.path.clone(), file);
    }
    if execution_files.len() != descriptor.execution_files.len()
        || descriptor
            .execution_files
            .iter()
            .any(|(path, kind)| !execution_files.contains(&(path.to_string(), kind.to_string())))
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "locked execution file set is incomplete",
        ));
    }
    Ok(VerifiedFiles {
        _directory: held_directory,
        files: held_files,
    })
}

fn open_engine_directory_guard(path: &Path) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
        .open(path)
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))
}

fn reject_unlocked_binaries(
    engine_dir: &Path,
    locked_files: &[LockedFile],
) -> Result<(), RuntimeError> {
    let allowed_exact: BTreeSet<String> = locked_files
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let allowed_folded: BTreeSet<String> = locked_files
        .iter()
        .map(|entry| entry.path.to_ascii_lowercase())
        .collect();
    if allowed_exact.len() != locked_files.len() || allowed_folded.len() != locked_files.len() {
        return Err(RuntimeError::new(
            "engine_integrity",
            "engine lock contains duplicate runtime paths",
        ));
    }
    let mut seen_folded = BTreeSet::new();
    let mut entry_count = 0_usize;
    for entry in fs::read_dir(engine_dir)
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?
    {
        let entry =
            entry.map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
        reject_reparse(&entry.path())?;
        entry_count = entry_count.saturating_add(1);
        let file_name = entry.file_name();
        let name = file_name.to_str().ok_or_else(|| {
            RuntimeError::new(
                "engine_integrity",
                "engine directory contains a non-Unicode runtime name",
            )
        })?;
        let folded = name.to_ascii_lowercase();
        if !entry
            .file_type()
            .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?
            .is_file()
            || !accept_runtime_entry_name(
                name,
                &folded,
                &allowed_exact,
                &allowed_folded,
                &mut seen_folded,
            )
        {
            return Err(RuntimeError::new(
                "engine_integrity",
                "engine directory contains an unlocked file or directory",
            ));
        }
    }
    if entry_count != locked_files.len() || seen_folded.len() != locked_files.len() {
        return Err(RuntimeError::new(
            "engine_integrity",
            "engine directory does not exactly match the embedded lock",
        ));
    }
    Ok(())
}

fn accept_runtime_entry_name(
    name: &str,
    folded: &str,
    allowed_exact: &BTreeSet<String>,
    allowed_folded: &BTreeSet<String>,
    seen_folded: &mut BTreeSet<String>,
) -> bool {
    allowed_exact.contains(name)
        && allowed_folded.contains(folded)
        && seen_folded.insert(folded.to_owned())
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedObjectIdentity {
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
    #[cfg(windows)]
    security_descriptor: Vec<u8>,
    #[cfg(not(windows))]
    length: u64,
}

struct SealedEngine {
    directory: PathBuf,
    executable: PathBuf,
    identities: BTreeMap<String, SealedObjectIdentity>,
    cleanup_lock: EngineLock,
    descriptor: EngineDescriptor,
}

impl SealedEngine {
    fn create(
        session_directory: &Path,
        lock: &EngineLock,
        source: &VerifiedFiles,
        descriptor: EngineDescriptor,
    ) -> Result<Self, RuntimeError> {
        #[cfg(not(windows))]
        {
            let _ = (session_directory, lock, source, descriptor);
            return Err(RuntimeError::new(
                "engine_integrity",
                "sealed engine execution is supported only on Windows",
            ));
        }
        #[cfg(windows)]
        {
            let execution_lock = execution_lock(lock, descriptor)?;
            reject_reparse(session_directory)?;
            let directory = session_directory.join(format!("engine-run-{}", random_hex(16)?));
            create_private_directory(&directory)
                .map_err(|error| RuntimeError::new("engine_integrity", error.message))?;
            let result = (|| {
                let directory_guard = open_engine_directory_guard(&directory)?;
                ensure_supported_seal_volume(&directory, &directory_guard)?;
                for locked in &execution_lock.runtime_files {
                    if Path::new(&locked.path).file_name() != Some(OsStr::new(&locked.path)) {
                        return Err(RuntimeError::new(
                            "engine_integrity",
                            "engine lock contains a nested runtime path",
                        ));
                    }
                    let source_file = source.files.get(&locked.path).ok_or_else(|| {
                        RuntimeError::new(
                            "engine_integrity",
                            "verified source file handle is missing",
                        )
                    })?;
                    copy_verified_file(source_file, &directory.join(&locked.path), locked.size)?;
                }
                for locked in &execution_lock.runtime_files {
                    apply_sealed_acl(&directory.join(&locked.path))?;
                }
                apply_sealed_acl(&directory)?;
                drop(directory_guard);

                let verified = verify_runtime_directory(&directory, &execution_lock, descriptor)?;
                let identities = sealed_identities(&verified)?;
                verify_sealed_directory_is_read_only(&directory)?;
                Ok(Self {
                    executable: directory.join(descriptor.executable_name),
                    directory: directory.clone(),
                    identities,
                    cleanup_lock: execution_lock.clone(),
                    descriptor,
                })
            })();
            if result.is_err() {
                let _ = cleanup_owned_engine_directory(&directory, &execution_lock);
            }
            result
        }
    }

    fn verify_for_launch(&self) -> Result<VerifiedFiles, RuntimeError> {
        let verified =
            verify_runtime_directory(&self.directory, &self.cleanup_lock, self.descriptor)?;
        let identities = sealed_identities(&verified)?;
        if identities != self.identities {
            return Err(RuntimeError::new(
                "engine_integrity",
                "sealed engine file identity, owner, or ACL changed before launch",
            ));
        }
        verify_sealed_directory_is_read_only(&self.directory)?;
        Ok(verified)
    }
}

fn execution_lock(
    lock: &EngineLock,
    descriptor: EngineDescriptor,
) -> Result<EngineLock, RuntimeError> {
    let has_disguised_binary = lock.runtime_files.iter().any(|entry| {
        let folded = entry.path.to_ascii_lowercase();
        matches!(
            Path::new(&folded).extension().and_then(OsStr::to_str),
            Some("exe" | "dll")
        ) && !descriptor
            .execution_files
            .contains(&(entry.path.as_str(), entry.kind.as_str()))
    });
    let runtime_files = lock
        .runtime_files
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "executable" | "library"))
        .cloned()
        .collect::<Vec<_>>();
    if has_disguised_binary
        || runtime_files.len() != descriptor.execution_files.len()
        || descriptor.execution_files.iter().any(|(path, kind)| {
            !runtime_files
                .iter()
                .any(|entry| entry.path == *path && entry.kind == *kind)
        })
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "engine lock does not define the exact execution file set",
        ));
    }
    Ok(EngineLock {
        schema_version: lock.schema_version,
        engine: lock.engine.clone(),
        version: lock.version.clone(),
        runtime_files,
    })
}

impl Drop for SealedEngine {
    fn drop(&mut self) {
        let _ = cleanup_owned_engine_directory(&self.directory, &self.cleanup_lock);
    }
}

#[cfg(windows)]
fn copy_verified_file(
    source: &File,
    destination: &Path,
    expected_size: u64,
) -> Result<(), RuntimeError> {
    let mut source = source
        .try_clone()
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
    let mut destination_file = create_private_config_file(destination)
        .map_err(|error| RuntimeError::new("engine_integrity", error.message))?;
    let copied = std::io::copy(
        &mut source.take(expected_size.saturating_add(1)),
        &mut destination_file,
    )
    .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
    if copied != expected_size {
        return Err(RuntimeError::new(
            "engine_integrity",
            "verified source changed size while sealing",
        ));
    }
    destination_file
        .sync_all()
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))
}

#[cfg(windows)]
fn cleanup_owned_engine_directory(directory: &Path, lock: &EngineLock) -> Result<(), RuntimeError> {
    if !directory.exists() {
        return Ok(());
    }
    reject_reparse(directory)?;
    let allowed = lock
        .runtime_files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(directory)
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?
    {
        let entry =
            entry.map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
        reject_reparse(&entry.path())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            RuntimeError::new(
                "session_recovery",
                "sealed engine contains a non-Unicode entry",
            )
        })?;
        if !allowed.contains(name)
            || !entry
                .file_type()
                .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?
                .is_file()
        {
            return Err(RuntimeError::new(
                "session_recovery",
                "sealed engine cleanup found an unrecognized entry",
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))?;
    }
    fs::remove_dir(directory)
        .map_err(|error| RuntimeError::new("session_recovery", error.to_string()))
}

#[cfg(not(windows))]
fn cleanup_owned_engine_directory(
    _directory: &Path,
    _lock: &EngineLock,
) -> Result<(), RuntimeError> {
    Ok(())
}

#[cfg(windows)]
fn ensure_supported_seal_volume(path: &Path, directory: &File) -> Result<(), RuntimeError> {
    use std::{os::windows::ffi::OsStrExt, os::windows::io::AsRawHandle, ptr};
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetVolumeInformationByHandleW, GetVolumePathNameW,
    };

    const DRIVE_FIXED_VALUE: u32 = 3;
    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut volume_path = vec![0_u16; 32_768];
    if unsafe {
        GetVolumePathNameW(
            wide_path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    } == 0
        || unsafe { GetDriveTypeW(volume_path.as_ptr()) } != DRIVE_FIXED_VALUE
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine execution requires a local fixed volume",
        ));
    }

    let mut flags = 0_u32;
    let mut filesystem = [0_u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not verify the sealed engine filesystem",
        ));
    }
    let length = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(filesystem.len());
    let filesystem = String::from_utf16_lossy(&filesystem[..length]);
    if !seal_volume_supported(DRIVE_FIXED_VALUE, flags, &filesystem) {
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine execution requires NTFS or ReFS with persistent ACLs",
        ));
    }
    Ok(())
}

fn seal_volume_supported(drive_type: u32, filesystem_flags: u32, filesystem: &str) -> bool {
    const DRIVE_FIXED_VALUE: u32 = 3;
    const FILE_PERSISTENT_ACLS_VALUE: u32 = 0x0000_0008;
    drive_type == DRIVE_FIXED_VALUE
        && filesystem_flags & FILE_PERSISTENT_ACLS_VALUE != 0
        && matches!(filesystem.to_ascii_uppercase().as_str(), "NTFS" | "REFS")
}

#[cfg(windows)]
fn apply_sealed_acl(path: &Path) -> Result<(), RuntimeError> {
    let user_sid = current_user_sid_string()?;
    let inheritance = if path
        .metadata()
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?
        .is_dir()
    {
        "OICI"
    } else {
        ""
    };
    apply_protected_acl(
        path,
        &format!("O:{user_sid}D:P(A;{inheritance};GRGXSD;;;{user_sid})(A;{inheritance};FA;;;SY)"),
    )
}

#[cfg(windows)]
fn apply_protected_acl(path: &Path, descriptor_sddl: &str) -> Result<(), RuntimeError> {
    apply_protected_acl_inner(path, descriptor_sddl, true)
}

#[cfg(all(windows, test))]
fn apply_protected_dacl_for_test(path: &Path, descriptor_sddl: &str) -> Result<(), RuntimeError> {
    apply_protected_acl_inner(path, descriptor_sddl, false)
}

#[cfg(windows)]
fn apply_protected_acl_inner(
    path: &Path,
    descriptor_sddl: &str,
    set_owner: bool,
) -> Result<(), RuntimeError> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{LocalFree, ERROR_SUCCESS},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, DACL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    };

    // Owner can read, execute, and later delete exact owned files, but cannot add or write.
    // SYSTEM remains the only recovery principal. The DACL is protected from inheritance.
    let descriptor_text = OsStr::new(descriptor_sddl)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not construct the sealed engine ACL",
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    let dacl_ok =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    if dacl_ok == 0 || present == 0 || dacl.is_null() {
        unsafe { LocalFree(descriptor) };
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine ACL did not contain a DACL",
        ));
    }
    let mut owner = ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
    {
        unsafe { LocalFree(descriptor) };
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine ACL did not contain an explicit owner",
        ));
    }
    let mut wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let security_information = DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION
        | if set_owner {
            OWNER_SECURITY_INFORMATION
        } else {
            0
        };
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_mut_ptr(),
            SE_FILE_OBJECT,
            security_information,
            if set_owner { owner } else { ptr::null_mut() },
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    if status != ERROR_SUCCESS {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not apply the sealed engine ACL",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn sealed_identities(
    verified: &VerifiedFiles,
) -> Result<BTreeMap<String, SealedObjectIdentity>, RuntimeError> {
    let mut identities = BTreeMap::new();
    identities.insert(
        ".".to_owned(),
        sealed_object_identity(&verified._directory, true)?,
    );
    for (name, file) in &verified.files {
        identities.insert(name.clone(), sealed_object_identity(file, false)?);
    }
    Ok(identities)
}

#[cfg(windows)]
fn sealed_object_identity(
    file: &File,
    expect_directory: bool,
) -> Result<SealedObjectIdentity, RuntimeError> {
    use std::{mem::size_of, os::windows::io::AsRawHandle, ptr, slice};
    use windows_sys::Win32::{
        Foundation::{LocalFree, ERROR_SUCCESS},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            GetSecurityDescriptorControl, GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION,
            GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        },
        Storage::FileSystem::{
            FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx, GetFileType, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO, FILE_TYPE_DISK,
        },
    };

    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::new("engine_integrity", error.to_string()))?;
    if metadata.is_dir() != expect_directory || (!expect_directory && !metadata.is_file()) {
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine object type changed",
        ));
    }
    let handle = file.as_raw_handle();
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine object is not a disk file",
        ));
    }
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine object is a reparse point or its attributes are unavailable",
        ));
    }
    let mut basic = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut basic) } == 0
        || (!expect_directory && basic.nNumberOfLinks != 1)
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine object has an unsupported link identity",
        ));
    }
    let mut information = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not read sealed engine file identity",
        ));
    }

    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not read sealed engine owner or ACL",
        ));
    }
    let acl_matches = sealed_acl_matches(owner, dacl, expect_directory);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    let descriptor_length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if !acl_matches || control_ok == 0 || descriptor_length == 0 || control & SE_DACL_PROTECTED == 0
    {
        unsafe { LocalFree(descriptor) };
        return Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine owner or protected ACL is invalid",
        ));
    }
    let security_descriptor =
        unsafe { slice::from_raw_parts(descriptor.cast(), descriptor_length) }.to_vec();
    unsafe { LocalFree(descriptor) };
    Ok(SealedObjectIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
        security_descriptor,
    })
}

#[cfg(windows)]
fn sealed_acl_matches(
    owner: windows_sys::Win32::Security::PSID,
    dacl: *const windows_sys::Win32::Security::ACL,
    expect_directory: bool,
) -> bool {
    use std::{mem::size_of, ptr};
    use windows_sys::Win32::Security::{
        AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation,
        WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
        INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, SECURITY_MAX_SID_SIZE,
    };

    const ACCESS_ALLOWED_ACE_TYPE_VALUE: u8 = 0;
    const OWNER_GENERIC_RX_DELETE: u32 = 0xa001_0000;
    const OWNER_FILE_RX_DELETE: u32 = 0x0013_00a9;
    const SYSTEM_FILE_ALL: u32 = 0x001f_01ff;
    const SYSTEM_GENERIC_ALL: u32 = 0x1000_0000;
    let current = match current_user_sid() {
        Ok(sid) => sid,
        Err(_) => return false,
    };
    if unsafe { EqualSid(owner, current.as_ptr().cast_mut().cast()) } == 0 {
        return false;
    }
    let mut system = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut system_size = system.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            ptr::null_mut(),
            system.as_mut_ptr().cast(),
            &mut system_size,
        )
    } == 0
    {
        return false;
    }
    system.truncate(system_size as usize);

    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return false;
    }
    let mut saw_current_effective = false;
    let mut saw_current_inheritable = false;
    let mut saw_system = false;
    for index in 0..information.AceCount {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return false;
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE_VALUE
            || ace.Header.AceSize < size_of::<ACCESS_ALLOWED_ACE>() as u16
        {
            return false;
        }
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if unsafe { EqualSid(sid, current.as_ptr().cast_mut().cast()) } != 0 {
            if ace.Header.AceFlags == 0 && ace.Mask == OWNER_FILE_RX_DELETE {
                if saw_current_effective {
                    return false;
                }
                saw_current_effective = true;
            } else if expect_directory
                && ace.Header.AceFlags
                    == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE) as u8
                && ace.Mask == OWNER_GENERIC_RX_DELETE
            {
                if saw_current_inheritable {
                    return false;
                }
                saw_current_inheritable = true;
            } else {
                return false;
            }
        } else if unsafe { EqualSid(sid, system.as_ptr().cast_mut().cast()) } != 0 {
            let flags_match = if expect_directory {
                ace.Header.AceFlags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
            } else {
                ace.Header.AceFlags == 0
            };
            if saw_system
                || !flags_match
                || !matches!(ace.Mask, SYSTEM_FILE_ALL | SYSTEM_GENERIC_ALL)
            {
                return false;
            }
            saw_system = true;
        } else {
            return false;
        }
    }
    saw_current_effective && (!expect_directory || saw_current_inheritable) && saw_system
}

#[cfg(windows)]
fn current_user_sid() -> Result<Vec<u8>, RuntimeError> {
    use std::{mem::size_of, ptr, slice};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER},
        Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not open the current user token",
        ));
    }
    let mut byte_count = 0_u32;
    let first =
        unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut byte_count) };
    if first != 0
        || unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || byte_count < size_of::<TOKEN_USER>() as u32
    {
        unsafe { CloseHandle(token) };
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not size the current user SID",
        ));
    }
    let mut storage = vec![0_usize; (byte_count as usize).div_ceil(size_of::<usize>())];
    let loaded = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            byte_count,
            &mut byte_count,
        )
    };
    if loaded == 0 {
        unsafe { CloseHandle(token) };
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not read the current user SID",
        ));
    }
    let sid = unsafe { (&*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let sid_length = unsafe { GetLengthSid(sid) } as usize;
    if sid_length == 0 {
        unsafe { CloseHandle(token) };
        return Err(RuntimeError::new(
            "engine_integrity",
            "current user SID is invalid",
        ));
    }
    let bytes = unsafe { slice::from_raw_parts(sid.cast::<u8>(), sid_length) }.to_vec();
    unsafe { CloseHandle(token) };
    Ok(bytes)
}

#[cfg(windows)]
fn current_user_sid_string() -> Result<String, RuntimeError> {
    use std::{os::windows::ffi::OsStringExt, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree, Security::Authorization::ConvertSidToStringSidW,
    };

    let sid = current_user_sid()?;
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut text) } == 0
        || text.is_null()
    {
        return Err(RuntimeError::new(
            "engine_integrity",
            "could not format the current user SID",
        ));
    }
    let mut length = 0_usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let result = std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(text, length) })
        .to_string_lossy()
        .into_owned();
    unsafe { LocalFree(text.cast()) };
    Ok(result)
}

#[cfg(windows)]
fn verify_sealed_directory_is_read_only(directory: &Path) -> Result<(), RuntimeError> {
    let probe = directory.join(".routedeck-late-write-probe.dll");
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Err(error) if error.raw_os_error() == Some(5) => Ok(()),
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(probe);
            Err(RuntimeError::new(
                "engine_integrity",
                "sealed engine directory still permits late file creation",
            ))
        }
        Err(_) => Err(RuntimeError::new(
            "engine_integrity",
            "sealed engine write-denial probe was inconclusive",
        )),
    }
}

#[cfg(not(windows))]
fn sealed_identities(
    _verified: &VerifiedFiles,
) -> Result<BTreeMap<String, SealedObjectIdentity>, RuntimeError> {
    Err(RuntimeError::new(
        "engine_integrity",
        "sealed engine execution is supported only on Windows",
    ))
}

#[cfg(not(windows))]
fn verify_sealed_directory_is_read_only(_directory: &Path) -> Result<(), RuntimeError> {
    Err(RuntimeError::new(
        "engine_integrity",
        "sealed engine execution is supported only on Windows",
    ))
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
    directory_guard: Option<File>,
    identity: ConfigIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigIdentity {
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
    #[cfg(windows)]
    security_descriptor: Vec<u8>,
    #[cfg(not(windows))]
    length: u64,
}

impl SessionConfig {
    pub(crate) fn create(root: &Path, contents: &str) -> Result<Self, RuntimeError> {
        Self::create_with_identity(root, contents, config_identity)
    }

    fn create_with_identity(
        root: &Path,
        contents: &str,
        identity_reader: impl FnOnce(&File) -> Result<ConfigIdentity, RuntimeError>,
    ) -> Result<Self, RuntimeError> {
        fs::create_dir_all(root)
            .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
        reject_reparse(root)?;
        let session_id = random_hex(16)?;
        let directory = root.join(format!("session-{session_id}"));
        create_private_directory(&directory)?;
        let result = (|| {
            let directory_guard = open_session_directory_guard(&directory)?;
            let (config_path, guard) = create_session_config(&directory, contents)?;
            let identity = identity_reader(&guard)?;
            Ok(Self {
                directory: directory.clone(),
                config_path,
                guard: Some(guard),
                directory_guard: Some(directory_guard),
                identity,
            })
        })();
        match result {
            Ok(session) => Ok(session),
            Err(error) => {
                let cleanup = cleanup_session_directory(&directory);
                if cleanup.is_err() {
                    return Err(RuntimeError::new(
                        "session_recovery",
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

    fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn revalidate_for_launch(&self) -> Result<File, RuntimeError> {
        reject_reparse(&self.directory)
            .map_err(|error| RuntimeError::new("session_storage", error.message))?;
        reject_reparse(&self.config_path)
            .map_err(|error| RuntimeError::new("session_storage", error.message))?;
        let reopened = open_config_guard(&self.config_path)?;
        if config_identity(&reopened)? != self.identity {
            return Err(RuntimeError::new(
                "session_storage",
                "session configuration identity or ACL changed before launch",
            ));
        }
        Ok(reopened)
    }
}

fn create_session_config(
    directory: &Path,
    contents: &str,
) -> Result<(PathBuf, File), RuntimeError> {
    let temporary = directory.join("config.tmp");
    let config_path = directory.join("config.json");
    let mut file = create_private_config_file(&temporary)?;
    file.write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    drop(file);
    fs::rename(&temporary, &config_path)
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    reject_reparse(&config_path)
        .map_err(|error| RuntimeError::new("session_storage", error.message))?;
    let mut guard = open_config_guard(&config_path)?;
    verify_config_contents(&mut guard, contents)?;
    Ok((config_path, guard))
}

fn verify_config_contents(file: &mut File, expected: &str) -> Result<(), RuntimeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual = hasher.finalize();
    let expected = Sha256::digest(expected.as_bytes());
    let matches = actual
        .iter()
        .zip(expected.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?;
    if !matches {
        return Err(RuntimeError::new(
            "session_storage",
            "session configuration contents changed before the protected handle was accepted",
        ));
    }
    Ok(())
}

fn open_config_guard(path: &Path) -> Result<File, RuntimeError> {
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
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))
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
        self.directory_guard.take();
        let _ = fs::remove_file(&self.config_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(windows)]
fn open_session_directory_guard(path: &Path) -> Result<File, RuntimeError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))
}

#[cfg(not(windows))]
fn open_session_directory_guard(path: &Path) -> Result<File, RuntimeError> {
    File::open(path).map_err(|error| RuntimeError::new("session_storage", error.to_string()))
}

#[cfg(windows)]
fn create_private_config_file(path: &Path) -> Result<File, RuntimeError> {
    use std::{mem::size_of, os::windows::ffi::OsStrExt, os::windows::io::FromRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ},
    };

    let descriptor_text: Vec<u16> = OsStr::new("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(RuntimeError::new(
            "session_storage",
            "could not construct private configuration ACL",
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(RuntimeError::new(
            "session_storage",
            "could not create private session configuration",
        ));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(not(windows))]
fn create_private_config_file(path: &Path) -> Result<File, RuntimeError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))
}

#[cfg(windows)]
fn config_identity(file: &File) -> Result<ConfigIdentity, RuntimeError> {
    use std::{mem::size_of, os::windows::io::AsRawHandle, ptr, slice};
    use windows_sys::Win32::{
        Foundation::{LocalFree, ERROR_SUCCESS},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            GetSecurityDescriptorControl, GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION,
            GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        },
        Storage::FileSystem::{
            FileIdInfo, GetFileInformationByHandleEx, GetFileType, FILE_ID_INFO, FILE_TYPE_DISK,
        },
    };

    if !file
        .metadata()
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?
        .is_file()
    {
        return Err(RuntimeError::new(
            "session_storage",
            "session configuration is not a regular file",
        ));
    }
    let handle = file.as_raw_handle();
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(RuntimeError::new(
            "session_storage",
            "session configuration is not a disk file",
        ));
    }
    let mut information = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(RuntimeError::new(
            "session_storage",
            "could not read session configuration identity",
        ));
    }

    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        return Err(RuntimeError::new(
            "session_storage",
            "could not read session configuration ACL",
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    let descriptor_length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if control_ok == 0 || descriptor_length == 0 || control & SE_DACL_PROTECTED == 0 {
        unsafe {
            LocalFree(descriptor);
        }
        return Err(RuntimeError::new(
            "session_storage",
            "session configuration ACL is not protected",
        ));
    }
    let security_descriptor =
        unsafe { slice::from_raw_parts(descriptor.cast(), descriptor_length) }.to_vec();
    unsafe {
        LocalFree(descriptor);
    }
    Ok(ConfigIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
        security_descriptor,
    })
}

#[cfg(not(windows))]
fn config_identity(file: &File) -> Result<ConfigIdentity, RuntimeError> {
    let length = file
        .metadata()
        .map_err(|error| RuntimeError::new("session_storage", error.to_string()))?
        .len();
    Ok(ConfigIdentity { length })
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

    let descriptor_text: Vec<u16> =
        OsStr::new("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
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
        config: &SessionConfig,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<String, RuntimeError>;

    fn start(
        &self,
        config: &SessionConfig,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<Box<dyn ManagedChild>, RuntimeError>;
}

pub(crate) struct VerifiedEngineLauncher {
    layout: FixedEngineLayout,
    descriptor: EngineDescriptor,
    prepared: Mutex<Option<PreparedVerification>>,
}

struct PreparedVerification {
    config_path: PathBuf,
    verified_files: VerifiedFiles,
    sealed_engine: SealedEngine,
    _config_guard: File,
}

impl VerifiedEngineLauncher {
    pub(crate) fn resolve() -> Result<Self, RuntimeError> {
        Self::resolve_for(EngineKind::SingBox)
    }

    pub(crate) fn resolve_for(kind: EngineKind) -> Result<Self, RuntimeError> {
        let descriptor = EngineDescriptor::for_kind(kind);
        Ok(Self {
            layout: FixedEngineLayout::resolve(descriptor)?,
            descriptor,
            prepared: Mutex::new(None),
        })
    }
}

impl EngineLauncher for VerifiedEngineLauncher {
    fn check(
        &self,
        config: &SessionConfig,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<String, RuntimeError> {
        let (source_guards, version) = self.layout.verify()?;
        let lock = embedded_engine_lock(self.descriptor)?;
        let sealed_engine =
            SealedEngine::create(config.directory(), &lock, &source_guards, self.descriptor)?;
        drop(source_guards);
        let _config_guard = config.revalidate_for_launch()?;
        let (mut suspended, check_guards) = create_suspended_engine(
            &sealed_engine.executable,
            &sealed_engine.directory,
            self.descriptor.check_command,
            config.path(),
            || sealed_engine.verify_for_launch(),
        )
        .map_err(as_config_check_error)?;
        let stderr = suspended.take_stderr().map_err(as_config_check_error)?;
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        let _reader = thread::Builder::new()
            .name("routedeck-check-stderr".into())
            .spawn(move || {
                let _ = stderr_tx.send(read_bounded(stderr, MAX_CHECK_STDERR));
            })
            .map_err(|_| RuntimeError::new("config_check", "could not start stderr reader"))?;
        let mut child = suspended.resume().map_err(as_config_check_error)?;
        let deadline = Instant::now() + CHECK_TIMEOUT;
        let exit_code = loop {
            if let Some(exit_code) = child.try_wait().map_err(as_config_check_error)? {
                break exit_code;
            }
            if Instant::now() >= deadline {
                child
                    .terminate_tree(Duration::from_secs(1))
                    .map_err(as_config_check_error)?;
                return Err(RuntimeError::new("config_check", "engine check timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        };
        child
            .terminate_tree(Duration::from_secs(1))
            .map_err(as_config_check_error)?;
        let raw = stderr_rx
            .recv_timeout(CHECK_READER_DRAIN_TIMEOUT)
            .map_err(|_| {
                RuntimeError::new(
                    "config_check",
                    "engine diagnostic pipe did not close after check",
                )
            })?;
        let sanitized = redactor.redact(&raw);
        if !sanitized.trim().is_empty() {
            diagnostics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(sanitized.clone());
        }
        if exit_code != 0 {
            return Err(RuntimeError::new(
                "config_check",
                if sanitized.trim().is_empty() {
                    format!(
                        "{} rejected the generated configuration",
                        self.descriptor.display_name
                    )
                } else {
                    sanitized
                },
            ));
        }

        drop(check_guards);
        let verified_files = sealed_engine.verify_for_launch()?;
        let config_guard = config.revalidate_for_launch()?;
        *self
            .prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PreparedVerification {
            config_path: config.path().to_owned(),
            verified_files,
            sealed_engine,
            _config_guard: config_guard,
        });

        Ok(version)
    }

    fn start(
        &self,
        config: &SessionConfig,
        redactor: Redactor,
        diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    ) -> Result<Box<dyn ManagedChild>, RuntimeError> {
        let prepared = self
            .prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .filter(|prepared| prepared.config_path == config.path())
            .ok_or_else(|| {
                RuntimeError::new(
                    "start_engine",
                    "engine launch was not prepared by the matching configuration check",
                )
            })?;
        let config_guard = config.revalidate_for_launch()?;
        let (mut suspended, run_guards) = create_suspended_engine(
            &prepared.sealed_engine.executable,
            &prepared.sealed_engine.directory,
            self.descriptor.run_command,
            config.path(),
            || prepared.sealed_engine.verify_for_launch(),
        )?;
        let stderr = suspended.take_stderr()?;
        let diagnostic_target = diagnostics.clone();
        let stderr_redactor = redactor.clone();
        let stderr_thread = thread::Builder::new()
            .name("routedeck-engine-stderr".into())
            .spawn(move || {
                capture_stderr(stderr, &stderr_redactor, &diagnostic_target);
            })
            .map_err(|_| RuntimeError::new("start_engine", "could not start stderr reader"))?;
        let child = suspended.resume()?;
        drop(prepared.verified_files);
        Ok(Box::new(RealManagedChild {
            child,
            stderr_thread: Some(stderr_thread),
            _verified_files: run_guards,
            _sealed_engine: prepared.sealed_engine,
            _config_guard: config_guard,
        }))
    }
}

fn as_config_check_error(error: RuntimeError) -> RuntimeError {
    RuntimeError::new("config_check", error.message().to_owned())
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
    child: PlatformProcess,
    stderr_thread: Option<thread::JoinHandle<()>>,
    _verified_files: VerifiedFiles,
    _sealed_engine: SealedEngine,
    _config_guard: File,
}

impl ManagedChild for RealManagedChild {
    fn pid(&self) -> u32 {
        self.child.pid()
    }

    fn is_alive(&mut self) -> Result<bool, RuntimeError> {
        self.child.try_wait().map(|status| status.is_none())
    }

    fn stop(&mut self) -> Result<(), RuntimeError> {
        let stopped = self.child.terminate_tree(Duration::from_secs(4));
        if stopped.is_ok() {
            if let Some(reader) = self.stderr_thread.take() {
                let _ = reader.join();
            }
        } else {
            self.stderr_thread.take();
        }
        stopped
    }
}

impl Drop for RealManagedChild {
    fn drop(&mut self) {
        let _ = self.stop();
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
        descriptor: EngineDescriptor,
    }

    impl FixtureLayout {
        fn create() -> Self {
            Self::create_for(EngineKind::SingBox)
        }

        fn create_for(kind: EngineKind) -> Self {
            let descriptor = EngineDescriptor::for_kind(kind);
            let root = std::env::temp_dir().join(format!(
                "routedeck-engine-fixture-{}",
                random_hex(8).unwrap()
            ));
            let engine = root.join(descriptor.directory_name);
            fs::create_dir_all(&engine).unwrap();
            let executable = b"fixture executable";
            let license = b"fixture license";
            fs::write(engine.join(descriptor.executable_name), executable).unwrap();
            let mut runtime_files = vec![LockedFile {
                path: descriptor.executable_name.into(),
                kind: "executable".into(),
                size: executable.len() as u64,
                sha256: digest(executable),
            }];
            if kind == EngineKind::SingBox {
                let cronet = b"fixture cronet";
                fs::write(engine.join(CRONET_DLL), cronet).unwrap();
                runtime_files.push(LockedFile {
                    path: CRONET_DLL.into(),
                    kind: "library".into(),
                    size: cronet.len() as u64,
                    sha256: digest(cronet),
                });
            }
            fs::write(engine.join("LICENSE"), license).unwrap();
            runtime_files.push(LockedFile {
                path: "LICENSE".into(),
                kind: "license".into(),
                size: license.len() as u64,
                sha256: digest(license),
            });
            let layout = FixedEngineLayout::from_package_root(&root, descriptor).unwrap();
            let lock = EngineLock {
                schema_version: 1,
                engine: descriptor.lock_engine.into(),
                version: descriptor.version.into(),
                runtime_files,
            };
            Self {
                root,
                layout,
                lock,
                descriptor,
            }
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
        fs::write(
            fixture
                .layout
                .engine_dir
                .join(fixture.descriptor.executable_name),
            b"wrong size",
        )
        .unwrap();
        assert!(fixture.layout.verify_lock(&fixture.lock).is_err());
    }

    #[test]
    fn descriptors_bind_each_pinned_manifest_to_its_own_runtime_directory() {
        let sing_box = EngineDescriptor::for_kind(EngineKind::SingBox);
        let xray = EngineDescriptor::for_kind(EngineKind::Xray);
        assert_eq!(sing_box.kind(), EngineKind::SingBox);
        assert_eq!(sing_box.directory_name(), "engine");
        assert_eq!(sing_box.executable_name(), "sing-box.exe");
        assert_eq!(xray.kind(), EngineKind::Xray);
        assert_eq!(xray.directory_name(), "xray");
        assert_eq!(xray.executable_name(), "xray.exe");

        let sing_box_lock = embedded_engine_lock(sing_box).unwrap();
        let xray_lock = embedded_engine_lock(xray).unwrap();
        assert_eq!(sing_box_lock.engine, "sing-box");
        assert_eq!(sing_box_lock.version, "1.13.19");
        assert_eq!(xray_lock.engine, "xray-core");
        assert_eq!(xray_lock.version, "26.3.27");

        let sing_box_fixture = FixtureLayout::create_for(EngineKind::SingBox);
        assert!(FixedEngineLayout::from_package_root(&sing_box_fixture.root, xray).is_err());
        let xray_fixture = FixtureLayout::create_for(EngineKind::Xray);
        xray_fixture.layout.verify_lock(&xray_fixture.lock).unwrap();
    }

    #[test]
    fn xray_execution_seal_contains_only_its_pinned_executable() {
        let fixture = FixtureLayout::create_for(EngineKind::Xray);
        let execution = execution_lock(&fixture.lock, fixture.descriptor).unwrap();
        assert_eq!(execution.runtime_files.len(), 1);
        assert_eq!(execution.runtime_files[0].path, XRAY_EXE);
        assert_eq!(execution.runtime_files[0].kind, "executable");

        let mut disguised = fixture.lock.clone();
        disguised.runtime_files.push(LockedFile {
            path: "foreign.dll".into(),
            kind: "license".into(),
            size: 1,
            sha256: digest(b"x"),
        });
        assert!(execution_lock(&disguised, fixture.descriptor).is_err());

        let mut wrong_identity = fixture.lock.clone();
        wrong_identity.engine = "sing-box".into();
        assert!(fixture.layout.verify_lock(&wrong_identity).is_err());
    }

    #[test]
    fn runtime_entry_names_reject_case_variants_and_folded_duplicates() {
        let exact = BTreeSet::from([SING_BOX_EXE.to_owned()]);
        let folded = BTreeSet::from([SING_BOX_EXE.to_ascii_lowercase()]);
        let mut seen = BTreeSet::new();
        assert!(!accept_runtime_entry_name(
            "SING-BOX.EXE",
            "sing-box.exe",
            &exact,
            &folded,
            &mut seen,
        ));
        assert!(accept_runtime_entry_name(
            SING_BOX_EXE,
            "sing-box.exe",
            &exact,
            &folded,
            &mut seen,
        ));
        assert!(!accept_runtime_entry_name(
            SING_BOX_EXE,
            "sing-box.exe",
            &exact,
            &folded,
            &mut seen,
        ));
    }

    #[test]
    fn execution_lock_contains_only_the_executable_and_adjacent_library() {
        let fixture = FixtureLayout::create();
        let execution = execution_lock(&fixture.lock, fixture.descriptor).unwrap();
        assert_eq!(execution.runtime_files.len(), 2);
        assert!(execution
            .runtime_files
            .iter()
            .any(|entry| entry.path == SING_BOX_EXE));
        assert!(execution
            .runtime_files
            .iter()
            .any(|entry| entry.path == CRONET_DLL));
        assert!(!execution
            .runtime_files
            .iter()
            .any(|entry| entry.path == "LICENSE"));

        let mut ambiguous = fixture.lock.clone();
        ambiguous.runtime_files.push(LockedFile {
            path: "late.dll".into(),
            kind: "library".into(),
            size: 1,
            sha256: digest(b"x"),
        });
        assert!(execution_lock(&ambiguous, fixture.descriptor).is_err());

        let mut disguised = fixture.lock.clone();
        disguised.runtime_files.push(LockedFile {
            path: "late.dll".into(),
            kind: "license".into(),
            size: 1,
            sha256: digest(b"x"),
        });
        assert!(execution_lock(&disguised, fixture.descriptor).is_err());
    }

    #[test]
    fn seal_volume_policy_rejects_remote_removable_and_non_acl_filesystems() {
        const FIXED: u32 = 3;
        const REMOTE: u32 = 4;
        const PERSISTENT_ACLS: u32 = 8;
        assert!(seal_volume_supported(FIXED, PERSISTENT_ACLS, "NTFS"));
        assert!(seal_volume_supported(FIXED, PERSISTENT_ACLS, "ReFS"));
        assert!(!seal_volume_supported(REMOTE, PERSISTENT_ACLS, "NTFS"));
        assert!(!seal_volume_supported(FIXED, 0, "NTFS"));
        assert!(!seal_volume_supported(FIXED, PERSISTENT_ACLS, "exFAT"));
    }

    #[cfg(windows)]
    #[test]
    fn verified_engine_guards_block_directory_replacement_and_file_mutation() {
        let fixture = FixtureLayout::create();
        let (guards, _) = fixture.layout.verify_lock(&fixture.lock).unwrap();
        assert!(fs::rename(
            &fixture.layout.engine_dir,
            fixture.root.join("engine-replaced")
        )
        .is_err());
        assert!(OpenOptions::new()
            .write(true)
            .open(fixture.layout.engine_dir.join(SING_BOX_EXE))
            .is_err());
        drop(guards);
        fs::write(fixture.layout.engine_dir.join("late.dll"), b"foreign").unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn sealed_engine_copy_blocks_late_names_and_detects_acl_tamper() {
        let fixture = FixtureLayout::create();
        let session = fixture
            .root
            .join(format!("session-{}", random_hex(16).unwrap()));
        create_private_directory(&session).unwrap();
        let (source, _) = fixture.layout.verify_lock(&fixture.lock).unwrap();
        let sealed =
            SealedEngine::create(&session, &fixture.lock, &source, fixture.descriptor).unwrap();
        drop(source);

        assert!(sealed.directory.starts_with(&session));
        assert_ne!(sealed.directory, fixture.layout.engine_dir);
        assert!(sealed.directory.join(SING_BOX_EXE).is_file());
        assert!(sealed.directory.join(CRONET_DLL).is_file());
        assert!(!sealed.directory.join("LICENSE").exists());
        assert!(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(sealed.directory.join("late.dll"))
            .is_err());
        assert!(OpenOptions::new()
            .write(true)
            .open(sealed.directory.join(SING_BOX_EXE))
            .is_err());
        let guards = sealed.verify_for_launch().unwrap();
        assert_eq!(guards.files.len(), 2);
        drop(guards);

        let user = current_user_sid_string().unwrap();
        apply_protected_dacl_for_test(
            &sealed.directory.join(SING_BOX_EXE),
            &format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"),
        )
        .unwrap();
        assert!(sealed.verify_for_launch().is_err());
        let sealed_directory = sealed.directory.clone();
        drop(sealed);
        assert!(!sealed_directory.exists());
        fs::remove_dir(session).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn sealed_engine_exact_preflight_rejects_a_late_dll_after_acl_tamper() {
        let fixture = FixtureLayout::create();
        let session = fixture
            .root
            .join(format!("session-{}", random_hex(16).unwrap()));
        create_private_directory(&session).unwrap();
        let (source, _) = fixture.layout.verify_lock(&fixture.lock).unwrap();
        let sealed =
            SealedEngine::create(&session, &fixture.lock, &source, fixture.descriptor).unwrap();
        drop(source);

        let user = current_user_sid_string().unwrap();
        apply_protected_dacl_for_test(
            &sealed.directory,
            &format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"),
        )
        .unwrap();
        let late = sealed.directory.join("late.dll");
        fs::write(&late, b"foreign").unwrap();
        assert!(sealed.verify_for_launch().is_err());

        fs::remove_file(late).unwrap();
        let sealed_directory = sealed.directory.clone();
        drop(sealed);
        assert!(!sealed_directory.exists());
        fs::remove_dir(session).unwrap();
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

    #[test]
    fn native_check_boundary_errors_are_remapped_to_config_check() {
        let error = as_config_check_error(RuntimeError::new(
            "start_engine",
            "fixture native launch failure",
        ));
        assert_eq!(error.stage(), "config_check");
        assert_eq!(error.message(), "fixture native launch failure");
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
    fn partial_session_construction_removes_generated_secret_data() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-session-partial-{}",
            random_hex(8).unwrap()
        ));
        let error = SessionConfig::create_with_identity(&root, "{\"secret\":\"fixture\"}", |_| {
            Err(RuntimeError::new(
                "session_storage",
                "injected identity failure",
            ))
        })
        .err()
        .expect("injected identity failure was accepted");
        assert_eq!(error.stage(), "session_storage");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn reopened_config_contents_must_match_exact_generated_bytes() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-config-content-fixture-{}",
            random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("config.json");
        fs::write(&path, b"{\"secret\":\"changed\"}").unwrap();
        let mut file = File::open(&path).unwrap();
        let error = verify_config_contents(&mut file, "{\"secret\":\"expected\"}").unwrap_err();
        assert_eq!(error.stage(), "session_storage");
        assert!(!error.message().contains("secret"));
        verify_config_contents(&mut file, "{\"secret\":\"changed\"}").unwrap();
        drop(file);
        fs::remove_file(path).unwrap();
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
