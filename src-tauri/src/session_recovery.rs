//! Offline cleanup of exact owned session files. No process is launched or killed,
//! and no Windows network setting is changed here. Existing directory/config
//! handles act as leases: DELETE access is denied while their owner is alive.
use super::*;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use windows_sys::Win32::{
    Foundation::GENERIC_READ,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};

pub(crate) const MARKER: &str = "session-owner.json";
const MAX_CONFIG: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Marker {
    schema_version: u32,
    directory: String,
    user_sid: String,
    config_sha256: String,
}

fn error() -> RuntimeError {
    RuntimeError::new(
        "session_recovery",
        "session is active or its saved ownership could not be verified",
    )
}

pub(super) fn write_marker(directory: &Path, contents: &str) -> Result<(), RuntimeError> {
    let value = serde_json::json!({
        "schemaVersion": 1,
        "directory": directory.file_name().and_then(OsStr::to_str).ok_or_else(error)?,
        "userSid": current_user_sid_string()?,
        "configSha256": format!("{:x}", Sha256::digest(contents.as_bytes())),
    });
    let mut file = create_private_config_file(&directory.join(MARKER))?;
    file.write_all(&serde_json::to_vec(&value).map_err(|_| error())?)
        .and_then(|_| file.sync_all())
        .map_err(|_| error())
}

fn named(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|id| {
        id.len() == 32
            && id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn lock(path: &Path, directory: bool) -> Result<File, RuntimeError> {
    reject_reparse(path).map_err(|_| error())?;
    let file = OpenOptions::new()
        .access_mode(GENERIC_READ | 0x0001_0000 /* DELETE */)
        .share_mode(
            FILE_SHARE_READ | FILE_SHARE_DELETE | if directory { FILE_SHARE_WRITE } else { 0 },
        )
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|_| error())?;
    let metadata = file.metadata().map_err(|_| error())?;
    if metadata.is_dir() != directory
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(error());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "routedeck-offline-recovery-{}",
            random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn abandon(mut session: SessionConfig) -> PathBuf {
        let path = session.directory.clone();
        session.guard.take();
        session.directory_guard.take();
        std::mem::forget(session);
        path
    }

    #[test]
    fn live_session_lease_prevents_cleanup_and_normal_drop_removes_all_files() {
        let root = root();
        let session = SessionConfig::create(&root, "{}").unwrap();
        assert!(CleanupPlan::inspect(&session.directory).is_err());
        drop(session);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn crashed_local_and_nested_helper_sessions_are_cleaned_without_launching_engines() {
        let root = root();
        let outer = SessionConfig::create(&root, "{\"fixture\":true}").unwrap();
        let nested = SessionConfig::create(&outer.directory, "{\"fixture\":true}").unwrap();
        abandon(nested);
        let directory = abandon(outer);
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        assert!(!directory.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn surviving_helper_lease_preserves_the_entire_parent_session() {
        let root = root();
        let outer = SessionConfig::create(&root, "{}").unwrap();
        let nested = SessionConfig::create(&outer.directory, "{}").unwrap();
        let directory = abandon(outer);
        assert!(CleanupPlan::inspect(&directory).is_err());
        assert!(directory.join("config.json").exists());
        drop(nested);
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn partial_cleanup_keeps_marker_and_can_be_retried_with_missing_config() {
        let root = root();
        let directory = abandon(SessionConfig::create(&root, "{}").unwrap());
        fs::remove_file(directory.join("config.json")).unwrap();
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn cleanup_can_finish_after_last_marker_was_already_removed() {
        let root = root();
        let directory = abandon(SessionConfig::create(&root, "{}").unwrap());
        fs::remove_file(directory.join("config.json")).unwrap();
        fs::remove_file(directory.join(MARKER)).unwrap();
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn mismatched_config_unknown_files_and_missing_marker_are_preserved() {
        let root = root();
        let directory = abandon(SessionConfig::create(&root, "{}").unwrap());
        fs::write(directory.join("config.json"), b"changed").unwrap();
        assert!(CleanupPlan::inspect(&directory).is_err());
        fs::write(directory.join("config.json"), b"{}").unwrap();
        fs::write(directory.join("foreign.txt"), b"do not remove").unwrap();
        assert!(CleanupPlan::inspect(&directory).is_err());
        assert!(directory.join("config.json").exists());
        fs::remove_file(directory.join("foreign.txt")).unwrap();
        let marker = fs::read(directory.join(MARKER)).unwrap();
        fs::remove_file(directory.join(MARKER)).unwrap();
        assert!(CleanupPlan::inspect(&directory).is_err());
        fs::write(directory.join(MARKER), marker).unwrap();
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn marker_cannot_name_another_directory_user_or_unknown_schema() {
        let root = root();
        let directory = abandon(SessionConfig::create(&root, "{}").unwrap());
        let path = directory.join(MARKER);
        let original = fs::read(&path).unwrap();
        let base: serde_json::Value = serde_json::from_slice(&original).unwrap();
        for (key, value) in [
            ("directory", serde_json::json!("../foreign")),
            ("userSid", serde_json::json!("S-1-1-0")),
            ("schemaVersion", serde_json::json!(2)),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut changed = base.clone();
            changed[key] = value;
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(CleanupPlan::inspect(&directory).is_err());
            assert!(directory.join("config.json").exists());
        }
        fs::write(&path, original).unwrap();
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn unexpected_or_modified_engine_files_are_not_removed() {
        let root = root();
        let directory = abandon(SessionConfig::create(&root, "{}").unwrap());
        let engine = directory.join(format!("engine-run-{}", "01".repeat(16)));
        fs::create_dir(&engine).unwrap();
        fs::write(engine.join("xray.exe"), b"not the reviewed binary").unwrap();
        assert!(CleanupPlan::inspect(&directory).is_err());
        assert!(engine.join("xray.exe").exists());
        fs::remove_file(engine.join("xray.exe")).unwrap();
        CleanupPlan::inspect(&directory).unwrap().remove().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn private_session_acl_uses_the_account_sid_instead_of_owner_rights() {
        use windows_sys::Win32::Security::{EqualSid, GetSecurityDescriptorOwner};
        let root = root();
        let session = SessionConfig::create(&root, "{}").unwrap();
        let identity = config_identity(session.guard.as_ref().unwrap()).unwrap();
        let mut owner = std::ptr::null_mut();
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorOwner(
                    identity.security_descriptor.as_ptr().cast_mut().cast(),
                    &mut owner,
                    &mut defaulted,
                )
            },
            0
        );
        let user = current_user_sid().unwrap();
        assert_ne!(
            unsafe { EqualSid(owner, user.as_ptr().cast_mut().cast()) },
            0
        );
        // The helper's journal inherits a concrete account ACE from this directory.
        let journal = session.directory.join("tun-journal.json");
        fs::write(&journal, b"fixture").unwrap();
        assert_eq!(fs::read(&journal).unwrap(), b"fixture");
        fs::remove_file(journal).unwrap();
        drop(session);
        fs::remove_dir(root).unwrap();
    }
}

fn bytes(file: &mut File, max: u64) -> Result<Vec<u8>, RuntimeError> {
    if file.metadata().map_err(|_| error())?.len() > max {
        return Err(error());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| error())?;
    let mut data = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut data)
        .map_err(|_| error())?;
    if data.len() as u64 > max {
        return Err(error());
    }
    Ok(data)
}

pub(crate) struct CleanupPlan {
    files: Vec<(PathBuf, File)>,
    markers: Vec<(PathBuf, File)>,
    directories: Vec<(PathBuf, File)>,
    pub(crate) journals: Vec<PathBuf>,
}

impl CleanupPlan {
    pub(crate) fn inspect(directory: &Path) -> Result<Self, RuntimeError> {
        let mut plan = Self {
            files: Vec::new(),
            markers: Vec::new(),
            directories: Vec::new(),
            journals: Vec::new(),
        };
        plan.session(directory, 0)?;
        Ok(plan)
    }

    fn session(&mut self, directory: &Path, depth: usize) -> Result<(), RuntimeError> {
        let name = directory
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(error)?;
        if depth > 1 || !named(name, "session-") {
            return Err(error());
        }
        let guard = lock(directory, true)?;
        // A crash can occur after deleting the last marker but before removing
        // its now-empty directory. There is no remaining data to infer or delete.
        if fs::read_dir(directory)
            .map_err(|_| error())?
            .next()
            .is_none()
        {
            self.directories.push((directory.to_owned(), guard));
            return Ok(());
        }
        let marker_path = directory.join(MARKER);
        let mut marker_file = lock(&marker_path, false)?;
        let marker: Marker =
            serde_json::from_slice(&bytes(&mut marker_file, 4096)?).map_err(|_| error())?;
        if marker.schema_version != 1
            || marker.directory != name
            || marker.user_sid != current_user_sid_string()?
            || marker.config_sha256.len() != 64
            || !marker
                .config_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(error());
        }
        let mut count = 0;
        for entry in fs::read_dir(directory).map_err(|_| error())? {
            let entry = entry.map_err(|_| error())?;
            count += 1;
            if count > 8 {
                return Err(error());
            }
            let path = entry.path();
            let entry_name = entry.file_name();
            let name = entry_name.to_str().ok_or_else(error)?;
            match name {
                MARKER => {}
                "config.json" => {
                    let mut file = lock(&path, false)?;
                    if format!("{:x}", Sha256::digest(bytes(&mut file, MAX_CONFIG)?))
                        != marker.config_sha256
                    {
                        return Err(error());
                    }
                    self.files.push((path, file));
                }
                "tun-journal.json" if depth == 0 => {
                    let mut file = lock(&path, false)?;
                    // The TUN boundary validates content and network ownership before deletion.
                    bytes(&mut file, 64 * 1024)?;
                    self.journals.push(path.clone());
                    self.files.push((path, file));
                }
                name if named(name, "session-") => self.session(&path, depth + 1)?,
                name if named(name, "engine-run-") => self.engine(&path)?,
                _ => return Err(error()),
            }
        }
        self.markers.push((marker_path, marker_file));
        // Children are always removed before parents; ownership markers are last.
        self.directories.push((directory.to_owned(), guard));
        Ok(())
    }

    fn engine(&mut self, directory: &Path) -> Result<(), RuntimeError> {
        let guard = lock(directory, true)?;
        let mut allowed = BTreeMap::new();
        for kind in [EngineKind::SingBox, EngineKind::Xray] {
            let descriptor = EngineDescriptor::for_kind(kind);
            for file in
                execution_lock(&embedded_engine_lock(descriptor)?, descriptor)?.runtime_files
            {
                allowed.insert(file.path.clone(), file);
            }
        }
        for entry in fs::read_dir(directory).map_err(|_| error())? {
            let entry = entry.map_err(|_| error())?;
            let name = entry.file_name();
            let expected = allowed
                .get(name.to_str().ok_or_else(error)?)
                .ok_or_else(error)?;
            let path = entry.path();
            let mut file = lock(&path, false)?;
            if file.metadata().map_err(|_| error())?.len() != expected.size {
                return Err(error());
            }
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer).map_err(|_| error())?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            if format!("{:x}", hasher.finalize()) != expected.sha256 {
                return Err(error());
            }
            self.files.push((path, file));
        }
        self.directories.push((directory.to_owned(), guard));
        Ok(())
    }

    pub(crate) fn remove(self) -> Result<(), RuntimeError> {
        // Guards remain alive during deletion. An active config, helper journal or
        // session directory cannot pass inspection because its lease denies DELETE.
        let Self {
            files,
            mut markers,
            directories,
            ..
        } = self;
        for (path, guard) in files {
            fs::remove_file(path).map_err(|_| error())?;
            drop(guard);
        }
        for (path, guard) in directories {
            if let Some(index) = markers
                .iter()
                .position(|(marker, _)| marker.parent() == Some(path.as_path()))
            {
                let (marker, marker_guard) = markers.remove(index);
                fs::remove_file(marker).map_err(|_| error())?;
                drop(marker_guard);
            }
            fs::remove_dir(&path).map_err(|_| error())?;
            drop(guard);
        }
        Ok(())
    }
}
