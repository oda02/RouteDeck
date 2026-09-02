use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use crate::subscription::MAX_INPUT_BYTES;

const STORE_VERSION: u32 = 1;
const MAX_STORED_BYTES: u64 = (MAX_INPUT_BYTES as u64 * 6) + 4_096;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSubscription {
    version: u32,
    content: String,
}

#[derive(Debug)]
pub(crate) struct SubscriptionStore {
    path: PathBuf,
}

impl SubscriptionStore {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn load(&self) -> io::Result<Option<String>> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() > MAX_STORED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored subscription is too large",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STORED_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STORED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored subscription is too large",
            ));
        }
        let stored: StoredSubscription = serde_json::from_slice(&bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stored subscription is not valid",
            )
        })?;
        if stored.version != STORE_VERSION || stored.content.len() > MAX_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored subscription version or content is invalid",
            ));
        }
        Ok(Some(stored.content))
    }

    pub(crate) fn save(&self, content: &str) -> io::Result<()> {
        if content.len() > MAX_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription is too large to store",
            ));
        }
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription store has no parent directory",
            )
        })?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec(&StoredSubscription {
            version: STORE_VERSION,
            content: content.to_owned(),
        })
        .map_err(io::Error::other)?;

        let (temporary_path, mut temporary) = create_temporary_file(parent, &self.path)?;
        let result = (|| {
            temporary.write_all(&bytes)?;
            temporary.sync_all()?;
            drop(temporary);
            atomic_replace(&temporary_path, &self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn create_temporary_file(parent: &Path, destination: &Path) -> io::Result<(PathBuf, File)> {
    let stem = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("subscription.json");
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{stem}.{}.{}.tmp", std::process::id(), sequence));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary subscription file",
    ))
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (PathBuf, SubscriptionStore) {
        let root = std::env::temp_dir().join(format!(
            "routedeck-subscription-store-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let store = SubscriptionStore::new(root.join("subscription.json"));
        (root, store)
    }

    #[test]
    fn save_then_load_round_trips_subscription() {
        let (root, store) = test_store();
        store.save("vless://fixture-one").unwrap();
        assert_eq!(
            store.load().unwrap().as_deref(),
            Some("vless://fixture-one")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_save_replaces_previous_content_without_leaving_temporary_files() {
        let (root, store) = test_store();
        store.save("vless://old").unwrap();
        store.save("hysteria2://new").unwrap();
        assert_eq!(store.load().unwrap().as_deref(), Some("hysteria2://new"));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_file_is_ignored_and_can_be_replaced_by_a_later_import() {
        let (root, store) = test_store();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("subscription.json"), b"not-json").unwrap();
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);

        store.save("vless://recovered").unwrap();
        assert_eq!(store.load().unwrap().as_deref(), Some("vless://recovered"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn clear_removes_saved_content_and_is_idempotent() {
        let (root, store) = test_store();
        store.save("vless://saved").unwrap();

        store.clear().unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.clear().unwrap();

        fs::remove_dir_all(root).unwrap();
    }
}
