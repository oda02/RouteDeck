use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use crate::subscription::MAX_INPUT_BYTES;

const STORE_VERSION: u32 = 3;
const MAX_STORED_BYTES: u64 = (MAX_INPUT_BYTES as u64 * 6) + 4_096;
pub(crate) const MAX_LIBRARY_SOURCES: usize = 64;
pub(crate) const MAX_LIBRARY_NODES: usize = 2_000;
pub(crate) const LEGACY_SOURCE_ID: &str = "00000000000000000000000000000000";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySubscription {
    version: u32,
    content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Subscription,
    Manual,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredSource {
    pub id: String,
    pub name: String,
    pub kind: SourceKind,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<u64>,
    #[serde(default)]
    pub revision: u64,
    // IDs follow the parsed node order. Refresh persists this mapping so source
    // reordering and credential rotation preserve selection after a restart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_ids: Vec<String>,
}

impl std::fmt::Debug for StoredSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoredSource([REDACTED])")
    }
}

// Do not derive Debug for the persisted structures: content contains credentials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLibrary {
    version: u32,
    sources: Vec<StoredSource>,
}

pub(crate) fn valid_source_name(name: &str) -> bool {
    !name.is_empty()
        && name == name.trim()
        && name.chars().count() <= 80
        && !name.chars().any(|ch| {
            ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        && !name.contains("://")
        && !name.contains('@')
        && crate::redaction::Redactor::default().redact(name) == name
}

pub(crate) fn validate_sources(sources: &[StoredSource]) -> io::Result<()> {
    let mut ids = std::collections::HashSet::new();
    let valid = sources.len() <= MAX_LIBRARY_SOURCES
        && sources.iter().all(|source| {
            source.id.len() == 32
                && source
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                && ids.insert(source.id.as_str())
                && valid_source_name(&source.name)
                && !source.content.is_empty()
                && source.content.len() <= MAX_INPUT_BYTES
                && (source.kind == SourceKind::Subscription || source.url.is_none())
                && source
                    .url
                    .as_deref()
                    .is_none_or(|url| crate::subscription_fetch::validate_url(url).is_ok())
                && source
                    .updated_at_ms
                    .is_none_or(|time| time <= 8_640_000_000_000_000)
                && source.node_ids.len() <= MAX_LIBRARY_NODES
                && {
                    let mut node_ids = std::collections::HashSet::new();
                    source.node_ids.iter().all(|id| {
                        let suffix = id
                            .strip_prefix(&format!("{}-", source.id))
                            .or_else(|| (source.id == LEGACY_SOURCE_ID).then_some(id.as_str()));
                        suffix.is_some_and(|value| {
                            value.len() == 32
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                })
                        }) && node_ids.insert(id)
                    })
                }
        })
        && sources
            .iter()
            .map(|source| source.content.len())
            .sum::<usize>()
            <= MAX_INPUT_BYTES;
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored server library is invalid or exceeds its limits",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct SubscriptionStore {
    path: PathBuf,
}

impl SubscriptionStore {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn load(&self) -> io::Result<Option<Vec<StoredSource>>> {
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
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stored subscription is not valid",
            )
        };
        // Deserialize directly into the closed structs so duplicate fields cannot
        // be hidden by an intermediate JSON object overwriting earlier values.
        let sources = match serde_json::from_slice::<LegacySubscription>(&bytes) {
            Ok(stored) if stored.version == 1 => {
                vec![StoredSource {
                    id: LEGACY_SOURCE_ID.into(),
                    name: "Сохранённые серверы".into(),
                    kind: SourceKind::Subscription,
                    content: stored.content,
                    url: None,
                    updated_at_ms: None,
                    revision: 0,
                    node_ids: Vec::new(),
                }]
            }
            _ => {
                let stored: StoredLibrary =
                    serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                if stored.version != 2 && stored.version != STORE_VERSION {
                    return Err(invalid());
                }
                stored.sources
            }
        };
        validate_sources(&sources)?;
        Ok(Some(sources))
    }

    pub(crate) fn save(&self, sources: &[StoredSource]) -> io::Result<()> {
        validate_sources(sources)?;
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "subscription store has no parent directory",
            )
        })?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec(&StoredLibrary {
            version: STORE_VERSION,
            sources: sources.to_vec(),
        })
        .map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_STORED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server library is too large to store",
            ));
        }

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

    fn source(content: &str) -> StoredSource {
        StoredSource {
            id: "1234567890abcdef1234567890abcdef".into(),
            name: "Test servers".into(),
            kind: SourceKind::Manual,
            content: content.into(),
            url: None,
            updated_at_ms: None,
            revision: 0,
            node_ids: Vec::new(),
        }
    }

    #[test]
    fn save_then_load_round_trips_subscription() {
        let (root, store) = test_store();
        store.save(&[source("vless://fixture-one")]).unwrap();
        assert_eq!(
            store.load().unwrap(),
            Some(vec![source("vless://fixture-one")])
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_save_replaces_previous_content_without_leaving_temporary_files() {
        let (root, store) = test_store();
        store.save(&[source("vless://old")]).unwrap();
        store.save(&[source("hysteria2://new")]).unwrap();
        assert_eq!(store.load().unwrap(), Some(vec![source("hysteria2://new")]));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_file_is_ignored_and_can_be_replaced_by_a_later_import() {
        let (root, store) = test_store();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("subscription.json"), b"not-json").unwrap();
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);

        store.save(&[source("vless://recovered")]).unwrap();
        assert_eq!(
            store.load().unwrap(),
            Some(vec![source("vless://recovered")])
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn clear_removes_saved_content_and_is_idempotent() {
        let (root, store) = test_store();
        store.save(&[source("vless://saved")]).unwrap();

        store.clear().unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.clear().unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_v1_loads_as_a_stable_source_and_next_save_uses_v3() {
        let (root, store) = test_store();
        fs::create_dir_all(&root).unwrap();
        fs::write(&store.path, br#"{"version":1,"content":"vless://legacy"}"#).unwrap();
        let sources = store.load().unwrap().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].id, LEGACY_SOURCE_ID);
        assert_eq!(sources[0].kind, SourceKind::Subscription);
        assert_eq!(sources[0].content, "vless://legacy");
        store.save(&sources).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).unwrap()).unwrap();
        assert_eq!(saved["version"], 3);
        assert_eq!(store.load().unwrap().unwrap(), sources);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_hostile_or_unknown_source_metadata_without_replacing_saved_data() {
        let (root, store) = test_store();
        let good = source("naive+https://fixture");
        store.save(std::slice::from_ref(&good)).unwrap();
        for name in [
            "https://provider.test/private-token",
            "user:password@host",
            "password=secret",
            "line\nbreak",
            "bad\u{202e}name",
            "",
        ] {
            let mut invalid = good.clone();
            invalid.name = name.into();
            assert!(store.save(&[invalid]).is_err());
            assert_eq!(store.load().unwrap(), Some(vec![good.clone()]));
        }
        let mut invalid = good.clone();
        invalid.id = "../source".into();
        assert!(store.save(&[invalid]).is_err());
        assert!(store.save(&[good.clone(), good.clone()]).is_err());
        assert!(store
            .save(&vec![good.clone(); MAX_LIBRARY_SOURCES + 1])
            .is_err());
        fs::write(
            &store.path,
            br#"{"version":2,"sources":[],"secret":"hidden"}"#,
        )
        .unwrap();
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        for bytes in [
            br#"{"version":1,"version":1,"content":"vless://fixture"}"#.as_slice(),
            br#"{"version":2,"sources":[],"sources":[]}"#.as_slice(),
            br#"{"version":4,"sources":[]}"#.as_slice(),
        ] {
            fs::write(&store.path, bytes).unwrap();
            assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_migrates_without_url_and_v3_round_trips_private_refresh_metadata() {
        let (root, store) = test_store();
        fs::create_dir_all(&root).unwrap();
        fs::write(&store.path, br#"{"version":2,"sources":[{"id":"1234567890abcdef1234567890abcdef","name":"Old subscription","kind":"subscription","content":"vless://fixture"}]}"#).unwrap();
        let mut sources = store.load().unwrap().unwrap();
        assert!(sources[0].url.is_none());
        assert!(sources[0].updated_at_ms.is_none());
        assert!(sources[0].node_ids.is_empty());
        sources[0].url = Some("https://provider.test/private-fixture-token".into());
        sources[0].updated_at_ms = Some(1_788_600_000_000);
        sources[0].revision = 5;
        sources[0].node_ids = vec![format!("{}-{}", sources[0].id, "a".repeat(32))];
        store.save(&sources).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), sources);
        assert!(!format!("{:?}", sources).contains("private-fixture-token"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_private_or_hostile_persisted_refresh_urls_and_foreign_node_ids() {
        let (root, store) = test_store();
        let mut good = source("vless://fixture");
        good.kind = SourceKind::Subscription;
        store.save(std::slice::from_ref(&good)).unwrap();
        for url in [
            "http://provider.test/",
            "https://127.0.0.1/",
            "https://192.168.0.1/",
            "https://user:secret@provider.test/",
            "https://localhost/",
            "file:///fixture",
        ] {
            let mut bad = good.clone();
            bad.url = Some(url.into());
            assert!(store.save(&[bad]).is_err());
            assert_eq!(store.load().unwrap().unwrap(), vec![good.clone()]);
        }
        let mut manual = good.clone();
        manual.kind = SourceKind::Manual;
        manual.url = Some("https://provider.test/fixture".into());
        assert!(store.save(&[manual]).is_err());
        for id in [
            "a".repeat(32),
            format!("{}-{}", "b".repeat(32), "c".repeat(32)),
            "../node".into(),
        ] {
            let mut bad = good.clone();
            bad.node_ids = vec![id];
            assert!(store.save(&[bad]).is_err());
        }
        let mut bad = good.clone();
        bad.node_ids = vec![format!("{}-{}", good.id, "a".repeat(32)); 2];
        assert!(store.save(&[bad]).is_err());
        let mut bad = good.clone();
        bad.updated_at_ms = Some(u64::MAX);
        assert!(store.save(&[bad]).is_err());
        // Loading uses the same validation before any persisted URL can be fetched.
        let mut value = serde_json::to_value(StoredLibrary {
            version: 3,
            sources: vec![good],
        })
        .unwrap();
        value["sources"][0]["url"] = serde_json::json!("https://127.0.0.1/private");
        fs::write(&store.path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(store.load().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn total_library_content_limit_is_enforced_before_writing() {
        let (root, store) = test_store();
        let first = source(&"a".repeat(MAX_INPUT_BYTES / 2 + 1));
        let mut second = first.clone();
        second.id = "fedcba0987654321fedcba0987654321".into();
        assert!(store.save(&[first, second]).is_err());
        assert!(!store.path.exists());
        assert!(!root.exists());
    }
}
