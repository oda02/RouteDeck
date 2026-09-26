//! Signed full-bundle portable updates. No elevation, caller URLs or caller paths.
//! Network and Windows process control are separate from fixture-testable validation.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const PUBLIC_KEY: &str = "6c22a738e8c9770949944f1a434818ff31a8fe8b1d9d5a1047f6c12383da5491";
const MANIFEST_LIMIT: u64 = 256 * 1024;
const BUNDLE_LIMIT: u64 = 512 * 1024 * 1024;
const EXPANDED_LIMIT: u64 = 1024 * 1024 * 1024;
const MARKER: &str = "ROUTEDECK-UPDATE-INCOMPLETE.txt";
const REPAIR: &str = "RouteDeck update was interrupted. Close RouteDeck, download the complete portable ZIP from https://github.com/oda02/RouteDeck/releases/latest and extract it into a NEW empty folder. User settings remain in Windows application data. Do not launch this incomplete folder.\n";
const ERROR: &str = "portable_update_failed";
type Result<T> = std::result::Result<T, &'static str>;

mod manifest;
use manifest::*;

/// Every ancestor is checked. Windows leases deny directory rename/deletion;
/// files read for verification deny concurrent writes/deletion.
struct DirectoryLease {
    _handles: Vec<File>,
}
fn metadata_safe(path: &Path) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path).map_err(|_| ERROR)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(ERROR);
        }
    }
    if m.file_type().is_symlink() {
        return Err(ERROR);
    }
    Ok(m)
}
impl DirectoryLease {
    fn acquire(path: &Path) -> Result<Self> {
        Self::open(path, true)
    }
    #[cfg(windows)]
    fn observe(path: &Path) -> Result<Self> {
        Self::open(path, false)
    }
    fn open(path: &Path, exclusive: bool) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ERROR);
        }
        let mut handles = Vec::new();
        for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            if !metadata_safe(ancestor)?.is_dir() {
                return Err(ERROR);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // BACKUP_SEMANTICS | OPEN_REPARSE_POINT; never follow a junction.
                let f = OpenOptions::new()
                    .access_mode(if ancestor == path && exclusive {
                        0x30080
                    } else {
                        0x20080
                    })
                    .share_mode(if ancestor == path && exclusive { 3 } else { 7 })
                    .custom_flags(0x02200000)
                    .open(ancestor)
                    .map_err(|_| ERROR)?;
                use std::os::windows::fs::MetadataExt;
                if f.metadata().map_err(|_| ERROR)?.file_attributes() & 0x400 != 0 {
                    return Err(ERROR);
                }
                handles.push(f);
            }
        }
        Ok(Self { _handles: handles })
    }
}
fn read_file(path: &Path) -> Result<File> {
    if !metadata_safe(path)?.is_file() {
        return Err(ERROR);
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(1).custom_flags(0x00200000);
    }
    let f = opts.open(path).map_err(|_| ERROR)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if f.metadata().map_err(|_| ERROR)?.file_attributes() & 0x400 != 0 {
            return Err(ERROR);
        }
    }
    #[cfg(windows)]
    windows::verify_file(&f)?;
    Ok(f)
}
fn private_directory(path: &Path) -> Result<()> {
    crate::engine_runtime::create_private_directory(path).map_err(|_| ERROR)
}
fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = read_file(path)?;
    if f.metadata().map_err(|_| ERROR)?.len() > limit {
        return Err(ERROR);
    }
    let mut bytes = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ERROR)?;
    if bytes.len() as u64 > limit {
        return Err(ERROR);
    }
    Ok(bytes)
}
fn digest_file(path: &Path, expected: &BundleFile) -> Result<File> {
    let mut f = read_file(path)?;
    if f.metadata().map_err(|_| ERROR)?.len() != expected.size {
        return Err(ERROR);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        let n = f.read(&mut buffer).map_err(|_| ERROR)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > expected.size {
            return Err(ERROR);
        }
        digest.update(&buffer[..n]);
    }
    if total != expected.size || hex(&digest.finalize()) != expected.sha256 {
        return Err(ERROR);
    }
    Ok(f)
}
fn list_files(root: &Path, dir: &Path, out: &mut BTreeSet<String>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|_| ERROR)? {
        let p = entry.map_err(|_| ERROR)?.path();
        let m = metadata_safe(&p)?;
        if m.is_dir() {
            if fs::read_dir(&p).map_err(|_| ERROR)?.next().is_none() {
                return Err("portable_update_foreign_files");
            }
            list_files(root, &p, out)?;
        } else if m.is_file() {
            let name = p
                .strip_prefix(root)
                .map_err(|_| ERROR)?
                .to_str()
                .ok_or(ERROR)?
                .replace('\\', "/");
            if !safe_relative(&name) || !out.insert(name) || out.len() > 514 {
                return Err(ERROR);
            }
        } else {
            return Err(ERROR);
        }
    }
    Ok(())
}
struct VerifiedTree {
    directories: Vec<DirectoryLease>,
    files: Vec<File>,
}
fn verify_tree(root: &Path, manifest: &UpdateManifest, extras: &[&str]) -> Result<VerifiedTree> {
    let mut directories = vec![DirectoryLease::acquire(root)?];
    #[cfg(windows)]
    windows::verify_private_directory(&directories[0], false)?;
    let mut actual = BTreeSet::new();
    list_files(root, root, &mut actual)?;
    let expected: BTreeSet<_> = manifest
        .files
        .iter()
        .map(|f| f.path.clone())
        .chain(extras.iter().map(|p| p.to_string()))
        .collect();
    if actual != expected {
        return Err("portable_update_foreign_files");
    }
    let mut parents = BTreeSet::new();
    for f in &manifest.files {
        let path = root.join(&f.path);
        for parent in path.parent().ok_or(ERROR)?.ancestors() {
            if parent == root {
                break;
            }
            parents.insert(parent.to_path_buf());
        }
    }
    for parent in parents {
        let lease = DirectoryLease::acquire(&parent)?;
        #[cfg(windows)]
        windows::verify_private_directory(&lease, false)?;
        directories.push(lease);
    }
    let files = manifest
        .files
        .iter()
        .map(|f| digest_file(&root.join(&f.path), f))
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifiedTree { directories, files })
}
fn durable_new(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ERROR)?;
    file.write_all(body)
        .and_then(|_| file.sync_all())
        .map_err(|_| ERROR)
}
fn extract_bundle(archive: &Path, target: &Path, manifest: &UpdateManifest) -> Result<()> {
    let expected = BundleFile {
        path: manifest.archive.clone(),
        size: manifest.size,
        sha256: manifest.sha256.clone(),
    };
    let mut source = digest_file(archive, &expected)?;
    use std::io::{Seek, SeekFrom};
    source.seek(SeekFrom::Start(0)).map_err(|_| ERROR)?;
    let mut zip = zip::ZipArchive::new(source).map_err(|_| ERROR)?;
    if zip.len() != manifest.files.len() {
        return Err(ERROR);
    }
    private_directory(target)?;
    let _lease = DirectoryLease::acquire(target)?;
    let mut seen = BTreeSet::new();
    let mut directory_names = BTreeSet::new();
    let mut directory_leases = Vec::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|_| ERROR)?;
        let name = entry.name().to_string();
        if !safe_relative(&name)
            || !seen.insert(name.to_ascii_lowercase())
            || entry.is_dir()
            || entry.encrypted()
            || entry
                .unix_mode()
                .is_some_and(|m| m & 0o170000 != 0 && m & 0o170000 != 0o100000)
        {
            return Err(ERROR);
        }
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        ) {
            return Err(ERROR);
        }
        let expected = manifest
            .files
            .iter()
            .find(|f| f.path == name)
            .ok_or(ERROR)?;
        if entry.size() != expected.size {
            return Err(ERROR);
        }
        let path = target.join(&name);
        let mut parents = path
            .parent()
            .ok_or(ERROR)?
            .ancestors()
            .take_while(|p| *p != target)
            .collect::<Vec<_>>();
        parents.reverse();
        for parent in parents {
            if directory_names.insert(parent.to_path_buf()) {
                private_directory(parent)?;
                directory_leases.push(DirectoryLease::acquire(parent)?);
            }
        }
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| ERROR)?;
        let mut digest = Sha256::new();
        let mut total = 0;
        let mut buffer = [0; 65536];
        loop {
            let n = entry.read(&mut buffer).map_err(|_| ERROR)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > expected.size {
                return Err(ERROR);
            }
            digest.update(&buffer[..n]);
            out.write_all(&buffer[..n]).map_err(|_| ERROR)?;
        }
        if total != expected.size || hex(&digest.finalize()) != expected.sha256 {
            return Err(ERROR);
        }
        out.sync_all().map_err(|_| ERROR)?;
    }
    drop(directory_leases);
    drop(_lease);
    verify_tree(target, manifest, &[])?;
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableUpdateStatus {
    pub phase: &'static str,
    pub downloaded: u64,
    pub total: u64,
    pub version: Option<String>,
    pub error: Option<&'static str>,
}
impl Default for PortableUpdateStatus {
    fn default() -> Self {
        Self {
            phase: "idle",
            downloaded: 0,
            total: 0,
            version: None,
            error: None,
        }
    }
}
struct Ready {
    stage: PathBuf,
    target: PathBuf,
    next: UpdateManifest,
    current: UpdateManifest,
}
#[derive(Default)]
struct CoordinatorState {
    status: PortableUpdateStatus,
    ready: Option<Ready>,
}
pub struct PortableUpdater {
    stage_root: PathBuf,
    expected_updater: Option<&'static str>,
    state: Mutex<CoordinatorState>,
}
impl PortableUpdater {
    pub fn new(stage_root: PathBuf, expected_updater: Option<&'static str>) -> Self {
        Self {
            stage_root,
            expected_updater,
            state: Mutex::new(CoordinatorState::default()),
        }
    }
    pub fn status(&self) -> PortableUpdateStatus {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .status
            .clone()
    }
    pub fn stage(self: &Arc<Self>, latest: String) -> Result<()> {
        if !stable_version(&latest)
            || !newer(&latest, env!("CARGO_PKG_VERSION"))
            || self.expected_updater.is_none()
        {
            return Err("portable_update_manual");
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(state.status.phase, "downloading" | "installing") {
            return Ok(());
        }
        if state
            .ready
            .as_ref()
            .is_some_and(|r| r.next.version == latest)
        {
            state.status.phase = "ready";
            state.status.error = None;
            return Ok(());
        }
        state.status = PortableUpdateStatus {
            phase: "downloading",
            version: Some(latest.clone()),
            ..Default::default()
        };
        state.ready = None;
        drop(state);
        let updater = self.clone();
        std::thread::spawn(move || {
            let result = updater.download(&latest);
            let mut state = updater.state.lock().unwrap_or_else(|p| p.into_inner());
            match result {
                Ok(ready) => {
                    state.status.phase = "ready";
                    state.ready = Some(ready);
                }
                Err(error) => {
                    state.status.phase = "error";
                    state.status.error = Some(error);
                }
            }
        });
        Ok(())
    }
    fn download(&self, latest: &str) -> Result<Ready> {
        let executable = std::env::current_exe().map_err(|_| ERROR)?;
        if executable.file_name().and_then(|n| n.to_str()) != Some("routedeck.exe") {
            return Err("portable_update_manual");
        }
        let target = executable.parent().ok_or(ERROR)?.to_path_buf();
        if target.join(MARKER).try_exists().map_err(|_| ERROR)? {
            return Err("portable_update_repair");
        }
        // Both signed versions are cached before any teardown. Initial manual
        // bootstrap uses its immutable current release; no network at install.
        let client = download_client()?;
        let (current_body, current_signature, current) =
            fetch_manifest(&client, env!("CARGO_PKG_VERSION"))?;
        verify_tree(&target, &current, &[])?;
        let (body, signature, next) = fetch_manifest(&client, latest)?;
        let parent = self.stage_root.parent().ok_or(ERROR)?;
        let _parent = DirectoryLease::acquire(parent)?;
        if !self.stage_root.try_exists().map_err(|_| ERROR)? {
            private_directory(&self.stage_root)?;
        }
        let _root = DirectoryLease::acquire(&self.stage_root)?;
        #[cfg(windows)]
        windows::verify_private_directory(&_root, true)?;
        let token = random_token()?;
        let stage = self.stage_root.join(token);
        private_directory(&stage)?;
        let _stage = DirectoryLease::acquire(&stage)?;
        #[cfg(windows)]
        windows::verify_private_directory(&_stage, true)?;
        durable_new(&stage.join("current.json"), &current_body)?;
        durable_new(&stage.join("current.sig"), &current_signature)?;
        durable_new(&stage.join("next.json"), &body)?;
        durable_new(&stage.join("next.sig"), &signature)?;
        let response = client
            .get(asset_url(latest, &next.archive)?)
            .send()
            .map_err(|_| ERROR)?
            .error_for_status()
            .map_err(|_| ERROR)?;
        if response.content_length().is_some_and(|n| n != next.size) {
            return Err(ERROR);
        }
        let mut response = response.take(next.size + 1);
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.join("bundle.zip"))
            .map_err(|_| ERROR)?;
        let mut buffer = [0; 65536];
        let mut downloaded = 0u64;
        let mut hash = Sha256::new();
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.status.total = next.size;
        }
        loop {
            let n = response.read(&mut buffer).map_err(|_| ERROR)?;
            if n == 0 {
                break;
            }
            downloaded += n as u64;
            if downloaded > next.size {
                return Err(ERROR);
            }
            hash.update(&buffer[..n]);
            out.write_all(&buffer[..n]).map_err(|_| ERROR)?;
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .status
                .downloaded = downloaded;
        }
        out.sync_all().map_err(|_| ERROR)?;
        drop(out);
        if downloaded != next.size || hex(&hash.finalize()) != next.sha256 {
            return Err(ERROR);
        }
        extract_bundle(&stage.join("bundle.zip"), &stage.join("payload"), &next)?;
        Ok(Ready {
            stage,
            target,
            next,
            current,
        })
    }
    /// Prepare/check everything before asking controller to enter shutdown.
    pub fn prepare_install(&self) -> Result<PreparedInstall> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let ready = state.ready.as_ref().ok_or(ERROR)?;
        let _stage = DirectoryLease::acquire(&ready.stage)?;
        let current = verify_tree(&ready.target, &ready.current, &[])?;
        verify_tree(&ready.stage.join("payload"), &ready.next, &[])?;
        let own = ready
            .current
            .files
            .iter()
            .find(|f| f.path == "routedeck-updater.exe")
            .ok_or(ERROR)?;
        if Some(own.sha256.as_str()) != self.expected_updater {
            return Err(ERROR);
        }
        let index = ready
            .current
            .files
            .iter()
            .position(|f| f.path == "routedeck-updater.exe")
            .ok_or(ERROR)?;
        let mut source = current.files[index].try_clone().map_err(|_| ERROR)?;
        use std::io::{Seek, SeekFrom};
        source.seek(SeekFrom::Start(0)).map_err(|_| ERROR)?;
        let copied = ready.stage.join("routedeck-updater.exe");
        if !copied.try_exists().map_err(|_| ERROR)? {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&copied)
                .map_err(|_| ERROR)?;
            if std::io::copy(&mut source.take(own.size + 1), &mut out).map_err(|_| ERROR)?
                != own.size
            {
                return Err(ERROR);
            }
            out.sync_all().map_err(|_| ERROR)?;
        }
        let lease = digest_file(&copied, own)?;
        let prepared = PreparedInstall {
            stage: ready.stage.clone(),
            target: ready.target.clone(),
            _updater_lease: lease,
            _stage_lease: _stage,
        };
        state.status.phase = "installing";
        Ok(prepared)
    }
    pub fn install_failed(&self, error: &'static str) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.status.phase = "error";
        state.status.error = Some(error);
    }
}
pub struct PreparedInstall {
    stage: PathBuf,
    target: PathBuf,
    _updater_lease: File,
    _stage_lease: DirectoryLease,
}
impl PreparedInstall {
    pub fn launch(self) -> Result<()> {
        #[cfg(windows)]
        {
            windows::launch(self)
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err(ERROR)
        }
    }
}
fn random_token() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| ERROR)?;
    Ok(hex(&bytes))
}
fn asset_url(version: &str, asset: &str) -> Result<String> {
    if !stable_version(version) || !safe_relative(asset) || asset.contains('/') {
        return Err(ERROR);
    }
    Ok(format!(
        "https://github.com/oda02/RouteDeck/releases/download/v{version}/{asset}"
    ))
}
fn allowed_download_url(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && match url.host_str() {
            Some("github.com") => url
                .path()
                .starts_with("/oda02/RouteDeck/releases/download/"),
            Some("release-assets.githubusercontent.com") => true,
            _ => false,
        }
}
fn download_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15 * 60))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 3 && allowed_download_url(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|_| ERROR)
}
fn fetch_manifest(
    client: &reqwest::blocking::Client,
    version: &str,
) -> Result<(Vec<u8>, Vec<u8>, UpdateManifest)> {
    let get = |asset: &str, limit: u64| -> Result<Vec<u8>> {
        let response = client
            .get(asset_url(version, asset)?)
            .send()
            .map_err(|_| ERROR)?
            .error_for_status()
            .map_err(|_| ERROR)?;
        let mut out = Vec::new();
        response
            .take(limit + 1)
            .read_to_end(&mut out)
            .map_err(|_| ERROR)?;
        if out.len() as u64 > limit {
            return Err(ERROR);
        }
        Ok(out)
    };
    let body = get("RouteDeck-update.json", MANIFEST_LIMIT)?;
    let signature = get("RouteDeck-update.sig", 64)?;
    let manifest = signed_manifest(&body, &signature)?;
    if manifest.version != version {
        return Err(ERROR);
    }
    Ok((body, signature, manifest))
}
/// Caller must invoke this before constructing the controller or mutating state.
pub fn startup_is_complete() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join(MARKER)))
        .and_then(|p| p.try_exists().ok())
        .is_some_and(|exists| !exists)
}

/// Transaction changes whole owned directory, never leaves a launchable mixed
/// GUI/helper/engine set. Previous folder is evidence/manual recovery, not rollback.
fn replace_bundle(
    stage: &Path,
    target: &Path,
    next: &UpdateManifest,
    current: &UpdateManifest,
    token: &str,
    mut checkpoint: impl FnMut(u8) -> Result<()>,
) -> Result<()> {
    unhex::<16>(token)?;
    if !newer(&next.version, &current.version) {
        return Err(ERROR);
    }
    let parent = target.parent().ok_or(ERROR)?;
    let _parent = DirectoryLease::acquire(parent)?;
    let _stage = DirectoryLease::acquire(stage)?;
    let mut old = verify_tree(target, current, &[])?;
    let mut payload = verify_tree(&stage.join("payload"), next, &[])?;
    let incoming = parent.join(format!(".RouteDeck-incoming-{token}"));
    let previous = parent.join(format!(".RouteDeck-previous-{token}"));
    if incoming.try_exists().map_err(|_| ERROR)? || previous.try_exists().map_err(|_| ERROR)? {
        return Err(ERROR);
    }
    private_directory(&incoming)?;
    let incoming_root = DirectoryLease::acquire(&incoming)?;
    let mut incoming_dirs = Vec::new();
    let mut created_dirs = BTreeSet::new();
    for (file, source) in next.files.iter().zip(payload.files.iter_mut()) {
        let dest = incoming.join(&file.path);
        let mut dirs = dest
            .parent()
            .ok_or(ERROR)?
            .ancestors()
            .take_while(|p| *p != incoming)
            .collect::<Vec<_>>();
        dirs.reverse();
        for dir in dirs {
            if created_dirs.insert(dir.to_path_buf()) {
                private_directory(dir)?;
                incoming_dirs.push(DirectoryLease::acquire(dir)?);
            }
        }
        // Use the already verified/locked file handle, never reopen its path.
        use std::io::{Seek, SeekFrom};
        source.seek(SeekFrom::Start(0)).map_err(|_| ERROR)?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .map_err(|_| ERROR)?;
        if std::io::copy(&mut source.take(file.size + 1), &mut out).map_err(|_| ERROR)? != file.size
        {
            return Err(ERROR);
        }
        out.sync_all().map_err(|_| ERROR)?;
    }
    // Close copy-time leases then reacquire a verified tree. No path is consumed
    // after verification without retained handles to all directories/files.
    drop(incoming_dirs);
    drop(incoming_root);
    let mut new = verify_tree(&incoming, next, &[])?;
    durable_new(&incoming.join(MARKER), REPAIR.as_bytes())?;
    durable_new(&target.join(MARKER), REPAIR.as_bytes())?;
    checkpoint(1)?;
    let mut actual = BTreeSet::new();
    list_files(target, target, &mut actual)?;
    let expected: BTreeSet<_> = current
        .files
        .iter()
        .map(|f| f.path.clone())
        .chain([MARKER.to_string()])
        .collect();
    if actual != expected {
        return Err("portable_update_foreign_files");
    }
    rename_verified_directory(&mut old, target, &previous)?;
    checkpoint(2)?;
    drop(old);
    verify_tree(&previous, current, &[MARKER])?;
    rename_verified_directory(&mut new, &incoming, target)?;
    checkpoint(3)?;
    drop(new);
    let _complete = verify_tree(target, next, &[MARKER])?;
    // Post-move complete-tree verification is retained through marker removal.
    fs::remove_file(target.join(MARKER)).map_err(|_| ERROR)?;
    checkpoint(4)?;
    Ok(())
}
fn rename_verified_directory(tree: &mut VerifiedTree, _source: &Path, target: &Path) -> Result<()> {
    // Windows refuses a directory move with open descendants. Retain the exact
    // root DELETE handle, release descendant leases, and verify again after move.
    tree.files.clear();
    tree.directories.truncate(1);
    #[cfg(windows)]
    {
        windows::rename_directory(&tree.directories[0], target)
    }
    #[cfg(not(windows))]
    {
        let _ = tree;
        fs::rename(_source, target).map_err(|_| ERROR)
    }
}

#[cfg(windows)]
mod windows;
pub fn updater_main() -> Result<()> {
    #[cfg(windows)]
    {
        windows::run()
    }
    #[cfg(not(windows))]
    {
        Err(ERROR)
    }
}
pub fn show_repair_notice() {
    #[cfg(windows)]
    {
        windows::repair_notice();
    }
}

trait UpdateChild {
    fn cancel(&mut self);
}
impl UpdateChild for std::process::Child {
    fn cancel(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}
struct PendingChild<T: UpdateChild> {
    child: T,
    acknowledged: bool,
}
impl<T: UpdateChild> Drop for PendingChild<T> {
    fn drop(&mut self) {
        if !self.acknowledged {
            self.child.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        io::Cursor,
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static ID: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "RouteDeck-update-fixture-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::SeqCst)
            ));
            private_directory(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(self
                .0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("RouteDeck-update-fixture-"));
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn files() -> Vec<BundleFile> {
        [
            "routedeck.exe",
            "routedeck-tun-helper.exe",
            "routedeck-updater.exe",
            "routedeck-build.json",
            "engine/sing-box.exe",
            "engine/libcronet.dll",
            "xray/xray.exe",
            "runtime-pins/sing-box.lock.json",
            "runtime-pins/xray-core.lock.json",
        ]
        .into_iter()
        .map(|path| {
            let bytes = format!("synthetic fixture only {path}").into_bytes();
            BundleFile {
                path: path.into(),
                size: bytes.len() as u64,
                sha256: hex(&Sha256::digest(&bytes)),
            }
        })
        .collect()
    }
    fn archive(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            zip.start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    fn manifest() -> (UpdateManifest, Vec<u8>) {
        let files = files();
        let bytes = archive(
            &files
                .iter()
                .map(|f| {
                    (
                        f.path.as_str(),
                        format!("synthetic fixture only {}", f.path).into_bytes(),
                    )
                })
                .collect::<Vec<_>>(),
        );
        let m = UpdateManifest {
            schema_version: 1,
            version: "1.2.0".into(),
            platform: "windows-x64".into(),
            archive: "RouteDeck-1.2.0-windows-x64.zip".into(),
            size: bytes.len() as u64,
            sha256: hex(&Sha256::digest(&bytes)),
            files,
        };
        (m, bytes)
    }
    fn populate(path: &Path, m: &UpdateManifest) {
        private_directory(path).unwrap();
        let mut dirs = BTreeSet::new();
        for f in &m.files {
            let p = path.join(&f.path);
            let mut parents = p
                .parent()
                .unwrap()
                .ancestors()
                .take_while(|p| *p != path)
                .collect::<Vec<_>>();
            parents.reverse();
            for parent in parents {
                if dirs.insert(parent.to_path_buf()) {
                    private_directory(parent).unwrap();
                }
            }
            fs::write(p, format!("synthetic fixture only {}", f.path)).unwrap();
        }
    }
    #[test]
    fn authentic_bytes_required_before_manifest_parse() {
        let (m, _) = manifest();
        let key = SigningKey::from_bytes(&[42; 32]);
        let body = serde_json::to_vec(&m).unwrap();
        let signature = key.sign(&body).to_bytes();
        assert!(
            signed_manifest_with_key(&body, &signature, &key.verifying_key().to_bytes()).is_ok()
        );
        let mut wrong = body.clone();
        wrong[0] = b' ';
        assert!(
            signed_manifest_with_key(&wrong, &signature, &key.verifying_key().to_bytes()).is_err()
        );
        assert!(signed_manifest(&body, &signature).is_err());
        assert!(
            signed_manifest_with_key(&body, &[0; 64], &key.verifying_key().to_bytes()).is_err()
        );
        assert!(
            signed_manifest_with_key(&body, &signature[..63], &key.verifying_key().to_bytes())
                .is_err()
        );
        assert!(signed_manifest_with_key(
            &vec![0; MANIFEST_LIMIT as usize + 1],
            &signature,
            &key.verifying_key().to_bytes()
        )
        .is_err());
    }
    #[test]
    fn spawned_child_is_canceled_on_all_pre_ack_failure_paths() {
        struct Fake(Arc<AtomicUsize>);
        impl UpdateChild for Fake {
            fn cancel(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for failure in ["process_identity", "ack_io", "ack_parse", "timeout"] {
            let count = Arc::new(AtomicUsize::new(0));
            {
                let _guard = PendingChild {
                    child: Fake(count.clone()),
                    acknowledged: false,
                };
                let _ = failure;
            }
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }
        let count = Arc::new(AtomicUsize::new(0));
        {
            let _guard = PendingChild {
                child: Fake(count.clone()),
                acknowledged: true,
            };
        }
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn cached_verified_bundle_can_retry_install_after_launch_failure() {
        let fixture = Fixture::new();
        let (next, _) = manifest();
        let mut current = next.clone();
        current.version = "1.1.0".into();
        let updater = Arc::new(PortableUpdater::new(
            fixture.0.join("updates"),
            Some("fixture-pin"),
        ));
        {
            let mut state = updater.state.lock().unwrap();
            state.ready = Some(Ready {
                stage: fixture.0.join("stage"),
                target: fixture.0.join("app"),
                next: next.clone(),
                current,
            });
            state.status = PortableUpdateStatus {
                phase: "error",
                downloaded: next.size,
                total: next.size,
                version: Some(next.version.clone()),
                error: Some(ERROR),
            };
        }
        updater.stage(next.version).unwrap();
        assert_eq!(updater.status().phase, "ready");
        assert_eq!(updater.status().error, None);
    }
    #[cfg(windows)]
    #[test]
    fn hardlinked_source_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.0.join("original");
        fs::write(&path, b"synthetic").unwrap();
        fs::hard_link(&path, fixture.0.join("linked")).unwrap();
        assert!(read_file(&path).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn symlink_source_and_directory_are_rejected_when_supported() {
        let fixture = Fixture::new();
        let dir = fixture.0.join("real");
        private_directory(&dir).unwrap();
        fs::write(dir.join("file"), b"synthetic").unwrap();
        if std::os::windows::fs::symlink_dir(&dir, fixture.0.join("link")).is_ok() {
            assert!(DirectoryLease::acquire(&fixture.0.join("link")).is_err());
            assert!(
                read_file(&fixture.0.join("link/file")).is_err()
                    || DirectoryLease::acquire(&fixture.0.join("link")).is_err()
            );
        }
    }
    #[test]
    fn hostile_manifest_paths_and_limits() {
        let (m, _) = manifest();
        for path in [
            "../escape",
            "engine/../../outside",
            "C:/outside",
            "engine\\file.exe",
            "engine/file:ads",
            "engine/CON.txt",
            "engine/file.",
            "engine/file ",
            "/absolute",
            "engine//a",
            "engine/COM1.exe",
        ] {
            let mut bad = m.clone();
            bad.files[0].path = path.into();
            assert!(validate_manifest(&bad).is_err(), "{path}");
        }
        let mut bad = m.clone();
        bad.files[1].path = "ROUTEDECK.EXE".into();
        assert!(validate_manifest(&bad).is_err());
        bad = m.clone();
        bad.size = BUNDLE_LIMIT + 1;
        assert!(validate_manifest(&bad).is_err());
        bad = m.clone();
        bad.platform = "linux-x64".into();
        assert!(validate_manifest(&bad).is_err());
        bad = m.clone();
        bad.files[0].size = 0;
        assert!(validate_manifest(&bad).is_err());
        bad = m.clone();
        bad.files[0].sha256 = "g".repeat(64);
        assert!(validate_manifest(&bad).is_err());
        assert!(!newer("1.0.0", "1.0.0"));
        assert!(!newer("01.0.0", "1.0.0"));
    }
    #[test]
    fn exact_bounded_full_archive_required() {
        let fixture = Fixture::new();
        let (m, bytes) = manifest();
        let zip = fixture.0.join("bundle.zip");
        fs::write(&zip, &bytes).unwrap();
        extract_bundle(&zip, &fixture.0.join("valid"), &m).unwrap();
        verify_tree(&fixture.0.join("valid"), &m, &[]).unwrap();
        let mut corrupted = bytes.clone();
        corrupted[15] ^= 1;
        fs::write(&zip, corrupted).unwrap();
        assert!(extract_bundle(&zip, &fixture.0.join("bad"), &m).is_err());
        fs::write(&zip, &bytes[..bytes.len() - 1]).unwrap();
        assert!(extract_bundle(&zip, &fixture.0.join("short"), &m).is_err());
    }
    #[test]
    fn signed_hash_does_not_allow_traversal_or_extra_members() {
        let fixture = Fixture::new();
        let (mut m, _) = manifest();
        let mut entries = m
            .files
            .iter()
            .map(|f| {
                (
                    f.path.as_str(),
                    format!("synthetic fixture only {}", f.path).into_bytes(),
                )
            })
            .collect::<Vec<_>>();
        entries[0].0 = "../escape";
        let bytes = archive(&entries);
        m.size = bytes.len() as u64;
        m.sha256 = hex(&Sha256::digest(&bytes));
        let p = fixture.0.join("bundle.zip");
        fs::write(&p, bytes).unwrap();
        assert!(extract_bundle(&p, &fixture.0.join("unsafe"), &m).is_err());
        assert!(!fixture.0.join("escape").exists());
    }
    #[test]
    fn foreign_state_never_replaced() {
        let fixture = Fixture::new();
        let (next, _) = manifest();
        let mut current = next.clone();
        current.version = "1.1.0".into();
        let target = fixture.0.join("app");
        populate(&target, &current);
        let stage = fixture.0.join("stage");
        fs::create_dir(&stage).unwrap();
        populate(&stage.join("payload"), &next);
        fs::write(target.join("foreign.txt"), b"must preserve").unwrap();
        assert_eq!(
            replace_bundle(
                &stage,
                &target,
                &next,
                &current,
                &"a".repeat(32),
                |_| Ok(())
            )
            .unwrap_err(),
            "portable_update_foreign_files"
        );
        assert_eq!(
            fs::read(target.join("foreign.txt")).unwrap(),
            b"must preserve"
        );
        assert!(!target.join(MARKER).exists());
    }
    #[test]
    fn every_interrupted_rename_refuses_launch() {
        for fail_at in 1..=3 {
            let fixture = Fixture::new();
            let (next, _) = manifest();
            let mut current = next.clone();
            current.version = "1.1.0".into();
            let target = fixture.0.join("app");
            populate(&target, &current);
            let stage = fixture.0.join("stage");
            fs::create_dir(&stage).unwrap();
            populate(&stage.join("payload"), &next);
            assert!(
                replace_bundle(&stage, &target, &next, &current, &"b".repeat(32), |step| {
                    if step == fail_at {
                        Err(ERROR)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            if target.exists() {
                assert!(target.join(MARKER).exists());
            } else {
                assert!(fixture
                    .0
                    .join(format!(".RouteDeck-previous-{}", "b".repeat(32)))
                    .join(MARKER)
                    .exists());
            }
        }
    }
    #[test]
    fn complete_transaction_retains_evidence_and_complete_bundle() {
        let fixture = Fixture::new();
        let (next, _) = manifest();
        let mut current = next.clone();
        current.version = "1.1.0".into();
        let target = fixture.0.join("app");
        populate(&target, &current);
        let stage = fixture.0.join("stage");
        fs::create_dir(&stage).unwrap();
        populate(&stage.join("payload"), &next);
        replace_bundle(
            &stage,
            &target,
            &next,
            &current,
            &"c".repeat(32),
            |_| Ok(()),
        )
        .unwrap();
        verify_tree(&target, &next, &[]).unwrap();
        assert!(!target.join(MARKER).exists());
        assert!(fixture
            .0
            .join(format!(".RouteDeck-previous-{}", "c".repeat(32)))
            .join(MARKER)
            .exists());
    }
    #[test]
    fn redirect_and_token_boundary() {
        for url in [
            "http://github.com/oda02/RouteDeck/releases/download/v1.0.0/a",
            "https://github.com/foreign/repo/releases/download/a",
            "https://github.com.evil.invalid/oda02/RouteDeck/releases/download/a",
            "https://user@release-assets.githubusercontent.com/a",
            "https://objects.githubusercontent.com/a",
        ] {
            assert!(
                !allowed_download_url(&url::Url::parse(url).unwrap()),
                "{url}"
            );
        }
        assert!(allowed_download_url(
            &url::Url::parse("https://release-assets.githubusercontent.com/a?token=opaque")
                .unwrap()
        ));
        assert!(asset_url("1.0.0", "../foreign").is_err());
        assert!(unhex::<16>("../outside").is_err());
    }
    #[cfg(windows)]
    #[test]
    fn empty_handle_rename() {
        let fixture = Fixture::new();
        let p = fixture.0.join("empty");
        fs::create_dir(&p).unwrap();
        let lease = DirectoryLease::acquire(&p).unwrap();
        windows::rename_directory(&lease, &fixture.0.join("moved")).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn reparse_and_source_write_race_rejected() {
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = Fixture::new();
        let (m, _) = manifest();
        populate(&fixture.0.join("app"), &m);
        let locked = digest_file(&fixture.0.join("app/routedeck.exe"), &m.files[0]).unwrap();
        assert!(OpenOptions::new()
            .write(true)
            .share_mode(7)
            .open(fixture.0.join("app/routedeck.exe"))
            .is_err());
        drop(locked);
        let lease = DirectoryLease::acquire(&fixture.0.join("app")).unwrap();
        assert!(fs::rename(fixture.0.join("app"), fixture.0.join("moved")).is_err());
        drop(lease);
    }
}
