use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

const MAX_PROXY_CONFIG_CHARS: usize = 4 * 1024;
#[allow(dead_code)] // Wired into the application controller by the next backend milestone.
const MAX_JOURNAL_BYTES: usize = 16 * 1024;
#[allow(dead_code)]
const JOURNAL_VERSION: u8 = 2;
#[allow(dead_code)]
const JOURNAL_FILE_NAME: &str = "system-proxy-session.json";
const CLEANUP_JOURNAL_FILE_NAME: &str = "system-proxy-cleanup.json";
#[allow(dead_code)]
const ROUTEDECK_PROXY_BYPASS: &str = "localhost;127.*;[::1];<local>";
#[allow(dead_code)]
const PROXY_TYPE_DIRECT_VALUE: u32 = 1;
const PROXY_TYPE_PROXY_VALUE: u32 = 2;
const MAX_LISTENER_TABLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SystemProxySnapshot {
    flags: u32,
    proxy_server: Option<String>,
    proxy_bypass: Option<String>,
    auto_config_url: Option<String>,
}

impl fmt::Debug for SystemProxySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemProxySnapshot")
            .field("flags", &self.flags)
            .field(
                "proxy_server",
                &self.proxy_server.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "proxy_bypass",
                &self.proxy_bypass.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "auto_config_url",
                &self.auto_config_url.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl SystemProxySnapshot {
    #[allow(dead_code)]
    fn routedeck(http_port: u16, owner_id: &str) -> Result<Self, SystemProxyError> {
        if http_port == 0 || !valid_owner_id(owner_id) {
            return Err(SystemProxyError::RecoveryRequired(
                "system proxy port must be non-zero",
            ));
        }
        Ok(Self {
            flags: PROXY_TYPE_DIRECT_VALUE | PROXY_TYPE_PROXY_VALUE,
            proxy_server: Some(format!("127.0.0.1:{http_port}")),
            // A reserved, unique name distinguishes this session from another
            // application reusing the same loopback port after a crash.
            proxy_bypass: Some(format!(
                "{ROUTEDECK_PROXY_BYPASS};routedeck-owner-{owner_id}.invalid"
            )),
            auto_config_url: None,
        })
    }

    fn valid(&self) -> bool {
        [
            self.proxy_server.as_deref(),
            self.proxy_bypass.as_deref(),
            self.auto_config_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(|value| value.len() <= MAX_PROXY_CONFIG_CHARS && !value.contains(['\0', '\r', '\n']))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum SystemProxyRestoreOutcome {
    NoJournal,
    Restored,
    ForeignPreserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxyDiagnostics {
    pub state: SystemProxyDiagnosticState,
    pub endpoint: Option<String>,
    pub detail: &'static str,
    pub cleanup_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SystemProxyDiagnosticState {
    Disabled,
    Owned,
    ForeignActive,
    Stale,
    Conflict,
    Unavailable,
}

impl SystemProxyDiagnostics {
    fn unavailable() -> Self {
        Self {
            state: SystemProxyDiagnosticState::Unavailable,
            endpoint: None,
            detail: "System Proxy diagnostics are unavailable",
            cleanup_token: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CleanupObservation {
    wininet: SystemProxySnapshot,
    policy: Option<u32>,
    user_enabled: Option<u32>,
    user_server: Option<String>,
    user_bypass: Option<String>,
    user_auto_config_url: Option<String>,
    ras_active: bool,
    listener_present: bool,
}

#[derive(Clone)]
struct CleanupPreview {
    token: String,
    observation: CleanupObservation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CleanupJournal {
    version: u8,
    owner_id: String,
    previous: CleanupObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SystemProxyError {
    Unchanged(&'static str),
    RecoveryRequired(&'static str),
}

impl SystemProxyError {
    #[cfg(test)]
    pub(crate) fn fixed(message: &'static str) -> Self {
        Self::RecoveryRequired(message)
    }

    pub(crate) fn may_have_changed(&self) -> bool {
        matches!(self, Self::RecoveryRequired(_))
    }

    fn unchanged(self) -> Self {
        match self {
            Self::Unchanged(message) | Self::RecoveryRequired(message) => Self::Unchanged(message),
        }
    }
}

impl fmt::Display for SystemProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged(message) | Self::RecoveryRequired(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for SystemProxyError {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(dead_code)]
struct SystemProxyJournal {
    version: u8,
    owner_id: String,
    previous: SystemProxySnapshot,
    applied: SystemProxySnapshot,
}

fn valid_owner_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl SystemProxyJournal {
    fn valid(&self) -> bool {
        let port = self
            .applied
            .proxy_server
            .as_deref()
            .and_then(|server| server.strip_prefix("127.0.0.1:"))
            .and_then(|port| port.parse::<u16>().ok());
        self.version == JOURNAL_VERSION
            && self.previous.valid()
            && port.is_some_and(|port| {
                SystemProxySnapshot::routedeck(port, &self.owner_id)
                    .is_ok_and(|expected| expected == self.applied)
            })
    }
}

#[allow(dead_code)]
trait SystemProxyBackend: Send + Sync {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError>;
    fn apply(&self, state: &SystemProxySnapshot) -> Result<(), SystemProxyError>;
    fn cleanup_observation(&self) -> Result<CleanupObservation, SystemProxyError> {
        Err(SystemProxyError::Unchanged(
            "System Proxy diagnostics are unavailable",
        ))
    }
    fn clear_manual_if_exact(
        &self,
        _expected: &CleanupObservation,
    ) -> Result<(), SystemProxyError> {
        Err(SystemProxyError::Unchanged(
            "stale System Proxy cleanup is unavailable",
        ))
    }
}

pub(crate) trait SystemProxyControl: Send + Sync {
    fn publish_loopback(&self, http_port: u16) -> Result<(), SystemProxyError>;
    fn is_owned(&self) -> Result<bool, SystemProxyError>;
    fn restore_if_owned(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError>;
    fn reconcile_stale_journal(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError>;
    fn diagnostics(&self) -> SystemProxyDiagnostics {
        SystemProxyDiagnostics::unavailable()
    }
    fn clear_stale(&self, _token: &str) -> Result<SystemProxyDiagnostics, SystemProxyError> {
        Err(SystemProxyError::Unchanged(
            "stale System Proxy cleanup is unavailable",
        ))
    }
}

#[allow(dead_code)]
struct WinInetSystemProxyBackend;

impl SystemProxyBackend for WinInetSystemProxyBackend {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
        #[cfg(windows)]
        {
            let snapshot = query_wininet_snapshot()?;
            let ras_active = query_ras_active().map_err(|_| fetch_proxy_error())?;
            validate_ownership_snapshot(&snapshot, ras_active, &WindowsFetchProxyRegistry)?;
            Ok(snapshot)
        }
        #[cfg(not(windows))]
        {
            Err(SystemProxyError::RecoveryRequired(
                "Windows System Proxy is unavailable on this platform",
            ))
        }
    }

    fn apply(&self, state: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
        #[cfg(windows)]
        {
            set_wininet_snapshot(state)
        }
        #[cfg(not(windows))]
        {
            let _ = state;
            Err(SystemProxyError::RecoveryRequired(
                "Windows System Proxy is unavailable on this platform",
            ))
        }
    }

    fn cleanup_observation(&self) -> Result<CleanupObservation, SystemProxyError> {
        #[cfg(windows)]
        {
            let registry = WindowsFetchProxyRegistry;
            let wininet = query_wininet_snapshot()?;
            let policy = registry.policy()?;
            let user_enabled = registry.enabled(FetchProxyScope::User)?;
            let user_server = registry.server(FetchProxyScope::User)?;
            let user_bypass = registry.bypass(FetchProxyScope::User)?;
            let user_auto_config_url = registry.auto_config_url(FetchProxyScope::User)?;
            let ras_active = query_ras_active().map_err(|_| fetch_proxy_error())?;
            let endpoint = user_server.as_deref().and_then(parse_single_loopback_proxy);
            let listener_present = match endpoint {
                Some(endpoint) => loopback_listener_present(endpoint.0)?,
                None => false,
            };
            Ok(CleanupObservation {
                wininet,
                policy,
                user_enabled,
                user_server,
                user_bypass,
                user_auto_config_url,
                ras_active,
                listener_present,
            })
        }
        #[cfg(not(windows))]
        {
            Err(SystemProxyError::Unchanged(
                "System Proxy diagnostics are unavailable",
            ))
        }
    }

    fn clear_manual_if_exact(&self, expected: &CleanupObservation) -> Result<(), SystemProxyError> {
        #[cfg(windows)]
        {
            if self.cleanup_observation()? != *expected {
                return Err(SystemProxyError::Unchanged(
                    "System Proxy changed; review diagnostics again",
                ));
            }
            disable_user_manual_proxy(expected.wininet.flags)
        }
        #[cfg(not(windows))]
        {
            let _ = expected;
            Err(SystemProxyError::Unchanged(
                "stale System Proxy cleanup is unavailable",
            ))
        }
    }
}

#[allow(dead_code)]
pub(crate) struct SystemProxyManager {
    journal_path: PathBuf,
    cleanup_journal_path: PathBuf,
    backend: Arc<dyn SystemProxyBackend>,
    cleanup_preview: Mutex<Option<CleanupPreview>>,
}

#[allow(dead_code)]
impl SystemProxyManager {
    pub(crate) fn new(app_local_data_dir: PathBuf) -> Self {
        Self {
            journal_path: app_local_data_dir.join(JOURNAL_FILE_NAME),
            cleanup_journal_path: app_local_data_dir.join(CLEANUP_JOURNAL_FILE_NAME),
            backend: Arc::new(WinInetSystemProxyBackend),
            cleanup_preview: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_backend(journal_path: PathBuf, backend: Arc<dyn SystemProxyBackend>) -> Self {
        Self {
            cleanup_journal_path: journal_path.with_file_name(CLEANUP_JOURNAL_FILE_NAME),
            journal_path,
            backend,
            cleanup_preview: Mutex::new(None),
        }
    }

    pub(crate) fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
        self.backend.snapshot()
    }

    pub(crate) fn publish_loopback(&self, http_port: u16) -> Result<(), SystemProxyError> {
        let owner_id = crate::engine_runtime::random_hex(16).map_err(|_| {
            SystemProxyError::Unchanged("could not allocate proxy ownership marker")
        })?;
        let applied = SystemProxySnapshot::routedeck(http_port, &owner_id)
            .map_err(SystemProxyError::unchanged)?;
        if self.load_journal()?.is_some() {
            return Err(SystemProxyError::RecoveryRequired(
                "a previous System Proxy session must be reconciled first",
            ));
        }
        let previous = self
            .backend
            .snapshot()
            .map_err(SystemProxyError::unchanged)?;
        if !previous.valid() {
            return Err(SystemProxyError::Unchanged(
                "Windows returned invalid proxy settings",
            ));
        }
        if previous.flags != PROXY_TYPE_DIRECT_VALUE {
            return Err(SystemProxyError::Unchanged(
                "another manual or automatic System Proxy is enabled; preserve it until the user resolves the conflict",
            ));
        }
        let journal = SystemProxyJournal {
            version: JOURNAL_VERSION,
            owner_id,
            previous: previous.clone(),
            applied: applied.clone(),
        };
        self.write_journal(&journal)?;
        // Keep the journal on every failure: the controller performs the one
        // ownership-checked rollback before stopping its live listeners.
        self.verify_exact(&previous)?;
        self.backend.apply(&applied).map_err(|_| {
            SystemProxyError::RecoveryRequired("could not publish the RouteDeck System Proxy")
        })?;
        self.verify_exact(&applied)
    }

    pub(crate) fn is_owned(&self) -> Result<bool, SystemProxyError> {
        let Some(journal) = self.load_journal()? else {
            return Ok(false);
        };
        Ok(self.backend.snapshot()? == journal.applied)
    }

    pub(crate) fn restore_if_owned(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError> {
        let Some(journal) = self.load_journal()? else {
            return Ok(SystemProxyRestoreOutcome::NoJournal);
        };
        let current = self.backend.snapshot()?;
        if current == journal.previous {
            // Publication never happened, or restoration succeeded before a
            // crash/removal failure. No Windows write is needed on retry.
            self.remove_journal()?;
            return Ok(SystemProxyRestoreOutcome::Restored);
        }
        if current != journal.applied {
            self.preserve_conflict_journal(&journal)?;
            return Ok(SystemProxyRestoreOutcome::ForeignPreserved);
        }
        self.backend.apply(&journal.previous).map_err(|_| {
            SystemProxyError::RecoveryRequired("could not restore Windows System Proxy settings")
        })?;
        self.verify_exact(&journal.previous).map_err(|_| {
            SystemProxyError::RecoveryRequired("Windows did not retain restored proxy settings")
        })?;
        self.remove_journal()?;
        Ok(SystemProxyRestoreOutcome::Restored)
    }

    pub(crate) fn reconcile_stale_journal(
        &self,
    ) -> Result<SystemProxyRestoreOutcome, SystemProxyError> {
        self.restore_if_owned()
    }

    pub(crate) fn diagnostics(&self) -> SystemProxyDiagnostics {
        // Every observation supersedes every prior user preview, including
        // observations that return early as unavailable, owned, or conflicted.
        *self
            .cleanup_preview
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        let observation = match self.backend.cleanup_observation() {
            Ok(observation) => observation,
            Err(_) => return SystemProxyDiagnostics::unavailable(),
        };
        match self.load_journal() {
            Ok(Some(journal)) if ownership_observation_matches(&observation, &journal) => {
                return SystemProxyDiagnostics {
                    state: SystemProxyDiagnosticState::Owned,
                    endpoint: sanitized_endpoint(&observation),
                    detail: "System Proxy is owned by RouteDeck",
                    cleanup_token: None,
                }
            }
            Ok(Some(_)) => {
                return SystemProxyDiagnostics {
                    state: SystemProxyDiagnosticState::Conflict,
                    endpoint: sanitized_endpoint(&observation),
                    detail: "System Proxy differs from RouteDeck ownership records",
                    cleanup_token: None,
                }
            }
            Err(_) => {
                return SystemProxyDiagnostics {
                    state: SystemProxyDiagnosticState::Conflict,
                    endpoint: sanitized_endpoint(&observation),
                    detail: "RouteDeck proxy ownership records require attention",
                    cleanup_token: None,
                }
            }
            Ok(None) => {}
        }
        let mut result = classify_cleanup_observation(&observation);
        if result.state == SystemProxyDiagnosticState::Stale {
            if let Ok(token) = crate::engine_runtime::random_hex(32) {
                *self
                    .cleanup_preview
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(CleanupPreview {
                    token: token.clone(),
                    observation,
                });
                result.cleanup_token = Some(token);
            } else {
                result.state = SystemProxyDiagnosticState::Unavailable;
                result.detail = "Could not prepare stale System Proxy cleanup";
            }
        } else {
            *self
                .cleanup_preview
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = None;
        }
        result
    }

    pub(crate) fn clear_stale(
        &self,
        token: &str,
    ) -> Result<SystemProxyDiagnostics, SystemProxyError> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SystemProxyError::Unchanged(
                "stale System Proxy cleanup preview is invalid",
            ));
        }
        if self.load_journal()?.is_some() {
            return Err(SystemProxyError::Unchanged(
                "RouteDeck proxy ownership must be reconciled first",
            ));
        }
        let preview = self
            .cleanup_preview
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .filter(|preview| preview.token == token)
            .ok_or(SystemProxyError::Unchanged(
                "stale System Proxy cleanup preview expired",
            ))?;
        let current = self
            .backend
            .cleanup_observation()
            .map_err(SystemProxyError::unchanged)?;
        if current != preview.observation
            || classify_cleanup_observation(&current).state != SystemProxyDiagnosticState::Stale
        {
            return Err(SystemProxyError::Unchanged(
                "System Proxy changed; review diagnostics again",
            ));
        }
        let owner_id = crate::engine_runtime::random_hex(16).map_err(|_| {
            SystemProxyError::Unchanged("could not allocate cleanup ownership marker")
        })?;
        let journal = CleanupJournal {
            version: 1,
            owner_id: owner_id.clone(),
            previous: current,
        };
        self.write_cleanup_journal(&journal, &owner_id)?;
        self.backend
            .clear_manual_if_exact(&journal.previous)
            .map_err(|error| match error {
                SystemProxyError::Unchanged(_) => {
                    SystemProxyError::Unchanged("System Proxy changed; review diagnostics again")
                }
                SystemProxyError::RecoveryRequired(_) => SystemProxyError::RecoveryRequired(
                    "could not clear stale System Proxy settings",
                ),
            })?;
        let after = self.backend.cleanup_observation()?;
        let mut expected_after = journal.previous.clone();
        expected_after.wininet.flags = disabled_manual_flags(expected_after.wininet.flags);
        expected_after.user_enabled = Some(0);
        if after != expected_after {
            return Err(SystemProxyError::RecoveryRequired(
                "Windows System Proxy changed during cleanup",
            ));
        }
        let result = classify_cleanup_observation(&after);
        if result.state != SystemProxyDiagnosticState::Disabled {
            return Err(SystemProxyError::RecoveryRequired(
                "Windows did not retain cleared System Proxy settings",
            ));
        }
        Ok(result)
    }

    fn write_cleanup_journal(
        &self,
        journal: &CleanupJournal,
        owner_id: &str,
    ) -> Result<(), SystemProxyError> {
        let path = self
            .cleanup_journal_path
            .with_file_name(format!("system-proxy-cleanup-{owner_id}.json"));
        let parent = path.parent().ok_or(SystemProxyError::RecoveryRequired(
            "proxy cleanup recovery path is invalid",
        ))?;
        fs::create_dir_all(parent).map_err(|_| {
            SystemProxyError::RecoveryRequired("could not create proxy cleanup recovery directory")
        })?;
        let bytes = serde_json::to_vec(journal).map_err(|_| {
            SystemProxyError::RecoveryRequired("could not serialize proxy cleanup recovery journal")
        })?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| {
                SystemProxyError::RecoveryRequired(
                    "could not create proxy cleanup recovery journal",
                )
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| {
                SystemProxyError::RecoveryRequired("could not write proxy cleanup recovery journal")
            })
    }

    fn verify_exact(&self, expected: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
        if self.backend.snapshot()? == *expected {
            Ok(())
        } else {
            Err(SystemProxyError::RecoveryRequired(
                "effective Windows System Proxy settings did not match",
            ))
        }
    }

    fn load_journal(&self) -> Result<Option<SystemProxyJournal>, SystemProxyError> {
        Self::load_journal_at(&self.journal_path)
    }

    fn load_journal_at(path: &Path) -> Result<Option<SystemProxyJournal>, SystemProxyError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(SystemProxyError::RecoveryRequired(
                    "could not read proxy recovery journal",
                ))
            }
        };
        let mut bytes = Vec::new();
        file.take((MAX_JOURNAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                SystemProxyError::RecoveryRequired("could not read proxy recovery journal")
            })?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(SystemProxyError::RecoveryRequired(
                "proxy recovery journal is invalid",
            ));
        }
        let journal: SystemProxyJournal = serde_json::from_slice(&bytes)
            .map_err(|_| SystemProxyError::RecoveryRequired("proxy recovery journal is invalid"))?;
        if !journal.valid() {
            return Err(SystemProxyError::RecoveryRequired(
                "proxy recovery journal is invalid",
            ));
        }
        Ok(Some(journal))
    }

    fn write_journal(&self, journal: &SystemProxyJournal) -> Result<(), SystemProxyError> {
        let parent = self
            .journal_path
            .parent()
            .ok_or(SystemProxyError::RecoveryRequired(
                "proxy recovery path is invalid",
            ))?;
        fs::create_dir_all(parent).map_err(|_| {
            SystemProxyError::RecoveryRequired("could not create proxy recovery directory")
        })?;
        let bytes = serde_json::to_vec(journal).map_err(|_| {
            SystemProxyError::RecoveryRequired("could not serialize proxy recovery journal")
        })?;
        // Exclusive creation prevents clobbering another controller's journal.
        // A partial write is deliberately retained and fails closed on recovery.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.journal_path)
            .map_err(|_| {
                SystemProxyError::RecoveryRequired("could not create proxy recovery journal")
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| {
                SystemProxyError::RecoveryRequired("could not write proxy recovery journal")
            })
    }

    fn preserve_conflict_journal(
        &self,
        journal: &SystemProxyJournal,
    ) -> Result<(), SystemProxyError> {
        let evidence = self
            .journal_path
            .with_extension(format!("{}.conflict.json", journal.owner_id));
        // hard_link is create-only, so existing evidence is never overwritten.
        // If archiving fails, leave the active journal for explicit recovery.
        if let Err(error) = fs::hard_link(&self.journal_path, &evidence) {
            // Retry a crash between link creation and active-journal removal.
            // Different or malformed existing evidence is never replaced.
            if error.kind() != std::io::ErrorKind::AlreadyExists
                || Self::load_journal_at(&evidence)?.as_ref() != Some(journal)
            {
                return Err(SystemProxyError::RecoveryRequired(
                    "could not preserve proxy conflict evidence",
                ));
            }
        }
        self.remove_journal()
    }

    fn remove_journal(&self) -> Result<(), SystemProxyError> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SystemProxyError::RecoveryRequired(
                "could not remove proxy recovery journal",
            )),
        }
    }
}

impl SystemProxyControl for SystemProxyManager {
    fn publish_loopback(&self, http_port: u16) -> Result<(), SystemProxyError> {
        SystemProxyManager::publish_loopback(self, http_port)
    }

    fn is_owned(&self) -> Result<bool, SystemProxyError> {
        SystemProxyManager::is_owned(self)
    }

    fn restore_if_owned(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError> {
        SystemProxyManager::restore_if_owned(self)
    }

    fn reconcile_stale_journal(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError> {
        SystemProxyManager::reconcile_stale_journal(self)
    }

    fn diagnostics(&self) -> SystemProxyDiagnostics {
        SystemProxyManager::diagnostics(self)
    }

    fn clear_stale(&self, token: &str) -> Result<SystemProxyDiagnostics, SystemProxyError> {
        SystemProxyManager::clear_stale(self, token)
    }
}

fn sanitized_endpoint(observation: &CleanupObservation) -> Option<String> {
    observation
        .user_server
        .as_deref()
        .and_then(parse_single_loopback_proxy)
        .map(|endpoint| endpoint.0.to_string())
}

fn ownership_observation_matches(
    observation: &CleanupObservation,
    journal: &SystemProxyJournal,
) -> bool {
    observation.wininet == journal.applied
        && !observation.ras_active
        && matches!(observation.policy, None | Some(1))
        && observation.user_enabled == Some(1)
        && observation.user_server == journal.applied.proxy_server
        && observation.user_bypass == journal.applied.proxy_bypass
        && observation.user_auto_config_url == journal.applied.auto_config_url
}

fn classify_cleanup_observation(observation: &CleanupObservation) -> SystemProxyDiagnostics {
    let endpoint = sanitized_endpoint(observation);
    let conflict = || SystemProxyDiagnostics {
        state: SystemProxyDiagnosticState::Conflict,
        endpoint: endpoint.clone(),
        detail: "System Proxy configuration is ambiguous and was preserved",
        cleanup_token: None,
    };
    if observation.ras_active
        || !matches!(observation.policy, None | Some(1))
        || observation.wininet.flags == 0
        || observation.wininet.flags & !15 != 0
        || observation.wininet.flags & (4 | 8) != 0
        || observation.wininet.auto_config_url.is_some()
        || observation
            .user_auto_config_url
            .as_deref()
            .is_some_and(|url| !url.is_empty())
    {
        return conflict();
    }
    let wininet_manual_matches = observation.wininet.flags & PROXY_TYPE_PROXY_VALUE != 0
        && observation.wininet.proxy_server == observation.user_server;
    match observation.user_enabled {
        None | Some(0) if observation.wininet.flags == PROXY_TYPE_DIRECT_VALUE => {
            SystemProxyDiagnostics {
                state: SystemProxyDiagnosticState::Disabled,
                endpoint: None,
                detail: "System Proxy is disabled",
                cleanup_token: None,
            }
        }
        Some(1)
            if endpoint.is_some()
                && observation.wininet.flags & PROXY_TYPE_PROXY_VALUE == 0
                && !observation.listener_present =>
        {
            SystemProxyDiagnostics {
                state: SystemProxyDiagnosticState::Stale,
                endpoint,
                detail: "A stale loopback System Proxy has no local listener",
                cleanup_token: None,
            }
        }
        Some(1)
            if endpoint.is_some()
                && (observation.wininet.flags == PROXY_TYPE_DIRECT_VALUE
                    || wininet_manual_matches)
                && observation.listener_present =>
        {
            SystemProxyDiagnostics {
                state: SystemProxyDiagnosticState::ForeignActive,
                endpoint,
                detail: "A local listener exists on the configured System Proxy port",
                cleanup_token: None,
            }
        }
        Some(1)
            if endpoint.is_some() && wininet_manual_matches && !observation.listener_present =>
        {
            SystemProxyDiagnostics {
                state: SystemProxyDiagnosticState::Stale,
                endpoint,
                detail: "A stale loopback System Proxy has no local listener",
                cleanup_token: None,
            }
        }
        _ => conflict(),
    }
}
#[derive(Clone, Copy)]
pub(crate) struct LoopbackProxyEndpoint(SocketAddr);

impl LoopbackProxyEndpoint {
    fn new(value: SocketAddr) -> Option<Self> {
        (value.port() != 0 && value.ip().is_loopback()).then_some(Self(value))
    }

    pub(crate) fn http_url(self) -> String {
        format!("http://{}", self.0)
    }
}

pub(crate) trait SystemProxyProvider: Send + Sync {
    fn current_loopback_proxy(&self) -> Result<Option<LoopbackProxyEndpoint>, SystemProxyError>;
}

pub(crate) struct WindowsSystemProxyProvider;

impl SystemProxyProvider for WindowsSystemProxyProvider {
    fn current_loopback_proxy(&self) -> Result<Option<LoopbackProxyEndpoint>, SystemProxyError> {
        #[cfg(windows)]
        {
            if query_ras_active().map_err(|_| fetch_proxy_error())? {
                return Ok(None);
            }
            // Some VPN clients update the flat manual settings while WinInet's
            // per-connection flags remain stale. This read-only fetch path must
            // not change the ownership snapshots used by SystemProxyManager.
            match read_manual_fetch_proxy(&WindowsFetchProxyRegistry)? {
                ManualFetchProxy::Disabled => Ok(None),
                ManualFetchProxy::Enabled(endpoint) => Ok(Some(endpoint)),
                ManualFetchProxy::Absent => {
                    let state = query_wininet_state().map_err(|_| fetch_proxy_error())?;
                    Ok(select_loopback_proxy(state))
                }
            }
        }
        #[cfg(not(windows))]
        {
            Ok(None)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FetchProxyScope {
    User,
    Machine,
}

enum ManualFetchProxy {
    Absent,
    Disabled,
    Enabled(LoopbackProxyEndpoint),
}

trait FetchProxyRegistry {
    fn policy(&self) -> Result<Option<u32>, SystemProxyError>;
    fn enabled(&self, scope: FetchProxyScope) -> Result<Option<u32>, SystemProxyError>;
    fn server(&self, scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError>;
    fn bypass(&self, _scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
        Ok(None)
    }
    fn auto_config_url(&self, _scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
        Ok(None)
    }
}

fn fetch_proxy_error() -> SystemProxyError {
    SystemProxyError::RecoveryRequired("could not read the current manual proxy configuration")
}

fn validate_ownership_snapshot(
    snapshot: &SystemProxySnapshot,
    ras_active: bool,
    registry: &impl FetchProxyRegistry,
) -> Result<(), SystemProxyError> {
    let ambiguous = || {
        SystemProxyError::RecoveryRequired(
            "Windows proxy configuration is ambiguous; preserve it until the conflict is resolved",
        )
    };
    // LAN WinInet settings are not authoritative for active RAS connections
    // or machine-scoped proxy policy. Do not synthesize a replacement snapshot.
    if ras_active || snapshot.flags == 0 || snapshot.flags & !15 != 0 {
        return Err(ambiguous());
    }
    if !matches!(registry.policy()?, None | Some(1)) {
        return Err(ambiguous());
    }
    let wininet_enabled = snapshot.flags & PROXY_TYPE_PROXY_VALUE != 0;
    match registry.enabled(FetchProxyScope::User)? {
        None | Some(0) if !wininet_enabled => Ok(()),
        Some(1) if wininet_enabled => {
            let flat_server = registry.server(FetchProxyScope::User)?;
            if flat_server
                .as_deref()
                .is_some_and(|server| !server.is_empty())
                && flat_server == snapshot.proxy_server
            {
                Ok(())
            } else {
                Err(ambiguous())
            }
        }
        _ => Err(ambiguous()),
    }
}

fn read_manual_fetch_proxy(
    registry: &impl FetchProxyRegistry,
) -> Result<ManualFetchProxy, SystemProxyError> {
    let scope = match registry.policy()? {
        Some(0) => FetchProxyScope::Machine,
        None | Some(1) => FetchProxyScope::User,
        Some(_) => return Err(fetch_proxy_error()),
    };
    match registry.enabled(scope)? {
        // Explicitly disabled must not revive a stale WinInet proxy value.
        Some(0) => Ok(ManualFetchProxy::Disabled),
        Some(1) => {
            let server = registry.server(scope)?.ok_or_else(fetch_proxy_error)?;
            let endpoint = parse_proxy_server(&server).ok_or_else(fetch_proxy_error)?;
            Ok(ManualFetchProxy::Enabled(endpoint))
        }
        Some(_) => Err(fetch_proxy_error()),
        // A machine policy must never fall back to another user's settings.
        None if scope == FetchProxyScope::Machine => Ok(ManualFetchProxy::Disabled),
        None => Ok(ManualFetchProxy::Absent),
    }
}

#[cfg(windows)]
struct WindowsFetchProxyRegistry;

#[cfg(windows)]
impl FetchProxyRegistry for WindowsFetchProxyRegistry {
    fn policy(&self) -> Result<Option<u32>, SystemProxyError> {
        read_fetch_registry_dword(FetchProxyScope::Machine, true, "ProxySettingsPerUser")
    }

    fn enabled(&self, scope: FetchProxyScope) -> Result<Option<u32>, SystemProxyError> {
        read_fetch_registry_dword(scope, false, "ProxyEnable")
    }

    fn server(&self, scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
        use windows_sys::Win32::System::Registry::RRF_RT_REG_SZ;
        let Some(bytes) = read_fetch_registry(scope, false, "ProxyServer", RRF_RT_REG_SZ)? else {
            return Ok(None);
        };
        decode_fetch_proxy_string(&bytes).map(Some)
    }

    fn bypass(&self, scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
        read_fetch_registry_string(scope, "ProxyOverride")
    }

    fn auto_config_url(&self, scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
        read_fetch_registry_string(scope, "AutoConfigURL")
    }
}

#[cfg(windows)]
fn read_fetch_registry_string(
    scope: FetchProxyScope,
    name: &str,
) -> Result<Option<String>, SystemProxyError> {
    use windows_sys::Win32::System::Registry::RRF_RT_REG_SZ;
    read_fetch_registry(scope, false, name, RRF_RT_REG_SZ)?
        .map(|bytes| decode_fetch_proxy_string(&bytes))
        .transpose()
}

fn decode_fetch_proxy_string(bytes: &[u8]) -> Result<String, SystemProxyError> {
    if bytes.len() < 2
        || bytes.len() > (MAX_PROXY_CONFIG_CHARS + 1) * 2
        || !bytes.len().is_multiple_of(2)
    {
        return Err(fetch_proxy_error());
    }
    let mut wide = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    if wide.pop() != Some(0) || wide.contains(&0) {
        return Err(fetch_proxy_error());
    }
    String::from_utf16(&wide).map_err(|_| fetch_proxy_error())
}

#[cfg(windows)]
fn read_fetch_registry_dword(
    scope: FetchProxyScope,
    policy: bool,
    name: &str,
) -> Result<Option<u32>, SystemProxyError> {
    use windows_sys::Win32::System::Registry::RRF_RT_REG_DWORD;
    read_fetch_registry(scope, policy, name, RRF_RT_REG_DWORD)?
        .map(|bytes| {
            let bytes: [u8; 4] = bytes.try_into().map_err(|_| fetch_proxy_error())?;
            Ok(u32::from_le_bytes(bytes))
        })
        .transpose()
}

#[cfg(windows)]
fn read_fetch_registry(
    scope: FetchProxyScope,
    policy: bool,
    name: &str,
    flags: u32,
) -> Result<Option<Vec<u8>>, SystemProxyError> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::{RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
    };
    let root = match scope {
        FetchProxyScope::User => HKEY_CURRENT_USER,
        FetchProxyScope::Machine => HKEY_LOCAL_MACHINE,
    };
    let path = if policy {
        "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    } else {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    };
    let path = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut bytes = vec![0u8; (MAX_PROXY_CONFIG_CHARS + 1) * 2];
    let mut length = bytes.len() as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            flags,
            ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    match status {
        ERROR_SUCCESS if length as usize <= bytes.len() => {
            bytes.truncate(length as usize);
            Ok(Some(bytes))
        }
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        _ => Err(fetch_proxy_error()),
    }
}

struct RawSystemProxyState {
    flags: u32,
    proxy_server: Option<String>,
    ras_active: bool,
}

fn select_loopback_proxy(state: RawSystemProxyState) -> Option<LoopbackProxyEndpoint> {
    if state.ras_active {
        return None;
    }
    if state.flags & PROXY_TYPE_PROXY_VALUE == 0 {
        return None;
    }
    let proxy_server = state
        .proxy_server
        .as_deref()
        .filter(|value| !value.trim().is_empty())?;
    parse_proxy_server(proxy_server)
}

fn parse_proxy_server(value: &str) -> Option<LoopbackProxyEndpoint> {
    if value.len() > MAX_PROXY_CONFIG_CHARS
        || value.contains('@')
        || value.contains("\r")
        || value.contains("\n")
    {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.contains('=') || value.contains(';') {
        let mut https = None;
        for entry in value.split(';') {
            let (scheme, endpoint) = entry.split_once('=')?;
            if endpoint.contains('=') || scheme.trim().is_empty() || endpoint.trim().is_empty() {
                return None;
            }
            if scheme.trim().eq_ignore_ascii_case("https") {
                let endpoint = parse_loopback_endpoint(endpoint.trim())?;
                if https.replace(endpoint).is_some() {
                    return None;
                }
            }
        }
        https
    } else {
        parse_loopback_endpoint(value)
    }
}

fn parse_single_loopback_proxy(value: &str) -> Option<LoopbackProxyEndpoint> {
    let value = value.trim();
    if value.contains(['=', ';']) {
        return None;
    }
    parse_loopback_endpoint(value)
}

#[cfg(windows)]
fn loopback_listener_present(endpoint: SocketAddr) -> Result<bool, SystemProxyError> {
    use std::mem::size_of;
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID},
        Networking::WinSock::{AF_INET, AF_INET6},
    };
    for (family, row_size, port_offset) in [
        (
            AF_INET as u32,
            size_of::<MIB_TCPROW_OWNER_PID>(),
            size_of::<u32>() * 2,
        ),
        (
            AF_INET6 as u32,
            size_of::<MIB_TCP6ROW_OWNER_PID>(),
            size_of::<u32>() * 5,
        ),
    ] {
        let table = read_listener_table(family)?;
        if listener_table_contains_port(&table, row_size, port_offset, endpoint.port())
            .map_err(|_| fetch_proxy_error())?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn read_listener_table(family: u32) -> Result<Vec<u8>, SystemProxyError> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER},
    };
    let mut byte_count = 0u32;
    let initial = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut byte_count,
            0,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if initial != ERROR_INSUFFICIENT_BUFFER && initial != NO_ERROR {
        return Err(fetch_proxy_error());
    }
    if byte_count as usize > MAX_LISTENER_TABLE_BYTES {
        return Err(fetch_proxy_error());
    }
    let mut storage = vec![0u8; (byte_count as usize).max(size_of::<u32>())];
    let mut status = ERROR_INSUFFICIENT_BUFFER;
    for _ in 0..3 {
        status = unsafe {
            GetExtendedTcpTable(
                storage.as_mut_ptr().cast(),
                &mut byte_count,
                0,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status != ERROR_INSUFFICIENT_BUFFER {
            break;
        }
        if byte_count as usize > MAX_LISTENER_TABLE_BYTES {
            return Err(fetch_proxy_error());
        }
        storage.resize(byte_count as usize, 0);
    }
    if status != NO_ERROR {
        return Err(fetch_proxy_error());
    }
    if byte_count as usize > storage.len() || byte_count as usize > MAX_LISTENER_TABLE_BYTES {
        return Err(fetch_proxy_error());
    }
    storage.truncate(byte_count as usize);
    Ok(storage)
}

fn listener_table_contains_port(
    bytes: &[u8],
    row_size: usize,
    port_offset: usize,
    port: u16,
) -> Result<bool, ()> {
    const HEADER_BYTES: usize = 4;
    if bytes.len() < HEADER_BYTES || row_size < port_offset.saturating_add(4) {
        return Err(());
    }
    let count = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| ())?) as usize;
    let required = HEADER_BYTES
        .checked_add(count.checked_mul(row_size).ok_or(())?)
        .ok_or(())?;
    if required > bytes.len() || required > MAX_LISTENER_TABLE_BYTES {
        return Err(());
    }
    for row in bytes[4..required].chunks_exact(row_size) {
        let encoded = u32::from_ne_bytes(
            row[port_offset..port_offset + 4]
                .try_into()
                .map_err(|_| ())?,
        );
        if u16::from_be(encoded as u16) == port {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_loopback_endpoint(value: &str) -> Option<LoopbackProxyEndpoint> {
    let endpoint = SocketAddr::from_str(value).ok()?;
    LoopbackProxyEndpoint::new(endpoint)
}

#[cfg(windows)]
fn query_wininet_state() -> Result<RawSystemProxyState, ()> {
    let snapshot = query_wininet_snapshot().map_err(|_| ())?;
    Ok(RawSystemProxyState {
        flags: snapshot.flags,
        proxy_server: snapshot.proxy_server,
        ras_active: false,
    })
}

#[cfg(windows)]
fn query_wininet_snapshot() -> Result<SystemProxySnapshot, SystemProxyError> {
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_FLAGS_UI,
    };

    query_wininet_snapshot_with_flags(INTERNET_PER_CONN_FLAGS_UI)
        .or_else(|_| query_wininet_snapshot_with_flags(INTERNET_PER_CONN_FLAGS))
}

#[cfg(windows)]
fn query_wininet_snapshot_with_flags(
    flags_option: u32,
) -> Result<SystemProxySnapshot, SystemProxyError> {
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::GlobalFree,
        Networking::WinInet::{
            InternetQueryOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
            INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_OPTIONW,
            INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_PROXY_BYPASS,
            INTERNET_PER_CONN_PROXY_SERVER,
        },
    };

    let mut options = [
        INTERNET_PER_CONN_OPTIONW {
            dwOption: flags_option,
            ..Default::default()
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            ..Default::default()
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
            ..Default::default()
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            ..Default::default()
        },
    ];
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let mut list_size = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
    let ok = unsafe {
        InternetQueryOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast::<c_void>(),
            &mut list_size,
        )
    };

    struct ReturnedString(*mut u16);
    impl Drop for ReturnedString {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    GlobalFree(self.0.cast());
                }
            }
        }
    }
    let proxy_server = ReturnedString(unsafe { options[1].Value.pszValue });
    let proxy_bypass = ReturnedString(unsafe { options[2].Value.pszValue });
    let auto_config_url = ReturnedString(unsafe { options[3].Value.pszValue });
    if ok == 0 || list.dwOptionError != 0 {
        return Err(SystemProxyError::RecoveryRequired(
            "could not query Windows System Proxy settings",
        ));
    }
    let state = SystemProxySnapshot {
        flags: unsafe { options[0].Value.dwValue },
        proxy_server: read_bounded_wide(proxy_server.0).map_err(|_| {
            SystemProxyError::RecoveryRequired("Windows returned an invalid proxy server")
        })?,
        proxy_bypass: read_bounded_wide(proxy_bypass.0).map_err(|_| {
            SystemProxyError::RecoveryRequired("Windows returned an invalid proxy bypass list")
        })?,
        auto_config_url: read_bounded_wide(auto_config_url.0).map_err(|_| {
            SystemProxyError::RecoveryRequired("Windows returned an invalid automatic proxy URL")
        })?,
    };
    if !state.valid() {
        return Err(SystemProxyError::RecoveryRequired(
            "Windows returned invalid proxy settings",
        ));
    }
    Ok(state)
}

#[cfg(windows)]
#[allow(dead_code)]
fn set_wininet_snapshot(state: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
        INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_AUTOCONFIG_URL,
        INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER,
    };

    if !state.valid() {
        return Err(SystemProxyError::RecoveryRequired(
            "invalid System Proxy settings",
        ));
    }
    let mut proxy_server = wide_optional(state.proxy_server.as_deref());
    let mut proxy_bypass = wide_optional(state.proxy_bypass.as_deref());
    let mut auto_config_url = wide_optional(state.auto_config_url.as_deref());
    let mut options = [
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
                dwValue: state.flags,
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: optional_wide_pointer(&mut proxy_server),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
            Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: optional_wide_pointer(&mut proxy_bypass),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: optional_wide_pointer(&mut auto_config_url),
            },
        },
    ];
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let updated = unsafe {
        InternetSetOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast::<c_void>(),
            size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        )
    };
    if updated == 0 {
        return Err(SystemProxyError::RecoveryRequired(
            "Windows rejected the System Proxy settings",
        ));
    }
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        if unsafe { InternetSetOptionW(ptr::null(), option, ptr::null(), 0) } == 0 {
            return Err(SystemProxyError::RecoveryRequired(
                "Windows did not refresh the System Proxy settings",
            ));
        }
    }
    Ok(())
}

fn disabled_manual_flags(previous_flags: u32) -> u32 {
    (previous_flags & !PROXY_TYPE_PROXY_VALUE) | PROXY_TYPE_DIRECT_VALUE
}

#[cfg(windows)]
fn disable_user_manual_proxy(previous_flags: u32) -> Result<(), SystemProxyError> {
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
            INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW,
            INTERNET_PER_CONN_OPTION_LISTW,
        },
        System::Registry::{RegSetKeyValueW, HKEY_CURRENT_USER, REG_DWORD},
    };
    let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let name = "ProxyEnable"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let disabled = 0u32;
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            name.as_ptr(),
            REG_DWORD,
            (&disabled as *const u32).cast(),
            size_of::<u32>() as u32,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(SystemProxyError::RecoveryRequired(
            "Windows rejected the manual proxy setting",
        ));
    }
    let mut option = INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
            dwValue: disabled_manual_flags(previous_flags),
        },
    };
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: ptr::null_mut(),
        dwOptionCount: 1,
        dwOptionError: 0,
        pOptions: &mut option,
    };
    if unsafe {
        InternetSetOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast::<c_void>(),
            size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        )
    } == 0
    {
        return Err(SystemProxyError::RecoveryRequired(
            "Windows rejected the WinInet manual proxy flag",
        ));
    }
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        if unsafe { InternetSetOptionW(ptr::null(), option, ptr::null(), 0) } == 0 {
            return Err(SystemProxyError::RecoveryRequired(
                "Windows did not refresh the System Proxy settings",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(dead_code)]
fn wide_optional(value: Option<&str>) -> Option<Vec<u16>> {
    value.map(|value| value.encode_utf16().chain(std::iter::once(0)).collect())
}

#[cfg(windows)]
#[allow(dead_code)]
fn optional_wide_pointer(value: &mut Option<Vec<u16>>) -> *mut u16 {
    value
        .as_mut()
        .map_or(std::ptr::null_mut(), |value| value.as_mut_ptr())
}

#[cfg(windows)]
fn read_bounded_wide(value: *const u16) -> Result<Option<String>, ()> {
    if value.is_null() {
        return Ok(None);
    }
    let mut length = 0;
    while length <= MAX_PROXY_CONFIG_CHARS {
        if unsafe { *value.add(length) } == 0 {
            let slice = unsafe { std::slice::from_raw_parts(value, length) };
            return String::from_utf16(slice).map(Some).map_err(|_| ());
        }
        length += 1;
    }
    Err(())
}

#[cfg(windows)]
fn query_ras_active() -> Result<bool, ()> {
    use std::mem::size_of;
    use windows_sys::Win32::NetworkManagement::Rras::{
        RasEnumConnectionsW, ERROR_BUFFER_TOO_SMALL, RASCONNW,
    };

    let mut connection = RASCONNW {
        dwSize: size_of::<RASCONNW>() as u32,
        ..Default::default()
    };
    let mut buffer_size = size_of::<RASCONNW>() as u32;
    let mut count = 0;
    let status = unsafe { RasEnumConnectionsW(&mut connection, &mut buffer_size, &mut count) };
    match status {
        0 => Ok(count != 0),
        ERROR_BUFFER_TOO_SMALL => Ok(true),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    use super::*;

    struct FakeBackend {
        current: Mutex<SystemProxySnapshot>,
    }

    impl FakeBackend {
        fn new(current: SystemProxySnapshot) -> Self {
            Self {
                current: Mutex::new(current),
            }
        }

        fn replace_foreign(&self, state: SystemProxySnapshot) {
            *self.current.lock().unwrap() = state;
        }
    }

    impl SystemProxyBackend for FakeBackend {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            Ok(self.current.lock().unwrap().clone())
        }

        fn apply(&self, state: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            *self.current.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    struct DiagnosticBackend {
        observation: Mutex<CleanupObservation>,
        applies: AtomicUsize,
        unavailable: AtomicBool,
    }

    impl DiagnosticBackend {
        fn stale() -> Self {
            Self {
                observation: Mutex::new(CleanupObservation {
                    wininet: direct_snapshot(),
                    policy: None,
                    user_enabled: Some(1),
                    user_server: Some("127.0.0.1:10808".into()),
                    user_bypass: Some("<local>".into()),
                    user_auto_config_url: None,
                    ras_active: false,
                    listener_present: false,
                }),
                applies: AtomicUsize::new(0),
                unavailable: AtomicBool::new(false),
            }
        }
    }

    impl SystemProxyBackend for DiagnosticBackend {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            Ok(self.observation.lock().unwrap().wininet.clone())
        }
        fn apply(&self, state: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            let mut observation = self.observation.lock().unwrap();
            observation.wininet = state.clone();
            observation.user_enabled = Some(0);
            observation.user_server = None;
            Ok(())
        }
        fn cleanup_observation(&self) -> Result<CleanupObservation, SystemProxyError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(SystemProxyError::Unchanged("fixture unavailable"));
            }
            Ok(self.observation.lock().unwrap().clone())
        }
        fn clear_manual_if_exact(
            &self,
            expected: &CleanupObservation,
        ) -> Result<(), SystemProxyError> {
            let mut observation = self.observation.lock().unwrap();
            if *observation != *expected {
                return Err(SystemProxyError::Unchanged("fixture changed"));
            }
            self.applies.fetch_add(1, Ordering::SeqCst);
            observation.wininet.flags = disabled_manual_flags(observation.wininet.flags);
            observation.user_enabled = Some(0);
            Ok(())
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "routedeck-system-proxy-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join(JOURNAL_FILE_NAME)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn direct_snapshot() -> SystemProxySnapshot {
        SystemProxySnapshot {
            flags: PROXY_TYPE_DIRECT_VALUE,
            proxy_server: None,
            proxy_bypass: None,
            auto_config_url: None,
        }
    }

    fn state(flags: u32, proxy_server: Option<&str>) -> RawSystemProxyState {
        RawSystemProxyState {
            flags,
            proxy_server: proxy_server.map(str::to_owned),
            ras_active: false,
        }
    }

    struct FakeFetchRegistry {
        policy: Result<Option<u32>, SystemProxyError>,
        user_enabled: Option<u32>,
        machine_enabled: Option<u32>,
        server: Option<String>,
        expected_scope: FetchProxyScope,
    }

    impl FetchProxyRegistry for FakeFetchRegistry {
        fn policy(&self) -> Result<Option<u32>, SystemProxyError> {
            self.policy.clone()
        }
        fn enabled(&self, scope: FetchProxyScope) -> Result<Option<u32>, SystemProxyError> {
            assert!(scope == self.expected_scope);
            Ok(match scope {
                FetchProxyScope::User => self.user_enabled,
                FetchProxyScope::Machine => self.machine_enabled,
            })
        }
        fn server(&self, scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
            assert!(scope == self.expected_scope);
            Ok(self.server.clone())
        }
    }

    fn fetch_registry(enabled: Option<u32>, server: Option<&str>) -> FakeFetchRegistry {
        FakeFetchRegistry {
            policy: Ok(None),
            user_enabled: enabled,
            machine_enabled: None,
            server: server.map(str::to_owned),
            expected_scope: FetchProxyScope::User,
        }
    }

    #[test]
    fn ownership_snapshot_rejects_stale_wininet_manual_flags() {
        let mut snapshot = direct_snapshot();
        snapshot.proxy_server = Some("127.0.0.1:10808".into());
        let enabled = fetch_registry(Some(1), Some("127.0.0.1:10808"));
        assert!(validate_ownership_snapshot(&snapshot, false, &enabled).is_err());

        snapshot.flags |= PROXY_TYPE_PROXY_VALUE;
        assert!(validate_ownership_snapshot(&snapshot, false, &enabled).is_ok());
        for disabled in [None, Some(0), Some(2), Some(u32::MAX)] {
            let registry = fetch_registry(disabled, Some("127.0.0.1:10808"));
            assert!(validate_ownership_snapshot(&snapshot, false, &registry).is_err());
        }
    }

    #[test]
    fn ownership_snapshot_requires_exact_enabled_server_agreement() {
        let mut snapshot = direct_snapshot();
        snapshot.flags |= PROXY_TYPE_PROXY_VALUE;
        snapshot.proxy_server = Some("127.0.0.1:10808".into());
        for server in [
            None,
            Some(""),
            Some("127.0.0.1:19090"),
            Some("localhost:10808"),
        ] {
            assert!(validate_ownership_snapshot(
                &snapshot,
                false,
                &fetch_registry(Some(1), server)
            )
            .is_err());
        }
    }

    #[test]
    fn ownership_snapshot_retains_disabled_saved_values_without_synthesizing() {
        let mut snapshot = direct_snapshot();
        snapshot.proxy_server = Some("old-disabled-proxy.test:8080".into());
        snapshot.auto_config_url = Some("https://disabled-pac.test/config.pac".into());
        let before = snapshot.clone();
        for enabled in [None, Some(0)] {
            let registry = fetch_registry(enabled, Some("different-disabled-proxy.test:9090"));
            assert!(validate_ownership_snapshot(&snapshot, false, &registry).is_ok());
            assert_eq!(snapshot, before);
        }
        for invalid in [Some(2), Some(u32::MAX)] {
            assert!(
                validate_ownership_snapshot(&snapshot, false, &fetch_registry(invalid, None))
                    .is_err()
            );
        }
    }

    #[test]
    fn ownership_snapshot_rejects_ras_machine_policy_and_unknown_flags() {
        let snapshot = direct_snapshot();
        let mut registry = fetch_registry(Some(0), None);
        assert!(validate_ownership_snapshot(&snapshot, true, &registry).is_err());
        for policy in [Some(0), Some(2), Some(u32::MAX)] {
            registry.policy = Ok(policy);
            assert!(validate_ownership_snapshot(&snapshot, false, &registry).is_err());
        }
        registry.policy = Ok(Some(1));
        assert!(validate_ownership_snapshot(&snapshot, false, &registry).is_ok());
        for flags in [0, 16, u32::MAX] {
            let mut invalid = snapshot.clone();
            invalid.flags = flags;
            assert!(validate_ownership_snapshot(&invalid, false, &registry).is_err());
        }
    }

    #[test]
    fn ownership_snapshot_propagates_every_registry_read_failure() {
        struct FailingRegistry(u8);
        impl FetchProxyRegistry for FailingRegistry {
            fn policy(&self) -> Result<Option<u32>, SystemProxyError> {
                if self.0 == 0 {
                    Err(fetch_proxy_error())
                } else {
                    Ok(None)
                }
            }
            fn enabled(&self, _scope: FetchProxyScope) -> Result<Option<u32>, SystemProxyError> {
                if self.0 == 1 {
                    Err(fetch_proxy_error())
                } else {
                    Ok(Some(1))
                }
            }
            fn server(&self, _scope: FetchProxyScope) -> Result<Option<String>, SystemProxyError> {
                Err(fetch_proxy_error())
            }
        }
        let mut snapshot = direct_snapshot();
        snapshot.flags |= PROXY_TYPE_PROXY_VALUE;
        snapshot.proxy_server = Some("127.0.0.1:10808".into());
        for stage in 0..3 {
            assert!(
                validate_ownership_snapshot(&snapshot, false, &FailingRegistry(stage)).is_err()
            );
        }
    }

    #[test]
    fn fetch_manual_setting_is_authoritative_even_when_wininet_flags_are_stale() {
        let enabled = fetch_registry(Some(1), Some("127.0.0.1:10808"));
        // DIRECT-only WinInet flags are irrelevant when flat settings exist.
        let stale = state(PROXY_TYPE_DIRECT_VALUE, Some("127.0.0.1:10808"));
        assert!(select_loopback_proxy(stale).is_none());
        let ManualFetchProxy::Enabled(endpoint) = read_manual_fetch_proxy(&enabled).unwrap() else {
            panic!("manual proxy was not selected");
        };
        assert_eq!(endpoint.http_url(), "http://127.0.0.1:10808");

        let disabled = fetch_registry(Some(0), Some("127.0.0.1:10808"));
        assert!(matches!(
            read_manual_fetch_proxy(&disabled).unwrap(),
            ManualFetchProxy::Disabled
        ));
        let stale = state(PROXY_TYPE_PROXY_VALUE, Some("127.0.0.1:10808"));
        assert!(select_loopback_proxy(stale).is_some());
    }

    #[test]
    fn fetch_machine_policy_never_uses_user_manual_settings() {
        let mut registry = fetch_registry(Some(1), Some("127.0.0.1:10808"));
        registry.policy = Ok(Some(0));
        registry.expected_scope = FetchProxyScope::Machine;
        for machine_enabled in [None, Some(0)] {
            registry.machine_enabled = machine_enabled;
            assert!(matches!(
                read_manual_fetch_proxy(&registry).unwrap(),
                ManualFetchProxy::Disabled
            ));
        }
        registry.user_enabled = Some(0);
        registry.machine_enabled = Some(1);
        assert!(matches!(
            read_manual_fetch_proxy(&registry).unwrap(),
            ManualFetchProxy::Enabled(_)
        ));
        registry.policy = Ok(Some(1));
        registry.expected_scope = FetchProxyScope::User;
        assert!(matches!(
            read_manual_fetch_proxy(&registry).unwrap(),
            ManualFetchProxy::Disabled
        ));
    }

    #[test]
    fn fetch_missing_disabled_and_invalid_settings_remain_distinct() {
        assert!(matches!(
            read_manual_fetch_proxy(&fetch_registry(None, None)).unwrap(),
            ManualFetchProxy::Absent
        ));
        assert!(matches!(
            read_manual_fetch_proxy(&fetch_registry(Some(0), None)).unwrap(),
            ManualFetchProxy::Disabled
        ));
        for server in [
            None,
            Some(""),
            Some("8.8.8.8:8080"),
            Some("user:token@127.0.0.1:8080"),
            Some("127.0.0.1:0"),
            Some("127.0.0.1:8080\r\n"),
        ] {
            assert!(read_manual_fetch_proxy(&fetch_registry(Some(1), server)).is_err());
        }
        assert!(read_manual_fetch_proxy(&fetch_registry(Some(7), Some("127.0.0.1:8080"))).is_err());
        let mut registry = fetch_registry(Some(1), Some("127.0.0.1:8080"));
        registry.policy = Err(fetch_proxy_error());
        assert!(read_manual_fetch_proxy(&registry).is_err());
        registry.policy = Ok(Some(7));
        assert!(read_manual_fetch_proxy(&registry).is_err());
        registry.policy = Ok(None);
        registry.server = Some("x".repeat(MAX_PROXY_CONFIG_CHARS + 1));
        assert!(read_manual_fetch_proxy(&registry).is_err());
    }

    #[test]
    fn fetch_registry_string_decoding_is_bounded_and_strict() {
        let encode = |value: &str| {
            value
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            decode_fetch_proxy_string(&encode("127.0.0.1:8080")).unwrap(),
            "127.0.0.1:8080"
        );
        for bytes in [
            vec![],
            vec![0],
            vec![1, 0],
            vec![0, 0, 0, 0],
            vec![0, 0xd8, 0, 0],
            vec![0; (MAX_PROXY_CONFIG_CHARS + 2) * 2],
        ] {
            assert!(decode_fetch_proxy_string(&bytes).is_err());
        }
    }

    #[test]
    fn accepts_only_numeric_loopback_static_http_proxy_shapes() {
        for value in [
            "127.0.0.1:7890",
            "127.24.1.9:10809",
            "[::1]:7890",
            "http=127.0.0.1:10809;https=[::1]:10810",
            "http=127.0.0.1:10809;https=127.0.0.1:10810;socks=127.0.0.1:10808",
        ] {
            assert!(select_loopback_proxy(state(
                PROXY_TYPE_DIRECT_VALUE | PROXY_TYPE_PROXY_VALUE,
                Some(value),
            ))
            .is_some());
        }
    }

    #[test]
    fn rejects_non_loopback_credentials_protocol_lists_and_ambiguity() {
        for value in [
            "localhost:7890",
            "192.168.1.1:7890",
            "8.8.8.8:7890",
            "user:secret@127.0.0.1:7890",
            "http://127.0.0.1:7890",
            "127.0.0.1:0",
            "http=127.0.0.1:10809",
            "http=127.0.0.1:1;",
            "https=127.0.0.1:1;https=127.0.0.1:2",
        ] {
            assert!(select_loopback_proxy(state(PROXY_TYPE_PROXY_VALUE, Some(value))).is_none());
        }
    }

    #[test]
    fn active_ras_skips_static_lan_proxy() {
        let mut ras = state(PROXY_TYPE_PROXY_VALUE, Some("127.0.0.1:7890"));
        ras.ras_active = true;
        assert!(select_loopback_proxy(ras).is_none());
    }

    #[test]
    fn disabled_or_empty_static_proxy_selects_direct() {
        assert!(select_loopback_proxy(state(PROXY_TYPE_DIRECT_VALUE, None)).is_none());
        assert!(select_loopback_proxy(state(PROXY_TYPE_PROXY_VALUE, Some("  "))).is_none());
    }

    #[test]
    fn detects_direct_wininet_and_stale_legacy_loopback_mismatch() {
        let observation = DiagnosticBackend::stale().cleanup_observation().unwrap();
        let diagnostics = classify_cleanup_observation(&observation);
        assert_eq!(diagnostics.state, SystemProxyDiagnosticState::Stale);
        assert_eq!(diagnostics.endpoint.as_deref(), Some("127.0.0.1:10808"));
        assert!(diagnostics.cleanup_token.is_none());
    }

    #[test]
    fn cleanup_requires_exact_one_use_preview_and_writes_evidence_first() {
        let root = TestRoot::new();
        let backend = Arc::new(DiagnosticBackend::stale());
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        let preview = manager.diagnostics();
        let token = preview.cleanup_token.unwrap();
        assert_eq!(
            manager.clear_stale(&token).unwrap().state,
            SystemProxyDiagnosticState::Disabled
        );
        assert_eq!(backend.applies.load(Ordering::SeqCst), 1);
        let after = backend.cleanup_observation().unwrap();
        assert_eq!(after.user_server.as_deref(), Some("127.0.0.1:10808"));
        assert_eq!(after.user_bypass.as_deref(), Some("<local>"));
        assert_eq!(after.user_auto_config_url, None);
        assert!(fs::read_dir(&root.0).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("system-proxy-cleanup-")));
        assert!(manager.clear_stale(&token).is_err());
        assert_eq!(backend.applies.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn manual_only_and_combined_flags_both_cleanup_to_direct() {
        for flags in [2, 3] {
            let root = TestRoot::new();
            let backend = Arc::new(DiagnosticBackend::stale());
            {
                let mut observation = backend.observation.lock().unwrap();
                observation.wininet.flags = flags;
                observation.wininet.proxy_server = observation.user_server.clone();
            }
            let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
            let token = manager.diagnostics().cleanup_token.unwrap();
            assert_eq!(
                manager.clear_stale(&token).unwrap().state,
                SystemProxyDiagnosticState::Disabled
            );
            let after = backend.cleanup_observation().unwrap();
            assert_eq!(after.wininet.flags, 1);
            assert_eq!(after.user_enabled, Some(0));
            assert_eq!(after.user_server.as_deref(), Some("127.0.0.1:10808"));
        }
    }

    #[test]
    fn cleanup_revalidation_preserves_changed_or_live_foreign_proxy() {
        let root = TestRoot::new();
        let backend = Arc::new(DiagnosticBackend::stale());
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        let token = manager.diagnostics().cleanup_token.unwrap();
        backend.observation.lock().unwrap().listener_present = true;
        assert!(manager.clear_stale(&token).is_err());
        assert_eq!(backend.applies.load(Ordering::SeqCst), 0);
        assert!(fs::read_dir(&root.0).unwrap().next().is_none());
    }

    #[test]
    fn every_diagnostic_attempt_invalidates_the_previous_cleanup_token() {
        let root = TestRoot::new();
        let backend = Arc::new(DiagnosticBackend::stale());
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        let token = manager.diagnostics().cleanup_token.unwrap();
        backend.unavailable.store(true, Ordering::SeqCst);
        assert_eq!(
            manager.diagnostics().state,
            SystemProxyDiagnosticState::Unavailable
        );
        backend.unavailable.store(false, Ordering::SeqCst);
        assert!(manager.clear_stale(&token).is_err());
        assert_eq!(backend.applies.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn listener_table_parser_accepts_both_layouts_and_rejects_malformed_bounds() {
        fn table(row_size: usize, port_offset: usize, port: u16) -> Vec<u8> {
            let mut bytes = vec![0u8; 4 + row_size];
            bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
            let encoded = u32::from(port.to_be());
            bytes[4 + port_offset..4 + port_offset + 4].copy_from_slice(&encoded.to_ne_bytes());
            bytes
        }
        // Zeroed address fields model wildcard listeners. Only the bounded
        // local-port field is relevant to this deliberately conservative check.
        let ipv4 = table(24, 8, 10808);
        let ipv6 = table(56, 20, 10809);
        assert_eq!(listener_table_contains_port(&ipv4, 24, 8, 10808), Ok(true));
        assert_eq!(listener_table_contains_port(&ipv4, 24, 8, 10809), Ok(false));
        assert_eq!(listener_table_contains_port(&ipv6, 56, 20, 10809), Ok(true));
        assert!(listener_table_contains_port(&[], 24, 8, 1).is_err());
        assert!(listener_table_contains_port(&[0; 4], 4, 8, 1).is_err());
        let mut truncated = ipv4.clone();
        truncated[..4].copy_from_slice(&2u32.to_ne_bytes());
        assert!(listener_table_contains_port(&truncated, 24, 8, 10808).is_err());
        let mut huge = vec![0u8; 4];
        huge[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(listener_table_contains_port(&huge, usize::MAX, 0, 1).is_err());
    }

    #[test]
    fn policies_pac_ras_and_non_loopback_settings_never_offer_cleanup() {
        let mut observation = DiagnosticBackend::stale().cleanup_observation().unwrap();
        for mutate in 0..5 {
            let mut candidate = observation.clone();
            match mutate {
                0 => candidate.policy = Some(0),
                1 => candidate.wininet.flags |= 4,
                2 => candidate.ras_active = true,
                3 => candidate.user_server = Some("192.0.2.1:8080".into()),
                _ => {
                    candidate.user_auto_config_url = Some("https://proxy.invalid/config.pac".into())
                }
            }
            let diagnostics = classify_cleanup_observation(&candidate);
            assert_eq!(diagnostics.state, SystemProxyDiagnosticState::Conflict);
            assert!(diagnostics.cleanup_token.is_none());
        }
        observation.listener_present = true;
        assert_eq!(
            classify_cleanup_observation(&observation).state,
            SystemProxyDiagnosticState::ForeignActive
        );
    }

    #[test]
    fn ownership_requires_journal_and_exact_legacy_registry_agreement() {
        let owner_id = "0123456789abcdef0123456789abcdef";
        let applied = SystemProxySnapshot::routedeck(10808, owner_id).unwrap();
        let journal = SystemProxyJournal {
            version: JOURNAL_VERSION,
            owner_id: owner_id.into(),
            previous: direct_snapshot(),
            applied: applied.clone(),
        };
        let mut observation = CleanupObservation {
            wininet: applied.clone(),
            policy: None,
            user_enabled: Some(1),
            user_server: applied.proxy_server.clone(),
            user_bypass: applied.proxy_bypass.clone(),
            user_auto_config_url: None,
            ras_active: false,
            listener_present: true,
        };
        assert!(ownership_observation_matches(&observation, &journal));
        observation.user_bypass = Some("<local>".into());
        assert!(!ownership_observation_matches(&observation, &journal));
        observation.user_bypass = applied.proxy_bypass;
        observation.user_enabled = Some(0);
        assert!(!ownership_observation_matches(&observation, &journal));
    }

    #[test]
    fn publishes_and_restores_exact_previous_state_without_touching_windows() {
        let root = TestRoot::new();
        let previous = SystemProxySnapshot {
            // Disabled settings must still be restored byte-for-byte.
            flags: PROXY_TYPE_DIRECT_VALUE,
            proxy_server: None,
            proxy_bypass: Some("<local>".into()),
            auto_config_url: Some("https://proxy.test/config.pac".into()),
        };
        let backend = Arc::new(FakeBackend::new(previous.clone()));
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());

        manager.publish_loopback(18443).unwrap();
        assert!(manager.is_owned().unwrap());
        assert!(root.journal().is_file());
        let published = backend.snapshot().unwrap();
        assert_eq!(published.proxy_server.as_deref(), Some("127.0.0.1:18443"));
        assert_eq!(published.auto_config_url, None);

        assert_eq!(
            manager.restore_if_owned().unwrap(),
            SystemProxyRestoreOutcome::Restored
        );
        assert_eq!(backend.snapshot().unwrap(), previous);
        assert!(!root.journal().exists());
    }

    #[test]
    fn preserves_foreign_change_and_relinquishes_stale_ownership() {
        let root = TestRoot::new();
        let backend = Arc::new(FakeBackend::new(direct_snapshot()));
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        manager.publish_loopback(18080).unwrap();
        let foreign = SystemProxySnapshot {
            flags: PROXY_TYPE_DIRECT_VALUE | PROXY_TYPE_PROXY_VALUE,
            proxy_server: Some("127.0.0.1:19090".into()),
            proxy_bypass: Some("<local>".into()),
            auto_config_url: None,
        };
        backend.replace_foreign(foreign.clone());

        assert!(!manager.is_owned().unwrap());
        assert_eq!(
            manager.restore_if_owned().unwrap(),
            SystemProxyRestoreOutcome::ForeignPreserved
        );
        assert_eq!(backend.snapshot().unwrap(), foreign);
        assert!(!root.journal().exists());
        let evidence: Vec<_> = fs::read_dir(&root.0).unwrap().collect();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0]
            .as_ref()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".conflict.json"));
    }

    #[test]
    fn stale_journal_recovery_uses_the_same_compare_before_restore_rule() {
        let root = TestRoot::new();
        let backend = Arc::new(FakeBackend::new(direct_snapshot()));
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        manager.publish_loopback(18081).unwrap();

        let restarted = SystemProxyManager::with_backend(root.journal(), backend.clone());
        assert_eq!(
            restarted.reconcile_stale_journal().unwrap(),
            SystemProxyRestoreOutcome::Restored
        );
        assert_eq!(backend.snapshot().unwrap(), direct_snapshot());
    }

    #[derive(Clone, Copy)]
    enum PublishInterference {
        BeforeApply,
        AfterApply,
        FailedApply,
        FailedWithoutChange,
    }

    struct InterferingBackend {
        current: Mutex<SystemProxySnapshot>,
        foreign: SystemProxySnapshot,
        snapshots: AtomicUsize,
        writes: AtomicUsize,
        interference: PublishInterference,
    }

    impl InterferingBackend {
        fn new(interference: PublishInterference) -> Self {
            Self {
                current: Mutex::new(direct_snapshot()),
                foreign: SystemProxySnapshot {
                    flags: PROXY_TYPE_DIRECT_VALUE | PROXY_TYPE_PROXY_VALUE,
                    proxy_server: Some("127.0.0.1:19090".into()),
                    proxy_bypass: None,
                    auto_config_url: None,
                },
                snapshots: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                interference,
            }
        }
    }

    impl SystemProxyBackend for InterferingBackend {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            if self.snapshots.fetch_add(1, Ordering::SeqCst) == 1
                && matches!(self.interference, PublishInterference::BeforeApply)
            {
                *self.current.lock().unwrap() = self.foreign.clone();
            }
            Ok(self.current.lock().unwrap().clone())
        }

        fn apply(&self, _state: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if !matches!(self.interference, PublishInterference::FailedWithoutChange) {
                // A foreign VPN wins immediately after the attempted write.
                *self.current.lock().unwrap() = self.foreign.clone();
            }
            if matches!(
                self.interference,
                PublishInterference::FailedApply | PublishInterference::FailedWithoutChange
            ) {
                Err(SystemProxyError::fixed("fixture apply failed"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn failed_publication_never_rolls_back_over_a_foreign_vpn() {
        for interference in [
            PublishInterference::BeforeApply,
            PublishInterference::AfterApply,
            PublishInterference::FailedApply,
        ] {
            let root = TestRoot::new();
            let backend = Arc::new(InterferingBackend::new(interference));
            let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
            assert!(manager
                .publish_loopback(18080)
                .unwrap_err()
                .may_have_changed());
            assert!(root.journal().exists());
            let writes = usize::from(!matches!(interference, PublishInterference::BeforeApply));
            assert_eq!(backend.writes.load(Ordering::SeqCst), writes);
            assert_eq!(
                manager.restore_if_owned().unwrap(),
                SystemProxyRestoreOutcome::ForeignPreserved
            );
            assert_eq!(backend.snapshot().unwrap(), backend.foreign);
            assert_eq!(backend.writes.load(Ordering::SeqCst), writes);
            assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
        }
    }

    #[test]
    fn failed_apply_without_change_restores_without_another_windows_write() {
        let root = TestRoot::new();
        let backend = Arc::new(InterferingBackend::new(
            PublishInterference::FailedWithoutChange,
        ));
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        assert!(manager.publish_loopback(18080).is_err());
        assert_eq!(
            manager.restore_if_owned().unwrap(),
            SystemProxyRestoreOutcome::Restored
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
        assert!(!root.journal().exists());
    }

    #[test]
    fn enabled_manual_pac_auto_detect_and_unknown_proxy_flags_block_takeover() {
        for flags in [0, 2, 3, 5, 9, 17, u32::MAX] {
            let root = TestRoot::new();
            let mut foreign = direct_snapshot();
            foreign.flags = flags;
            let backend = Arc::new(FakeBackend::new(foreign.clone()));
            let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
            let error = manager.publish_loopback(18080).unwrap_err();
            assert!(!error.may_have_changed());
            assert_eq!(backend.snapshot().unwrap(), foreign);
            assert!(!root.journal().exists());
        }
    }

    #[test]
    fn owner_marker_distinguishes_reused_loopback_ports() {
        let root = TestRoot::new();
        let backend = Arc::new(FakeBackend::new(direct_snapshot()));
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        manager.publish_loopback(18080).unwrap();
        let first = backend.snapshot().unwrap();
        manager.restore_if_owned().unwrap();
        manager.publish_loopback(18080).unwrap();
        let second = backend.snapshot().unwrap();
        assert_ne!(first.proxy_bypass, second.proxy_bypass);
        backend.replace_foreign(first);
        assert!(!manager.is_owned().unwrap());
        assert_eq!(
            manager.restore_if_owned().unwrap(),
            SystemProxyRestoreOutcome::ForeignPreserved
        );
    }

    #[test]
    fn legacy_malformed_and_forged_journals_fail_closed() {
        let root = TestRoot::new();
        let backend = Arc::new(FakeBackend::new(direct_snapshot()));
        let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
        manager.publish_loopback(18080).unwrap();
        let valid = fs::read(root.journal()).unwrap();
        let published = backend.snapshot().unwrap();
        for tampering in 0..5 {
            let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            match tampering {
                0 => {
                    value["version"] = 1.into();
                    value.as_object_mut().unwrap().remove("ownerId");
                }
                1 => value["ownerId"] = "../../foreign".into(),
                2 => value["applied"]["proxyServer"] = "127.0.0.1:018080".into(),
                3 => value["applied"]["proxyBypass"] = "<local>".into(),
                _ => value["applied"]["flags"] = 1.into(),
            }
            let forged = serde_json::to_vec(&value).unwrap();
            fs::write(root.journal(), &forged).unwrap();
            assert!(manager.reconcile_stale_journal().is_err());
            assert_eq!(backend.snapshot().unwrap(), published);
            assert_eq!(fs::read(root.journal()).unwrap(), forged);
        }
        fs::write(root.journal(), vec![b' '; MAX_JOURNAL_BYTES + 1]).unwrap();
        assert!(manager.reconcile_stale_journal().is_err());
        assert_eq!(backend.snapshot().unwrap(), published);
    }

    #[test]
    fn exclusive_journal_creation_never_replaces_existing_evidence() {
        let root = TestRoot::new();
        let backend = Arc::new(FakeBackend::new(direct_snapshot()));
        let manager = SystemProxyManager::with_backend(root.journal(), backend);
        manager.publish_loopback(18080).unwrap();
        let before = fs::read(root.journal()).unwrap();
        let journal = manager.load_journal().unwrap().unwrap();
        assert!(manager.write_journal(&journal).is_err());
        assert_eq!(fs::read(root.journal()).unwrap(), before);
    }

    #[test]
    fn conflict_archive_retry_preserves_existing_evidence() {
        for matching in [true, false] {
            let root = TestRoot::new();
            let backend = Arc::new(FakeBackend::new(direct_snapshot()));
            let manager = SystemProxyManager::with_backend(root.journal(), backend.clone());
            manager.publish_loopback(18080).unwrap();
            let journal = manager.load_journal().unwrap().unwrap();
            let archive = root
                .journal()
                .with_extension(format!("{}.conflict.json", journal.owner_id));
            let evidence = if matching {
                fs::read(root.journal()).unwrap()
            } else {
                b"unrelated preserved evidence".to_vec()
            };
            fs::write(&archive, &evidence).unwrap();
            let mut foreign = direct_snapshot();
            foreign.flags = 9;
            backend.replace_foreign(foreign.clone());
            let result = manager.restore_if_owned();
            if matching {
                assert_eq!(result.unwrap(), SystemProxyRestoreOutcome::ForeignPreserved);
            } else {
                assert!(result.is_err());
                assert!(root.journal().exists());
            }
            assert_eq!(backend.snapshot().unwrap(), foreign);
            assert_eq!(fs::read(archive).unwrap(), evidence);
        }
    }
}
