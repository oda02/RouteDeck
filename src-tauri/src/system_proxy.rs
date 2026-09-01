use std::{fmt, fs, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use serde::{Deserialize, Serialize};

const MAX_PROXY_CONFIG_CHARS: usize = 4 * 1024;
#[allow(dead_code)] // Wired into the application controller by the next backend milestone.
const MAX_JOURNAL_BYTES: usize = 16 * 1024;
#[allow(dead_code)]
const JOURNAL_VERSION: u8 = 1;
#[allow(dead_code)]
const JOURNAL_FILE_NAME: &str = "system-proxy-session.json";
#[allow(dead_code)]
const ROUTEDECK_PROXY_BYPASS: &str = "localhost;127.*;[::1];<local>";
#[allow(dead_code)]
const PROXY_TYPE_DIRECT_VALUE: u32 = 1;
const PROXY_TYPE_PROXY_VALUE: u32 = 2;

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
    fn routedeck(http_port: u16) -> Result<Self, SystemProxyError> {
        if http_port == 0 {
            return Err(SystemProxyError("system proxy port must be non-zero"));
        }
        Ok(Self {
            flags: PROXY_TYPE_DIRECT_VALUE | PROXY_TYPE_PROXY_VALUE,
            proxy_server: Some(format!("127.0.0.1:{http_port}")),
            proxy_bypass: Some(ROUTEDECK_PROXY_BYPASS.into()),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemProxyError(&'static str);

impl SystemProxyError {
    #[cfg(test)]
    pub(crate) fn fixed(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for SystemProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for SystemProxyError {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(dead_code)]
struct SystemProxyJournal {
    version: u8,
    previous: SystemProxySnapshot,
    applied: SystemProxySnapshot,
}

#[allow(dead_code)]
trait SystemProxyBackend: Send + Sync {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError>;
    fn apply(&self, state: &SystemProxySnapshot) -> Result<(), SystemProxyError>;
}

pub(crate) trait SystemProxyControl: Send + Sync {
    fn publish_loopback(&self, http_port: u16) -> Result<(), SystemProxyError>;
    fn is_owned(&self) -> Result<bool, SystemProxyError>;
    fn restore_if_owned(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError>;
    fn reconcile_stale_journal(&self) -> Result<SystemProxyRestoreOutcome, SystemProxyError>;
}

#[allow(dead_code)]
struct WinInetSystemProxyBackend;

impl SystemProxyBackend for WinInetSystemProxyBackend {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
        #[cfg(windows)]
        {
            query_wininet_snapshot()
        }
        #[cfg(not(windows))]
        {
            Err(SystemProxyError(
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
            Err(SystemProxyError(
                "Windows System Proxy is unavailable on this platform",
            ))
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct SystemProxyManager {
    journal_path: PathBuf,
    backend: Arc<dyn SystemProxyBackend>,
}

#[allow(dead_code)]
impl SystemProxyManager {
    pub(crate) fn new(app_local_data_dir: PathBuf) -> Self {
        Self {
            journal_path: app_local_data_dir.join(JOURNAL_FILE_NAME),
            backend: Arc::new(WinInetSystemProxyBackend),
        }
    }

    #[cfg(test)]
    fn with_backend(journal_path: PathBuf, backend: Arc<dyn SystemProxyBackend>) -> Self {
        Self {
            journal_path,
            backend,
        }
    }

    pub(crate) fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
        self.backend.snapshot()
    }

    pub(crate) fn publish_loopback(&self, http_port: u16) -> Result<(), SystemProxyError> {
        let applied = SystemProxySnapshot::routedeck(http_port)?;
        if self.load_journal()?.is_some() {
            return Err(SystemProxyError(
                "a previous System Proxy session must be reconciled first",
            ));
        }
        let previous = self.backend.snapshot()?;
        if !previous.valid() {
            return Err(SystemProxyError("Windows returned invalid proxy settings"));
        }
        let journal = SystemProxyJournal {
            version: JOURNAL_VERSION,
            previous: previous.clone(),
            applied: applied.clone(),
        };
        self.write_journal(&journal)?;

        if self.backend.apply(&applied).is_err() {
            let restored = self
                .backend
                .apply(&previous)
                .and_then(|_| self.verify_exact(&previous));
            if restored.is_ok() {
                let _ = self.remove_journal();
            }
            return Err(SystemProxyError(
                "could not publish the RouteDeck System Proxy",
            ));
        }
        if self.verify_exact(&applied).is_err() {
            let restored = self
                .backend
                .apply(&previous)
                .and_then(|_| self.verify_exact(&previous));
            if restored.is_ok() {
                let _ = self.remove_journal();
            }
            return Err(SystemProxyError(
                "Windows did not retain the RouteDeck System Proxy settings",
            ));
        }
        Ok(())
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
        if current != journal.applied {
            self.remove_journal()?;
            return Ok(SystemProxyRestoreOutcome::ForeignPreserved);
        }
        self.backend
            .apply(&journal.previous)
            .map_err(|_| SystemProxyError("could not restore Windows System Proxy settings"))?;
        self.verify_exact(&journal.previous)
            .map_err(|_| SystemProxyError("Windows did not retain restored proxy settings"))?;
        self.remove_journal()?;
        Ok(SystemProxyRestoreOutcome::Restored)
    }

    pub(crate) fn reconcile_stale_journal(
        &self,
    ) -> Result<SystemProxyRestoreOutcome, SystemProxyError> {
        self.restore_if_owned()
    }

    fn verify_exact(&self, expected: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
        if self.backend.snapshot()? == *expected {
            Ok(())
        } else {
            Err(SystemProxyError(
                "effective Windows System Proxy settings did not match",
            ))
        }
    }

    fn load_journal(&self) -> Result<Option<SystemProxyJournal>, SystemProxyError> {
        let bytes = match fs::read(&self.journal_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SystemProxyError("could not read proxy recovery journal")),
        };
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(SystemProxyError("proxy recovery journal is invalid"));
        }
        let journal: SystemProxyJournal = serde_json::from_slice(&bytes)
            .map_err(|_| SystemProxyError("proxy recovery journal is invalid"))?;
        if journal.version != JOURNAL_VERSION
            || !journal.previous.valid()
            || !journal.applied.valid()
        {
            return Err(SystemProxyError("proxy recovery journal is invalid"));
        }
        Ok(Some(journal))
    }

    fn write_journal(&self, journal: &SystemProxyJournal) -> Result<(), SystemProxyError> {
        let parent = self
            .journal_path
            .parent()
            .ok_or(SystemProxyError("proxy recovery path is invalid"))?;
        fs::create_dir_all(parent)
            .map_err(|_| SystemProxyError("could not create proxy recovery directory"))?;
        let bytes = serde_json::to_vec(journal)
            .map_err(|_| SystemProxyError("could not serialize proxy recovery journal"))?;
        let temporary = self.journal_path.with_extension("json.tmp");
        let _ = fs::remove_file(&temporary);
        fs::write(&temporary, bytes)
            .and_then(|_| fs::rename(&temporary, &self.journal_path))
            .map_err(|_| SystemProxyError("could not write proxy recovery journal"))
    }

    fn remove_journal(&self) -> Result<(), SystemProxyError> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SystemProxyError("could not remove proxy recovery journal")),
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
    fn current_loopback_proxy(&self) -> Option<LoopbackProxyEndpoint>;
}

pub(crate) struct WindowsSystemProxyProvider;

impl SystemProxyProvider for WindowsSystemProxyProvider {
    fn current_loopback_proxy(&self) -> Option<LoopbackProxyEndpoint> {
        #[cfg(windows)]
        {
            let mut state = query_wininet_state().ok()?;
            state.ras_active = query_ras_active().unwrap_or(true);
            select_loopback_proxy(state)
        }
        #[cfg(not(windows))]
        {
            None
        }
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
        return Err(SystemProxyError(
            "could not query Windows System Proxy settings",
        ));
    }
    let state = SystemProxySnapshot {
        flags: unsafe { options[0].Value.dwValue },
        proxy_server: read_bounded_wide(proxy_server.0)
            .map_err(|_| SystemProxyError("Windows returned an invalid proxy server"))?,
        proxy_bypass: read_bounded_wide(proxy_bypass.0)
            .map_err(|_| SystemProxyError("Windows returned an invalid proxy bypass list"))?,
        auto_config_url: read_bounded_wide(auto_config_url.0)
            .map_err(|_| SystemProxyError("Windows returned an invalid automatic proxy URL"))?,
    };
    if !state.valid() {
        return Err(SystemProxyError("Windows returned invalid proxy settings"));
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
        return Err(SystemProxyError("invalid System Proxy settings"));
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
        return Err(SystemProxyError(
            "Windows rejected the System Proxy settings",
        ));
    }
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        if unsafe { InternetSetOptionW(ptr::null(), option, ptr::null(), 0) } == 0 {
            return Err(SystemProxyError(
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
        atomic::{AtomicUsize, Ordering},
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
    fn publishes_and_restores_exact_previous_state_without_touching_windows() {
        let root = TestRoot::new();
        let previous = SystemProxySnapshot {
            flags: PROXY_TYPE_DIRECT_VALUE | 8,
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
}
