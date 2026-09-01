use std::{net::SocketAddr, str::FromStr};

const MAX_PROXY_CONFIG_CHARS: usize = 4 * 1024;
const PROXY_TYPE_DIRECT_VALUE: u32 = 1;
const PROXY_TYPE_PROXY_VALUE: u32 = 2;
const PROXY_TYPE_AUTO_PROXY_URL_VALUE: u32 = 4;
const PROXY_TYPE_AUTO_DETECT_VALUE: u32 = 8;
const KNOWN_PROXY_FLAGS: u32 = PROXY_TYPE_DIRECT_VALUE
    | PROXY_TYPE_PROXY_VALUE
    | PROXY_TYPE_AUTO_PROXY_URL_VALUE
    | PROXY_TYPE_AUTO_DETECT_VALUE;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemProxyError {
    Unavailable,
    PolicyBlocked,
}

#[derive(Clone, Copy)]
pub(crate) struct LoopbackProxyEndpoint(SocketAddr);

impl LoopbackProxyEndpoint {
    fn new(value: SocketAddr) -> Result<Self, SystemProxyError> {
        if value.port() == 0 || !value.ip().is_loopback() {
            return Err(SystemProxyError::PolicyBlocked);
        }
        Ok(Self(value))
    }

    pub(crate) fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

pub(crate) trait SystemProxyProvider: Send + Sync {
    fn current_loopback_proxy(&self) -> Result<LoopbackProxyEndpoint, SystemProxyError>;
}

pub(crate) struct WindowsSystemProxyProvider;

impl SystemProxyProvider for WindowsSystemProxyProvider {
    fn current_loopback_proxy(&self) -> Result<LoopbackProxyEndpoint, SystemProxyError> {
        #[cfg(windows)]
        {
            let mut state = query_wininet_state()?;
            state.ras_active = query_ras_active()?;
            validate_system_proxy_state(state)
        }
        #[cfg(not(windows))]
        {
            Err(SystemProxyError::Unavailable)
        }
    }
}

struct RawSystemProxyState {
    flags: u32,
    proxy_server: Option<String>,
    autoconfig_url: Option<String>,
    autodiscovery_flags: u32,
    ras_active: bool,
}

fn validate_system_proxy_state(
    state: RawSystemProxyState,
) -> Result<LoopbackProxyEndpoint, SystemProxyError> {
    if state.ras_active
        || state.flags & !KNOWN_PROXY_FLAGS != 0
        || state.flags & (PROXY_TYPE_AUTO_PROXY_URL_VALUE | PROXY_TYPE_AUTO_DETECT_VALUE) != 0
        || state
            .autoconfig_url
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || state.autodiscovery_flags != 0
    {
        return Err(SystemProxyError::PolicyBlocked);
    }
    if state.flags & PROXY_TYPE_PROXY_VALUE == 0 {
        return Err(SystemProxyError::Unavailable);
    }
    let proxy_server = state
        .proxy_server
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(SystemProxyError::Unavailable)?;
    parse_proxy_server(proxy_server)
}

fn parse_proxy_server(value: &str) -> Result<LoopbackProxyEndpoint, SystemProxyError> {
    if value.len() > MAX_PROXY_CONFIG_CHARS
        || value.contains('@')
        || value.contains("\r")
        || value.contains("\n")
    {
        return Err(SystemProxyError::PolicyBlocked);
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(SystemProxyError::Unavailable);
    }
    if value.contains('=') || value.contains(';') {
        let mut http_seen = false;
        let mut https = None;
        for entry in value.split(';') {
            let (scheme, endpoint) = entry
                .split_once('=')
                .ok_or(SystemProxyError::PolicyBlocked)?;
            if endpoint.contains('=') || scheme.trim().is_empty() || endpoint.trim().is_empty() {
                return Err(SystemProxyError::PolicyBlocked);
            }
            let endpoint = parse_loopback_endpoint(endpoint.trim())?;
            match scheme.trim().to_ascii_lowercase().as_str() {
                "http" if !http_seen => http_seen = true,
                "https" if https.replace(endpoint).is_none() => {}
                _ => return Err(SystemProxyError::PolicyBlocked),
            }
        }
        https.ok_or(SystemProxyError::PolicyBlocked)
    } else {
        parse_loopback_endpoint(value)
    }
}

fn parse_loopback_endpoint(value: &str) -> Result<LoopbackProxyEndpoint, SystemProxyError> {
    let endpoint = SocketAddr::from_str(value).map_err(|_| SystemProxyError::PolicyBlocked)?;
    LoopbackProxyEndpoint::new(endpoint)
}

#[cfg(test)]
pub(crate) fn test_loopback_proxy(value: SocketAddr) -> LoopbackProxyEndpoint {
    match LoopbackProxyEndpoint::new(value) {
        Ok(endpoint) => endpoint,
        Err(_) => panic!("test loopback proxy must be valid"),
    }
}

#[cfg(windows)]
fn query_wininet_state() -> Result<RawSystemProxyState, SystemProxyError> {
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_FLAGS_UI,
    };

    query_wininet_state_with_flags(INTERNET_PER_CONN_FLAGS_UI)
        .or_else(|_| query_wininet_state_with_flags(INTERNET_PER_CONN_FLAGS))
}

#[cfg(windows)]
fn query_wininet_state_with_flags(
    flags_option: u32,
) -> Result<RawSystemProxyState, SystemProxyError> {
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::GlobalFree,
        Networking::WinInet::{
            InternetQueryOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
            INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_AUTODISCOVERY_FLAGS,
            INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTION_LISTW,
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
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            ..Default::default()
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTODISCOVERY_FLAGS,
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

    struct ReturnedStrings(*mut u16, *mut u16);
    impl Drop for ReturnedStrings {
        fn drop(&mut self) {
            for value in [self.0, self.1] {
                if !value.is_null() {
                    unsafe {
                        GlobalFree(value.cast());
                    }
                }
            }
        }
    }
    let returned = ReturnedStrings(unsafe { options[1].Value.pszValue }, unsafe {
        options[2].Value.pszValue
    });
    if ok == 0 || list.dwOptionError != 0 {
        return Err(SystemProxyError::Unavailable);
    }
    let state = RawSystemProxyState {
        flags: unsafe { options[0].Value.dwValue },
        proxy_server: read_bounded_wide(returned.0)?,
        autoconfig_url: read_bounded_wide(returned.1)?,
        autodiscovery_flags: unsafe { options[3].Value.dwValue },
        ras_active: false,
    };
    Ok(state)
}

#[cfg(windows)]
fn read_bounded_wide(value: *const u16) -> Result<Option<String>, SystemProxyError> {
    if value.is_null() {
        return Ok(None);
    }
    let mut length = 0;
    while length <= MAX_PROXY_CONFIG_CHARS {
        if unsafe { *value.add(length) } == 0 {
            let slice = unsafe { std::slice::from_raw_parts(value, length) };
            return String::from_utf16(slice)
                .map(Some)
                .map_err(|_| SystemProxyError::PolicyBlocked);
        }
        length += 1;
    }
    Err(SystemProxyError::PolicyBlocked)
}

#[cfg(windows)]
fn query_ras_active() -> Result<bool, SystemProxyError> {
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
        _ => Err(SystemProxyError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(flags: u32, proxy_server: Option<&str>) -> RawSystemProxyState {
        RawSystemProxyState {
            flags,
            proxy_server: proxy_server.map(str::to_owned),
            autoconfig_url: None,
            autodiscovery_flags: 0,
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
        ] {
            assert!(validate_system_proxy_state(state(
                PROXY_TYPE_DIRECT_VALUE | PROXY_TYPE_PROXY_VALUE,
                Some(value),
            ))
            .is_ok());
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
            "http=127.0.0.1:1;http=127.0.0.1:2",
            "http=127.0.0.1:10809",
            "socks=127.0.0.1:1080",
            "http=127.0.0.1:1;",
        ] {
            assert!(matches!(
                validate_system_proxy_state(state(PROXY_TYPE_PROXY_VALUE, Some(value))),
                Err(SystemProxyError::PolicyBlocked)
            ));
        }
    }

    #[test]
    fn rejects_pac_wpad_unknown_flags_and_ras_without_exposing_values() {
        let mut cases = vec![
            RawSystemProxyState {
                flags: PROXY_TYPE_PROXY_VALUE | PROXY_TYPE_AUTO_PROXY_URL_VALUE,
                proxy_server: Some("127.0.0.1:7890".into()),
                autoconfig_url: Some("https://secret-pac.test/config?token=secret".into()),
                autodiscovery_flags: 0,
                ras_active: false,
            },
            RawSystemProxyState {
                flags: PROXY_TYPE_PROXY_VALUE | PROXY_TYPE_AUTO_DETECT_VALUE,
                proxy_server: Some("127.0.0.1:7890".into()),
                autoconfig_url: None,
                autodiscovery_flags: 1,
                ras_active: false,
            },
            state(PROXY_TYPE_PROXY_VALUE | 0x8000_0000, Some("127.0.0.1:7890")),
        ];
        let mut ras = state(PROXY_TYPE_PROXY_VALUE, Some("127.0.0.1:7890"));
        ras.ras_active = true;
        cases.push(ras);
        for case in cases {
            assert!(matches!(
                validate_system_proxy_state(case),
                Err(SystemProxyError::PolicyBlocked)
            ));
        }
    }

    #[test]
    fn disabled_or_empty_static_proxy_is_unavailable() {
        assert!(matches!(
            validate_system_proxy_state(state(PROXY_TYPE_DIRECT_VALUE, None)),
            Err(SystemProxyError::Unavailable)
        ));
        assert!(matches!(
            validate_system_proxy_state(state(PROXY_TYPE_PROXY_VALUE, Some("  "))),
            Err(SystemProxyError::Unavailable)
        ));
    }
}
