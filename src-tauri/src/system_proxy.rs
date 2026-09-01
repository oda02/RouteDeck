use std::{net::SocketAddr, str::FromStr};

const MAX_PROXY_CONFIG_CHARS: usize = 4 * 1024;
#[cfg(test)]
const PROXY_TYPE_DIRECT_VALUE: u32 = 1;
const PROXY_TYPE_PROXY_VALUE: u32 = 2;
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
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_FLAGS_UI,
    };

    query_wininet_state_with_flags(INTERNET_PER_CONN_FLAGS_UI)
        .or_else(|_| query_wininet_state_with_flags(INTERNET_PER_CONN_FLAGS))
}

#[cfg(windows)]
fn query_wininet_state_with_flags(flags_option: u32) -> Result<RawSystemProxyState, ()> {
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::GlobalFree,
        Networking::WinInet::{
            InternetQueryOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_PER_CONN_OPTIONW,
            INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_PROXY_SERVER,
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
    let returned = ReturnedString(unsafe { options[1].Value.pszValue });
    if ok == 0 || list.dwOptionError != 0 {
        return Err(());
    }
    let state = RawSystemProxyState {
        flags: unsafe { options[0].Value.dwValue },
        proxy_server: read_bounded_wide(returned.0)?,
        ras_active: false,
    };
    Ok(state)
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
    use super::*;

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
}
