use std::{
    collections::BTreeSet,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str,
    time::{Duration, Instant},
};

use reqwest::{blocking::Client, header::LOCATION, redirect::Policy, Proxy};
use url::{Host, Url};

use crate::{
    subscription::MAX_INPUT_BYTES,
    system_proxy::{LoopbackProxyEndpoint, SystemProxyProvider, WindowsSystemProxyProvider},
};

const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionFetchErrorKind {
    UrlInvalid,
    PolicyBlocked,
    FetchFailed,
    ResponseTooLarge,
    Timeout,
    InvalidEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionFetchStage {
    Url,
    Dns,
    Fetch,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubscriptionFetchError {
    kind: SubscriptionFetchErrorKind,
    stage: SubscriptionFetchStage,
}

impl SubscriptionFetchError {
    pub(crate) fn new(kind: SubscriptionFetchErrorKind, stage: SubscriptionFetchStage) -> Self {
        Self { kind, stage }
    }

    pub(crate) fn kind(self) -> SubscriptionFetchErrorKind {
        self.kind
    }

    pub(crate) fn stage(self) -> SubscriptionFetchStage {
        self.stage
    }
}

pub(crate) trait SubscriptionFetcher: Send + Sync {
    fn fetch(&self, raw_url: &str) -> Result<String, SubscriptionFetchError>;
}

pub(crate) struct HttpsSubscriptionFetcher;

impl SubscriptionFetcher for HttpsSubscriptionFetcher {
    fn fetch(&self, raw_url: &str) -> Result<String, SubscriptionFetchError> {
        // Reject malformed secret-bearing input before inspecting machine state.
        validate_url(raw_url)?;
        let proxy = WindowsSystemProxyProvider
            .current_loopback_proxy()
            .map_err(|_| fetch_error())?;
        fetch_with(
            raw_url,
            &SystemDnsResolver,
            &StandardHttpsTransport { proxy },
            Instant::now(),
        )
    }
}

trait DnsResolver {
    fn resolve(&self, host: &str, timeout: Duration)
        -> Result<Vec<IpAddr>, SubscriptionFetchError>;
}

trait HttpsTransport {
    fn requires_local_dns(&self) -> bool {
        true
    }

    fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        timeout: Duration,
    ) -> Result<TransportResponse, SubscriptionFetchError>;
}

struct TransportResponse {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

fn fetch_with(
    raw_url: &str,
    resolver: &dyn DnsResolver,
    transport: &dyn HttpsTransport,
    started: Instant,
) -> Result<String, SubscriptionFetchError> {
    let mut current = validate_url(raw_url)?;
    for redirect_count in 0..=MAX_REDIRECTS {
        let addresses = if transport.requires_local_dns() {
            let remaining = remaining_budget(started)?;
            resolve_and_validate(&current, resolver, remaining.min(DNS_TIMEOUT))?
        } else {
            Vec::new()
        };
        let response = transport.get(&current, &addresses, remaining_budget(started)?)?;
        if is_redirect(response.status) {
            if redirect_count == MAX_REDIRECTS {
                return Err(policy_error(SubscriptionFetchStage::Url));
            }
            let location = response
                .location
                .as_deref()
                .ok_or_else(|| policy_error(SubscriptionFetchStage::Url))?;
            let next = current
                .join(location)
                .map_err(|_| policy_error(SubscriptionFetchStage::Url))?;
            current =
                validate_parsed_url(next).map_err(|_| policy_error(SubscriptionFetchStage::Url))?;
            continue;
        }
        if response.status != 200 {
            return Err(fetch_error());
        }
        if response.body.len() > MAX_INPUT_BYTES {
            return Err(response_too_large_error());
        }
        let text = str::from_utf8(&response.body).map_err(|_| {
            SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::InvalidEncoding,
                SubscriptionFetchStage::Response,
            )
        })?;
        return Ok(text.to_owned());
    }
    Err(policy_error(SubscriptionFetchStage::Url))
}

struct StandardHttpsTransport {
    proxy: Option<LoopbackProxyEndpoint>,
}

impl HttpsTransport for StandardHttpsTransport {
    fn requires_local_dns(&self) -> bool {
        self.proxy.is_none()
    }

    fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        timeout: Duration,
    ) -> Result<TransportResponse, SubscriptionFetchError> {
        let host = url.host_str().ok_or_else(url_error)?;
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connection_verbose(false)
            .https_only(true)
            .no_hickory_dns()
            .connect_timeout(timeout.min(CONNECT_TIMEOUT))
            .timeout(timeout)
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();

        if let Some(proxy) = self.proxy {
            let proxy = Proxy::https(proxy.http_url()).map_err(|_| fetch_error())?;
            builder = builder.proxy(proxy);
        } else {
            builder = builder.no_proxy().resolve_to_addrs(host, addresses);
        }

        let client = builder.build().map_err(|_| fetch_error())?;
        let mut response = client.get(url.clone()).send().map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(LOCATION)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(|_| policy_error(SubscriptionFetchStage::Url))?;
        let body = if status == 200 {
            if !content_encodings_allowed(
                response
                    .headers()
                    .get_all(reqwest::header::CONTENT_ENCODING)
                    .iter()
                    .map(|value| value.as_bytes()),
            ) {
                return Err(fetch_error());
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_INPUT_BYTES as u64)
            {
                return Err(response_too_large_error());
            }
            read_bounded_body(&mut response)?
        } else {
            Vec::new()
        };
        Ok(TransportResponse {
            status,
            location,
            body,
        })
    }
}

fn remaining_budget(started: Instant) -> Result<Duration, SubscriptionFetchError> {
    OVERALL_TIMEOUT
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(timeout_error)
}

pub(crate) fn validate_url(raw_url: &str) -> Result<Url, SubscriptionFetchError> {
    if raw_url.is_empty() || raw_url.len() > MAX_URL_BYTES {
        return Err(url_error());
    }
    validate_parsed_url(Url::parse(raw_url).map_err(|_| url_error())?)
}

fn validate_parsed_url(url: Url) -> Result<Url, SubscriptionFetchError> {
    if url.as_str().len() > MAX_URL_BYTES
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
        || url.port_or_known_default().is_none()
    {
        return Err(url_error());
    }
    if let Some(host) = url.host_str() {
        let host = host.trim_end_matches('.');
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
            || host.to_ascii_lowercase().ends_with(".local")
        {
            return Err(policy_error(SubscriptionFetchStage::Url));
        }
    }
    match url.host() {
        Some(Host::Ipv4(address)) if !is_public_destination(IpAddr::V4(address)) => {
            return Err(policy_error(SubscriptionFetchStage::Url));
        }
        Some(Host::Ipv6(address)) if !is_public_destination(IpAddr::V6(address)) => {
            return Err(policy_error(SubscriptionFetchStage::Url));
        }
        _ => {}
    }
    Ok(url)
}

fn resolve_and_validate(
    url: &Url,
    resolver: &dyn DnsResolver,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, SubscriptionFetchError> {
    let port = url.port_or_known_default().ok_or_else(url_error)?;
    let raw_addresses = match url.host().ok_or_else(url_error)? {
        Host::Ipv4(address) => vec![IpAddr::V4(address)],
        Host::Ipv6(address) => vec![IpAddr::V6(address)],
        Host::Domain(domain) => resolver.resolve(domain, timeout)?,
    };
    if raw_addresses.is_empty() || raw_addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(policy_error(SubscriptionFetchStage::Dns));
    }
    let mut unique = BTreeSet::new();
    for address in raw_addresses {
        if !is_public_destination(address) {
            return Err(policy_error(SubscriptionFetchStage::Dns));
        }
        unique.insert(address);
    }
    if unique.is_empty() || unique.len() > MAX_RESOLVED_ADDRESSES {
        return Err(policy_error(SubscriptionFetchStage::Dns));
    }
    Ok(unique
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect())
}

fn is_public_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .into_iter()
    .any(|(network, prefix)| in_ipv4_prefix(value, network, prefix))
}

fn in_ipv4_prefix(value: u32, network: u32, prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    value & mask == network & mask
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let value = u128::from(address);
    in_ipv6_prefix(
        value,
        u128::from(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)),
        3,
    ) && ![
        (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
        (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
    ]
    .into_iter()
    .any(|(network, prefix)| in_ipv6_prefix(value, u128::from(network), prefix))
}

fn in_ipv6_prefix(value: u128, network: u128, prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    value & mask == network & mask
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn url_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::UrlInvalid,
        SubscriptionFetchStage::Url,
    )
}

fn policy_error(stage: SubscriptionFetchStage) -> SubscriptionFetchError {
    SubscriptionFetchError::new(SubscriptionFetchErrorKind::PolicyBlocked, stage)
}

fn timeout_error() -> SubscriptionFetchError {
    timeout_error_at(SubscriptionFetchStage::Fetch)
}

fn timeout_error_at(stage: SubscriptionFetchStage) -> SubscriptionFetchError {
    SubscriptionFetchError::new(SubscriptionFetchErrorKind::Timeout, stage)
}

fn fetch_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::FetchFailed,
        SubscriptionFetchStage::Fetch,
    )
}

fn response_too_large_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::ResponseTooLarge,
        SubscriptionFetchStage::Response,
    )
}

fn map_reqwest_error(error: reqwest::Error) -> SubscriptionFetchError {
    if error.is_timeout() {
        timeout_error()
    } else {
        fetch_error()
    }
}

fn content_encodings_allowed<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> bool {
    values
        .into_iter()
        .all(|value| value.eq_ignore_ascii_case(b"identity"))
}

fn read_bounded_body(reader: &mut impl Read) -> Result<Vec<u8>, SubscriptionFetchError> {
    let mut body = Vec::with_capacity(16 * 1024);
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| fetch_error())?;
    if body.len() > MAX_INPUT_BYTES {
        return Err(response_too_large_error());
    }
    Ok(body)
}

struct SystemDnsResolver;

#[cfg(windows)]
impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        host: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
        resolve_windows_dns(host, timeout)
    }
}

#[cfg(not(windows))]
impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        _host: &str,
        _timeout: Duration,
    ) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
        Err(dns_fetch_error())
    }
}

#[cfg(windows)]
#[path = "subscription_windows_dns.rs"]
mod windows_dns;

#[cfg(windows)]
fn resolve_windows_dns(
    host: &str,
    timeout: Duration,
) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
    windows_dns::resolve(host, timeout)
}

#[cfg(windows)]
fn windows_dns_error(status: i32) -> SubscriptionFetchError {
    if status == windows_sys::Win32::Networking::WinSock::WSAETIMEDOUT {
        timeout_error_at(SubscriptionFetchStage::Dns)
    } else {
        dns_fetch_error()
    }
}

fn dns_fetch_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::FetchFailed,
        SubscriptionFetchStage::Dns,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        io::Cursor,
        sync::Mutex,
    };

    use super::*;

    type FakeDnsAnswers = HashMap<String, VecDeque<Result<Vec<IpAddr>, SubscriptionFetchError>>>;

    struct FakeResolver {
        answers: Mutex<FakeDnsAnswers>,
    }

    impl FakeResolver {
        fn new(entries: impl IntoIterator<Item = (&'static str, Vec<Vec<IpAddr>>)>) -> Self {
            Self {
                answers: Mutex::new(
                    entries
                        .into_iter()
                        .map(|(host, answers)| {
                            (
                                host.to_owned(),
                                answers.into_iter().map(Ok).collect::<VecDeque<_>>(),
                            )
                        })
                        .collect(),
                ),
            }
        }
    }

    impl DnsResolver for FakeResolver {
        fn resolve(
            &self,
            host: &str,
            _timeout: Duration,
        ) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
            self.answers
                .lock()
                .unwrap()
                .get_mut(host)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| Err(fetch_error()))
        }
    }

    struct FakeTransport {
        responses: Mutex<VecDeque<Result<TransportResponse, SubscriptionFetchError>>>,
        calls: Mutex<Vec<(String, Vec<SocketAddr>)>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<Result<TransportResponse, SubscriptionFetchError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpsTransport for FakeTransport {
        fn get(
            &self,
            url: &Url,
            addresses: &[SocketAddr],
            _timeout: Duration,
        ) -> Result<TransportResponse, SubscriptionFetchError> {
            self.calls.lock().unwrap().push((
                url.host_str().unwrap_or_default().to_owned(),
                addresses.to_vec(),
            ));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(fetch_error()))
        }
    }

    struct ProxyLikeFakeTransport(FakeTransport);

    impl HttpsTransport for ProxyLikeFakeTransport {
        fn requires_local_dns(&self) -> bool {
            false
        }

        fn get(
            &self,
            url: &Url,
            addresses: &[SocketAddr],
            timeout: Duration,
        ) -> Result<TransportResponse, SubscriptionFetchError> {
            self.0.get(url, addresses, timeout)
        }
    }

    fn response(status: u16, location: Option<&str>, body: &[u8]) -> TransportResponse {
        TransportResponse {
            status,
            location: location.map(str::to_owned),
            body: body.to_vec(),
        }
    }

    fn public_v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, last))
    }

    #[test]
    fn url_policy_is_https_only_without_authority_credentials_or_fragments() {
        for url in [
            "http://public.test/sub",
            "https://user:secret@public.test/sub",
            "https://public.test/sub#secret",
            "https://localhost/sub",
            "https://service.local/sub",
            "https://127.0.0.1/sub",
            "https://[::1]/sub",
            "not a url",
        ] {
            assert!(validate_url(url).is_err(), "accepted {url}");
        }
        assert!(validate_url("https://public.test/sub?token=secret").is_ok());
    }

    #[test]
    fn destination_policy_rejects_ssrf_and_reserved_addresses() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            let address: IpAddr = address.parse().unwrap();
            assert!(!is_public_destination(address), "accepted {address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_destination(address.parse().unwrap()));
        }
    }

    #[test]
    fn redirects_revalidate_dns_and_allow_three() {
        let resolver =
            FakeResolver::new([("public.test", vec![vec![public_v4(1)]; MAX_REDIRECTS + 1])]);
        let transport = FakeTransport::new(vec![
            Ok(response(301, Some("/second"), b"")),
            Ok(response(302, Some("/third"), b"")),
            Ok(response(307, Some("/final"), b"")),
            Ok(response(200, None, b"hysteria2://secret@example.test:443")),
        ]);
        assert!(fetch_with(
            "https://public.test/start",
            &resolver,
            &transport,
            Instant::now()
        )
        .unwrap()
        .starts_with("hysteria2://"));
        assert_eq!(transport.calls.lock().unwrap().len(), MAX_REDIRECTS + 1);
    }

    #[test]
    fn proxy_path_leaves_origin_dns_to_standard_proxy_transport() {
        let resolver = FakeResolver::new([]);
        let transport = ProxyLikeFakeTransport(FakeTransport::new(vec![Ok(response(
            200,
            None,
            b"vless://fixture",
        ))]));
        let result = fetch_with(
            "https://proxy-resolved.test/sub",
            &resolver,
            &transport,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(result, "vless://fixture");
        let calls = transport.0.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1.is_empty());
    }

    #[test]
    fn redirect_downgrade_missing_location_and_excess_are_blocked() {
        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let downgrade =
            FakeTransport::new(vec![Ok(response(302, Some("http://public.test/sub"), b""))]);
        assert_eq!(
            fetch_with(
                "https://public.test/start",
                &resolver,
                &downgrade,
                Instant::now()
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::PolicyBlocked
        );

        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let missing = FakeTransport::new(vec![Ok(response(302, None, b""))]);
        assert!(fetch_with(
            "https://public.test/start",
            &resolver,
            &missing,
            Instant::now()
        )
        .is_err());
    }

    #[test]
    fn mixed_or_rebound_dns_is_blocked_before_second_request() {
        let resolver = FakeResolver::new([(
            "public.test",
            vec![
                vec![public_v4(8)],
                vec![public_v4(8), "127.0.0.1".parse().unwrap()],
            ],
        )]);
        let transport = FakeTransport::new(vec![Ok(response(
            302,
            Some("https://public.test/again"),
            b"",
        ))]);
        let error = fetch_with(
            "https://public.test/start",
            &resolver,
            &transport,
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.stage(), SubscriptionFetchStage::Dns);
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn body_limit_and_utf8_are_enforced() {
        let oversized = vec![b'x'; MAX_INPUT_BYTES + 1];
        assert_eq!(
            read_bounded_body(&mut Cursor::new(oversized))
                .unwrap_err()
                .kind(),
            SubscriptionFetchErrorKind::ResponseTooLarge
        );
        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let transport = FakeTransport::new(vec![Ok(response(200, None, &[0xff, 0xfe]))]);
        assert_eq!(
            fetch_with(
                "https://public.test/sub",
                &resolver,
                &transport,
                Instant::now()
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::InvalidEncoding
        );
    }

    #[test]
    fn content_encoding_policy_is_simple_and_explicit() {
        assert!(content_encodings_allowed(std::iter::empty()));
        assert!(content_encodings_allowed([b"identity".as_slice()]));
        assert!(!content_encodings_allowed([b"gzip".as_slice()]));
    }

    #[test]
    fn non_success_status_does_not_consume_response_body() {
        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let transport = FakeTransport::new(vec![Ok(response(
            404,
            None,
            &vec![b'x'; MAX_INPUT_BYTES + 1],
        ))]);
        assert_eq!(
            fetch_with(
                "https://public.test/sub",
                &resolver,
                &transport,
                Instant::now()
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::FetchFailed
        );
    }

    #[test]
    fn exhausted_budget_times_out_before_transport() {
        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let transport = FakeTransport::new(vec![]);
        let error = fetch_with(
            "https://public.test/sub",
            &resolver,
            &transport,
            Instant::now() - OVERALL_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::Timeout);
        assert!(transport.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn errors_are_finite_and_do_not_retain_url() {
        for error in [timeout_error(), fetch_error()] {
            let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
            let transport = FakeTransport::new(vec![Err(error)]);
            let raw = "https://public.test/sub?token=never-emit-me";
            let returned = fetch_with(raw, &resolver, &transport, Instant::now()).unwrap_err();
            assert_eq!(returned, error);
            let debug = format!("{returned:?}");
            assert!(!debug.contains("never-emit-me"));
            assert!(!debug.contains(raw));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_timeout_retains_dns_stage() {
        let error = windows_dns_error(windows_sys::Win32::Networking::WinSock::WSAETIMEDOUT);
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::Timeout);
        assert_eq!(error.stage(), SubscriptionFetchStage::Dns);
    }
}
