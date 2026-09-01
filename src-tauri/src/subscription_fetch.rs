use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    str,
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{blocking::Client, header::LOCATION, redirect::Policy};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use serde::Deserialize;
use url::{Host, Url};

use crate::{
    subscription::MAX_INPUT_BYTES,
    system_proxy::{
        LoopbackProxyEndpoint, SystemProxyError, SystemProxyProvider, WindowsSystemProxyProvider,
    },
};

const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_AND_READ_TIMEOUT: Duration = Duration::from_secs(5);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_CHUNKS: usize = 4 * 1024;
const MAX_CHUNK_FRAMING_BYTES: usize = 64 * 1024;
const MAX_TRAILER_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionFetchTransport {
    Direct,
    CurrentLoopbackSystemProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionFetchErrorKind {
    UrlInvalid,
    PolicyBlocked,
    FetchFailed,
    ResponseTooLarge,
    Timeout,
    InvalidEncoding,
    ProxyUnavailable,
    ProxyPolicyBlocked,
    ProxyConnectFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionFetchStage {
    Url,
    Dns,
    Fetch,
    Response,
    Proxy,
    ProxyConnect,
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
    fn fetch(
        &self,
        raw_url: &str,
        transport: SubscriptionFetchTransport,
    ) -> Result<String, SubscriptionFetchError>;
}

pub(crate) struct HttpsSubscriptionFetcher;

impl SubscriptionFetcher for HttpsSubscriptionFetcher {
    fn fetch(
        &self,
        raw_url: &str,
        transport: SubscriptionFetchTransport,
    ) -> Result<String, SubscriptionFetchError> {
        match transport {
            SubscriptionFetchTransport::Direct => fetch_with(
                raw_url,
                &SystemDnsResolver,
                &PinnedHttpsTransport,
                Instant::now(),
            ),
            SubscriptionFetchTransport::CurrentLoopbackSystemProxy => {
                // Fail invalid/oversized URLs before inspecting any machine state.
                validate_url(raw_url)?;
                let endpoint = WindowsSystemProxyProvider
                    .current_loopback_proxy()
                    .map_err(map_system_proxy_error)?;
                fetch_with(
                    raw_url,
                    &SystemDnsResolver,
                    &LoopbackProxyHttpsTransport::production(endpoint),
                    Instant::now(),
                )
            }
        }
    }
}

trait DnsResolver {
    fn resolve(&self, host: &str, timeout: Duration)
        -> Result<Vec<IpAddr>, SubscriptionFetchError>;
}

trait HttpsTransport {
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
        let remaining = remaining_budget(started)?;
        let addresses = resolve_and_validate(&current, resolver, remaining.min(DNS_TIMEOUT))?;
        let remaining = remaining_budget(started)?;
        let response = transport.get(
            &current,
            &addresses,
            remaining.min(CONNECT_AND_READ_TIMEOUT),
        )?;
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
            return Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::FetchFailed,
                SubscriptionFetchStage::Fetch,
            ));
        }
        if response.body.len() > MAX_INPUT_BYTES {
            return Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::ResponseTooLarge,
                SubscriptionFetchStage::Response,
            ));
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

fn remaining_budget(started: Instant) -> Result<Duration, SubscriptionFetchError> {
    OVERALL_TIMEOUT
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(timeout_error)
}

fn validate_url(raw_url: &str) -> Result<Url, SubscriptionFetchError> {
    if raw_url.is_empty() || raw_url.len() > MAX_URL_BYTES {
        return Err(url_error());
    }
    let parsed = Url::parse(raw_url).map_err(|_| url_error())?;
    validate_parsed_url(parsed)
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
        // IETF protocol assignments include Teredo, benchmarking, ORCHID,
        // anycast services, and other non-ordinary destinations.
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

fn response_too_large_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::ResponseTooLarge,
        SubscriptionFetchStage::Response,
    )
}

fn proxy_connect_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::ProxyConnectFailed,
        SubscriptionFetchStage::ProxyConnect,
    )
}

fn map_system_proxy_error(error: SystemProxyError) -> SubscriptionFetchError {
    match error {
        SystemProxyError::Unavailable => SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::ProxyUnavailable,
            SubscriptionFetchStage::Proxy,
        ),
        SystemProxyError::PolicyBlocked => SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::ProxyPolicyBlocked,
            SubscriptionFetchStage::Proxy,
        ),
    }
}

struct PinnedHttpsTransport;

impl HttpsTransport for PinnedHttpsTransport {
    fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        timeout: Duration,
    ) -> Result<TransportResponse, SubscriptionFetchError> {
        let host = url.host_str().ok_or_else(url_error)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connection_verbose(false)
            .no_proxy()
            .https_only(true)
            .no_hickory_dns()
            .connect_timeout(timeout.min(CONNECT_AND_READ_TIMEOUT))
            .timeout(timeout)
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .resolve_to_addrs(host, addresses)
            .build()
            .map_err(|_| fetch_error())?;
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
            read_bounded_decoded(&mut response)?
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

struct LoopbackProxyHttpsTransport {
    proxy: LoopbackProxyEndpoint,
    exchange: Arc<dyn ProxyTunnelExchange>,
}

impl LoopbackProxyHttpsTransport {
    fn production(proxy: LoopbackProxyEndpoint) -> Self {
        Self {
            proxy,
            exchange: Arc::new(NativeProxyTunnelExchange),
        }
    }
}

impl HttpsTransport for LoopbackProxyHttpsTransport {
    fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        timeout: Duration,
    ) -> Result<TransportResponse, SubscriptionFetchError> {
        let started = Instant::now();
        let mut last_connect_error = proxy_connect_error();
        for destination in addresses {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or_else(|| timeout_error_at(SubscriptionFetchStage::ProxyConnect))?;
            if remaining.is_zero() {
                return Err(timeout_error_at(SubscriptionFetchStage::ProxyConnect));
            }
            let plan = build_proxy_request_plan(url, *destination)?;
            match self.exchange.execute(self.proxy, &plan, remaining) {
                Ok(response) => return Ok(response),
                Err(error) if error.kind() == SubscriptionFetchErrorKind::ProxyConnectFailed => {
                    last_connect_error = error;
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_connect_error)
    }
}

struct ProxyRequestPlan {
    destination: SocketAddr,
    server_name: String,
    host_header: String,
    request_target: String,
}

fn build_proxy_request_plan(
    url: &Url,
    destination: SocketAddr,
) -> Result<ProxyRequestPlan, SubscriptionFetchError> {
    let default_port = url.port_or_known_default().ok_or_else(url_error)?;
    if destination.port() != default_port {
        return Err(policy_error(SubscriptionFetchStage::Dns));
    }
    let (server_name, host) = match url.host().ok_or_else(url_error)? {
        Host::Ipv4(value) => (value.to_string(), value.to_string()),
        Host::Ipv6(value) => (value.to_string(), format!("[{value}]")),
        Host::Domain(value) => (value.to_owned(), value.to_owned()),
    };
    let host_header = if default_port == 443 {
        host
    } else {
        format!("{host}:{default_port}")
    };
    let mut request_target = url.path().to_owned();
    if request_target.is_empty() {
        request_target.push('/');
    }
    if let Some(query) = url.query() {
        request_target.push('?');
        request_target.push_str(query);
    }
    if request_target.len() > MAX_URL_BYTES
        || !request_target.is_ascii()
        || !host_header.is_ascii()
        || !server_name.is_ascii()
    {
        return Err(url_error());
    }
    Ok(ProxyRequestPlan {
        destination,
        server_name,
        host_header,
        request_target,
    })
}

trait ProxyTunnelExchange: Send + Sync {
    fn execute(
        &self,
        proxy: LoopbackProxyEndpoint,
        plan: &ProxyRequestPlan,
        timeout: Duration,
    ) -> Result<TransportResponse, SubscriptionFetchError>;
}

struct NativeProxyTunnelExchange;

impl ProxyTunnelExchange for NativeProxyTunnelExchange {
    fn execute(
        &self,
        proxy: LoopbackProxyEndpoint,
        plan: &ProxyRequestPlan,
        timeout: Duration,
    ) -> Result<TransportResponse, SubscriptionFetchError> {
        let started = Instant::now();
        let deadline = started
            .checked_add(timeout)
            .ok_or_else(|| timeout_error_at(SubscriptionFetchStage::ProxyConnect))?;
        let stream = TcpStream::connect_timeout(&proxy.socket_addr(), timeout)
            .map_err(map_proxy_io_error)?;
        let mut stream = DeadlineIo::new(stream, deadline);
        stream
            .write_all(&connect_request(plan.destination))
            .and_then(|_| stream.flush())
            .map_err(map_proxy_io_error)?;
        let connect_head = read_header_block(&mut stream).map_err(map_proxy_io_error)?;
        validate_connect_response(&connect_head)?;

        let mut tls_config = ClientConfig::with_platform_verifier().map_err(|_| fetch_error())?;
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name =
            ServerName::try_from(plan.server_name.clone()).map_err(|_| url_error())?;
        let connection =
            ClientConnection::new(Arc::new(tls_config), server_name).map_err(|_| fetch_error())?;
        // Keep the deadline wrapper *inside* Rustls so every raw socket read/write
        // made during one high-level TLS operation rechecks the absolute deadline.
        let mut tls = StreamOwned::new(connection, stream);
        tls.write_all(&origin_request(plan))
            .and_then(|_| tls.flush())
            .map_err(map_io_error)?;
        read_origin_response(&mut tls)
    }
}

trait SocketTimeouts {
    fn set_socket_timeouts(&self, timeout: Duration) -> io::Result<()>;
}

impl SocketTimeouts for TcpStream {
    fn set_socket_timeouts(&self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

struct DeadlineIo<T> {
    inner: T,
    deadline: Instant,
}

impl<T> DeadlineIo<T> {
    fn new(inner: T, deadline: Instant) -> Self {
        Self { inner, deadline }
    }
}

impl<T: SocketTimeouts> DeadlineIo<T> {
    fn prepare_io(&self) -> io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request deadline elapsed"))?;
        self.inner.set_socket_timeouts(remaining)
    }
}

impl<T: Read + SocketTimeouts> Read for DeadlineIo<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.prepare_io()?;
        self.inner.read(buffer)
    }
}

impl<T: Write + SocketTimeouts> Write for DeadlineIo<T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.prepare_io()?;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.prepare_io()?;
        self.inner.flush()
    }
}

fn connect_request(destination: SocketAddr) -> Vec<u8> {
    let authority = match destination {
        SocketAddr::V4(value) => value.to_string(),
        SocketAddr::V6(value) => format!("[{}]:{}", value.ip(), value.port()),
    };
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
}

fn origin_request(plan: &ProxyRequestPlan) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\nUser-Agent: RouteDeck/0.1\r\n\r\n",
        plan.request_target, plan.host_header
    )
    .into_bytes()
}

struct ParsedResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
}

fn validate_connect_response(bytes: &[u8]) -> Result<(), SubscriptionFetchError> {
    let parsed = parse_response_head(bytes).map_err(|_| proxy_connect_error())?;
    if parsed.status != 200 {
        return Err(proxy_connect_error());
    }
    Ok(())
}

fn read_header_block(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    while bytes.len() < MAX_RESPONSE_HEADER_BYTES {
        reader.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "response headers exceed the fixed limit",
    ))
}

fn parse_response_head(bytes: &[u8]) -> Result<ParsedResponseHead, ()> {
    if !bytes.ends_with(b"\r\n\r\n") || !bytes.is_ascii() {
        return Err(());
    }
    let text = str::from_utf8(bytes).map_err(|_| ())?;
    let mut lines = text[..text.len() - 2].split("\r\n");
    let status_line = lines.next().ok_or(())?;
    if status_line.len() > MAX_HEADER_LINE_BYTES {
        return Err(());
    }
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().ok_or(())?;
    let status_text = status_parts.next().ok_or(())?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status_text.len() != 3
        || !status_text.bytes().all(|value| value.is_ascii_digit())
    {
        return Err(());
    }
    let status = status_text.parse::<u16>().map_err(|_| ())?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if headers.len() == MAX_RESPONSE_HEADERS
            || line.len() > MAX_HEADER_LINE_BYTES
            || line.starts_with([' ', '\t'])
        {
            return Err(());
        }
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.is_empty() || !name.bytes().all(is_header_name_byte) {
            return Err(());
        }
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| byte < 0x20 && byte != b'\t' || byte == 0x7f)
        {
            return Err(());
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(ParsedResponseHead { status, headers })
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn read_origin_response(
    reader: &mut impl Read,
) -> Result<TransportResponse, SubscriptionFetchError> {
    let head = read_header_block(reader).map_err(map_io_error)?;
    let parsed = parse_response_head(&head).map_err(|_| fetch_error())?;
    let location = unique_header(&parsed.headers, "location")?;
    let encodings = header_values(&parsed.headers, "content-encoding")
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().as_bytes());
    if !content_encodings_allowed(encodings) {
        return Err(fetch_error());
    }
    let transfer_encoding = unique_header(&parsed.headers, "transfer-encoding")?;
    let content_length = unique_header(&parsed.headers, "content-length")?;
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(fetch_error());
    }
    if let Some(transfer_encoding) = transfer_encoding.as_deref() {
        if !transfer_encoding.eq_ignore_ascii_case("chunked") {
            return Err(fetch_error());
        }
    }
    let content_length = content_length
        .as_deref()
        .map(parse_content_length)
        .transpose()?;
    if is_redirect(parsed.status) || parsed.status != 200 {
        return Ok(TransportResponse {
            status: parsed.status,
            location,
            body: Vec::new(),
        });
    }
    let body = if let Some(transfer_encoding) = transfer_encoding {
        debug_assert!(transfer_encoding.eq_ignore_ascii_case("chunked"));
        read_chunked_body(reader)?
    } else if let Some(content_length) = content_length {
        if content_length > MAX_INPUT_BYTES {
            return Err(response_too_large_error());
        }
        let mut body = vec![0_u8; content_length];
        reader.read_exact(&mut body).map_err(map_io_error)?;
        body
    } else {
        read_bounded_decoded(reader)?
    };
    Ok(TransportResponse {
        status: parsed.status,
        location,
        body,
    })
}

fn parse_content_length(value: &str) -> Result<usize, SubscriptionFetchError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(fetch_error());
    }
    value.parse::<usize>().map_err(|_| fetch_error())
}

fn header_values<'a>(
    headers: &'a [(String, String)],
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(header_name, _)| header_name == name)
        .map(|(_, value)| value.as_str())
}

fn unique_header(
    headers: &[(String, String)],
    name: &str,
) -> Result<Option<String>, SubscriptionFetchError> {
    let mut values = header_values(headers, name);
    let first = values.next().map(str::to_owned);
    if values.next().is_some() {
        return Err(fetch_error());
    }
    Ok(first)
}

fn read_chunked_body(reader: &mut impl Read) -> Result<Vec<u8>, SubscriptionFetchError> {
    let mut body = Vec::with_capacity(16 * 1024);
    let mut chunks = 0_usize;
    let mut framing_bytes = 0_usize;
    loop {
        let line = read_crlf_line(reader, MAX_CHUNK_LINE_BYTES).map_err(map_io_error)?;
        chunks = chunks.saturating_add(1);
        framing_bytes = framing_bytes.saturating_add(line.len() + 2);
        if chunks > MAX_CHUNKS || framing_bytes > MAX_CHUNK_FRAMING_BYTES {
            return Err(fetch_error());
        }
        if line.is_empty() || line.contains(&b';') || !line.iter().all(u8::is_ascii_hexdigit) {
            return Err(fetch_error());
        }
        let line = str::from_utf8(&line).map_err(|_| fetch_error())?;
        let length = usize::from_str_radix(line, 16).map_err(|_| fetch_error())?;
        if length == 0 {
            read_trailers(reader)?;
            return Ok(body);
        }
        if length > MAX_INPUT_BYTES.saturating_sub(body.len()) {
            return Err(response_too_large_error());
        }
        let previous = body.len();
        body.resize(previous + length, 0);
        reader
            .read_exact(&mut body[previous..])
            .map_err(map_io_error)?;
        let mut terminator = [0_u8; 2];
        reader.read_exact(&mut terminator).map_err(map_io_error)?;
        if terminator != *b"\r\n" {
            return Err(fetch_error());
        }
        framing_bytes = framing_bytes.saturating_add(2);
        if framing_bytes > MAX_CHUNK_FRAMING_BYTES {
            return Err(fetch_error());
        }
    }
}

fn read_crlf_line(reader: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while line.len() <= limit {
        reader.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "line exceeds the fixed limit",
    ))
}

fn read_trailers(reader: &mut impl Read) -> Result<(), SubscriptionFetchError> {
    let mut total: usize = 0;
    for _ in 0..=MAX_RESPONSE_HEADERS {
        let line = read_crlf_line(reader, MAX_HEADER_LINE_BYTES).map_err(map_io_error)?;
        total = total.saturating_add(line.len() + 2);
        if total > MAX_TRAILER_BYTES {
            return Err(fetch_error());
        }
        if line.is_empty() {
            return Ok(());
        }
        if !line.is_ascii() || matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(fetch_error());
        }
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            return Err(fetch_error());
        };
        let (name, value_with_colon) = line.split_at(separator);
        let value = &value_with_colon[1..];
        if name.is_empty()
            || !name.iter().copied().all(is_header_name_byte)
            || value
                .iter()
                .any(|byte| *byte < 0x20 && *byte != b'\t' || *byte == 0x7f)
        {
            return Err(fetch_error());
        }
    }
    Err(fetch_error())
}

fn content_encodings_allowed<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> bool {
    values
        .into_iter()
        .all(|value| value.eq_ignore_ascii_case(b"identity"))
}

fn read_bounded_decoded(reader: &mut impl Read) -> Result<Vec<u8>, SubscriptionFetchError> {
    let mut body = Vec::with_capacity(16 * 1024);
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(map_io_error)?;
    if body.len() > MAX_INPUT_BYTES {
        return Err(SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::ResponseTooLarge,
            SubscriptionFetchStage::Response,
        ));
    }
    Ok(body)
}

fn map_reqwest_error(error: reqwest::Error) -> SubscriptionFetchError {
    if error.is_timeout() {
        timeout_error()
    } else {
        fetch_error()
    }
}

fn map_io_error(error: io::Error) -> SubscriptionFetchError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        timeout_error()
    } else {
        fetch_error()
    }
}

fn map_proxy_io_error(error: io::Error) -> SubscriptionFetchError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        timeout_error_at(SubscriptionFetchStage::ProxyConnect)
    } else {
        proxy_connect_error()
    }
}

fn fetch_error() -> SubscriptionFetchError {
    SubscriptionFetchError::new(
        SubscriptionFetchErrorKind::FetchFailed,
        SubscriptionFetchStage::Fetch,
    )
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
fn resolve_windows_dns(
    host: &str,
    timeout: Duration,
) -> Result<Vec<IpAddr>, SubscriptionFetchError> {
    use std::{mem::size_of, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::Networking::WinSock::{
        FreeAddrInfoExW, GetAddrInfoExW, WSACleanup, WSAStartup, ADDRINFOEXW, AF_INET, AF_INET6,
        AF_UNSPEC, IPPROTO_TCP, NS_DNS, SOCKADDR_IN, SOCKADDR_IN6, SOCK_STREAM, TIMEVAL, WSADATA,
    };

    struct Winsock;
    impl Drop for Winsock {
        fn drop(&mut self) {
            unsafe { WSACleanup() };
        }
    }

    let mut data = WSADATA::default();
    if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
        return Err(dns_fetch_error());
    }
    let _winsock = Winsock;
    let wide_host = std::ffi::OsStr::new(host)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let hints = ADDRINFOEXW {
        ai_family: AF_UNSPEC as i32,
        ai_socktype: SOCK_STREAM,
        ai_protocol: IPPROTO_TCP,
        ..Default::default()
    };
    let mut results = ptr::null_mut();
    let timeout = TIMEVAL {
        tv_sec: timeout.as_secs().min(i32::MAX as u64) as i32,
        tv_usec: timeout.subsec_micros() as i32,
    };
    let status = unsafe {
        GetAddrInfoExW(
            wide_host.as_ptr(),
            ptr::null(),
            NS_DNS,
            ptr::null(),
            &hints,
            &mut results,
            &timeout,
            ptr::null(),
            None,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(windows_dns_error(status));
    }
    struct Results(*mut ADDRINFOEXW);
    impl Drop for Results {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { FreeAddrInfoExW(self.0) };
            }
        }
    }
    let _results = Results(results);
    let mut addresses = Vec::new();
    let mut current = results;
    while !current.is_null() {
        if addresses.len() == MAX_RESOLVED_ADDRESSES {
            return Err(policy_error(SubscriptionFetchStage::Dns));
        }
        let entry = unsafe { &*current };
        if entry.ai_addr.is_null() {
            return Err(policy_error(SubscriptionFetchStage::Dns));
        }
        match entry.ai_family as u16 {
            AF_INET if entry.ai_addrlen >= size_of::<SOCKADDR_IN>() => {
                let address = unsafe { &*entry.ai_addr.cast::<SOCKADDR_IN>() };
                let bytes = unsafe { address.sin_addr.S_un.S_un_b };
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                )));
            }
            AF_INET6 if entry.ai_addrlen >= size_of::<SOCKADDR_IN6>() => {
                let address = unsafe { &*entry.ai_addr.cast::<SOCKADDR_IN6>() };
                addresses.push(IpAddr::V6(Ipv6Addr::from(unsafe {
                    address.sin6_addr.u.Byte
                })));
            }
            _ => return Err(policy_error(SubscriptionFetchStage::Dns)),
        }
        current = entry.ai_next;
    }
    Ok(addresses)
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
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
        thread,
    };

    use super::*;
    use crate::system_proxy::test_loopback_proxy;

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

    struct RecordedProxyCall {
        proxy: SocketAddr,
        destination: SocketAddr,
        server_name: String,
        host_header: String,
        request_target: String,
    }

    struct FakeTlsTunnelExchange {
        calls: Mutex<Vec<RecordedProxyCall>>,
        responses: Mutex<VecDeque<TransportResponse>>,
    }

    impl FakeTlsTunnelExchange {
        fn new(responses: Vec<TransportResponse>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
    }

    impl ProxyTunnelExchange for FakeTlsTunnelExchange {
        fn execute(
            &self,
            proxy: LoopbackProxyEndpoint,
            plan: &ProxyRequestPlan,
            _timeout: Duration,
        ) -> Result<TransportResponse, SubscriptionFetchError> {
            self.calls.lock().unwrap().push(RecordedProxyCall {
                proxy: proxy.socket_addr(),
                destination: plan.destination,
                server_name: plan.server_name.clone(),
                host_header: plan.host_header.clone(),
                request_target: plan.request_target.clone(),
            });
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(fetch_error)
        }
    }

    struct FailingTlsTunnelExchange(SubscriptionFetchError);

    impl ProxyTunnelExchange for FailingTlsTunnelExchange {
        fn execute(
            &self,
            _proxy: LoopbackProxyEndpoint,
            _plan: &ProxyRequestPlan,
            _timeout: Duration,
        ) -> Result<TransportResponse, SubscriptionFetchError> {
            Err(self.0)
        }
    }

    struct DeadlineFixture {
        touched: Arc<AtomicBool>,
    }

    impl SocketTimeouts for DeadlineFixture {
        fn set_socket_timeouts(&self, _timeout: Duration) -> io::Result<()> {
            self.touched.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    impl Read for DeadlineFixture {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.touched.store(true, Ordering::SeqCst);
            Ok(0)
        }
    }

    struct SlowByteSocket {
        reads: Arc<AtomicUsize>,
    }

    impl SocketTimeouts for SlowByteSocket {
        fn set_socket_timeouts(&self, _timeout: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for SlowByteSocket {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(3));
            buffer[0] = b'x';
            Ok(1)
        }
    }

    struct TlsLikeMultiReader<T> {
        inner: T,
    }

    impl<T: Read> Read for TlsLikeMultiReader<T> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read_exact(&mut buffer[..1])?;
            self.inner.read_exact(&mut buffer[1..2])?;
            Ok(2)
        }
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

    fn fake_proxy_transport(exchange: Arc<FakeTlsTunnelExchange>) -> LoopbackProxyHttpsTransport {
        LoopbackProxyHttpsTransport {
            proxy: test_loopback_proxy("127.0.0.1:10809".parse().unwrap()),
            exchange,
        }
    }

    #[test]
    fn url_policy_is_https_only_without_authority_credentials_or_fragments() {
        for url in [
            "http://public.test/sub",
            "https://user:secret@public.test/sub",
            "https://public.test/sub#secret",
            "https://localhost/sub",
            "https://service.local/sub",
            "not a url",
        ] {
            assert!(validate_url(url).is_err(), "accepted {url}");
        }
        assert!(validate_url("https://public.test/sub?token=secret").is_ok());
        assert!(validate_url(&format!(
            "https://public.test/{}",
            "x".repeat(MAX_URL_BYTES)
        ))
        .is_err());
    }

    #[test]
    fn destination_policy_rejects_ssrf_and_reserved_ipv4_ipv6_classes() {
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
            "64:ff9b::7f00:1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            let address: IpAddr = address.parse().unwrap();
            assert!(!is_public_destination(address), "accepted {address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            let address: IpAddr = address.parse().unwrap();
            assert!(is_public_destination(address), "rejected {address}");
        }
    }

    #[test]
    fn mixed_or_rebound_dns_answer_fails_before_the_next_request() {
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
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::PolicyBlocked);
        assert_eq!(error.stage(), SubscriptionFetchStage::Dns);
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn manual_redirects_revalidate_each_https_hop_and_allow_three() {
        let resolver =
            FakeResolver::new([("public.test", vec![vec![public_v4(1)]; MAX_REDIRECTS + 1])]);
        let transport = FakeTransport::new(vec![
            Ok(response(301, Some("/second"), b"")),
            Ok(response(302, Some("/third"), b"")),
            Ok(response(307, Some("/final"), b"")),
            Ok(response(200, None, b"hysteria2://secret@example.test:443")),
        ]);
        let result = fetch_with(
            "https://public.test/start",
            &resolver,
            &transport,
            Instant::now(),
        )
        .unwrap();
        assert!(result.starts_with("hysteria2://"));
        assert_eq!(transport.calls.lock().unwrap().len(), MAX_REDIRECTS + 1);
    }

    #[test]
    fn redirect_downgrade_missing_location_and_excess_are_blocked() {
        let resolver =
            FakeResolver::new([("public.test", vec![vec![public_v4(1)]; MAX_REDIRECTS + 1])]);
        let downgrade =
            FakeTransport::new(vec![Ok(response(302, Some("http://public.test/sub"), b""))]);
        assert_eq!(
            fetch_with(
                "https://public.test/start",
                &resolver,
                &downgrade,
                Instant::now(),
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::PolicyBlocked
        );

        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let missing = FakeTransport::new(vec![Ok(response(302, None, b""))]);
        assert_eq!(
            fetch_with(
                "https://public.test/start",
                &resolver,
                &missing,
                Instant::now(),
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::PolicyBlocked
        );

        let resolver =
            FakeResolver::new([("public.test", vec![vec![public_v4(1)]; MAX_REDIRECTS + 1])]);
        let redirects = FakeTransport::new(
            (0..=MAX_REDIRECTS)
                .map(|_| Ok(response(302, Some("/again"), b"")))
                .collect(),
        );
        assert_eq!(
            fetch_with(
                "https://public.test/start",
                &resolver,
                &redirects,
                Instant::now(),
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::PolicyBlocked
        );
    }

    #[test]
    fn decoded_body_limit_and_utf8_are_enforced() {
        let oversized = vec![b'x'; MAX_INPUT_BYTES + 1];
        let error = read_bounded_decoded(&mut Cursor::new(oversized)).unwrap_err();
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::ResponseTooLarge);

        let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
        let transport = FakeTransport::new(vec![Ok(response(200, None, &[0xff, 0xfe]))]);
        assert_eq!(
            fetch_with(
                "https://public.test/sub",
                &resolver,
                &transport,
                Instant::now(),
            )
            .unwrap_err()
            .kind(),
            SubscriptionFetchErrorKind::InvalidEncoding
        );
    }

    #[test]
    fn compressed_responses_are_rejected_without_a_decoder_dependency() {
        assert!(content_encodings_allowed(std::iter::empty()));
        assert!(content_encodings_allowed([b"identity".as_slice()]));
        assert!(content_encodings_allowed([b"IDENTITY".as_slice()]));
        assert!(!content_encodings_allowed([b"gzip".as_slice()]));
        assert!(!content_encodings_allowed([b"br".as_slice()]));
        assert!(!content_encodings_allowed([
            b"identity".as_slice(),
            b"gzip".as_slice(),
        ]));
    }

    #[test]
    fn non_success_status_wins_over_oversized_or_invalid_response_body() {
        for body in [vec![b'x'; MAX_INPUT_BYTES + 1], vec![0xff, 0xfe]] {
            let resolver = FakeResolver::new([("public.test", vec![vec![public_v4(1)]])]);
            let transport = FakeTransport::new(vec![Ok(response(404, None, &body))]);
            let error = fetch_with(
                "https://public.test/sub",
                &resolver,
                &transport,
                Instant::now(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), SubscriptionFetchErrorKind::FetchFailed);
            assert_eq!(error.stage(), SubscriptionFetchStage::Fetch);
        }
    }

    #[test]
    fn empty_too_many_and_private_ip_literal_destinations_are_blocked() {
        let empty = FakeResolver::new([("public.test", vec![vec![]])]);
        let transport = FakeTransport::new(vec![]);
        assert!(fetch_with(
            "https://public.test/sub",
            &empty,
            &transport,
            Instant::now()
        )
        .is_err());

        let too_many = FakeResolver::new([(
            "public.test",
            vec![(1..=MAX_RESOLVED_ADDRESSES + 1)
                .map(|index| IpAddr::V4(Ipv4Addr::new(8, 8, 4, index as u8)))
                .collect()],
        )]);
        assert!(fetch_with(
            "https://public.test/sub",
            &too_many,
            &transport,
            Instant::now()
        )
        .is_err());
        assert!(fetch_with(
            "https://127.0.0.1/sub",
            &too_many,
            &transport,
            Instant::now()
        )
        .is_err());
    }

    #[test]
    fn exhausted_overall_budget_is_a_timeout_before_dns_or_transport() {
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
    fn transport_timeout_and_failure_are_finite_and_secret_free() {
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

    #[test]
    fn loopback_proxy_plan_connects_to_pinned_ip_with_original_sni_and_host() {
        let exchange = Arc::new(FakeTlsTunnelExchange::new(vec![response(
            200,
            None,
            b"hysteria2://secret@example.test:443",
        )]));
        let transport = fake_proxy_transport(exchange.clone());
        let url = Url::parse("https://subscription.example:8443/list?token=secret").unwrap();
        let destination: SocketAddr = "8.8.8.8:8443".parse().unwrap();
        let response = transport
            .get(&url, &[destination], Duration::from_secs(1))
            .unwrap();
        assert_eq!(response.status, 200);
        let calls = exchange.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert!(call.proxy.ip().is_loopback());
        assert_eq!(call.destination, destination);
        assert_eq!(call.server_name, "subscription.example");
        assert_eq!(call.host_header, "subscription.example:8443");
        assert_eq!(call.request_target, "/list?token=secret");

        let connect = String::from_utf8(connect_request(destination)).unwrap();
        assert!(connect.contains("CONNECT 8.8.8.8:8443 HTTP/1.1"));
        assert!(!connect.contains("subscription.example"));
        assert!(!connect.contains("token"));
        let origin = String::from_utf8(origin_request(
            &build_proxy_request_plan(&url, destination).unwrap(),
        ))
        .unwrap();
        assert!(origin.contains("Host: subscription.example:8443\r\n"));
        assert!(origin.starts_with("GET /list?token=secret HTTP/1.1\r\n"));
        assert!(!origin.contains("Proxy-Authorization"));
        assert!(!origin.contains("Referer"));
    }

    #[test]
    fn ipv6_literal_uses_unbracketed_certificate_identity_and_bracketed_http_host() {
        let url = Url::parse("https://[2606:4700:4700::1111]/list").unwrap();
        let destination: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let plan = build_proxy_request_plan(&url, destination).unwrap();
        assert_eq!(plan.server_name, "2606:4700:4700::1111");
        assert_eq!(plan.host_header, "[2606:4700:4700::1111]");
        assert!(matches!(
            ServerName::try_from(plan.server_name.clone()).unwrap(),
            ServerName::IpAddress(_)
        ));
        let connect = String::from_utf8(connect_request(destination)).unwrap();
        assert!(connect.contains("CONNECT [2606:4700:4700::1111]:443 HTTP/1.1"));
    }

    #[test]
    fn proxy_redirect_revalidates_dns_and_pins_each_new_destination() {
        let resolver = FakeResolver::new([
            ("one.test", vec![vec![public_v4(1)]]),
            ("two.test", vec![vec![public_v4(2)]]),
        ]);
        let exchange = Arc::new(FakeTlsTunnelExchange::new(vec![
            response(302, Some("https://two.test/final"), b""),
            response(200, None, b"vless://fixture"),
        ]));
        let transport = fake_proxy_transport(exchange.clone());
        let result = fetch_with(
            "https://one.test/start",
            &resolver,
            &transport,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(result, "vless://fixture");
        let calls = exchange.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].destination.ip(), public_v4(1));
        assert_eq!(calls[0].server_name, "one.test");
        assert_eq!(calls[1].destination.ip(), public_v4(2));
        assert_eq!(calls[1].server_name, "two.test");
    }

    #[test]
    fn mixed_dns_is_rejected_before_loopback_proxy_exchange() {
        let resolver = FakeResolver::new([(
            "public.test",
            vec![vec![public_v4(1), "127.0.0.1".parse().unwrap()]],
        )]);
        let exchange = Arc::new(FakeTlsTunnelExchange::new(Vec::new()));
        let transport = fake_proxy_transport(exchange.clone());
        let error = fetch_with(
            "https://public.test/sub",
            &resolver,
            &transport,
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::PolicyBlocked);
        assert!(exchange.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn connect_response_parser_is_strict_and_secret_free() {
        assert!(validate_connect_response(
            b"HTTP/1.1 200 Connection established\r\nProxy-Agent: fixture\r\n\r\n"
        )
        .is_ok());
        for bytes in [
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\n\n".as_slice(),
            b"HTTP/2 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n folded: no\r\n\r\n".as_slice(),
        ] {
            let error = validate_connect_response(bytes).unwrap_err();
            assert_eq!(error.kind(), SubscriptionFetchErrorKind::ProxyConnectFailed);
            assert_eq!(error.stage(), SubscriptionFetchStage::ProxyConnect);
        }
    }

    #[test]
    fn proxy_origin_http_parser_bounds_chunked_length_and_duplicate_framing() {
        let mut valid = Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
        );
        assert_eq!(read_origin_response(&mut valid).unwrap().body, b"test");

        let mut duplicate =
            Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx");
        assert!(read_origin_response(&mut duplicate).is_err());

        let mut signed_length = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx");
        assert!(read_origin_response(&mut signed_length).is_err());

        let mut malformed_redirect = Cursor::new(
            b"HTTP/1.1 302 Found\r\nLocation: https://next.test/\r\nContent-Length: +1\r\n\r\n",
        );
        assert!(read_origin_response(&mut malformed_redirect).is_err());

        let mut invalid_chunk = Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\ntest\r\n0\r\n\r\n",
        );
        assert!(read_origin_response(&mut invalid_chunk).is_err());

        let mut too_many_chunks = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..=MAX_CHUNKS {
            too_many_chunks.extend_from_slice(b"1\r\nx\r\n");
        }
        too_many_chunks.extend_from_slice(b"0\r\n\r\n");
        assert!(read_origin_response(&mut Cursor::new(too_many_chunks)).is_err());

        let oversized = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_INPUT_BYTES + 1
        );
        let error = match read_origin_response(&mut Cursor::new(oversized.into_bytes())) {
            Err(error) => error,
            Ok(_) => panic!("oversized response was accepted"),
        };
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::ResponseTooLarge);

        let compressed = b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx";
        let error = match read_origin_response(&mut Cursor::new(compressed)) {
            Err(error) => error,
            Ok(_) => panic!("compressed response was accepted"),
        };
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::FetchFailed);
    }

    #[test]
    fn proxy_timeout_error_is_finite_and_does_not_retain_url_or_endpoint() {
        let transport = LoopbackProxyHttpsTransport {
            proxy: test_loopback_proxy("127.0.0.1:49152".parse().unwrap()),
            exchange: Arc::new(FailingTlsTunnelExchange(timeout_error_at(
                SubscriptionFetchStage::ProxyConnect,
            ))),
        };
        let url = Url::parse("https://secret-host.test/list?token=never-emit").unwrap();
        let error = match transport.get(
            &url,
            &["8.8.8.8:443".parse().unwrap()],
            Duration::from_secs(1),
        ) {
            Err(error) => error,
            Ok(_) => panic!("proxy timeout was accepted"),
        };
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::Timeout);
        assert_eq!(error.stage(), SubscriptionFetchStage::ProxyConnect);
        let serialized = format!("{error:?}");
        assert!(!serialized.contains("secret-host"));
        assert!(!serialized.contains("never-emit"));
        assert!(!serialized.contains("49152"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_timeout_retains_the_dns_stage() {
        let error = windows_dns_error(windows_sys::Win32::Networking::WinSock::WSAETIMEDOUT);
        assert_eq!(error.kind(), SubscriptionFetchErrorKind::Timeout);
        assert_eq!(error.stage(), SubscriptionFetchStage::Dns);
    }

    #[test]
    fn absolute_deadline_stops_incremental_reads_before_touching_transport() {
        let touched = Arc::new(AtomicBool::new(false));
        let fixture = DeadlineFixture {
            touched: touched.clone(),
        };
        let mut reader = DeadlineIo::new(fixture, Instant::now() - Duration::from_millis(1));
        let error = reader.read(&mut [0_u8; 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!touched.load(Ordering::SeqCst));
    }

    #[test]
    fn deadline_inside_tls_like_reader_rechecks_each_raw_socket_read() {
        let reads = Arc::new(AtomicUsize::new(0));
        let socket = SlowByteSocket {
            reads: reads.clone(),
        };
        let inner = DeadlineIo::new(socket, Instant::now() + Duration::from_millis(1));
        let mut tls_like = TlsLikeMultiReader { inner };
        let error = tls_like.read(&mut [0_u8; 2]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
