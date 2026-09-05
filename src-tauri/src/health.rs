use std::{
    error::Error as _,
    io::{self, Read},
    net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use reqwest::{blocking::Client, redirect::Policy, Proxy, StatusCode};

use crate::{
    config::LocalPorts,
    engine_runtime::{ManagedChild, RuntimeError},
    runtime_constants::HEALTH_PROXY_USERNAME,
};

const PROOF_URL: &str = "https://www.gstatic.com/generate_204";
const STARTUP_PROOF_TIMEOUT: Duration = Duration::from_secs(8);
const LISTENER_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PROOF_BODY: usize = 1024;
const MAX_ERROR_SIGNAL_BYTES: usize = 2 * 1024;
const STEADY_MEASUREMENT_BUDGET: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeFailureClass {
    Timeout,
    ProxyAuthentication,
    ProxyTunnelRejected,
    TunnelClosed,
    TlsHandshake,
    LoopbackConnect,
    ResponseBody,
    Request,
}

impl ProbeFailureClass {
    fn description(self) -> &'static str {
        match self {
            Self::Timeout => "timed out while the selected outbound was establishing HTTPS",
            Self::ProxyAuthentication => {
                "the authenticated loopback proxy rejected the proof credentials"
            }
            Self::ProxyTunnelRejected => {
                "the loopback proxy could not establish an HTTPS tunnel through the selected outbound"
            }
            Self::TunnelClosed => {
                "the HTTPS tunnel closed before the proof endpoint responded; the selected outbound or protocol handshake failed"
            }
            Self::TlsHandshake => "the HTTPS proof handshake failed after the proxy tunnel opened",
            Self::LoopbackConnect => "the verified RouteDeck loopback proxy stopped accepting connections",
            Self::ResponseBody => "the HTTPS proof response could not be read",
            Self::Request => "the HTTPS proof request failed for an unclassified transport reason",
        }
    }
}

#[derive(Clone)]
pub(crate) struct HealthRoute {
    port: u16,
    password: String,
}

impl std::fmt::Debug for HealthRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HealthRoute")
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl HealthRoute {
    pub(crate) fn new(port: u16, password: String) -> Self {
        Self { port, password }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProofResult {
    pub latency_ms: u64,
}

pub(crate) trait TrafficProber: Send + Sync {
    fn prove(&self, route: &HealthRoute) -> Result<ProofResult, RuntimeError>;

    // Optional UX measurement, never a readiness proof or a direct-route fallback.
    fn warm_latency(&self, _route: &HealthRoute) -> Option<u64> {
        None
    }

    fn prove_ordinary(&self, http_port: u16) -> Result<ProofResult, RuntimeError> {
        self.prove(&HealthRoute::new(http_port, String::new()))
    }

    fn prove_tun_capture(&self) -> Result<ProofResult, RuntimeError> {
        Err(RuntimeError::new(
            "tun_capture",
            "an unproxied TUN traffic proof is unavailable",
        ))
    }
}

pub(crate) struct HttpsTrafficProber;

impl TrafficProber for HttpsTrafficProber {
    fn prove(&self, route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
        prove_via_http_proxy(route.port, Some(&route.password))
    }

    fn warm_latency(&self, route: &HealthRoute) -> Option<u64> {
        warm_latency_via_health_route(route)
    }

    fn prove_ordinary(&self, http_port: u16) -> Result<ProofResult, RuntimeError> {
        prove_via_http_proxy(http_port, None)
    }

    fn prove_tun_capture(&self) -> Result<ProofResult, RuntimeError> {
        prove_without_proxy()
    }
}

fn warm_latency_via_health_route(route: &HealthRoute) -> Option<u64> {
    let deadline = Instant::now() + STEADY_MEASUREMENT_BUDGET;
    let relay = SingleConnectionRelay::start(route.port, deadline).ok()?;
    let proxy = Proxy::all(format!("http://127.0.0.1:{}", relay.port))
        .ok()?
        .basic_auth(HEALTH_PROXY_USERNAME, &route.password);
    let client = Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(Policy::none())
        .https_only(true)
        .http1_only()
        .pool_max_idle_per_host(1)
        .timeout(STEADY_MEASUREMENT_BUDGET)
        .build()
        .ok()?;
    collect_steady_samples(&client, &relay, deadline, PROOF_URL)
}

// The URL parameter is private: production calls only with the fixed HTTPS
// endpoint above; isolated tests exercise HTTP pooling using a loopback fixture.
fn collect_steady_samples(
    client: &Client,
    relay: &SingleConnectionRelay,
    deadline: Instant,
    proof_url: &str,
) -> Option<u64> {
    // The warm request consumes DNS/CONNECT/TLS setup. The relay permits exactly
    // one upstream connection: reqwest cannot silently retry a cold connection
    // and have that duration mistaken for a warmed HTTP response.
    let result = median_after_warmup(|| {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let started = Instant::now();
        let mut response = client
            .get(proof_url)
            .timeout(remaining)
            .header("accept", "*/*")
            .header("cache-control", "no-store")
            .send()
            .ok()?;
        if !steady_headers_valid(response.status(), response.version(), response.headers()) {
            return None;
        }
        let mut body = Vec::new();
        (&mut response)
            .take((MAX_PROOF_BODY + 1) as u64)
            .read_to_end(&mut body)
            .ok()?;
        if !body.is_empty() || Instant::now() >= deadline || !relay.valid() {
            return None;
        }
        Some(started.elapsed().as_millis().min(u64::MAX as u128) as u64)
    });
    result.filter(|_| relay.valid() && Instant::now() < deadline)
}

fn steady_headers_valid(
    status: StatusCode,
    version: reqwest::Version,
    headers: &reqwest::header::HeaderMap,
) -> bool {
    status == StatusCode::NO_CONTENT
        && version == reqwest::Version::HTTP_11
        && !headers.contains_key(reqwest::header::TRANSFER_ENCODING)
        && headers
            .get_all(reqwest::header::CONTENT_LENGTH)
            .iter()
            .all(|value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|text| text.parse::<u64>().ok())
                    == Some(0)
            })
        && !headers
            .get_all(reqwest::header::CONNECTION)
            .iter()
            .any(|value| {
                value.to_str().map_or(true, |text| {
                    text.split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"))
                })
            })
}

fn median_after_warmup(mut sample: impl FnMut() -> Option<u64>) -> Option<u64> {
    sample()?;
    let mut samples = [sample()?, sample()?, sample()?];
    samples.sort_unstable();
    Some(samples[1])
}

// Only the first accepted stream is forwarded, and only to the fixed loopback
// health port. Keep the listener bound until Drop so a local process cannot claim
// the endpoint and receive proxy credentials if reqwest attempts to reconnect.
struct SingleConnectionRelay {
    port: u16,
    stop: Arc<AtomicBool>,
    valid: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    _listener: RelayListener,
}

// Field order is intentional: close the listener before releasing our Winsock
// startup reference. SingleConnectionRelay joins every worker before this drops.
struct RelayListener {
    listener: TcpListener,
    #[cfg(windows)]
    _winsock: WinsockLease,
}

#[cfg(windows)]
struct WinsockLease;

#[cfg(windows)]
impl WinsockLease {
    fn acquire() -> io::Result<Self> {
        use windows_sys::Win32::Networking::WinSock::{WSAStartup, WSADATA};
        let mut data = std::mem::MaybeUninit::<WSADATA>::zeroed();
        // Each successful WSAStartup owns one process-wide reference; never rely
        // on reqwest or a previous std socket having initialized Winsock for us.
        let result = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let lease = Self;
        if unsafe { data.assume_init() }.wVersion != 0x0202 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Winsock 2.2 unavailable",
            ));
        }
        Ok(lease)
    }
}

#[cfg(windows)]
impl Drop for WinsockLease {
    fn drop(&mut self) {
        // Balanced only with this lease's successful WSAStartup; other clients'
        // references remain intact.
        unsafe {
            windows_sys::Win32::Networking::WinSock::WSACleanup();
        }
    }
}

#[cfg(windows)]
fn bind_relay_listener() -> io::Result<RelayListener> {
    use std::{
        mem::size_of,
        os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket},
    };
    use windows_sys::Win32::Networking::WinSock::{
        bind, listen, setsockopt, WSAGetLastError, WSASocketW, AF_INET, INVALID_SOCKET, IN_ADDR,
        IN_ADDR_0, IPPROTO_TCP, SOCKADDR_IN, SOCK_STREAM, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    };
    let winsock = WinsockLease::acquire()?;
    let raw = unsafe {
        WSASocketW(
            AF_INET as i32,
            SOCK_STREAM,
            IPPROTO_TCP,
            std::ptr::null(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if raw == INVALID_SOCKET {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    // OwnedSocket closes the handle on every failure after this point, before
    // the Winsock lease is released. No caller-provided address/port is accepted.
    let socket = unsafe { OwnedSocket::from_raw_socket(raw as _) };
    let enabled: i32 = 1;
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            size_of::<i32>() as i32,
        )
    } != 0
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let address = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
        },
        sin_zero: [0; 8],
    };
    if unsafe {
        bind(
            socket.as_raw_socket() as _,
            (&address as *const SOCKADDR_IN).cast(),
            size_of::<SOCKADDR_IN>() as i32,
        )
    } != 0
        || unsafe { listen(socket.as_raw_socket() as _, 1) } != 0
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(RelayListener {
        listener: TcpListener::from(socket),
        _winsock: winsock,
    })
}

#[cfg(not(windows))]
fn bind_relay_listener() -> io::Result<RelayListener> {
    Ok(RelayListener {
        listener: TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?,
    })
}

impl SingleConnectionRelay {
    fn start(health_port: u16, deadline: Instant) -> io::Result<Self> {
        let bound = bind_relay_listener()?;
        let listener = &bound.listener;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let worker_listener = listener.try_clone()?;
        worker_listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let valid = Arc::new(AtomicBool::new(true));
        let worker_stop = stop.clone();
        let worker_valid = valid.clone();
        let worker = thread::Builder::new()
            .name("routedeck-latency-relay".into())
            .spawn(move || {
                let _ = forward_single_connection(
                    worker_listener,
                    health_port,
                    deadline,
                    &worker_stop,
                    &worker_valid,
                );
                if !worker_stop.load(Ordering::Acquire) {
                    worker_valid.store(false, Ordering::Release);
                }
            })?;
        Ok(Self {
            port,
            stop,
            valid,
            worker: Some(worker),
            _listener: bound,
        })
    }

    fn valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }
}

impl Drop for SingleConnectionRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn forward_single_connection(
    listener: TcpListener,
    health_port: u16,
    deadline: Instant,
    stop: &AtomicBool,
    valid: &AtomicBool,
) -> io::Result<()> {
    let client = loop {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, peer)) if peer.ip().is_loopback() => break stream,
            Ok((stream, _)) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error),
        }
    };
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(250));
    if remaining.is_zero() {
        return Ok(());
    }
    let upstream = TcpStream::connect_timeout(
        &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, health_port)),
        remaining,
    )?;
    client.set_nonblocking(false)?;
    upstream.set_nonblocking(false)?;
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(());
    }
    for stream in [&client, &upstream] {
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(50))))?;
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(50))))?;
    }
    let finished = AtomicBool::new(false);
    let copy = |reader: &TcpStream, writer: &TcpStream| {
        let _ = forward_bytes(reader, writer, deadline, stop, &finished);
        valid.store(false, Ordering::Release);
        finished.store(true, Ordering::Release);
    };
    thread::scope(|scope| {
        let result = (|| {
            // Blocking directional copies introduce no polling delay into samples.
            // The watchdog alone polls; shutdown wakes both bounded copy workers.
            thread::Builder::new()
                .name("routedeck-latency-upload".into())
                .spawn_scoped(scope, || copy(&client, &upstream))?;
            thread::Builder::new()
                .name("routedeck-latency-download".into())
                .spawn_scoped(scope, || copy(&upstream, &client))?;
            while !stop.load(Ordering::Acquire)
                && !finished.load(Ordering::Acquire)
                && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((additional, _)) => {
                        let _ = additional.shutdown(Shutdown::Both);
                        valid.store(false, Ordering::Release);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })();
        valid.store(false, Ordering::Release);
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        result
    })
}

fn forward_bytes(
    mut reader: &TcpStream,
    mut writer: &TcpStream,
    deadline: Instant,
    stop: &AtomicBool,
    finished: &AtomicBool,
) -> io::Result<()> {
    use std::io::Write;
    let mut buffer = [0; 16 * 1024];
    let mut transferred = 0;
    while !stop.load(Ordering::Acquire)
        && !finished.load(Ordering::Acquire)
        && Instant::now() < deadline
    {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        transferred += count;
        if transferred > 256 * 1024 {
            break;
        }
        // Timeout in a partial write invalidates this optional measurement; do
        // not replay bytes. Read timeouts only check cancellation, with no delay
        // when actual response bytes are available.
        writer.write_all(&buffer[..count])?;
    }
    Ok(())
}

fn prove_without_proxy() -> Result<ProofResult, RuntimeError> {
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(STARTUP_PROOF_TIMEOUT)
        .build()
        .map_err(|error| RuntimeError::new("tun_capture", error.to_string()))?;
    let started = Instant::now();
    let response = client
        .get(PROOF_URL)
        .header("accept", "*/*")
        .header("cache-control", "no-store")
        .send()
        .map_err(|error| RuntimeError::new("tun_capture", error.to_string()))?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(RuntimeError::new(
            "tun_capture",
            format!(
                "unproxied TUN proof endpoint returned HTTP {}",
                response.status()
            ),
        ));
    }
    let mut body = Vec::new();
    response
        .take((MAX_PROOF_BODY + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| RuntimeError::new("tun_capture", "unproxied TUN proof body failed"))?;
    if body.len() > MAX_PROOF_BODY {
        return Err(RuntimeError::new(
            "tun_capture",
            "unproxied TUN proof response exceeded the body limit",
        ));
    }
    Ok(ProofResult {
        latency_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

fn prove_via_http_proxy(
    port: u16,
    health_password: Option<&str>,
) -> Result<ProofResult, RuntimeError> {
    let proxy_kind = proof_proxy_kind(health_password.is_some());
    let proxy_url = format!("http://127.0.0.1:{port}");
    let mut proxy = Proxy::all(&proxy_url)
        .map_err(|_| RuntimeError::new("prove_traffic", "local proof proxy URL is invalid"))?;
    if let Some(password) = health_password {
        proxy = proxy.basic_auth(HEALTH_PROXY_USERNAME, password);
    }
    let client = Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(Policy::none())
        .timeout(STARTUP_PROOF_TIMEOUT)
        .build()
        .map_err(|error| RuntimeError::new("prove_traffic", error.to_string()))?;
    let started = Instant::now();
    let response = client
        .get(PROOF_URL)
        .header("accept", "*/*")
        .header("cache-control", "no-store")
        .send()
        .map_err(|error| proof_request_error(error, health_password.is_some()))?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(RuntimeError::new(
            "prove_traffic",
            format!(
                "{proxy_kind}: proof endpoint returned HTTP {}",
                response.status()
            ),
        ));
    }
    let mut body = Vec::new();
    response
        .take((MAX_PROOF_BODY + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| {
            RuntimeError::new(
                "prove_traffic",
                format!("{proxy_kind}: the HTTPS proof response could not be read"),
            )
        })?;
    if body.len() > MAX_PROOF_BODY {
        return Err(RuntimeError::new(
            "prove_traffic",
            format!("{proxy_kind}: proof response exceeded the body limit"),
        ));
    }
    Ok(ProofResult {
        latency_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

fn proof_request_error(error: reqwest::Error, authenticated: bool) -> RuntimeError {
    let mut signals = String::new();
    let mut source = error.source();
    for _ in 0..12 {
        let Some(cause) = source else {
            break;
        };
        if !signals.is_empty() {
            signals.push(' ');
        }
        append_bounded_signal(&mut signals, &cause.to_string());
        if signals.len() >= MAX_ERROR_SIGNAL_BYTES {
            break;
        }
        source = cause.source();
    }
    let class = classify_error_signals(
        error.is_timeout(),
        error.is_connect(),
        error.is_body() || error.is_decode(),
        &signals,
    );
    let proxy_kind = proof_proxy_kind(authenticated);
    RuntimeError::new(
        "prove_traffic",
        format!("{proxy_kind}: {}", class.description()),
    )
}

fn proof_proxy_kind(authenticated: bool) -> &'static str {
    if authenticated {
        "private health proxy"
    } else {
        "ordinary local proxy"
    }
}

fn append_bounded_signal(target: &mut String, source: &str) {
    for character in source.chars() {
        if target.len().saturating_add(character.len_utf8()) > MAX_ERROR_SIGNAL_BYTES {
            break;
        }
        target.push(character);
    }
}

fn classify_error_signals(
    timed_out: bool,
    connect_error: bool,
    body_error: bool,
    source_chain: &str,
) -> ProbeFailureClass {
    let signal = source_chain.to_ascii_lowercase();
    if timed_out || signal.contains("timed out") || signal.contains("timeout") {
        return ProbeFailureClass::Timeout;
    }
    if signal.contains("407")
        || signal.contains("proxy authentication")
        || signal.contains("proxy-authenticate")
    {
        return ProbeFailureClass::ProxyAuthentication;
    }
    if signal.contains("unsuccessful tunnel")
        || signal.contains("proxy connect")
        || signal.contains("connect tunnel")
    {
        return ProbeFailureClass::ProxyTunnelRejected;
    }
    if signal.contains("connection closed")
        || signal.contains("connection reset")
        || signal.contains("unexpected eof")
        || signal.contains("broken pipe")
    {
        return ProbeFailureClass::TunnelClosed;
    }
    if signal.contains("tls")
        || signal.contains("certificate")
        || signal.contains("handshake")
        || signal.contains("invalid peer")
    {
        return ProbeFailureClass::TlsHandshake;
    }
    if connect_error {
        return ProbeFailureClass::LoopbackConnect;
    }
    if body_error {
        return ProbeFailureClass::ResponseBody;
    }
    ProbeFailureClass::Request
}

pub(crate) trait ListenerVerifier: Send + Sync {
    fn wait_until_ready(
        &self,
        ports: LocalPorts,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError>;

    fn verify_owned_now(
        &self,
        ports: LocalPorts,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError>;

    fn wait_until_sidecar_ready(
        &self,
        port: u16,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError>;

    fn verify_sidecar_owned_now(
        &self,
        port: u16,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError>;
}

pub(crate) struct TcpListenerVerifier;

impl ListenerVerifier for TcpListenerVerifier {
    fn wait_until_ready(
        &self,
        ports: LocalPorts,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + LISTENER_TIMEOUT;
        let expected = [ports.http, ports.socks, ports.health];
        loop {
            if !child.is_alive()? {
                return Err(RuntimeError::new(
                    "verify_listeners",
                    "sing-box exited before listeners became ready",
                ));
            }
            if listeners_owned_now(expected, ports, child.pid())? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(RuntimeError::new(
                    "verify_listeners",
                    "expected loopback listeners did not become ready",
                ));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    fn verify_owned_now(
        &self,
        ports: LocalPorts,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError> {
        if !child.is_alive()? {
            return Err(RuntimeError::new(
                "engine_process",
                "sing-box process is not running",
            ));
        }
        if listeners_owned_now([ports.http, ports.socks, ports.health], ports, child.pid())? {
            Ok(())
        } else {
            Err(RuntimeError::new(
                "verify_listeners",
                "loopback listener ownership proof failed",
            ))
        }
    }

    fn wait_until_sidecar_ready(
        &self,
        port: u16,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + LISTENER_TIMEOUT;
        loop {
            if !child.is_alive()? {
                return Err(RuntimeError::new(
                    "verify_listeners",
                    "Xray exited before its private bridge became ready",
                ));
            }
            if sidecar_listener_owned_now(port, child.pid())? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(RuntimeError::new(
                    "verify_listeners",
                    "the private Xray bridge listener did not become ready",
                ));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    fn verify_sidecar_owned_now(
        &self,
        port: u16,
        child: &mut dyn ManagedChild,
    ) -> Result<(), RuntimeError> {
        if !child.is_alive()? {
            return Err(RuntimeError::new(
                "engine_process",
                "Xray sidecar process is not running",
            ));
        }
        if sidecar_listener_owned_now(port, child.pid())? {
            Ok(())
        } else {
            Err(RuntimeError::new(
                "verify_listeners",
                "private Xray bridge ownership proof failed",
            ))
        }
    }
}

fn listeners_owned_now(
    expected: [u16; 3],
    ports: LocalPorts,
    pid: u32,
) -> Result<bool, RuntimeError> {
    let accepting = expected.iter().all(|port| {
        TcpStream::connect_timeout(
            &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, *port)),
            Duration::from_millis(100),
        )
        .is_ok()
    });
    Ok(accepting && loopback_ports_owned_by(&[ports.http, ports.socks, ports.health], pid)?)
}

fn sidecar_listener_owned_now(port: u16, pid: u32) -> Result<bool, RuntimeError> {
    let accepting = TcpStream::connect_timeout(
        &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        Duration::from_millis(100),
    )
    .is_ok();
    Ok(accepting && loopback_ports_owned_by(&[port], pid)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerOwner {
    local_address: u32,
    port: u16,
    pid: u32,
}

fn owners_match(owners: &[ListenerOwner], ports: &[u16], pid: u32) -> bool {
    let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
    ports.iter().all(|port| {
        owners
            .iter()
            .any(|owner| owner.local_address == loopback && owner.port == *port && owner.pid == pid)
    })
}

#[cfg(windows)]
fn loopback_ports_owned_by(ports: &[u16], pid: u32) -> Result<bool, RuntimeError> {
    use std::{mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
        },
        Networking::WinSock::AF_INET,
    };

    let mut byte_count = 0_u32;
    let initial = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut byte_count,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if initial != ERROR_INSUFFICIENT_BUFFER && initial != NO_ERROR {
        return Err(RuntimeError::new(
            "verify_listeners",
            "could not query listener ownership",
        ));
    }
    let mut storage = Vec::new();
    let mut status = ERROR_INSUFFICIENT_BUFFER;
    for _ in 0..3 {
        let word_count = (byte_count as usize).div_ceil(size_of::<u64>()).max(1);
        storage.resize(word_count, 0_u64);
        status = unsafe {
            GetExtendedTcpTable(
                storage.as_mut_ptr().cast(),
                &mut byte_count,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status != ERROR_INSUFFICIENT_BUFFER {
            break;
        }
    }
    if status != NO_ERROR {
        return Err(RuntimeError::new(
            "verify_listeners",
            "could not read listener ownership",
        ));
    }
    let base = storage.as_ptr().cast::<u8>();
    let row_count = unsafe { ptr::read_unaligned(base.cast::<u32>()) } as usize;
    let required = size_of::<u32>()
        .saturating_add(row_count.saturating_mul(size_of::<MIB_TCPROW_OWNER_PID>()));
    if required > byte_count as usize {
        return Err(RuntimeError::new(
            "verify_listeners",
            "listener ownership table was malformed",
        ));
    }
    let row_base = unsafe { base.add(size_of::<u32>()) };
    let mut owners = Vec::with_capacity(row_count);
    for index in 0..row_count {
        let row = unsafe {
            ptr::read_unaligned(
                row_base
                    .add(index * size_of::<MIB_TCPROW_OWNER_PID>())
                    .cast::<MIB_TCPROW_OWNER_PID>(),
            )
        };
        owners.push(ListenerOwner {
            local_address: row.dwLocalAddr,
            port: u16::from_be(row.dwLocalPort as u16),
            pid: row.dwOwningPid,
        });
    }
    Ok(owners_match(&owners, ports, pid))
}

#[cfg(not(windows))]
fn loopback_ports_owned_by(_ports: &[u16], _pid: u32) -> Result<bool, RuntimeError> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn warm_sample_excludes_setup_and_uses_three_sample_median() {
        let mut values = [Some(900), Some(51), Some(17), Some(29)].into_iter();
        assert_eq!(median_after_warmup(|| values.next().flatten()), Some(29));
        assert!(values.next().is_none());
        for missing in 0..4 {
            let mut calls = 0;
            assert_eq!(
                median_after_warmup(|| {
                    let index = calls;
                    calls += 1;
                    (index != missing).then_some(20)
                }),
                None
            );
            assert_eq!(calls, missing + 1);
        }
    }

    #[test]
    fn warm_headers_require_persistent_empty_http11_204() {
        use reqwest::{
            header::{HeaderMap, HeaderValue, CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING},
            Version,
        };
        let mut headers = HeaderMap::new();
        assert!(steady_headers_valid(
            StatusCode::NO_CONTENT,
            Version::HTTP_11,
            &headers
        ));
        assert!(!steady_headers_valid(
            StatusCode::OK,
            Version::HTTP_11,
            &headers
        ));
        assert!(!steady_headers_valid(
            StatusCode::NO_CONTENT,
            Version::HTTP_10,
            &headers
        ));
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Close"));
        assert!(!steady_headers_valid(
            StatusCode::NO_CONTENT,
            Version::HTTP_11,
            &headers
        ));
        headers.clear();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(!steady_headers_valid(
            StatusCode::NO_CONTENT,
            Version::HTTP_11,
            &headers
        ));
        headers.clear();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(!steady_headers_valid(
            StatusCode::NO_CONTENT,
            Version::HTTP_11,
            &headers
        ));
    }

    #[test]
    fn reqwest_loopback_fixture_reuses_four_consumed_204_responses_on_one_connection() {
        use std::io::{BufRead, BufReader};
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let health_port = upstream.local_addr().unwrap().port();
        let (release, receive) = std::sync::mpsc::channel();
        let fixture = thread::spawn(move || {
            let mut target = fixture_accept(&upstream);
            let mut reader = BufReader::new(target.try_clone().unwrap());
            let mut requests = 0;
            for _ in 0..4 {
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                requests += 1;
                target.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n").unwrap();
            }
            let _ = receive.recv_timeout(Duration::from_secs(3));
            assert!(
                matches!(upstream.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
            requests
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let relay = SingleConnectionRelay::start(health_port, deadline).unwrap();
        let client = Client::builder()
            .no_proxy()
            .proxy(Proxy::all(format!("http://127.0.0.1:{}", relay.port)).unwrap())
            .http1_only()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let result = collect_steady_samples(
            &client,
            &relay,
            deadline,
            "http://fixture.invalid/generate_204",
        );
        // Client owns the pool until all samples are evaluated, then relay Drop
        // wakes and joins both forwarding workers before releasing its endpoint.
        drop(client);
        drop(relay);
        release.send(()).unwrap();
        assert_eq!(fixture.join().unwrap(), 4);
        assert!(result.is_some());
    }

    #[test]
    fn reqwest_loopback_fixture_cannot_count_a_reconnected_response_as_warm() {
        use std::io::{BufRead, BufReader};
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let health_port = upstream.local_addr().unwrap().port();
        let fixture = thread::spawn(move || {
            let mut target = fixture_accept(&upstream);
            let mut reader = BufReader::new(target.try_clone().unwrap());
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
            }
            target
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            // Abrupt close without a Connection: close hint forces reqwest to
            // notice the EOF or attempt a new connection; neither yields latency.
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let relay = SingleConnectionRelay::start(health_port, deadline).unwrap();
        let client = Client::builder()
            .no_proxy()
            .proxy(Proxy::all(format!("http://127.0.0.1:{}", relay.port)).unwrap())
            .http1_only()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        assert_eq!(
            collect_steady_samples(
                &client,
                &relay,
                deadline,
                "http://fixture.invalid/generate_204"
            ),
            None
        );
        drop(client);
        drop(relay);
        fixture.join().unwrap();
    }

    fn fixture_accept(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    return stream;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                other => panic!("fixture accept failed: {other:?}"),
            }
        }
    }

    #[test]
    fn local_relay_fixture_forwards_one_connection_and_invalidates_reconnect() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let relay = SingleConnectionRelay::start(
            upstream.local_addr().unwrap().port(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(b"one").unwrap();
        let mut target = fixture_accept(&upstream);
        let mut bytes = [0; 3];
        target.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"one");
        target.write_all(b"two").unwrap();
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"two");
        assert!(relay.valid());
        let _second = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while relay.valid() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!relay.valid());
        assert_eq!(median_after_warmup(|| relay.valid().then_some(5)), None);
        assert!(
            matches!(upstream.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        // The owner handle stays bound even after the forwarding worker exits.
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, relay.port)).is_err());
        let started = Instant::now();
        drop(relay);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(target.read(&mut bytes).unwrap(), 0);
    }

    #[test]
    fn local_relay_fixture_drop_cancels_idle_accept_without_waiting_for_budget() {
        let relay =
            SingleConnectionRelay::start(9, Instant::now() + STEADY_MEASUREMENT_BUDGET).unwrap();
        let started = Instant::now();
        drop(relay);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(windows)]
    #[test]
    fn windows_relay_exclusive_bind_rejects_hostile_reuseaddr_even_after_worker_exits() {
        use std::{
            mem::size_of,
            os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket},
        };
        use windows_sys::Win32::Networking::WinSock::{
            bind, getsockopt, setsockopt, WSAGetLastError, WSASocketW, AF_INET, INVALID_SOCKET,
            IN_ADDR, IN_ADDR_0, IPPROTO_TCP, SOCKADDR_IN, SOCK_STREAM, SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE, SO_REUSEADDR, WSAEACCES, WSAEADDRINUSE,
            WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
        };
        let relay =
            SingleConnectionRelay::start(9, Instant::now() + Duration::from_millis(50)).unwrap();
        let mut exclusive: i32 = 0;
        let mut length = size_of::<i32>() as i32;
        assert_eq!(
            unsafe {
                getsockopt(
                    relay._listener.listener.as_raw_socket() as _,
                    SOL_SOCKET,
                    SO_EXCLUSIVEADDRUSE,
                    (&mut exclusive as *mut i32).cast(),
                    &mut length,
                )
            },
            0
        );
        assert_eq!(exclusive, 1);
        let _winsock = WinsockLease::acquire().unwrap();
        for after_worker_exit in [false, true] {
            if after_worker_exit {
                let deadline = Instant::now() + Duration::from_secs(1);
                while relay.valid() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(1));
                }
                assert!(!relay.valid());
            }
            let raw = unsafe {
                WSASocketW(
                    AF_INET as i32,
                    SOCK_STREAM,
                    IPPROTO_TCP,
                    std::ptr::null(),
                    0,
                    WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            assert_ne!(raw, INVALID_SOCKET);
            let attacker = unsafe { OwnedSocket::from_raw_socket(raw as _) };
            let reuse: i32 = 1;
            assert_eq!(
                unsafe {
                    setsockopt(
                        attacker.as_raw_socket() as _,
                        SOL_SOCKET,
                        SO_REUSEADDR,
                        (&reuse as *const i32).cast(),
                        size_of::<i32>() as i32,
                    )
                },
                0
            );
            let address = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: relay.port.to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                    },
                },
                sin_zero: [0; 8],
            };
            assert_ne!(
                unsafe {
                    bind(
                        attacker.as_raw_socket() as _,
                        (&address as *const SOCKADDR_IN).cast(),
                        size_of::<SOCKADDR_IN>() as i32,
                    )
                },
                0
            );
            assert!(matches!(
                unsafe { WSAGetLastError() },
                WSAEACCES | WSAEADDRINUSE
            ));
        }
        drop(relay);
    }

    #[test]
    fn local_relay_fixture_deadline_shuts_down_both_streams_and_keeps_port_reserved() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let relay = SingleConnectionRelay::start(
            upstream.local_addr().unwrap().port(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut target = fixture_accept(&upstream);
        let mut bytes = [0; 1];
        assert_eq!(client.read(&mut bytes).unwrap(), 0);
        assert_eq!(target.read(&mut bytes).unwrap(), 0);
        assert!(!relay.valid());
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, relay.port)).is_err());
        drop(relay);
    }

    #[test]
    fn proof_has_one_https_target_and_no_direct_fallback_field() {
        assert!(PROOF_URL.starts_with("https://"));
        let route = HealthRoute::new(12345, "fixture-secret".into());
        assert_eq!(route.port, 12345);
        let debug = format!("{route:?}");
        assert!(!debug.contains("fixture-secret"));
        assert!(!debug.contains("direct"));
    }

    #[test]
    fn request_failure_classifier_is_finite_and_actionable() {
        assert_eq!(proof_proxy_kind(true), "private health proxy");
        assert_eq!(proof_proxy_kind(false), "ordinary local proxy");
        assert_eq!(
            classify_error_signals(true, true, false, "certificate failure"),
            ProbeFailureClass::Timeout
        );
        assert_eq!(
            classify_error_signals(false, true, false, "proxy returned HTTP 407"),
            ProbeFailureClass::ProxyAuthentication
        );
        assert_eq!(
            classify_error_signals(false, true, false, "unsuccessful tunnel"),
            ProbeFailureClass::ProxyTunnelRejected
        );
        assert_eq!(
            classify_error_signals(
                false,
                true,
                false,
                "connection closed before message completed"
            ),
            ProbeFailureClass::TunnelClosed
        );
        assert_eq!(
            classify_error_signals(false, true, false, "TLS handshake EOF"),
            ProbeFailureClass::TlsHandshake
        );
        assert_eq!(
            classify_error_signals(false, true, false, "invalid peer certificate"),
            ProbeFailureClass::TlsHandshake
        );
        assert_eq!(
            classify_error_signals(false, true, false, "connection refused"),
            ProbeFailureClass::LoopbackConnect
        );
        assert_eq!(
            classify_error_signals(false, false, true, "body decode"),
            ProbeFailureClass::ResponseBody
        );
        for class in [
            ProbeFailureClass::Timeout,
            ProbeFailureClass::ProxyAuthentication,
            ProbeFailureClass::ProxyTunnelRejected,
            ProbeFailureClass::TunnelClosed,
            ProbeFailureClass::TlsHandshake,
            ProbeFailureClass::LoopbackConnect,
            ProbeFailureClass::ResponseBody,
            ProbeFailureClass::Request,
        ] {
            let description = class.description();
            assert!(description.len() < 200);
            assert!(!description.contains("https://"));
            assert!(!description.contains("secret"));
        }
        let mut bounded = String::new();
        append_bounded_signal(&mut bounded, &"э".repeat(MAX_ERROR_SIGNAL_BYTES));
        assert!(bounded.len() <= MAX_ERROR_SIGNAL_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn failed_explicit_health_proxy_is_never_bypassed() {
        use std::{net::TcpListener, sync::mpsc, thread};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_tx.send(()).unwrap();
            drop(stream);
        });
        let result = HttpsTrafficProber.prove(&HealthRoute::new(port, "fixture-secret".into()));
        assert!(result.is_err());
        accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn failed_explicit_ordinary_proxy_is_never_bypassed() {
        use std::{net::TcpListener, sync::mpsc, thread};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_tx.send(()).unwrap();
            drop(stream);
        });
        let result = HttpsTrafficProber.prove_ordinary(port);
        assert!(result.is_err());
        accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn foreign_listener_pid_cannot_satisfy_ownership_proof() {
        let ports = LocalPorts {
            http: 18080,
            socks: 18081,
            health: 18082,
        };
        let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
        let mut owners = [ports.http, ports.socks, ports.health].map(|port| ListenerOwner {
            local_address: loopback,
            port,
            pid: 42,
        });
        let expected = [ports.http, ports.socks, ports.health];
        assert!(owners_match(&owners, &expected, 42));
        owners[1].pid = 7;
        assert!(!owners_match(&owners, &expected, 42));
        assert!(owners_match(&owners, &[ports.http], 42));
    }

    #[cfg(windows)]
    #[test]
    fn windows_listener_table_matches_real_loopback_ports_and_current_pid() {
        use std::{net::TcpListener, thread, time::Duration};

        let http = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let socks = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let health = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ports = LocalPorts {
            http: http.local_addr().unwrap().port(),
            socks: socks.local_addr().unwrap().port(),
            health: health.local_addr().unwrap().port(),
        };
        let pid = std::process::id();
        let expected = [ports.http, ports.socks, ports.health];
        let mut owned = false;
        for _ in 0..20 {
            if loopback_ports_owned_by(&expected, pid).unwrap() {
                owned = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            owned,
            "current process listeners were not attributed to its PID"
        );
        assert!(!loopback_ports_owned_by(&expected, pid.wrapping_add(1)).unwrap());
    }
}
