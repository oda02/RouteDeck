use std::{
    error::Error as _,
    io::Read,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
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

    fn prove_ordinary(&self, http_port: u16) -> Result<ProofResult, RuntimeError> {
        self.prove(&HealthRoute::new(http_port, String::new()))
    }
}

pub(crate) struct HttpsTrafficProber;

impl TrafficProber for HttpsTrafficProber {
    fn prove(&self, route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
        prove_via_http_proxy(route.port, Some(&route.password))
    }

    fn prove_ordinary(&self, http_port: u16) -> Result<ProofResult, RuntimeError> {
        prove_via_http_proxy(http_port, None)
    }
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
    Ok(accepting && loopback_ports_owned_by(ports, pid)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerOwner {
    local_address: u32,
    port: u16,
    pid: u32,
}

fn owners_match(owners: &[ListenerOwner], ports: LocalPorts, pid: u32) -> bool {
    let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
    [ports.http, ports.socks, ports.health].iter().all(|port| {
        owners
            .iter()
            .any(|owner| owner.local_address == loopback && owner.port == *port && owner.pid == pid)
    })
}

#[cfg(windows)]
fn loopback_ports_owned_by(ports: LocalPorts, pid: u32) -> Result<bool, RuntimeError> {
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
fn loopback_ports_owned_by(_ports: LocalPorts, _pid: u32) -> Result<bool, RuntimeError> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(owners_match(&owners, ports, 42));
        owners[1].pid = 7;
        assert!(!owners_match(&owners, ports, 42));
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
        let mut owned = false;
        for _ in 0..20 {
            if loopback_ports_owned_by(ports, pid).unwrap() {
                owned = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            owned,
            "current process listeners were not attributed to its PID"
        );
        assert!(!loopback_ports_owned_by(ports, pid.wrapping_add(1)).unwrap());
    }
}
