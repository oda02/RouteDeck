use std::{
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
}

pub(crate) struct HttpsTrafficProber;

impl TrafficProber for HttpsTrafficProber {
    fn prove(&self, route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
        let proxy_url = format!("http://127.0.0.1:{}", route.port);
        let proxy = Proxy::all(&proxy_url)
            .map_err(|_| RuntimeError::new("prove_traffic", "health proxy URL is invalid"))?
            .basic_auth(HEALTH_PROXY_USERNAME, &route.password);
        let client = Client::builder()
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
            .map_err(|error| RuntimeError::new("prove_traffic", error.to_string()))?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(RuntimeError::new(
                "prove_traffic",
                format!("health endpoint returned HTTP {}", response.status()),
            ));
        }
        let mut body = Vec::new();
        response
            .take((MAX_PROOF_BODY + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|error| RuntimeError::new("prove_traffic", error.to_string()))?;
        if body.len() > MAX_PROOF_BODY {
            return Err(RuntimeError::new(
                "prove_traffic",
                "health response exceeded the body limit",
            ));
        }
        Ok(ProofResult {
            latency_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        })
    }
}

pub(crate) trait ListenerVerifier: Send + Sync {
    fn wait_until_ready(
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
            if expected.iter().all(|port| {
                TcpStream::connect_timeout(
                    &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, *port)),
                    Duration::from_millis(100),
                )
                .is_ok()
            }) && loopback_ports_owned_by(ports, child.pid())?
            {
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
