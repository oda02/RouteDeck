//! Opt-in localhost-only DNS routing regression; no actual VPN, TUN, elevation,
//! Windows network configuration changes, subscription secrets, or Internet use.
//!
//! From src-tauri: `cargo run --locked --offline --example diagnose_dns_hijack`.
//! Requires the pinned sing-box runtime already staged in target/release/engine;
//! the existing verified launcher checks its hashes and never downloads a binary.
//! Old/new DNS rules are taken from the production generator; only a synthetic
//! direct loopback inbound is executed. Every child and session is cleaned up.
#![allow(dead_code)]
use routedeck_lib::{config, redaction};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

mod engine_runtime {
    include!("../src/engine_runtime.rs");
    pub(crate) fn fixture_launcher(root: &Path) -> Result<VerifiedEngineLauncher, RuntimeError> {
        let descriptor = EngineDescriptor::for_kind(EngineKind::SingBox);
        Ok(VerifiedEngineLauncher {
            layout: FixedEngineLayout::from_package_root(root, descriptor)?,
            descriptor,
            prepared: Mutex::new(None),
        })
    }
}
#[path = "../src/windows_process.rs"]
mod windows_process;
use engine_runtime::{DiagnosticBuffer, EngineLauncher, SessionConfig};

const IO_TIMEOUT: Duration = Duration::from_millis(700);
const QUESTION: &[u8] = b"\x07fixture\x07invalid\x00\x00\x01\x00\x01";

struct FixtureDns {
    port: u16,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}
impl FixtureDns {
    fn start() -> Result<Self, &'static str> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| "fixture_bind")?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|_| "fixture_timeout")?;
        let port = socket.local_addr().map_err(|_| "fixture_address")?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let worker_stop = stop.clone();
        let worker_requests = requests.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut bytes = [0u8; 512];
            while !worker_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let Ok((length, peer)) = socket.recv_from(&mut bytes) else {
                    continue;
                };
                if !peer.ip().is_loopback() || length < 12 || &bytes[12..length] != QUESTION {
                    continue;
                }
                worker_requests.fetch_add(1, Ordering::AcqRel);
                let mut response = bytes[..length].to_vec();
                response[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 123,
                ]);
                let _ = socket.send_to(&response, peer);
            }
        });
        Ok(Self {
            port,
            stop,
            requests,
            worker: Some(worker),
        })
    }
}
impl Drop for FixtureDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn request(id: u16) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    bytes[2] = 1;
    bytes[5] = 1;
    bytes.extend_from_slice(QUESTION);
    bytes
}

fn valid_answer(bytes: &[u8], id: u16) -> bool {
    bytes.len() >= 28
        && bytes[..2] == id.to_be_bytes()
        && bytes[2] & 0x80 != 0
        && bytes[3] & 0x0f == 0
        && bytes[7] == 1
        && bytes.ends_with(&[192, 0, 2, 123])
}

fn query_udp(port: u16, id: u16) -> bool {
    (|| -> std::io::Result<bool> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.connect((Ipv4Addr::LOCALHOST, port))?;
        socket.send(&request(id))?;
        let mut bytes = [0; 512];
        let length = socket.recv(&mut bytes)?;
        Ok(valid_answer(&bytes[..length], id))
    })()
    .unwrap_or(false)
}

fn query_tcp(port: u16, id: u16) -> bool {
    (|| -> std::io::Result<bool> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut socket = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        let packet = request(id);
        socket.write_all(&(packet.len() as u16).to_be_bytes())?;
        socket.write_all(&packet)?;
        let mut size = [0; 2];
        socket.read_exact(&mut size)?;
        let size = u16::from_be_bytes(size) as usize;
        if size > 512 {
            return Ok(false);
        }
        let mut bytes = vec![0; size];
        socket.read_exact(&mut bytes)?;
        Ok(valid_answer(&bytes, id))
    })()
    .unwrap_or(false)
}

fn generated_rules() -> Result<(serde_json::Value, serde_json::Value), &'static str> {
    use routedeck_lib::domain::{DefaultRoute, DnsPolicy, Ipv6Policy, LanPolicy, RoutePolicy};
    let parsed = routedeck_lib::subscription::import_subscription(
        b"hysteria2://fixture-password@fixture.invalid:443?sni=fixture.invalid#fixture",
    )
    .map_err(|_| "fixture_node")?;
    let node = parsed.nodes.first().ok_or("fixture_node")?;
    let policy = RoutePolicy {
        default: DefaultRoute::Vpn,
        apps: vec![],
        lan: LanPolicy::FollowDefault,
        ipv6: Ipv6Policy::Disabled,
        dns: DnsPolicy::CurrentNetwork,
    };
    let generated = config::generate_config(config::ConfigRequest {
        node,
        policy: &policy,
        mode: config::CaptureMode::Tun(config::TunSettings::default()),
        ports: config::LocalPorts {
            http: 18080,
            socks: 18081,
            health: 18082,
        },
        health_password: "fixture-health-password".into(),
        vpn_dns: None,
        insecure_approval: None,
        tun_upstream: Some(config::TunUpstream {
            interface_alias: "Fixture Ethernet".into(),
            ipv4_dns_server: None,
        }),
        naive_udp_over_tcp: false,
    })
    .map_err(|_| "generate_fixture")?;
    let value: serde_json::Value =
        serde_json::from_str(generated.as_str()).map_err(|_| "generated_json")?;
    let dns = value
        .pointer("/route/rules/1")
        .cloned()
        .ok_or("generated_dns_rule")?;
    let guard = value
        .pointer("/route/rules/2")
        .cloned()
        .ok_or("generated_guard")?;
    if dns != json!({"inbound":["tun-in"],"network":["tcp","udp"],"port":53,"action":"hijack-dns"})
    {
        return Err("unexpected_production_dns_rule");
    }
    if guard
        != json!({"inbound":["tun-in"],"ip_cidr":["172.19.0.0/30"],"action":"reject","method":"drop"})
    {
        return Err("unexpected_production_guard");
    }
    Ok((dns, guard))
}

fn run_case(
    label: &'static str,
    new_rule: bool,
    destination_port: u16,
) -> Result<(), &'static str> {
    let dns = FixtureDns::start()?;
    let tcp_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| "reserve_tcp")?;
    let port = tcp_reservation
        .local_addr()
        .map_err(|_| "reserve_address")?
        .port();
    let udp_reservation =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).map_err(|_| "reserve_udp")?;
    let (mut dns_rule, guard) = generated_rules()?;
    if !new_rule {
        let rule = dns_rule.as_object_mut().ok_or("dns_rule_shape")?;
        rule.remove("port");
        rule.remove("network");
        rule.insert("protocol".into(), json!("dns"));
    }
    let config = json!({
        "log":{"level":"error","timestamp":false},
        "dns": {
            "servers":[{"type":"udp","tag":"fixture","server":"127.0.0.1","server_port":dns.port}],
            "final":"fixture", "disable_cache":true
        },
        "inbounds":[{
            "type":"direct", "tag":"tun-in", "listen":"127.0.0.1", "listen_port":port,
            "override_address":"172.19.0.2", "override_port":destination_port
        }],
        "route":{"rules":[
            dns_rule,
            guard,
            {"action":"reject","method":"drop"}
        ]},
        "outbounds":[{"type":"direct","tag":"direct"}]
    });
    // No API can receive a caller-selected address: DNS only dials loopback and
    // route fallthrough is rejected before the otherwise unused direct outbound.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let session = SessionConfig::create(
        &root.join("target/dns-hijack-fixtures"),
        &config.to_string(),
    )
    .map_err(|_| "session_create")?;
    let directory = session.path().parent().ok_or("session_path")?.to_owned();
    let launcher = engine_runtime::fixture_launcher(&root.join("target/release"))
        .map_err(|_| "engine_layout")?;
    let diagnostics = Arc::new(Mutex::new(DiagnosticBuffer::default()));
    let version = launcher
        .check(
            &session,
            redaction::Redactor::default(),
            diagnostics.clone(),
        )
        .map_err(|_| "config_check")?;
    if version != "1.13.21" {
        return Err("engine_version");
    }
    drop(tcp_reservation);
    drop(udp_reservation);
    let mut child = launcher
        .start(&session, redaction::Redactor::default(), diagnostics)
        .map_err(|_| "engine_start")?;
    let test_result = (|| {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if !child.is_alive().map_err(|_| "engine_state")? {
                return Err("engine_died");
            }
            if TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_millis(50),
            )
            .is_ok()
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("listener_timeout");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let udp = query_udp(port, 0x1201);
        let tcp = query_tcp(port, 0x1202);
        let hits = dns.requests.load(Ordering::Acquire);
        let expected = new_rule && destination_port == 53;
        println!("case={label} udp_answer={udp} tcp_answer={tcp} fixture_dns_hits={hits}");
        if udp != expected || tcp != expected || (expected && hits != 2) || (!expected && hits != 0)
        {
            return Err("unexpected_routing_result");
        }
        Ok(())
    })();
    child.stop().map_err(|_| "engine_stop")?;
    if child.is_alive().map_err(|_| "engine_state")? {
        return Err("engine_remains");
    }
    drop(child);
    drop(launcher);
    drop(session);
    if directory.exists() {
        return Err("session_remains");
    }
    println!("case={label} child_stopped=true session_removed=true");
    test_result
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| {
        run_case("old_protocol_rule", false, 53)?;
        run_case("new_port53_rule", true, 53)?;
        run_case("non53_still_rejected", true, 54)?;
        Ok::<_, &'static str>(())
    });
    match result {
        Ok(Ok(())) => println!("result=passed"),
        Ok(Err(stage)) => {
            println!("result=failed stage={stage}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("result=failed stage=panic");
            std::process::exit(1);
        }
    }
}
