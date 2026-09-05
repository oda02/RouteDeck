use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::domain::{
    AppRouteAction, DefaultRoute, DnsPolicy, HysteriaObfsKind, InsecureApproval, Ipv6Policy,
    LanPolicy, Node, NodeProtocol, PacketEncoding, PortSelection, RoutePolicy, Secret, TlsOptions,
    VlessFlow, VlessTransport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPorts {
    pub http: u16,
    pub socks: u16,
    pub health: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureMode {
    LocalProxy,
    SystemProxy,
    Tun(TunSettings),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunStack {
    System,
    Gvisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunTrafficNetwork {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunTrafficAction {
    Block,
    Direct,
    Vpn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunTrafficRule {
    pub network: TunTrafficNetwork,
    pub port: u16,
    pub action: TunTrafficAction,
}

pub fn default_tun_traffic_rules() -> Vec<TunTrafficRule> {
    vec![TunTrafficRule {
        network: TunTrafficNetwork::Udp,
        port: 443,
        action: TunTrafficAction::Block,
    }]
}

pub fn validate_tun_traffic_rules(rules: &[TunTrafficRule]) -> Result<(), ConfigError> {
    if rules.len() > 32 || rules.iter().any(|rule| rule.port == 0 || rule.port == 53) {
        return Err(ConfigError::new("TUN traffic rules are invalid"));
    }
    Ok(())
}

impl Default for TunStack {
    fn default() -> Self {
        Self::Gvisor
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    pub ipv4_address: String,
    pub ipv6_address: Option<String>,
    pub stack: TunStack,
    pub traffic_rules: Vec<TunTrafficRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunUpstream {
    pub interface_alias: String,
    pub ipv4_dns_server: Option<Ipv4Addr>,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            ipv4_address: "172.19.0.1/30".into(),
            ipv6_address: Some("fdfe:dcba:9876::1/126".into()),
            stack: TunStack::default(),
            traffic_rules: default_tun_traffic_rules(),
        }
    }
}

pub struct ConfigRequest<'a> {
    pub node: &'a Node,
    pub policy: &'a RoutePolicy,
    pub mode: CaptureMode,
    pub ports: LocalPorts,
    pub health_password: String,
    pub vpn_dns: Option<VpnDnsServer>,
    pub insecure_approval: Option<&'a InsecureApproval>,
    pub tun_upstream: Option<TunUpstream>,
    pub naive_udp_over_tcp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnDnsServer {
    pub server: IpAddr,
    pub server_name: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocksBridge {
    pub server_port: u16,
}

pub struct GeneratedConfig(String);

impl GeneratedConfig {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for GeneratedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedConfig([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(&'static str);

impl ConfigError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

pub fn generate_config(request: ConfigRequest<'_>) -> Result<GeneratedConfig, ConfigError> {
    generate_config_with_selected(request, None)
}

pub fn generate_socks_bridge_config(
    request: ConfigRequest<'_>,
    bridge: SocksBridge,
) -> Result<GeneratedConfig, ConfigError> {
    if !matches!(
        request.node.protocol(),
        NodeProtocol::Vless(vless) if vless.tls.reality.is_some()
    ) {
        return Err(ConfigError::new(
            "SOCKS bridge is only supported for VLESS REALITY nodes",
        ));
    }
    if bridge.server_port == 0 {
        return Err(ConfigError::new("SOCKS bridge port must be non-zero"));
    }
    generate_config_with_selected(request, Some(selected_socks_bridge(bridge.server_port)))
}

fn generate_config_with_selected(
    request: ConfigRequest<'_>,
    selected_override: Option<Value>,
) -> Result<GeneratedConfig, ConfigError> {
    validate_request(&request)?;
    let selected_is_socks_bridge = selected_override.is_some();
    let tun_upstream_alias = request
        .tun_upstream
        .as_ref()
        .map(validated_tun_interface_alias)
        .transpose()?;
    let tun_own_prefixes = match &request.mode {
        CaptureMode::Tun(settings) => {
            let mut prefixes = vec![canonical_tun_prefix(&settings.ipv4_address)?];
            if request.policy.ipv6 == Ipv6Policy::Enabled {
                if let Some(address) = &settings.ipv6_address {
                    prefixes.push(canonical_tun_prefix(address)?);
                }
            }
            Some(prefixes)
        }
        CaptureMode::LocalProxy | CaptureMode::SystemProxy => None,
    };
    let health_password = Secret::new(request.health_password)
        .map_err(|_| ConfigError::new("invalid health-listener credential"))?;

    let mut inbounds = vec![
        json!({
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "listen_port": request.ports.http
        }),
        json!({
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": request.ports.socks
        }),
        json!({
            "type": "http",
            "tag": "health-in",
            "listen": "127.0.0.1",
            "listen_port": request.ports.health,
            "users": [{
                "username": crate::runtime_constants::HEALTH_PROXY_USERNAME,
                "password": health_password.expose()
            }]
        }),
    ];
    if let CaptureMode::Tun(settings) = &request.mode {
        let mut addresses = vec![Value::String(settings.ipv4_address.clone())];
        if request.policy.ipv6 == Ipv6Policy::Enabled {
            if let Some(address) = &settings.ipv6_address {
                addresses.push(Value::String(address.clone()));
            }
        }
        inbounds.push(json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "RouteDeck",
            "address": addresses,
            "auto_route": true,
            "strict_route": true,
            "stack": settings.stack
        }));
    }

    let mut selected = match selected_override {
        Some(selected) => selected,
        None => selected_outbound(request.node, request.naive_udp_over_tcp)?,
    };
    let mut bootstrap_dns = if matches!(request.mode, CaptureMode::Tun(_)) {
        request
            .tun_upstream
            .as_ref()
            .and_then(|upstream| upstream.ipv4_dns_server)
            .map_or_else(
                || json!({ "type": "local", "tag": "bootstrap" }),
                |server| {
                    json!({
                        "type": "tcp", "tag": "bootstrap", "server": server,
                        "server_port": 53,
                        "bind_interface": tun_upstream_alias.expect("validated TUN upstream")
                    })
                },
            )
    } else {
        json!({ "type": "local", "tag": "bootstrap" })
    };
    if selected_is_socks_bridge {
        if let Some(interface_alias) = tun_upstream_alias {
            bootstrap_dns
                .as_object_mut()
                .expect("generated DNS server must be an object")
                .insert("bind_interface".into(), json!(interface_alias));
        }
    }
    let mut dns_servers = vec![bootstrap_dns];
    let dns_final = match request.policy.dns {
        DnsPolicy::CurrentNetwork => "bootstrap",
        DnsPolicy::Vpn => {
            let dns = request.vpn_dns.as_ref().ok_or_else(|| {
                ConfigError::new("VPN DNS server is required by the route policy")
            })?;
            selected
                .as_object_mut()
                .ok_or_else(|| ConfigError::new("internal outbound generation failure"))?
                .insert("domain_resolver".into(), Value::String("bootstrap".into()));
            dns_servers.push(json!({
                "type": "https",
                "tag": "remote-dns",
                "server": dns.server.to_string(),
                "server_port": 443,
                "path": dns.path,
                "tls": { "enabled": true, "server_name": dns.server_name },
                "detour": "selected"
            }));
            "remote-dns"
        }
    };

    let mut rules = Vec::new();
    // This must stay first: it makes an end-to-end probe structurally incapable of direct fallback.
    rules.push(json!({ "inbound": ["health-in"], "action": "route", "outbound": "selected" }));
    if matches!(request.mode, CaptureMode::Tun(_)) {
        // TUN metadata has no sniffed protocol at pre-match time. Match the DNS port
        // directly so Windows DNS to the virtual gateway is handled before its own-prefix drop.
        rules.push(tun_dns_hijack_rule());
        rules.push(json!({
            "inbound": ["tun-in"],
            "ip_cidr": tun_own_prefixes
                .as_ref()
                .expect("validated TUN mode must have canonical own prefixes"),
            "action": "reject",
            "method": "drop"
        }));
    }
    // User traffic must not escape an IPv4-only policy through a more-specific app or LAN rule.
    // Health remains first; TUN DNS hijacking and the own-prefix guard remain ahead of this rule.
    if request.policy.ipv6 == Ipv6Policy::Disabled {
        rules.push(json!({ "ip_version": 6, "action": "reject" }));
    }
    if let CaptureMode::Tun(settings) = &request.mode {
        for traffic_rule in &settings.traffic_rules {
            let network = match traffic_rule.network {
                TunTrafficNetwork::Tcp => "tcp",
                TunTrafficNetwork::Udp => "udp",
            };
            rules.push(match traffic_rule.action {
                TunTrafficAction::Block => json!({
                    "inbound": ["tun-in"],
                    "network": [network],
                    "port": traffic_rule.port,
                    "action": "reject",
                    "method": "default",
                    "no_drop": true
                }),
                TunTrafficAction::Direct | TunTrafficAction::Vpn => json!({
                    "inbound": ["tun-in"],
                    "network": [network],
                    "port": traffic_rule.port,
                    "action": "route",
                    "outbound": match traffic_rule.action {
                        TunTrafficAction::Direct => "direct",
                        TunTrafficAction::Vpn => "selected",
                        TunTrafficAction::Block => unreachable!(),
                    }
                }),
            });
        }
    }
    for app in &request.policy.apps {
        rules.push(json!({
            // sing-box 1.13.x compares Windows process paths case-sensitively. Preserve the
            // QueryFullProcessImageNameW casing supplied by the application picker; only the
            // identity/duplicate checks in the domain model may use a lower-cased key.
            "process_path": [app.process_path.trim().replace('/', "\\")],
            "action": "route",
            "outbound": action_outbound(app.action)
        }));
    }
    if request.policy.lan == LanPolicy::Direct {
        rules.push(json!({ "ip_is_private": true, "action": "route", "outbound": "direct" }));
    }

    let mut route = json!({
        "rules": rules,
        "final": default_outbound(request.policy.default),
        "default_domain_resolver": "bootstrap"
    });
    if matches!(request.mode, CaptureMode::Tun(_)) && !selected_is_socks_bridge {
        route
            .as_object_mut()
            .expect("generated route must be an object")
            .insert(
                "default_interface".into(),
                json!(tun_upstream_alias.expect("validated TUN mode must have an upstream")),
            );
    }

    let mut direct = json!({ "type": "direct", "tag": "direct" });
    if selected_is_socks_bridge {
        if let Some(interface_alias) = tun_upstream_alias {
            direct
                .as_object_mut()
                .expect("generated direct outbound must be an object")
                .insert("bind_interface".into(), json!(interface_alias));
        }
    }

    let root = json!({
        // Runtime failures must remain diagnosable. The controller captures stderr into a
        // bounded buffer and applies the session redactor before storing any line.
        "log": { "level": "error", "timestamp": false },
        "dns": {
            "servers": dns_servers,
            "final": dns_final,
            "strategy": if request.policy.ipv6 == Ipv6Policy::Enabled { "prefer_ipv4" } else { "ipv4_only" }
        },
        "inbounds": inbounds,
        "outbounds": [selected, direct],
        "route": route
    });
    validate_no_direct_health(&root)?;
    if let Some(prefixes) = &tun_own_prefixes {
        validate_tun_own_prefix_guard(&root, prefixes)?;
        validate_tun_upstream_binding(
            &root,
            tun_upstream_alias.expect("validated TUN mode must have an upstream"),
            selected_is_socks_bridge,
        )?;
    }
    let text = serde_json::to_string_pretty(&root)
        .map_err(|_| ConfigError::new("could not serialize generated configuration"))?;
    Ok(GeneratedConfig(text))
}

fn selected_socks_bridge(server_port: u16) -> Value {
    json!({
        "type": "socks",
        "tag": "selected",
        "server": "127.0.0.1",
        "server_port": server_port,
        "version": "5"
    })
}

pub fn validate_no_direct_health(config: &Value) -> Result<(), ConfigError> {
    let selected = config
        .get("outbounds")
        .and_then(Value::as_array)
        .and_then(|outbounds| {
            outbounds
                .iter()
                .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("selected"))
        })
        .ok_or_else(|| ConfigError::new("generated configuration has no selected outbound"))?;
    if matches!(
        selected.get("type").and_then(Value::as_str),
        None | Some("direct" | "block")
    ) {
        return Err(ConfigError::new(
            "selected outbound cannot bypass or block the traffic proof",
        ));
    }
    let inbounds = config
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfigError::new("generated configuration has no inbounds"))?;
    let health = inbounds
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some("health-in"))
        .ok_or_else(|| ConfigError::new("generated configuration has no health inbound"))?;
    if health.get("listen").and_then(Value::as_str) != Some("127.0.0.1")
        || health
            .get("users")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err(ConfigError::new(
            "health inbound must be authenticated and loopback-only",
        ));
    }
    let rules = config
        .pointer("/route/rules")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfigError::new("generated configuration has no route rules"))?;
    let first = rules
        .first()
        .ok_or_else(|| ConfigError::new("generated configuration has no health route"))?;
    if !rule_mentions_health(first)
        || first.get("action").and_then(Value::as_str) != Some("route")
        || first.get("outbound").and_then(Value::as_str) != Some("selected")
    {
        return Err(ConfigError::new(
            "health traffic is not forced through selected outbound",
        ));
    }
    if rules.iter().skip(1).any(rule_mentions_health) {
        return Err(ConfigError::new(
            "health traffic has an ambiguous later route",
        ));
    }
    Ok(())
}

fn tun_dns_hijack_rule() -> Value {
    json!({ "inbound": ["tun-in"], "network": ["tcp", "udp"], "port": 53, "action": "hijack-dns" })
}

pub(crate) fn validate_tun_dns_hijack(config: &Value) -> Result<(), ConfigError> {
    if config.pointer("/route/rules/1") != Some(&tun_dns_hijack_rule()) {
        return Err(ConfigError::new(
            "TUN TCP/UDP port 53 DNS hijack must precede the own-prefix guard",
        ));
    }
    Ok(())
}

pub(crate) fn validate_tun_own_prefix_guard(
    config: &Value,
    expected_prefixes: &[String],
) -> Result<(), ConfigError> {
    let tun_inbound = config
        .get("inbounds")
        .and_then(Value::as_array)
        .and_then(|inbounds| {
            inbounds
                .iter()
                .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some("tun-in"))
        })
        .ok_or_else(|| ConfigError::new("generated configuration has no TUN inbound"))?;
    let inbound_prefixes = tun_inbound
        .get("address")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfigError::new("generated TUN inbound has no addresses"))?
        .iter()
        .map(|address| {
            address
                .as_str()
                .ok_or_else(|| ConfigError::new("generated TUN address is invalid"))
                .and_then(canonical_tun_prefix)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if inbound_prefixes != expected_prefixes {
        return Err(ConfigError::new(
            "TUN own-prefix guard does not match the inbound networks",
        ));
    }
    let rules = config
        .pointer("/route/rules")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfigError::new("generated configuration has no route rules"))?;
    validate_tun_dns_hijack(config)?;
    let guard = rules
        .get(2)
        .ok_or_else(|| ConfigError::new("TUN own-prefix guard is missing"))?;
    let actual_prefixes = guard
        .get("ip_cidr")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfigError::new("TUN own-prefix guard has no CIDRs"))?;
    let prefix_match = actual_prefixes.len() == expected_prefixes.len()
        && actual_prefixes
            .iter()
            .zip(expected_prefixes)
            .all(|(actual, expected)| actual.as_str() == Some(expected.as_str()));
    if guard.pointer("/inbound/0").and_then(Value::as_str) != Some("tun-in")
        || guard
            .get("inbound")
            .and_then(Value::as_array)
            .is_none_or(|inbounds| inbounds.len() != 1)
        || !prefix_match
        || guard.get("action").and_then(Value::as_str) != Some("reject")
        || guard.get("method").and_then(Value::as_str) != Some("drop")
        || guard.get("outbound").is_some()
    {
        return Err(ConfigError::new(
            "TUN own-prefix guard must drop the exact TUN CIDRs before routing",
        ));
    }
    Ok(())
}

fn validate_tun_upstream_binding(
    config: &Value,
    expected_alias: &str,
    socks_bridge: bool,
) -> Result<(), ConfigError> {
    let route = config
        .get("route")
        .and_then(Value::as_object)
        .ok_or_else(|| ConfigError::new("generated configuration has no route"))?;
    if route.contains_key("auto_detect_interface") {
        return Err(ConfigError::new(
            "TUN upstream must be sealed before automatic route mutation",
        ));
    }
    let outbounds = config
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| ConfigError::new("generated configuration has no outbounds"))?;
    let selected = outbounds
        .iter()
        .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("selected"))
        .ok_or_else(|| ConfigError::new("generated configuration has no selected outbound"))?;
    let direct = outbounds
        .iter()
        .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("direct"))
        .ok_or_else(|| ConfigError::new("generated configuration has no direct outbound"))?;
    let bootstrap = config
        .pointer("/dns/servers")
        .and_then(Value::as_array)
        .and_then(|servers| {
            servers
                .iter()
                .find(|server| server.get("tag").and_then(Value::as_str) == Some("bootstrap"))
        })
        .ok_or_else(|| ConfigError::new("generated configuration has no bootstrap DNS server"))?;

    if socks_bridge {
        let selected_is_unbound_loopback = selected.get("type").and_then(Value::as_str)
            == Some("socks")
            && selected.get("server").and_then(Value::as_str) == Some("127.0.0.1")
            && selected.get("bind_interface").is_none();
        if !selected_is_unbound_loopback
            || route.get("default_interface").is_some()
            || direct.get("bind_interface").and_then(Value::as_str) != Some(expected_alias)
            || bootstrap.get("bind_interface").and_then(Value::as_str) != Some(expected_alias)
        {
            return Err(ConfigError::new(
                "TUN SOCKS bridge does not preserve loopback and physical bindings",
            ));
        }
    } else if route.get("default_interface").and_then(Value::as_str) != Some(expected_alias)
        || selected.get("bind_interface").is_some()
        || direct.get("bind_interface").is_some()
        || !(bootstrap.get("bind_interface").is_none()
            || (bootstrap.get("type").and_then(Value::as_str) == Some("tcp")
                && bootstrap.get("bind_interface").and_then(Value::as_str) == Some(expected_alias)))
    {
        return Err(ConfigError::new(
            "native TUN outbounds are not sealed to the physical interface",
        ));
    }
    Ok(())
}

fn validate_request(request: &ConfigRequest<'_>) -> Result<(), ConfigError> {
    if request.node.requires_insecure_approval()
        && !request
            .insecure_approval
            .is_some_and(|approval| approval.matches(request.node))
    {
        return Err(ConfigError::new(
            "insecure TLS requires explicit approval for the current node security identity",
        ));
    }
    let ports = [
        request.ports.http,
        request.ports.socks,
        request.ports.health,
    ];
    if ports.contains(&0) || ports.into_iter().collect::<BTreeSet<_>>().len() != ports.len() {
        return Err(ConfigError::new(
            "local listener ports must be non-zero and distinct",
        ));
    }
    request
        .policy
        .validate()
        .map_err(|_| ConfigError::new("route policy is invalid"))?;
    if matches!(request.mode, CaptureMode::LocalProxy)
        && (request.policy.default != DefaultRoute::Vpn
            || !request.policy.apps.is_empty()
            || request.policy.lan != LanPolicy::FollowDefault)
    {
        return Err(ConfigError::new(
            "proxy runtime must route ordinary traffic through selected outbound",
        ));
    }
    if let CaptureMode::Tun(settings) = &request.mode {
        let upstream = request
            .tun_upstream
            .as_ref()
            .ok_or_else(|| ConfigError::new("TUN physical upstream is required"))?;
        validated_tun_interface_alias(upstream)?;
        if upstream.ipv4_dns_server.is_some_and(|address| {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address == Ipv4Addr::BROADCAST
        }) {
            return Err(ConfigError::new("TUN DNS server is invalid"));
        }
        validate_tun_address(&settings.ipv4_address, false)?;
        validate_tun_traffic_rules(&settings.traffic_rules)?;
        if request.policy.ipv6 == Ipv6Policy::Enabled {
            let address = settings
                .ipv6_address
                .as_deref()
                .ok_or_else(|| ConfigError::new("IPv6 TUN address is required"))?;
            validate_tun_address(address, true)?;
        }
    } else if request.tun_upstream.is_some() {
        return Err(ConfigError::new(
            "physical upstream binding is only valid in TUN mode",
        ));
    }
    if let Some(dns) = &request.vpn_dns {
        if dns.server_name.is_empty()
            || dns.server_name.chars().any(char::is_control)
            || !dns.path.starts_with('/')
            || dns.path.len() > 1_024
            || dns.path.chars().any(char::is_control)
        {
            return Err(ConfigError::new("VPN DNS endpoint is invalid"));
        }
    }
    Ok(())
}

pub(crate) fn validated_tun_interface_alias(upstream: &TunUpstream) -> Result<&str, ConfigError> {
    let alias = upstream.interface_alias.as_str();
    if alias.is_empty()
        || alias.trim() != alias
        || alias.encode_utf16().count() > 256
        || alias.chars().any(char::is_control)
        || alias.eq_ignore_ascii_case("RouteDeck")
    {
        return Err(ConfigError::new("TUN physical interface alias is invalid"));
    }
    Ok(alias)
}

fn validate_tun_address(value: &str, ipv6: bool) -> Result<(), ConfigError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ConfigError::new("TUN address must include a prefix length"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ConfigError::new("TUN address is invalid"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ConfigError::new("TUN prefix is invalid"))?;
    match (address, ipv6) {
        (IpAddr::V4(address), false) if address.is_private() && prefix <= 32 => Ok(()),
        (IpAddr::V6(address), true)
            if (address.segments()[0] & 0xfe00) == 0xfc00 && prefix <= 128 =>
        {
            Ok(())
        }
        _ => Err(ConfigError::new(
            "TUN address must use a private address family",
        )),
    }
}

pub(crate) fn canonical_tun_prefix(value: &str) -> Result<String, ConfigError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ConfigError::new("TUN address must include a prefix length"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ConfigError::new("TUN address is invalid"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ConfigError::new("TUN prefix is invalid"))?;
    let network = match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
        _ => return Err(ConfigError::new("TUN prefix is invalid")),
    };
    Ok(format!("{network}/{prefix}"))
}

fn selected_outbound(node: &Node, naive_udp_over_tcp: bool) -> Result<Value, ConfigError> {
    let mut object = Map::new();
    object.insert(
        "type".into(),
        Value::String(
            match node.protocol() {
                NodeProtocol::Vless(_) => "vless",
                NodeProtocol::Hysteria2(_) => "hysteria2",
                NodeProtocol::Naive(_) => "naive",
            }
            .into(),
        ),
    );
    object.insert("tag".into(), Value::String("selected".into()));
    object.insert("server".into(), Value::String(node.server().into()));
    match node.protocol() {
        NodeProtocol::Vless(vless) => {
            object.insert("server_port".into(), json!(vless.server_port));
            object.insert("uuid".into(), json!(vless.uuid.expose()));
            if let Some(VlessFlow::Vision) = vless.flow {
                object.insert("flow".into(), json!("xtls-rprx-vision"));
            }
            if let Some(encoding) = vless.packet_encoding {
                object.insert(
                    "packet_encoding".into(),
                    json!(match encoding {
                        PacketEncoding::PacketAddr => "packetaddr",
                        PacketEncoding::Xudp => "xudp",
                    }),
                );
            }
            match &vless.transport {
                VlessTransport::Tcp => {}
                VlessTransport::WebSocket { path, host } => {
                    let mut transport = Map::new();
                    transport.insert("type".into(), json!("ws"));
                    transport.insert("path".into(), json!(path));
                    if let Some(host) = host {
                        transport.insert("headers".into(), json!({ "Host": host }));
                    }
                    object.insert("transport".into(), Value::Object(transport));
                }
                VlessTransport::Grpc { service_name } => {
                    let mut transport = Map::new();
                    transport.insert("type".into(), json!("grpc"));
                    if !service_name.is_empty() {
                        transport.insert("service_name".into(), json!(service_name));
                    }
                    object.insert("transport".into(), Value::Object(transport));
                }
            }
            if vless.tls.enabled {
                object.insert("tls".into(), tls_value(&vless.tls, true));
            }
        }
        NodeProtocol::Hysteria2(hysteria) => {
            match &hysteria.ports {
                PortSelection::Single(port) => {
                    object.insert("server_port".into(), json!(port));
                }
                PortSelection::Ranges(ports) => {
                    object.insert("server_ports".into(), json!(ports));
                }
            }
            if let Some(interval) = &hysteria.hop_interval {
                object.insert("hop_interval".into(), json!(interval));
            }
            object.insert("password".into(), json!(hysteria.password.expose()));
            if let Some(obfs) = &hysteria.obfs {
                object.insert(
                    "obfs".into(),
                    json!({
                        "type": match obfs.kind { HysteriaObfsKind::Salamander => "salamander" },
                        "password": obfs.password.expose()
                    }),
                );
            }
            object.insert("tls".into(), tls_value(&hysteria.tls, true));
        }
        NodeProtocol::Naive(naive) => {
            object.insert("server_port".into(), json!(naive.server_port));
            if let Some(username) = &naive.username {
                object.insert("username".into(), json!(username.expose()));
            }
            if let Some(password) = &naive.password {
                object.insert("password".into(), json!(password.expose()));
            }
            if !naive.extra_headers.is_empty() {
                object.insert("extra_headers".into(), json!(naive.extra_headers));
            }
            if naive.quic {
                object.insert("quic".into(), json!(true));
            }
            object.insert("tls".into(), tls_value(&naive.tls, true));
            if naive_udp_over_tcp {
                object.insert(
                    "udp_over_tcp".into(),
                    json!({ "enabled": true, "version": 2 }),
                );
            }
        }
    }
    Ok(Value::Object(object))
}

fn tls_value(tls: &TlsOptions, include_enabled: bool) -> Value {
    let mut object = Map::new();
    if include_enabled {
        object.insert("enabled".into(), json!(true));
    }
    if let Some(value) = &tls.server_name {
        object.insert("server_name".into(), json!(value));
    }
    if tls.insecure {
        object.insert("insecure".into(), json!(true));
    }
    if !tls.alpn.is_empty() {
        object.insert("alpn".into(), json!(tls.alpn));
    }
    if !tls.certificate_public_key_sha256.is_empty() {
        object.insert(
            "certificate_public_key_sha256".into(),
            json!(tls
                .certificate_public_key_sha256
                .iter()
                .map(Secret::expose)
                .collect::<Vec<_>>()),
        );
    }
    if let Some(fingerprint) = &tls.utls_fingerprint {
        object.insert(
            "utls".into(),
            json!({ "enabled": true, "fingerprint": fingerprint }),
        );
    }
    if let Some(reality) = &tls.reality {
        object.insert("reality".into(), json!({ "enabled": true, "public_key": reality.public_key.expose(), "short_id": reality.short_id.expose() }));
    }
    if !tls.ech_config.is_empty() {
        object.insert("ech".into(), json!({ "enabled": true, "config": tls.ech_config.iter().map(Secret::expose).collect::<Vec<_>>() }));
    }
    Value::Object(object)
}

fn action_outbound(action: AppRouteAction) -> &'static str {
    match action {
        AppRouteAction::Direct => "direct",
        AppRouteAction::Vpn => "selected",
    }
}

fn default_outbound(default: DefaultRoute) -> &'static str {
    match default {
        DefaultRoute::Direct => "direct",
        DefaultRoute::Vpn => "selected",
    }
}

fn rule_mentions_health(rule: &Value) -> bool {
    rule.get("inbound")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some("health-in"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::SourceFormat, subscription::import_subscription};

    fn node(link: &str) -> Node {
        import_subscription(link.as_bytes())
            .unwrap()
            .nodes
            .remove(0)
    }

    fn policy(default: DefaultRoute) -> RoutePolicy {
        RoutePolicy {
            default,
            apps: Vec::new(),
            lan: LanPolicy::FollowDefault,
            ipv6: Ipv6Policy::Enabled,
            dns: DnsPolicy::CurrentNetwork,
        }
    }

    fn request<'a>(node: &'a Node, policy: &'a RoutePolicy) -> ConfigRequest<'a> {
        ConfigRequest {
            node,
            policy,
            mode: CaptureMode::LocalProxy,
            ports: LocalPorts {
                http: 18080,
                socks: 18081,
                health: 18082,
            },
            health_password: "fixture-health-secret".into(),
            vpn_dns: None,
            insecure_approval: None,
            tun_upstream: None,
            naive_udp_over_tcp: false,
        }
    }

    fn tun_upstream(interface_alias: &str) -> TunUpstream {
        TunUpstream {
            interface_alias: interface_alias.into(),
            ipv4_dns_server: None,
        }
    }

    #[test]
    fn deterministic_vless_local_proxy_forces_all_ordinary_traffic_to_selected() {
        let link = "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none&security=tls&type=tcp&sni=cover.test&flow=xtls-rprx-vision";
        let node = node(link);
        assert_eq!(node.source_format(), SourceFormat::ShareLink);
        let policy = policy(DefaultRoute::Vpn);
        let first = generate_config(request(&node, &policy)).unwrap();
        let second = generate_config(request(&node, &policy)).unwrap();
        assert_eq!(first.as_str(), second.as_str());
        let value: Value = serde_json::from_str(first.as_str()).unwrap();
        validate_no_direct_health(&value).unwrap();
        assert_eq!(
            value.pointer("/route/final").and_then(Value::as_str),
            Some("selected")
        );

        assert_eq!(
            value.pointer("/outbounds/0/flow").and_then(Value::as_str),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            value
                .pointer("/inbounds/2/users/0/username")
                .and_then(Value::as_str),
            Some(crate::runtime_constants::HEALTH_PROXY_USERNAME)
        );
        assert_eq!(
            value.pointer("/log/level").and_then(Value::as_str),
            Some("error")
        );
        assert_eq!(
            value.pointer("/log/timestamp").and_then(Value::as_bool),
            Some(false)
        );
        assert!(value.pointer("/log/disabled").is_none());
        assert!(value.pointer("/route/auto_detect_interface").is_none());
        assert!(!first.as_str().contains("dns_mode"));
        assert!(!first.as_str().contains("hop_interval_max"));
        assert!(!first.as_str().contains("\"engine\""));
        assert!(!format!("{first:?}").contains("fixture-health-secret"));
    }

    #[test]
    fn preserves_all_vless_reality_client_fields_from_share_link() {
        let public_key = "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789";
        let link = format!(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=cover.test&fp=chrome&pbk={public_key}&sid=a1b2&spx=%2Fprivate#Reality"
        );
        let node = node(&link);
        let policy = policy(DefaultRoute::Vpn);
        let value: Value =
            serde_json::from_str(generate_config(request(&node, &policy)).unwrap().as_str())
                .unwrap();

        assert_eq!(
            value.pointer("/outbounds/0/type").and_then(Value::as_str),
            Some("vless")
        );
        assert_eq!(
            value.pointer("/outbounds/0/flow").and_then(Value::as_str),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/tls/server_name")
                .and_then(Value::as_str),
            Some("cover.test")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/tls/utls/fingerprint")
                .and_then(Value::as_str),
            Some("chrome")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/tls/reality/public_key")
                .and_then(Value::as_str),
            Some(public_key)
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/tls/reality/short_id")
                .and_then(Value::as_str),
            Some("a1b2")
        );
        assert!(value.pointer("/outbounds/0/transport").is_none());
        assert!(!value.to_string().contains("spx"));
        assert!(!value.to_string().contains("private"));
    }

    #[test]
    fn vless_reality_bridge_replaces_only_the_selected_outbound() {
        let node = node(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2",
        );
        let policy = policy(DefaultRoute::Vpn);
        let generated = generate_socks_bridge_config(
            request(&node, &policy),
            SocksBridge { server_port: 19090 },
        )
        .unwrap();
        let value: Value = serde_json::from_str(generated.as_str()).unwrap();

        assert_eq!(
            value.pointer("/outbounds/0/type").and_then(Value::as_str),
            Some("socks")
        );
        assert_eq!(
            value.pointer("/outbounds/0/server").and_then(Value::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/server_port")
                .and_then(Value::as_u64),
            Some(19090)
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/version")
                .and_then(Value::as_str),
            Some("5")
        );
        assert_eq!(
            value.pointer("/route/final").and_then(Value::as_str),
            Some("selected")
        );
        assert_eq!(
            value
                .pointer("/route/rules/0/inbound/0")
                .and_then(Value::as_str),
            Some("health-in")
        );
        assert_eq!(
            value
                .pointer("/route/rules/0/outbound")
                .and_then(Value::as_str),
            Some("selected")
        );
        assert!(!generated.as_str().contains("example.test"));
        assert!(value.pointer("/outbounds/0/username").is_none());
        assert!(value.pointer("/outbounds/0/password").is_none());
        assert!(value.pointer("/route/default_interface").is_none());
        assert!(value.pointer("/route/auto_detect_interface").is_none());
        assert!(value.pointer("/outbounds/0/bind_interface").is_none());
        assert!(value.pointer("/outbounds/1/bind_interface").is_none());
        assert!(value.pointer("/dns/servers/0/bind_interface").is_none());
    }

    #[test]
    fn bridge_rejects_non_reality_nodes_and_zero_port() {
        let policy = policy(DefaultRoute::Vpn);
        let tls = node(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?security=tls&type=tcp&sni=cover.test",
        );
        assert!(generate_socks_bridge_config(
            request(&tls, &policy),
            SocksBridge { server_port: 19090 }
        )
        .is_err());

        let reality = node(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2",
        );
        assert!(generate_socks_bridge_config(
            request(&reality, &policy),
            SocksBridge { server_port: 0 }
        )
        .is_err());
    }

    #[test]
    fn local_proxy_rejects_renderer_routing_drafts() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test#fixture");
        let direct = policy(DefaultRoute::Direct);
        assert!(generate_config(request(&node, &direct)).is_err());
        let mut app_draft = policy(DefaultRoute::Vpn);
        app_draft.apps.push(crate::domain::AppRoute {
            process_path: r"C:\Apps\Browser.exe".into(),
            process_name: Some("Browser.exe".into()),
            action: AppRouteAction::Direct,
        });
        assert!(generate_config(request(&node, &app_draft)).is_err());
        let mut lan_draft = policy(DefaultRoute::Vpn);
        lan_draft.lan = LanPolicy::Direct;
        assert!(generate_config(request(&node, &lan_draft)).is_err());
    }

    #[test]
    fn system_proxy_applies_direct_default_and_case_preserving_application_routes() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test#fixture");
        let mut direct = policy(DefaultRoute::Direct);
        direct.lan = LanPolicy::Direct;
        direct.apps.push(crate::domain::AppRoute {
            process_path: r"C:/Program Files/Browser/Browser.EXE".into(),
            process_name: Some("Browser.exe".into()),
            action: AppRouteAction::Vpn,
        });
        let mut system_request = request(&node, &direct);
        system_request.mode = CaptureMode::SystemProxy;
        let generated = generate_config(system_request).unwrap();
        let value: Value = serde_json::from_str(generated.as_str()).unwrap();
        let rules = value
            .pointer("/route/rules")
            .and_then(Value::as_array)
            .unwrap();

        assert_eq!(
            rules[0].get("inbound").and_then(Value::as_array).unwrap(),
            &[json!("health-in")]
        );
        assert_eq!(
            rules[0].get("outbound").and_then(Value::as_str),
            Some("selected")
        );
        assert_eq!(
            rules[1]
                .get("process_path")
                .and_then(Value::as_array)
                .unwrap(),
            &[json!(r"C:\Program Files\Browser\Browser.EXE")]
        );
        assert_eq!(
            rules[1].get("outbound").and_then(Value::as_str),
            Some("selected")
        );
        assert_eq!(
            rules[2].get("ip_is_private").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            value.pointer("/route/final").and_then(Value::as_str),
            Some("direct")
        );
        assert!(value.pointer("/route/default_interface").is_none());
        assert!(value.pointer("/route/auto_detect_interface").is_none());
        assert!(value.pointer("/outbounds/0/bind_interface").is_none());
        assert!(value.pointer("/outbounds/1/bind_interface").is_none());
        assert!(value.pointer("/dns/servers/0/bind_interface").is_none());
    }

    #[test]
    fn system_proxy_ordinary_ingress_has_selected_as_its_final_route() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test#fixture");
        let mut selected = policy(DefaultRoute::Vpn);
        selected.lan = LanPolicy::FollowDefault;
        let mut selected_request = request(&node, &selected);
        selected_request.mode = CaptureMode::SystemProxy;
        let generated = generate_config(selected_request).unwrap();
        let value: Value = serde_json::from_str(generated.as_str()).unwrap();

        assert_eq!(
            value.pointer("/route/final").and_then(Value::as_str),
            Some("selected")
        );
        assert!(value
            .pointer("/route/rules")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .all(|rule| rule.get("process_path").is_none()));
    }

    #[test]
    fn system_proxy_vpn_default_keeps_direct_application_exception_before_final() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test#fixture");
        let mut selected = policy(DefaultRoute::Vpn);
        selected.lan = LanPolicy::Direct;
        selected.apps.push(crate::domain::AppRoute {
            process_path: r"C:\Apps\Browser.exe".into(),
            process_name: Some("Browser.exe".into()),
            action: AppRouteAction::Direct,
        });
        let mut system_request = request(&node, &selected);
        system_request.mode = CaptureMode::SystemProxy;
        let generated = generate_config(system_request).unwrap();
        let value: Value = serde_json::from_str(generated.as_str()).unwrap();
        let rules = value
            .pointer("/route/rules")
            .and_then(Value::as_array)
            .unwrap();

        assert_eq!(
            rules[0].get("outbound").and_then(Value::as_str),
            Some("selected")
        );
        assert_eq!(
            rules[1].get("process_path").and_then(Value::as_array),
            Some(&vec![json!(r"C:\Apps\Browser.exe")])
        );
        assert_eq!(
            rules[1].get("outbound").and_then(Value::as_str),
            Some("direct")
        );
        assert_eq!(
            value.pointer("/route/final").and_then(Value::as_str),
            Some("selected")
        );
    }

    #[test]
    fn structural_validator_rejects_direct_or_late_health_routes() {
        let mut value = json!({
            "outbounds": [{"type":"vless","tag":"selected"}],
            "inbounds": [{"tag":"health-in","listen":"127.0.0.1","users":[{"username":"x","password":"y"}]}],
            "route": {"rules":[{"inbound":["health-in"],"action":"route","outbound":"direct"}]}
        });
        assert!(validate_no_direct_health(&value).is_err());
        value["outbounds"][0]["type"] = json!("direct");
        assert!(validate_no_direct_health(&value).is_err());
        value["outbounds"][0]["type"] = json!("vless");
        value["route"]["rules"] = json!([
            {"inbound":["health-in"],"action":"route","outbound":"selected"},
            {"inbound":["health-in"],"action":"route","outbound":"direct"}
        ]);
        assert!(validate_no_direct_health(&value).is_err());
    }

    #[test]
    fn emits_hysteria_and_naive_113_shapes() {
        let hy2 = node("hysteria2://fixture-password@example.test:443?alpn=h3&fp=chrome&obfs=salamander&obfs-password=fixture-obfs&security=tls&sni=example.test");
        let naive = node("naive+quic://fixture-user:fixture-pass@example.test:443");
        let policy = policy(DefaultRoute::Vpn);
        let hy2_value: Value =
            serde_json::from_str(generate_config(request(&hy2, &policy)).unwrap().as_str())
                .unwrap();
        assert_eq!(
            hy2_value
                .pointer("/outbounds/0/obfs/type")
                .and_then(Value::as_str),
            Some("salamander")
        );
        assert_eq!(
            hy2_value
                .pointer("/outbounds/0/tls/alpn/0")
                .and_then(Value::as_str),
            Some("h3")
        );
        assert!(hy2_value.pointer("/outbounds/0/tls/utls").is_none());
        let naive_value: Value =
            serde_json::from_str(generate_config(request(&naive, &policy)).unwrap().as_str())
                .unwrap();
        assert_eq!(
            naive_value
                .pointer("/outbounds/0/quic")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(naive_value.pointer("/outbounds/0/udp_over_tcp").is_none());

        let mut uot_request = request(&naive, &policy);
        uot_request.naive_udp_over_tcp = true;
        let uot_value: Value =
            serde_json::from_str(generate_config(uot_request).unwrap().as_str()).unwrap();
        assert_eq!(
            uot_value.pointer("/outbounds/0/udp_over_tcp"),
            Some(&json!({"enabled": true, "version": 2}))
        );

        let mut ignored_request = request(&hy2, &policy);
        ignored_request.naive_udp_over_tcp = true;
        let ignored_value: Value =
            serde_json::from_str(generate_config(ignored_request).unwrap().as_str()).unwrap();
        assert!(ignored_value.pointer("/outbounds/0/udp_over_tcp").is_none());
        assert_eq!(
            naive_value
                .pointer("/outbounds/0/tls/enabled")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn tun_has_fixed_interface_and_no_114_fields() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut request = request(&node, &policy);
        request.mode = CaptureMode::Tun(TunSettings::default());
        request.tun_upstream = Some(tun_upstream("Ethernet"));
        let config = generate_config(request).unwrap();
        let value: Value = serde_json::from_str(config.as_str()).unwrap();
        assert_eq!(
            value
                .pointer("/inbounds/3/interface_name")
                .and_then(Value::as_str),
            Some("RouteDeck")
        );
        assert_eq!(
            value.pointer("/inbounds/3/stack").and_then(Value::as_str),
            Some("gvisor")
        );
        assert_eq!(
            value
                .pointer("/inbounds/3/strict_route")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(value.pointer("/inbounds/3/dns_mode").is_none());
        assert!(value.pointer("/route/auto_detect_interface").is_none());
        assert_eq!(
            value
                .pointer("/route/default_interface")
                .and_then(Value::as_str),
            Some("Ethernet")
        );
        for pointer in [
            "/outbounds/0/bind_interface",
            "/outbounds/1/bind_interface",
            "/dns/servers/0/bind_interface",
        ] {
            assert!(value.pointer(pointer).is_none(), "unexpected {pointer}");
        }
        let own_prefix_guard = value.pointer("/route/rules/2").unwrap();
        assert_eq!(
            own_prefix_guard.get("ip_cidr").and_then(Value::as_array),
            Some(&vec![json!("172.19.0.0/30"), json!("fdfe:dcba:9876::/126")])
        );
        assert_eq!(
            own_prefix_guard.get("action").and_then(Value::as_str),
            Some("reject")
        );
        assert_eq!(
            own_prefix_guard.get("method").and_then(Value::as_str),
            Some("drop")
        );
    }

    #[test]
    fn tun_stack_is_a_closed_lowercase_choice() {
        assert_eq!(TunStack::default(), TunStack::Gvisor);
        assert_eq!(
            serde_json::from_str::<TunStack>(r#""system""#).unwrap(),
            TunStack::System
        );
        assert_eq!(
            serde_json::from_str::<TunStack>(r#""gvisor""#).unwrap(),
            TunStack::Gvisor
        );
        for rejected in [r#""mixed""#, r#""Gvisor""#, r#""""#, "null"] {
            assert!(serde_json::from_str::<TunStack>(rejected).is_err());
        }

        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut generated_request = request(&node, &policy);
        generated_request.mode = CaptureMode::Tun(TunSettings {
            stack: TunStack::Gvisor,
            ..TunSettings::default()
        });
        generated_request.tun_upstream = Some(tun_upstream("Ethernet"));
        let value: Value =
            serde_json::from_str(generate_config(generated_request).unwrap().as_str()).unwrap();
        assert_eq!(
            value.pointer("/inbounds/3/stack").and_then(Value::as_str),
            Some("gvisor")
        );
    }

    #[test]
    fn tun_traffic_rules_are_ordered_closed_and_tun_scoped() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut configured = request(&node, &policy);
        configured.mode = CaptureMode::Tun(TunSettings {
            traffic_rules: vec![
                TunTrafficRule {
                    network: TunTrafficNetwork::Udp,
                    port: 443,
                    action: TunTrafficAction::Block,
                },
                TunTrafficRule {
                    network: TunTrafficNetwork::Tcp,
                    port: 8443,
                    action: TunTrafficAction::Direct,
                },
                TunTrafficRule {
                    network: TunTrafficNetwork::Udp,
                    port: 123,
                    action: TunTrafficAction::Vpn,
                },
            ],
            ..TunSettings::default()
        });
        configured.tun_upstream = Some(tun_upstream("Ethernet"));
        let value: Value =
            serde_json::from_str(generate_config(configured).unwrap().as_str()).unwrap();
        let rules = value.pointer("/route/rules").unwrap().as_array().unwrap();
        assert_eq!(
            rules[3],
            json!({
                "inbound":["tun-in"], "network":["udp"], "port":443,
                "action":"reject", "method":"default", "no_drop":true
            })
        );
        assert_eq!(
            rules[4],
            json!({
                "inbound":["tun-in"], "network":["tcp"], "port":8443,
                "action":"route", "outbound":"direct"
            })
        );
        assert_eq!(
            rules[5],
            json!({
                "inbound":["tun-in"], "network":["udp"], "port":123,
                "action":"route", "outbound":"selected"
            })
        );

        assert!(
            validate_tun_traffic_rules(&vec![default_tun_traffic_rules()[0].clone(); 33]).is_err()
        );
        for port in [0, 53] {
            assert!(validate_tun_traffic_rules(&[TunTrafficRule {
                network: TunTrafficNetwork::Udp,
                port,
                action: TunTrafficAction::Block,
            }])
            .is_err());
        }
        assert!(serde_json::from_str::<TunTrafficRule>(
            r#"{"network":"udp","port":443,"action":"block","extra":true}"#
        )
        .is_err());

        let mut disabled = request(&node, &policy);
        disabled.mode = CaptureMode::Tun(TunSettings {
            traffic_rules: Vec::new(),
            ..TunSettings::default()
        });
        disabled.tun_upstream = Some(tun_upstream("Ethernet"));
        let disabled: Value =
            serde_json::from_str(generate_config(disabled).unwrap().as_str()).unwrap();
        assert_eq!(
            disabled
                .pointer("/route/rules")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn native_naive_tun_uses_the_sealed_route_interface() {
        let node = node("naive+quic://fixture-user:fixture-pass@example.test:443");
        let policy = policy(DefaultRoute::Vpn);
        let mut config_request = request(&node, &policy);
        config_request.mode = CaptureMode::Tun(TunSettings::default());
        config_request.tun_upstream = Some(tun_upstream("Wi-Fi 2"));
        let value: Value =
            serde_json::from_str(generate_config(config_request).unwrap().as_str()).unwrap();

        assert_eq!(
            value.pointer("/outbounds/0/type").and_then(Value::as_str),
            Some("naive")
        );
        assert_eq!(
            value
                .pointer("/route/default_interface")
                .and_then(Value::as_str),
            Some("Wi-Fi 2")
        );
        assert!(value.pointer("/route/auto_detect_interface").is_none());
        validate_tun_upstream_binding(&value, "Wi-Fi 2", false).unwrap();
    }

    #[test]
    fn reality_tun_keeps_loopback_unbound_and_binds_physical_egress() {
        let node = node(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2",
        );
        let policy = policy(DefaultRoute::Vpn);
        let mut config_request = request(&node, &policy);
        config_request.mode = CaptureMode::Tun(TunSettings::default());
        config_request.tun_upstream = Some(tun_upstream("Ethernet 3"));
        let value: Value = serde_json::from_str(
            generate_socks_bridge_config(config_request, SocksBridge { server_port: 19090 })
                .unwrap()
                .as_str(),
        )
        .unwrap();

        assert_eq!(
            value.pointer("/outbounds/0/type").and_then(Value::as_str),
            Some("socks")
        );
        assert_eq!(
            value.pointer("/outbounds/0/server").and_then(Value::as_str),
            Some("127.0.0.1")
        );
        assert!(value.pointer("/outbounds/0/bind_interface").is_none());
        assert_eq!(
            value
                .pointer("/outbounds/1/bind_interface")
                .and_then(Value::as_str),
            Some("Ethernet 3")
        );
        assert_eq!(
            value
                .pointer("/dns/servers/0/bind_interface")
                .and_then(Value::as_str),
            Some("Ethernet 3")
        );
        assert!(value.pointer("/route/default_interface").is_none());
        assert!(value.pointer("/route/auto_detect_interface").is_none());
        validate_tun_upstream_binding(&value, "Ethernet 3", true).unwrap();
    }

    #[test]
    fn tun_upstream_validator_rejects_mutated_native_and_bridge_bindings() {
        let hy2_node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut native_request = request(&hy2_node, &policy);
        native_request.mode = CaptureMode::Tun(TunSettings::default());
        native_request.tun_upstream = Some(tun_upstream("Ethernet"));
        let native = generate_config(native_request).unwrap();
        let mut native_value: Value = serde_json::from_str(native.as_str()).unwrap();
        native_value["route"]["default_interface"] = json!("Wi-Fi");
        assert!(validate_tun_upstream_binding(&native_value, "Ethernet", false).is_err());
        native_value["route"]["default_interface"] = json!("Ethernet");
        native_value["route"]["auto_detect_interface"] = json!(true);
        assert!(validate_tun_upstream_binding(&native_value, "Ethernet", false).is_err());

        let reality = node(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2",
        );
        let mut bridge_request = request(&reality, &policy);
        bridge_request.mode = CaptureMode::Tun(TunSettings::default());
        bridge_request.tun_upstream = Some(tun_upstream("Ethernet"));
        let bridge =
            generate_socks_bridge_config(bridge_request, SocksBridge { server_port: 19090 })
                .unwrap();
        let mut bridge_value: Value = serde_json::from_str(bridge.as_str()).unwrap();
        bridge_value["outbounds"][0]["bind_interface"] = json!("Ethernet");
        assert!(validate_tun_upstream_binding(&bridge_value, "Ethernet", true).is_err());
        bridge_value["outbounds"][0]
            .as_object_mut()
            .unwrap()
            .remove("bind_interface");
        bridge_value["dns"]["servers"][0]["bind_interface"] = json!("Wi-Fi");
        assert!(validate_tun_upstream_binding(&bridge_value, "Ethernet", true).is_err());
    }

    #[test]
    fn tun_current_network_dns_pins_only_an_explicit_physical_ipv4_resolver() {
        let hy2_node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut pinned = request(&hy2_node, &policy);
        pinned.mode = CaptureMode::Tun(TunSettings::default());
        pinned.tun_upstream = Some(TunUpstream {
            interface_alias: "Ethernet".into(),
            ipv4_dns_server: Some("192.0.2.53".parse().unwrap()),
        });
        let value: Value = serde_json::from_str(generate_config(pinned).unwrap().as_str()).unwrap();
        assert_eq!(
            value.pointer("/dns/servers/0"),
            Some(&json!({
                "type":"tcp", "tag":"bootstrap", "server":"192.0.2.53",
                "server_port":53, "bind_interface":"Ethernet"
            }))
        );

        let bridge_node = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2");
        let mut bridge = request(&bridge_node, &policy);
        bridge.mode = CaptureMode::Tun(TunSettings::default());
        bridge.tun_upstream = Some(TunUpstream {
            interface_alias: "Ethernet".into(),
            ipv4_dns_server: Some("192.0.2.53".parse().unwrap()),
        });
        let bridge: Value = serde_json::from_str(
            generate_socks_bridge_config(bridge, SocksBridge { server_port: 19090 })
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(
            bridge.pointer("/dns/servers/0"),
            value.pointer("/dns/servers/0")
        );
        assert_eq!(
            bridge.pointer("/outbounds/1/bind_interface"),
            Some(&json!("Ethernet"))
        );

        for invalid in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            let mut request = request(&hy2_node, &policy);
            request.mode = CaptureMode::Tun(TunSettings::default());
            request.tun_upstream = Some(TunUpstream {
                interface_alias: "Ethernet".into(),
                ipv4_dns_server: Some(invalid.parse().unwrap()),
            });
            assert!(generate_config(request).is_err());
        }

        let mut fallback = request(&hy2_node, &policy);
        fallback.mode = CaptureMode::Tun(TunSettings::default());
        fallback.tun_upstream = Some(tun_upstream("Ethernet"));
        let value: Value =
            serde_json::from_str(generate_config(fallback).unwrap().as_str()).unwrap();
        assert_eq!(value.pointer("/dns/servers/0/type"), Some(&json!("local")));
    }

    #[test]
    fn upstream_binding_is_required_only_for_tun_and_aliases_are_strict() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut missing = request(&node, &policy);
        missing.mode = CaptureMode::Tun(TunSettings::default());
        assert!(generate_config(missing).is_err());

        for invalid in ["", " Ethernet", "Ethernet ", "RouteDeck", "bad\nname"] {
            let mut invalid_request = request(&node, &policy);
            invalid_request.mode = CaptureMode::Tun(TunSettings::default());
            invalid_request.tun_upstream = Some(tun_upstream(invalid));
            assert!(
                generate_config(invalid_request).is_err(),
                "accepted {invalid:?}"
            );
        }

        let mut proxy_request = request(&node, &policy);
        proxy_request.mode = CaptureMode::SystemProxy;
        proxy_request.tun_upstream = Some(tun_upstream("Ethernet"));
        assert!(generate_config(proxy_request).is_err());
    }

    #[test]
    fn tun_own_prefix_guard_is_structurally_required_after_dns_hijack() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut config_request = request(&node, &policy);
        config_request.mode = CaptureMode::Tun(TunSettings::default());
        config_request.tun_upstream = Some(tun_upstream("Wi-Fi"));
        let generated = generate_config(config_request).unwrap();
        let mut value: Value = serde_json::from_str(generated.as_str()).unwrap();
        let expected = vec![
            "172.19.0.0/30".to_string(),
            "fdfe:dcba:9876::/126".to_string(),
        ];

        validate_tun_own_prefix_guard(&value, &expected).unwrap();
        value["route"]["rules"].as_array_mut().unwrap().swap(1, 2);
        assert!(validate_tun_own_prefix_guard(&value, &expected).is_err());
        value["route"]["rules"].as_array_mut().unwrap().swap(1, 2);
        value["route"]["rules"][2]["ip_cidr"] = json!(["172.19.0.1/30"]);
        assert!(validate_tun_own_prefix_guard(&value, &expected).is_err());
        value["route"]["rules"][2]["ip_cidr"] = json!(["172.19.0.0/30", "fdfe:dcba:9876::/126"]);
        value["inbounds"][3]["address"][0] = json!("10.9.0.1/30");
        assert!(validate_tun_own_prefix_guard(&value, &expected).is_err());
    }

    #[test]
    fn tun_dns_hijack_uses_port_without_sniff_for_both_networks_and_families() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        for ipv6 in [Ipv6Policy::Disabled, Ipv6Policy::Enabled] {
            for default in [DefaultRoute::Direct, DefaultRoute::Vpn] {
                let mut policy = policy(default);
                policy.ipv6 = ipv6;
                let mut config_request = request(&node, &policy);
                config_request.mode = CaptureMode::Tun(TunSettings::default());
                config_request.tun_upstream = Some(tun_upstream("Ethernet"));
                let generated = generate_config(config_request).unwrap();
                let value: Value = serde_json::from_str(generated.as_str()).unwrap();
                validate_tun_dns_hijack(&value).unwrap();
                assert_eq!(value["route"]["rules"][0]["outbound"], "selected");
                assert_eq!(value["route"]["rules"][1]["network"], json!(["tcp", "udp"]));
                assert_eq!(value["route"]["rules"][1]["port"], 53);
                assert!(value["route"]["rules"][1].get("protocol").is_none());
                assert_eq!(value["route"]["rules"][2]["method"], "drop");
                assert!(value["route"]["rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|rule| rule["action"] != "sniff"));
            }
        }
    }

    #[test]
    fn tun_dns_validator_rejects_sniff_dependency_and_scope_or_order_mutations() {
        let valid = json!({"route":{"rules":[{},tun_dns_hijack_rule(),{}]}});
        validate_tun_dns_hijack(&valid).unwrap();
        for invalid_rule in [
            json!({"inbound":["tun-in"],"protocol":"dns","action":"hijack-dns"}),
            json!({"inbound":["tun-in"],"network":["tcp","udp"],"port":53,"protocol":"dns","action":"hijack-dns"}),
            json!({"inbound":["tun-in","http-in"],"network":["tcp","udp"],"port":53,"action":"hijack-dns"}),
            json!({"inbound":["tun-in"],"network":["udp"],"port":53,"action":"hijack-dns"}),
            json!({"inbound":["tun-in"],"network":["tcp","udp"],"port":54,"action":"hijack-dns"}),
        ] {
            let mut invalid = valid.clone();
            invalid["route"]["rules"][1] = invalid_rule;
            assert!(validate_tun_dns_hijack(&invalid).is_err());
        }
        let mut reordered = valid;
        reordered["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .swap(1, 2);
        assert!(validate_tun_dns_hijack(&reordered).is_err());
    }

    #[test]
    fn ipv4_only_tun_guard_uses_only_the_actual_ipv4_network() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let mut policy = policy(DefaultRoute::Vpn);
        policy.ipv6 = Ipv6Policy::Disabled;
        let mut config_request = request(&node, &policy);
        config_request.mode = CaptureMode::Tun(TunSettings {
            ipv4_address: "10.7.5.9/24".into(),
            ipv6_address: Some("fdfe:dcba:9876::1/126".into()),
            ..TunSettings::default()
        });
        config_request.tun_upstream = Some(tun_upstream("Wi-Fi"));
        let value: Value =
            serde_json::from_str(generate_config(config_request).unwrap().as_str()).unwrap();

        assert_eq!(
            value
                .pointer("/route/rules/2/ip_cidr")
                .and_then(Value::as_array),
            Some(&vec![json!("10.7.5.0/24")])
        );
    }

    #[test]
    fn duplicate_ports_and_public_tun_addresses_are_rejected() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let policy = policy(DefaultRoute::Vpn);
        let mut duplicate = request(&node, &policy);
        duplicate.ports.health = duplicate.ports.http;
        assert!(generate_config(duplicate).is_err());
        let mut public = request(&node, &policy);
        public.mode = CaptureMode::Tun(TunSettings {
            ipv4_address: "203.0.113.1/30".into(),
            ipv6_address: Some("fdfe:dcba:9876::1/126".into()),
            ..TunSettings::default()
        });
        public.tun_upstream = Some(tun_upstream("Ethernet"));
        assert!(generate_config(public).is_err());
    }

    #[test]
    fn emits_closed_vless_transport_shapes() {
        let policy = policy(DefaultRoute::Vpn);
        let ws = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=tls&type=ws&path=%2Fsocket&host=cdn.test&sni=cover.test");
        let grpc = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=tls&type=grpc&serviceName=route&sni=cover.test");
        let ws_value: Value =
            serde_json::from_str(generate_config(request(&ws, &policy)).unwrap().as_str()).unwrap();
        assert_eq!(
            ws_value
                .pointer("/outbounds/0/transport/type")
                .and_then(Value::as_str),
            Some("ws")
        );
        assert_eq!(
            ws_value
                .pointer("/outbounds/0/transport/headers/Host")
                .and_then(Value::as_str),
            Some("cdn.test")
        );
        let grpc_value: Value =
            serde_json::from_str(generate_config(request(&grpc, &policy)).unwrap().as_str())
                .unwrap();
        assert_eq!(
            grpc_value
                .pointer("/outbounds/0/transport/service_name")
                .and_then(Value::as_str),
            Some("route")
        );
        let grpc_empty = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=tls&type=grpc&sni=cover.test");
        let empty_value: Value = serde_json::from_str(
            generate_config(request(&grpc_empty, &policy))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(
            empty_value
                .pointer("/outbounds/0/transport/type")
                .and_then(Value::as_str),
            Some("grpc")
        );
        assert!(empty_value
            .pointer("/outbounds/0/transport/service_name")
            .is_none());
    }

    #[test]
    fn ipv6_reject_precedes_overlapping_app_and_lan_routes() {
        let node = node("hysteria2://fixture-password@example.test:443?sni=example.test");
        let mut policy = policy(DefaultRoute::Vpn);
        policy.ipv6 = Ipv6Policy::Disabled;
        policy.lan = LanPolicy::Direct;
        policy.apps.push(crate::domain::AppRoute {
            process_path: r"C:\Apps\Browser.exe".into(),
            process_name: Some("Browser.exe".into()),
            action: AppRouteAction::Vpn,
        });
        let mut config_request = request(&node, &policy);
        config_request.mode = CaptureMode::Tun(TunSettings::default());
        config_request.tun_upstream = Some(tun_upstream("Ethernet"));
        let value: Value =
            serde_json::from_str(generate_config(config_request).unwrap().as_str()).unwrap();
        let rules = value.pointer("/route/rules").unwrap().as_array().unwrap();
        assert_eq!(
            rules[0].pointer("/inbound/0").and_then(Value::as_str),
            Some("health-in")
        );
        assert_eq!(
            rules[1].get("action").and_then(Value::as_str),
            Some("hijack-dns")
        );
        assert_eq!(rules[2].get("method").and_then(Value::as_str), Some("drop"));
        assert_eq!(rules[3].get("ip_version").and_then(Value::as_u64), Some(6));
        assert_eq!(rules[4].get("port").and_then(Value::as_u64), Some(443));
        assert!(rules[5].get("process_path").is_some());
        assert_eq!(
            rules[6].get("ip_is_private").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn insecure_nodes_require_exact_controller_owned_approval() {
        let uri =
            node("hysteria2://fixture@example.test:443?sni=example.test&insecure=1#uri-insecure");
        let json = node_from_subscription(
            r#"{"type":"hysteria2","tag":"json-insecure","server":"example.test","server_port":443,"password":"fixture","tls":{"enabled":true,"server_name":"example.test","insecure":true}}"#,
        );
        let clash = node_from_subscription(
            "proxies:\n  - name: clash-insecure\n    type: hysteria2\n    server: example.test\n    port: 443\n    password: fixture\n    sni: example.test\n    skip-cert-verify: true\n",
        );
        let policy = policy(DefaultRoute::Vpn);
        for insecure in [&uri, &json, &clash] {
            let error = generate_config(request(insecure, &policy)).unwrap_err();
            assert_eq!(
                error.to_string(),
                "insecure TLS requires explicit approval for the current node security identity"
            );
        }

        let approved = node_from_subscription(
            r#"{"type":"vless","tag":"approval","server":"example.test","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"example.test","insecure":true,"certificate_public_key_sha256":["pin-a"]}}"#,
        );
        let changed = node_from_subscription(
            r#"{"type":"vless","tag":"approval","server":"example.test","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"example.test","insecure":true,"certificate_public_key_sha256":["pin-b"]}}"#,
        );
        assert_eq!(approved.update_key(), changed.update_key());
        let approval = InsecureApproval::record_explicit_user_approval(&approved).unwrap();
        assert!(!format!("{approval:?}").contains("pin-a"));
        let mut exact = request(&approved, &policy);
        exact.insecure_approval = Some(&approval);
        let value: Value = serde_json::from_str(generate_config(exact).unwrap().as_str()).unwrap();
        assert_eq!(
            value
                .pointer("/outbounds/0/tls/insecure")
                .and_then(Value::as_bool),
            Some(true)
        );
        let mut mismatch = request(&changed, &policy);
        mismatch.insecure_approval = Some(&approval);
        assert!(generate_config(mismatch).is_err());
        let mut wrong_node = request(&uri, &policy);
        wrong_node.insecure_approval = Some(&approval);
        assert!(generate_config(wrong_node).is_err());
    }

    #[test]
    fn clash_hysteria_hopping_config_uses_ports_and_normalized_interval() {
        let node = node_from_subscription(
            "proxies:\n  - name: hopping\n    type: hysteria2\n    server: example.test\n    port: 443\n    ports: 2000-2010,8443\n    hop-interval: 15\n    password: fixture\n    sni: example.test\n",
        );
        let policy = policy(DefaultRoute::Vpn);
        let value: Value =
            serde_json::from_str(generate_config(request(&node, &policy)).unwrap().as_str())
                .unwrap();
        assert_eq!(
            value
                .pointer("/outbounds/0/hop_interval")
                .and_then(Value::as_str),
            Some("15s")
        );
        assert!(value.pointer("/outbounds/0/server_port").is_none());
        assert_eq!(
            value
                .pointer("/outbounds/0/server_ports/0")
                .and_then(Value::as_str),
            Some("2000:2010")
        );
    }

    fn node_from_subscription(input: &str) -> Node {
        import_subscription(input.as_bytes())
            .unwrap()
            .nodes
            .remove(0)
    }
}
