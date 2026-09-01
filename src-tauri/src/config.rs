use std::{collections::BTreeSet, fmt, net::IpAddr};

use serde_json::{json, Map, Value};

use crate::domain::{
    canonical_process_path, AppRouteAction, DefaultRoute, DnsPolicy, HysteriaObfsKind,
    InsecureApproval, Ipv6Policy, LanPolicy, Node, NodeProtocol, PacketEncoding, PortSelection,
    RoutePolicy, Secret, TlsOptions, VlessFlow, VlessTransport,
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
    Tun(TunSettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    pub ipv4_address: String,
    pub ipv6_address: Option<String>,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            ipv4_address: "172.19.0.1/30".into(),
            ipv6_address: Some("fdfe:dcba:9876::1/126".into()),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnDnsServer {
    pub server: IpAddr,
    pub server_name: String,
    pub path: String,
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
    validate_request(&request)?;
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
            "stack": "system"
        }));
    }

    let mut selected = selected_outbound(request.node)?;
    let mut dns_servers = vec![json!({ "type": "local", "tag": "bootstrap" })];
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
        rules.push(json!({ "inbound": ["tun-in"], "protocol": "dns", "action": "hijack-dns" }));
    }
    // User traffic must not escape an IPv4-only policy through a more-specific app or LAN rule.
    // Health remains first and TUN DNS hijacking remains ahead of this reject rule.
    if request.policy.ipv6 == Ipv6Policy::Disabled {
        rules.push(json!({ "ip_version": 6, "action": "reject" }));
    }
    for app in &request.policy.apps {
        rules.push(json!({
            "process_path": [canonical_process_path(&app.process_path)],
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
    if matches!(request.mode, CaptureMode::Tun(_)) {
        route
            .as_object_mut()
            .expect("generated route must be an object")
            .insert("auto_detect_interface".into(), json!(true));
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
        "outbounds": [selected, { "type": "direct", "tag": "direct" }],
        "route": route
    });
    validate_no_direct_health(&root)?;
    let text = serde_json::to_string_pretty(&root)
        .map_err(|_| ConfigError::new("could not serialize generated configuration"))?;
    Ok(GeneratedConfig(text))
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
            "local proxy runtime must route ordinary traffic through selected outbound",
        ));
    }
    if let CaptureMode::Tun(settings) = &request.mode {
        validate_tun_address(&settings.ipv4_address, false)?;
        if request.policy.ipv6 == Ipv6Policy::Enabled {
            let address = settings
                .ipv6_address
                .as_deref()
                .ok_or_else(|| ConfigError::new("IPv6 TUN address is required"))?;
            validate_tun_address(address, true)?;
        }
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

fn selected_outbound(node: &Node) -> Result<Value, ConfigError> {
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
        let config = generate_config(request).unwrap();
        let value: Value = serde_json::from_str(config.as_str()).unwrap();
        assert_eq!(
            value
                .pointer("/inbounds/3/interface_name")
                .and_then(Value::as_str),
            Some("RouteDeck")
        );
        assert!(value.pointer("/inbounds/3/dns_mode").is_none());
        assert_eq!(
            value
                .pointer("/route/auto_detect_interface")
                .and_then(Value::as_bool),
            Some(true)
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
        });
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
        assert_eq!(rules[2].get("ip_version").and_then(Value::as_u64), Some(6));
        assert!(rules[3].get("process_path").is_some());
        assert_eq!(
            rules[4].get("ip_is_private").and_then(Value::as_bool),
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
