use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Host;

pub const MAX_DISPLAY_NAME_BYTES: usize = 512;
pub const MAX_SECRET_BYTES: usize = 8 * 1024;
pub const MAX_HEADER_COUNT: usize = 16;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_APP_RULES: usize = 512;
pub const MAX_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub(crate) fn new(value: String) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::new("secret value is empty"));
        }
        Self::new_allow_empty(value)
    }

    pub(crate) fn new_allow_empty(value: String) -> Result<Self, DomainError> {
        if value.len() > MAX_SECRET_BYTES {
            return Err(DomainError::new("secret value is too long"));
        }
        if value.chars().any(char::is_control) {
            return Err(DomainError::new("secret value contains control characters"));
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    ShareLink,
    Base64List,
    SingBoxJson,
    ClashYaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Vless,
    Hysteria2,
    Naive,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Node {
    pub(crate) id: String,
    pub(crate) update_key: String,
    pub(crate) display_name: String,
    pub(crate) server: String,
    pub(crate) protocol: NodeProtocol,
    pub(crate) source_format: SourceFormat,
}

impl Node {
    pub(crate) fn create(
        display_name: String,
        server: String,
        protocol: NodeProtocol,
        source_format: SourceFormat,
        source_ordinal: usize,
    ) -> Result<Self, DomainError> {
        validate_display_name(&display_name)?;
        let server = normalize_server(&server)?;
        protocol.validate()?;
        let identity = format!(
            "{}|{}|{}|{}",
            protocol.kind_name(),
            server,
            display_name.trim().to_lowercase(),
            protocol.identity_components()
        );
        let update_key = stable_id(identity.as_bytes());
        let id = stable_id(format!("{update_key}|{source_format:?}|{source_ordinal}").as_bytes());
        Ok(Self {
            id,
            update_key,
            display_name: display_name.trim().to_owned(),
            server,
            protocol,
            source_format,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn update_key(&self) -> &str {
        &self.update_key
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn protocol_kind(&self) -> ProtocolKind {
        self.protocol.kind()
    }

    pub fn source_format(&self) -> SourceFormat {
        self.source_format
    }

    pub(crate) fn protocol(&self) -> &NodeProtocol {
        &self.protocol
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Node")
            .field("id", &self.id)
            .field("update_key", &self.update_key)
            .field("server", &self.server)
            .field("protocol", &self.protocol.kind())
            .field("source_format", &self.source_format)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum NodeProtocol {
    Vless(VlessNode),
    Hysteria2(Hysteria2Node),
    Naive(NaiveNode),
}

impl NodeProtocol {
    fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Vless(node) => {
                validate_port(node.server_port)?;
                validate_uuid(node.uuid.expose())?;
                node.tls.validate()?;
                if node.flow.is_some() && !node.tls.enabled {
                    return Err(DomainError::new("VLESS Vision requires TLS"));
                }
                node.transport.validate()?;
                if node.flow.is_some() && node.transport != VlessTransport::Tcp {
                    return Err(DomainError::new(
                        "VLESS Vision is only supported with TCP transport",
                    ));
                }
            }
            Self::Hysteria2(node) => {
                if let Some(interval) = &node.hop_interval {
                    validate_hop_interval(interval)?;
                }
                if !node.tls.enabled {
                    return Err(DomainError::new("Hysteria2 requires TLS"));
                }
                node.tls.validate()?;
            }
            Self::Naive(node) => {
                validate_port(node.server_port)?;
                validate_headers(&node.extra_headers)?;
                if !node.tls.enabled {
                    return Err(DomainError::new("Naive requires TLS"));
                }
                node.tls.validate()?;
            }
        }
        Ok(())
    }

    pub(crate) fn kind(&self) -> ProtocolKind {
        match self {
            Self::Vless(_) => ProtocolKind::Vless,
            Self::Hysteria2(_) => ProtocolKind::Hysteria2,
            Self::Naive(_) => ProtocolKind::Naive,
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Self::Vless(_) => "vless",
            Self::Hysteria2(_) => "hysteria2",
            Self::Naive(_) => "naive",
        }
    }

    fn identity_components(&self) -> String {
        match self {
            Self::Vless(node) => format!(
                "{}|{:?}|{:?}|{:?}|{}",
                node.server_port,
                node.flow,
                node.packet_encoding,
                node.transport,
                node.tls.non_secret_identity()
            ),
            Self::Hysteria2(node) => format!(
                "{:?}|{}|{}|{}",
                node.ports,
                node.hop_interval.as_deref().unwrap_or_default(),
                node.obfs
                    .as_ref()
                    .map(|value| value.kind as u8)
                    .unwrap_or_default(),
                node.tls.non_secret_identity()
            ),
            Self::Naive(node) => format!(
                "{}|{}|{:?}|{}",
                node.server_port,
                node.quic,
                node.extra_headers.keys().collect::<Vec<_>>(),
                node.tls.non_secret_identity()
            ),
        }
    }
}

impl fmt::Debug for NodeProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeProtocol")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VlessNode {
    pub(crate) server_port: u16,
    pub(crate) uuid: Secret,
    pub(crate) flow: Option<VlessFlow>,
    pub(crate) packet_encoding: Option<PacketEncoding>,
    pub(crate) transport: VlessTransport,
    pub(crate) tls: TlsOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessTransport {
    Tcp,
    WebSocket { path: String, host: Option<String> },
    Grpc { service_name: String },
}

impl VlessTransport {
    fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Tcp => Ok(()),
            Self::WebSocket { path, host } => {
                if path.is_empty()
                    || path.len() > 2_048
                    || !path.starts_with('/')
                    || path.chars().any(char::is_control)
                {
                    return Err(DomainError::new("invalid VLESS WebSocket path"));
                }
                if let Some(host) = host {
                    normalize_server(host)?;
                }
                Ok(())
            }
            Self::Grpc { service_name } => {
                if service_name.is_empty()
                    || service_name.len() > 1_024
                    || service_name.chars().any(char::is_control)
                {
                    return Err(DomainError::new("invalid VLESS gRPC service name"));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    Vision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    PacketAddr,
    Xudp,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Hysteria2Node {
    pub(crate) ports: PortSelection,
    pub(crate) hop_interval: Option<String>,
    pub(crate) password: Secret,
    pub(crate) obfs: Option<HysteriaObfs>,
    pub(crate) tls: TlsOptions,
}

#[derive(Clone, PartialEq, Eq)]
pub enum PortSelection {
    Single(u16),
    Ranges(Vec<String>),
}

impl PortSelection {
    pub(crate) fn single(port: u16) -> Result<Self, DomainError> {
        validate_port(port)?;
        Ok(Self::Single(port))
    }

    pub(crate) fn ranges(values: Vec<String>) -> Result<Self, DomainError> {
        if values.is_empty() || values.len() > 32 {
            return Err(DomainError::new("server_ports must contain 1 to 32 items"));
        }
        let normalized = values
            .into_iter()
            .map(|value| normalize_port_range(&value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::Ranges(normalized))
    }

    pub(crate) fn primary_port(&self) -> u16 {
        match self {
            Self::Single(port) => *port,
            Self::Ranges(values) => values[0]
                .split(':')
                .next()
                .and_then(|part| part.parse().ok())
                .unwrap_or(1),
        }
    }
}

impl fmt::Debug for PortSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(port) => formatter.debug_tuple("Single").field(port).finish(),
            Self::Ranges(values) => formatter.debug_tuple("Ranges").field(values).finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HysteriaObfs {
    pub(crate) kind: HysteriaObfsKind,
    pub(crate) password: Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteriaObfsKind {
    Salamander,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NaiveNode {
    pub(crate) server_port: u16,
    pub(crate) username: Option<Secret>,
    pub(crate) password: Option<Secret>,
    pub(crate) quic: bool,
    pub(crate) extra_headers: BTreeMap<String, String>,
    pub(crate) tls: TlsOptions,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TlsOptions {
    pub(crate) enabled: bool,
    pub(crate) server_name: Option<String>,
    pub(crate) insecure: bool,
    pub(crate) alpn: Vec<String>,
    pub(crate) certificate_public_key_sha256: Vec<Secret>,
    pub(crate) ech_config: Vec<Secret>,
    pub(crate) utls_fingerprint: Option<String>,
    pub(crate) reality: Option<RealityOptions>,
}

impl TlsOptions {
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            server_name: None,
            insecure: false,
            alpn: Vec::new(),
            certificate_public_key_sha256: Vec::new(),
            ech_config: Vec::new(),
            utls_fingerprint: None,
            reality: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if !self.enabled
            && (self.server_name.is_some()
                || self.insecure
                || !self.alpn.is_empty()
                || !self.certificate_public_key_sha256.is_empty()
                || !self.ech_config.is_empty()
                || self.utls_fingerprint.is_some()
                || self.reality.is_some())
        {
            return Err(DomainError::new(
                "TLS options are present while TLS is disabled",
            ));
        }
        if let Some(server_name) = &self.server_name {
            normalize_server(server_name)?;
        }
        if self.alpn.len() > 8 {
            return Err(DomainError::new("too many ALPN values"));
        }
        for value in &self.alpn {
            if value.is_empty() || value.len() > 32 || value.chars().any(char::is_control) {
                return Err(DomainError::new("invalid ALPN value"));
            }
        }
        if let Some(fingerprint) = &self.utls_fingerprint {
            const ALLOWED: &[&str] = &[
                "chrome",
                "firefox",
                "edge",
                "safari",
                "ios",
                "android",
                "random",
                "randomized",
            ];
            if !ALLOWED.contains(&fingerprint.as_str()) {
                return Err(DomainError::new("unsupported uTLS fingerprint"));
            }
        }
        if let Some(reality) = &self.reality {
            reality.validate()?;
        }
        Ok(())
    }

    fn non_secret_identity(&self) -> String {
        format!(
            "{}|{}|{}|{:?}|{}|{}",
            self.enabled,
            self.server_name
                .as_deref()
                .unwrap_or_default()
                .to_lowercase(),
            self.insecure,
            self.alpn,
            self.utls_fingerprint.as_deref().unwrap_or_default(),
            self.reality.is_some()
        )
    }
}

impl fmt::Debug for TlsOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsOptions")
            .field("enabled", &self.enabled)
            .field("server_name", &self.server_name)
            .field("insecure", &self.insecure)
            .field("alpn", &self.alpn)
            .field("certificate_public_key_sha256", &"[REDACTED]")
            .field("ech_config", &"[REDACTED]")
            .field("utls_fingerprint", &self.utls_fingerprint)
            .field("reality", &self.reality)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RealityOptions {
    pub(crate) public_key: Secret,
    pub(crate) short_id: Secret,
}

impl RealityOptions {
    fn validate(&self) -> Result<(), DomainError> {
        let public_key = self.public_key.expose();
        if public_key.len() != 43
            || !public_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DomainError::new("invalid REALITY public key"));
        }
        let short_id = self.short_id.expose();
        if short_id.len() > 16
            || !short_id.len().is_multiple_of(2)
            || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DomainError::new("invalid REALITY short ID"));
        }
        Ok(())
    }
}

impl fmt::Debug for RealityOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RealityOptions([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultRoute {
    Direct,
    Vpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppRouteAction {
    Direct,
    Vpn,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRoute {
    pub process_path: String,
    pub process_name: Option<String>,
    pub action: AppRouteAction,
}

impl fmt::Debug for AppRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppRoute")
            .field("process_path", &"[REDACTED]")
            .field("process_name", &self.process_name)
            .field("action", &self.action)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanPolicy {
    Direct,
    FollowDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Policy {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsPolicy {
    Vpn,
    CurrentNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicy {
    pub default: DefaultRoute,
    pub apps: Vec<AppRoute>,
    pub lan: LanPolicy,
    pub ipv6: Ipv6Policy,
    pub dns: DnsPolicy,
}

impl RoutePolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.apps.len() > MAX_APP_RULES {
            return Err(DomainError::new("too many application route rules"));
        }
        let mut actions = HashMap::new();
        for app in &self.apps {
            validate_process_path(&app.process_path)?;
            if let Some(name) = &app.process_name {
                if name.is_empty()
                    || name.len() > 260
                    || name.chars().any(|character| character.is_control())
                {
                    return Err(DomainError::new("invalid process name"));
                }
            }
            let key = canonical_process_path(&app.process_path);
            if let Some(previous) = actions.insert(key, app.action) {
                if previous != app.action {
                    return Err(DomainError::new(
                        "the same process path has conflicting route actions",
                    ));
                }
                return Err(DomainError::new("duplicate application route rule"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    message: &'static str,
}

impl DomainError {
    pub(crate) fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for DomainError {}

pub(crate) fn validate_uuid(value: &str) -> Result<(), DomainError> {
    if value.len() != 36 {
        return Err(DomainError::new("invalid VLESS UUID"));
    }
    for (index, byte) in value.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(DomainError::new("invalid VLESS UUID"));
            }
        } else if !byte.is_ascii_hexdigit() {
            return Err(DomainError::new("invalid VLESS UUID"));
        }
    }
    if value
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .all(|byte| byte == b'0')
    {
        return Err(DomainError::new("nil VLESS UUID is not allowed"));
    }
    Ok(())
}

pub(crate) fn normalize_server(value: &str) -> Result<String, DomainError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 253 || value.chars().any(char::is_control) {
        return Err(DomainError::new("invalid server address"));
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    match Host::parse(value) {
        Ok(Host::Domain(domain)) if domain.len() <= 253 => Ok(domain.to_ascii_lowercase()),
        _ => Err(DomainError::new("invalid server address")),
    }
}

pub(crate) fn validate_port(port: u16) -> Result<(), DomainError> {
    if port == 0 {
        Err(DomainError::new("port must be between 1 and 65535"))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_hop_interval(value: &str) -> Result<(), DomainError> {
    let number = value
        .strip_suffix('s')
        .ok_or_else(|| DomainError::new("hop interval must use whole seconds"))?;
    let seconds: u32 = number
        .parse()
        .map_err(|_| DomainError::new("invalid hop interval"))?;
    if !(1..=3600).contains(&seconds) {
        return Err(DomainError::new("hop interval is out of range"));
    }
    Ok(())
}

pub(crate) fn validate_headers(headers: &BTreeMap<String, String>) -> Result<(), DomainError> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(DomainError::new("too many extra headers"));
    }
    let mut total = 0usize;
    let mut normalized_names = HashMap::new();
    for (name, value) in headers {
        if name.is_empty()
            || !name.bytes().all(is_header_name_byte)
            || name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            return Err(DomainError::new("invalid or forbidden extra header name"));
        }
        if normalized_names
            .insert(name.to_ascii_lowercase(), ())
            .is_some()
        {
            return Err(DomainError::new("duplicate extra header name"));
        }
        if value.chars().any(|character| {
            let code = character as u32;
            (code <= 0x1f && character != '\t') || code == 0x7f
        }) {
            return Err(DomainError::new(
                "extra header contains a control character",
            ));
        }
        total = total.saturating_add(name.len() + value.len() + 2);
    }
    if total > MAX_HEADER_BYTES {
        return Err(DomainError::new("extra headers are too large"));
    }
    Ok(())
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

fn validate_display_name(value: &str) -> Result<(), DomainError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_DISPLAY_NAME_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(DomainError::new("invalid display name"));
    }
    Ok(())
}

fn normalize_port_range(value: &str) -> Result<String, DomainError> {
    let value = value.trim();
    let mut parts = value.split(':');
    let start: u16 = parts
        .next()
        .ok_or_else(|| DomainError::new("invalid server port range"))?
        .parse()
        .map_err(|_| DomainError::new("invalid server port range"))?;
    validate_port(start)?;
    match parts.next() {
        None => Ok(start.to_string()),
        Some(end) if parts.next().is_none() => {
            let end: u16 = end
                .parse()
                .map_err(|_| DomainError::new("invalid server port range"))?;
            validate_port(end)?;
            if start > end {
                return Err(DomainError::new("server port range is reversed"));
            }
            Ok(format!("{start}:{end}"))
        }
        _ => Err(DomainError::new("invalid server port range")),
    }
}

fn validate_process_path(value: &str) -> Result<(), DomainError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.chars().any(char::is_control)
        || (!value.contains('\\') && !value.contains('/'))
    {
        return Err(DomainError::new("invalid process path"));
    }
    Ok(())
}

pub(crate) fn canonical_process_path(value: &str) -> String {
    value.trim().replace('/', "\\").to_lowercase()
}

fn stable_id(identity: &[u8]) -> String {
    let digest = Sha256::digest(identity);
    let mut result = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        use fmt::Write as _;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_debug_as_plaintext() {
        let secret = Secret::new("fixture-password".into()).unwrap();
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn uuid_validation_is_strict() {
        validate_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        assert!(validate_uuid("00000000-0000-0000-0000-000000000000").is_err());
        assert!(validate_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn conflicting_process_rules_are_rejected_case_insensitively() {
        let policy = RoutePolicy {
            default: DefaultRoute::Direct,
            apps: vec![
                AppRoute {
                    process_path: r"C:\Apps\Browser.exe".into(),
                    process_name: None,
                    action: AppRouteAction::Direct,
                },
                AppRoute {
                    process_path: r"c:/apps/browser.exe".into(),
                    process_name: None,
                    action: AppRouteAction::Vpn,
                },
            ],
            lan: LanPolicy::Direct,
            ipv6: Ipv6Policy::Enabled,
            dns: DnsPolicy::Vpn,
        };
        assert!(policy.validate().is_err());
        assert!(!format!("{policy:?}").contains("Browser.exe"));
    }

    #[test]
    fn forbidden_naive_headers_are_rejected() {
        let headers = BTreeMap::from([("Proxy-Authorization".into(), "fixture".into())]);
        assert!(validate_headers(&headers).is_err());
        let duplicate = BTreeMap::from([
            ("X-Fixture".into(), "first".into()),
            ("x-fixture".into(), "second".into()),
        ]);
        assert!(validate_headers(&duplicate).is_err());
        for control in ['\0', '\u{0001}', '\u{001f}', '\u{007f}'] {
            let headers = BTreeMap::from([("X-Fixture".into(), format!("safe{control}unsafe"))]);
            assert!(validate_headers(&headers).is_err());
        }
        let tab = BTreeMap::from([("X-Fixture".into(), "safe\tvalue".into())]);
        validate_headers(&tab).unwrap();
    }

    #[test]
    fn stable_update_key_excludes_credentials_and_instance_id_uses_ordinal() {
        let make = |uuid: &str, ordinal: usize| {
            Node::create(
                "Fixture node".into(),
                "Example.COM".into(),
                NodeProtocol::Vless(VlessNode {
                    server_port: 443,
                    uuid: Secret::new(uuid.into()).unwrap(),
                    flow: Some(VlessFlow::Vision),
                    packet_encoding: Some(PacketEncoding::Xudp),
                    transport: VlessTransport::Tcp,
                    tls: TlsOptions {
                        enabled: true,
                        server_name: Some("example.com".into()),
                        insecure: false,
                        alpn: Vec::new(),
                        certificate_public_key_sha256: Vec::new(),
                        ech_config: Vec::new(),
                        utls_fingerprint: None,
                        reality: None,
                    },
                }),
                SourceFormat::ShareLink,
                ordinal,
            )
            .unwrap()
        };
        let first = make("11111111-2222-3333-4444-555555555555", 0);
        let second = make("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 1);
        assert_eq!(first.update_key(), second.update_key());
        assert_ne!(first.id(), second.id());
        assert!(!format!("{first:?}").contains("11111111"));
    }
}
