use std::{collections::BTreeMap, fmt, str};

use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};
use url::Url;

use crate::domain::{
    validate_headers, validate_hop_interval, Hysteria2Node, HysteriaObfs, HysteriaObfsKind,
    NaiveNode, Node, NodeProtocol, PacketEncoding, PortSelection, RealityOptions, Secret,
    SourceFormat, TlsOptions, VlessFlow, VlessNode,
};

pub const MAX_INPUT_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_NODES: usize = 2_000;
const MAX_JSON_DEPTH: usize = 32;

#[derive(Debug)]
pub struct ImportReport {
    pub nodes: Vec<Node>,
    pub rejected: Vec<NodeRejection>,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRejection {
    pub index: usize,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportError(&'static str);

impl ImportError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ImportError {}

pub fn import_subscription(input: &[u8]) -> Result<ImportReport, ImportError> {
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(ImportError::new(
            "subscription size is outside the allowed range",
        ));
    }
    let text = str::from_utf8(input).map_err(|_| ImportError::new("subscription is not UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text).trim();
    if text.is_empty() {
        return Err(ImportError::new("subscription is empty"));
    }
    if matches!(text.as_bytes().first(), Some(b'{') | Some(b'[')) {
        return import_json(text);
    }
    if contains_share_line(text) {
        return import_lines(text, SourceFormat::ShareLink);
    }
    let decoded = decode_base64_once(text)?;
    let decoded = str::from_utf8(&decoded)
        .map_err(|_| ImportError::new("decoded subscription is not UTF-8"))?;
    if !contains_share_line(decoded) {
        return Err(ImportError::new(
            "decoded subscription is not a share-link list",
        ));
    }
    import_lines(decoded, SourceFormat::Base64List)
}

fn contains_share_line(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(|line| {
            matches!(
                line.split_once("://")
                    .map(|pair| pair.0.to_ascii_lowercase())
                    .as_deref(),
                Some("vless" | "hysteria2" | "hy2" | "naive+https" | "naive+quic")
            )
        })
}

fn import_lines(text: &str, source: SourceFormat) -> Result<ImportReport, ImportError> {
    let mut nodes = Vec::new();
    let mut rejected = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LINE_BYTES {
            rejected.push(NodeRejection {
                index,
                reason: "share link is too long",
            });
            continue;
        }
        if nodes.len() + rejected.len() >= MAX_NODES {
            return Err(ImportError::new("subscription contains too many nodes"));
        }
        match parse_share_link(line, source) {
            Ok(node) => nodes.push(node),
            Err(reason) => rejected.push(NodeRejection {
                index,
                reason: reason.0,
            }),
        }
    }
    finish_report(nodes, rejected, Vec::new())
}

fn decode_base64_once(text: &str) -> Result<Vec<u8>, ImportError> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    if compact.is_empty() || compact.len() > MAX_INPUT_BYTES.saturating_mul(2) {
        return Err(ImportError::new("invalid base64 subscription"));
    }
    let engines: [&base64::engine::general_purpose::GeneralPurpose; 4] = [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in engines {
        if let Ok(decoded) = engine.decode(compact.as_bytes()) {
            if decoded.len() > MAX_INPUT_BYTES {
                return Err(ImportError::new("decoded subscription is too large"));
            }
            return Ok(decoded);
        }
    }
    Err(ImportError::new("invalid base64 subscription"))
}

fn parse_share_link(line: &str, source: SourceFormat) -> Result<Node, ImportError> {
    let lower = line.to_ascii_lowercase();
    if !has_valid_percent_encoding(line) {
        return Err(ImportError::new("share link has invalid percent encoding"));
    }
    if lower.contains("%0d") || lower.contains("%0a") || line.chars().any(char::is_control) {
        return Err(ImportError::new("share link contains a control character"));
    }
    let url = Url::parse(line).map_err(|_| ImportError::new("malformed share link"))?;
    match url.scheme().to_ascii_lowercase().as_str() {
        "vless" => parse_vless_url(&url, source),
        "hysteria2" | "hy2" => parse_hysteria_url(&url, source),
        "naive+https" | "naive+quic" => parse_naive_url(&url, source),
        _ => Err(ImportError::new("unsupported share-link scheme")),
    }
}

fn parse_vless_url(url: &Url, source: SourceFormat) -> Result<Node, ImportError> {
    require_authority_only(url)?;
    let query = strict_query(
        url,
        &[
            "security",
            "encryption",
            "flow",
            "type",
            "sni",
            "alpn",
            "fp",
            "pbk",
            "sid",
            "packetEncoding",
        ],
    )?;
    let uuid = decode_component(url.username())?;
    if url.password().is_some() {
        return Err(ImportError::new(
            "VLESS user info must contain only the UUID",
        ));
    }
    crate::domain::validate_uuid(&uuid).map_err(|_| ImportError::new("invalid VLESS UUID"))?;
    let server = host(url)?;
    let port = url
        .port()
        .ok_or_else(|| ImportError::new("VLESS port is required"))?;
    let encryption = query
        .get("encryption")
        .map(String::as_str)
        .unwrap_or("none");
    if !matches!(encryption, "" | "none") {
        return Err(ImportError::new("unsupported VLESS encryption"));
    }
    if query
        .get("type")
        .is_some_and(|value| !matches!(value.as_str(), "" | "tcp"))
    {
        return Err(ImportError::new("unsupported VLESS transport"));
    }
    let flow = match query.get("flow").map(String::as_str).unwrap_or("") {
        "" => None,
        "xtls-rprx-vision" => Some(VlessFlow::Vision),
        _ => return Err(ImportError::new("unsupported VLESS flow")),
    };
    let security = query.get("security").map(String::as_str).unwrap_or("none");
    let has_tls_parameters = ["sni", "alpn", "fp", "pbk", "sid"]
        .iter()
        .any(|key| query.contains_key(*key));
    if security == "none" && has_tls_parameters {
        return Err(ImportError::new(
            "TLS parameters are present while VLESS security is disabled",
        ));
    }
    if security == "tls" && (query.contains_key("pbk") || query.contains_key("sid")) {
        return Err(ImportError::new(
            "REALITY parameters require VLESS security=reality",
        ));
    }
    let mut tls = if security == "none" {
        TlsOptions::disabled()
    } else {
        tls_from_query(&query)?
    };
    match security {
        "none" | "tls" => {}
        "reality" => {
            let public_key = required_secret(&query, "pbk", "REALITY public key is required")?;
            let short_id = Secret::new_allow_empty(query.get("sid").cloned().unwrap_or_default())
                .map_err(|_| ImportError::new("REALITY short ID is invalid"))?;
            tls.reality = Some(RealityOptions {
                public_key,
                short_id,
            });
        }
        _ => return Err(ImportError::new("unsupported VLESS security")),
    }
    let packet_encoding = match query
        .get("packetEncoding")
        .map(String::as_str)
        .unwrap_or("")
    {
        "" => None,
        "packetaddr" => Some(PacketEncoding::PacketAddr),
        "xudp" => Some(PacketEncoding::Xudp),
        _ => return Err(ImportError::new("unsupported VLESS packet encoding")),
    };
    let name = display_name(url, "VLESS", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Vless(VlessNode {
            server_port: port,
            uuid: secret(uuid)?,
            flow,
            packet_encoding,
            tls,
        }),
        source,
    )
    .map_err(|_| ImportError::new("invalid VLESS node"))
}

fn parse_hysteria_url(url: &Url, source: SourceFormat) -> Result<Node, ImportError> {
    require_authority_only(url)?;
    let query = strict_query(
        url,
        &[
            "obfs",
            "obfs-password",
            "sni",
            "insecure",
            "ech",
            "pinSHA256",
        ],
    )?;
    if query.contains_key("pinSHA256") {
        return Err(ImportError::new(
            "Hysteria certificate fingerprint import is not supported",
        ));
    }
    let server = host(url)?;
    let port = url.port().unwrap_or(443);
    let mut auth = decode_component(url.username())?;
    if let Some(password) = url.password() {
        if !auth.is_empty() {
            auth.push(':');
        }
        auth.push_str(&decode_component(password)?);
    }
    if auth.is_empty() {
        return Err(ImportError::new("Hysteria2 authentication is required"));
    }
    let obfs = match query.get("obfs").map(String::as_str).unwrap_or("") {
        "" => None,
        "salamander" => Some(HysteriaObfs {
            kind: HysteriaObfsKind::Salamander,
            password: required_secret(
                &query,
                "obfs-password",
                "Hysteria2 obfs password is required",
            )?,
        }),
        _ => return Err(ImportError::new("unsupported Hysteria2 obfuscation")),
    };
    if query.contains_key("obfs-password") && obfs.is_none() {
        return Err(ImportError::new("Hysteria2 obfs password has no obfs type"));
    }
    let tls = tls_from_query(&query)?;
    let name = display_name(url, "Hysteria2", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Hysteria2(Hysteria2Node {
            ports: PortSelection::single(port)
                .map_err(|_| ImportError::new("invalid Hysteria2 port"))?,
            hop_interval: None,
            password: secret(auth)?,
            obfs,
            tls,
        }),
        source,
    )
    .map_err(|_| ImportError::new("invalid Hysteria2 node"))
}

fn parse_naive_url(url: &Url, source: SourceFormat) -> Result<Node, ImportError> {
    require_authority_only(url)?;
    let query = strict_query(url, &["extra-headers"])?;
    let server = host(url)?;
    let port = url.port().unwrap_or(443);
    let username = optional_url_secret(url.username())?;
    let password = url
        .password()
        .map(decode_component)
        .transpose()?
        .map(secret)
        .transpose()?;
    if username.is_none() != password.is_none() {
        return Err(ImportError::new(
            "Naive username and password must be supplied together",
        ));
    }
    let headers = query
        .get("extra-headers")
        .map(|value| parse_header_extension(value))
        .transpose()?
        .unwrap_or_default();
    validate_headers(&headers).map_err(|_| ImportError::new("invalid Naive extra headers"))?;
    let tls = TlsOptions {
        enabled: true,
        server_name: Some(server.clone()),
        insecure: false,
        alpn: Vec::new(),
        certificate_public_key_sha256: Vec::new(),
        ech_config: Vec::new(),
        utls_fingerprint: None,
        reality: None,
    };
    let name = display_name(url, "Naive", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Naive(NaiveNode {
            server_port: port,
            username,
            password,
            quic: url.scheme().eq_ignore_ascii_case("naive+quic"),
            extra_headers: headers,
            tls,
        }),
        source,
    )
    .map_err(|_| ImportError::new("invalid Naive node"))
}

fn import_json(text: &str) -> Result<ImportReport, ImportError> {
    let root: Value =
        serde_json::from_str(text).map_err(|_| ImportError::new("invalid sing-box JSON"))?;
    if json_depth(&root) > MAX_JSON_DEPTH {
        return Err(ImportError::new("JSON nesting is too deep"));
    }
    let (items, warnings): (Vec<&Value>, Vec<&'static str>) = match &root {
        Value::Array(items) => (items.iter().collect(), Vec::new()),
        Value::Object(object) if object.contains_key("outbounds") => {
            strict_keys(object, &["outbounds"])
                .map_err(|_| ImportError::new("unsupported top-level sing-box field"))?;
            let items = object
                .get("outbounds")
                .and_then(Value::as_array)
                .ok_or_else(|| ImportError::new("outbounds must be an array"))?;
            (items.iter().collect(), Vec::new())
        }
        Value::Object(object) if object.contains_key("type") => (vec![&root], Vec::new()),
        _ => return Err(ImportError::new("JSON is not a supported outbound list")),
    };
    if items.len() > MAX_NODES {
        return Err(ImportError::new("subscription contains too many nodes"));
    }
    let mut nodes = Vec::new();
    let mut rejected = Vec::new();
    for (index, value) in items.into_iter().enumerate() {
        match parse_json_outbound(value) {
            Ok(node) => nodes.push(node),
            Err(error) => rejected.push(NodeRejection {
                index,
                reason: error.0,
            }),
        }
    }
    finish_report(nodes, rejected, warnings)
}

fn parse_json_outbound(value: &Value) -> Result<Node, ImportError> {
    let object = value
        .as_object()
        .ok_or_else(|| ImportError::new("outbound must be an object"))?;
    match required_str(object, "type")? {
        "vless" => parse_json_vless(object),
        "hysteria2" => parse_json_hysteria(object),
        "naive" => parse_json_naive(object),
        _ => Err(ImportError::new("unsupported outbound type")),
    }
}

fn parse_json_vless(object: &Map<String, Value>) -> Result<Node, ImportError> {
    strict_keys(
        object,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "uuid",
            "flow",
            "packet_encoding",
            "tls",
        ],
    )?;
    let server = required_str(object, "server")?.to_owned();
    let port = required_port(object, "server_port")?;
    let uuid = required_str(object, "uuid")?.to_owned();
    crate::domain::validate_uuid(&uuid).map_err(|_| ImportError::new("invalid VLESS UUID"))?;
    let flow = match optional_str(object, "flow")? {
        None | Some("") => None,
        Some("xtls-rprx-vision") => Some(VlessFlow::Vision),
        _ => return Err(ImportError::new("unsupported VLESS flow")),
    };
    let packet_encoding = match optional_str(object, "packet_encoding")? {
        None | Some("") => None,
        Some("packetaddr") => Some(PacketEncoding::PacketAddr),
        Some("xudp") => Some(PacketEncoding::Xudp),
        _ => return Err(ImportError::new("unsupported VLESS packet encoding")),
    };
    let tls = parse_json_tls(object.get("tls"), true, false)?;
    let name = json_name(object, "VLESS", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Vless(VlessNode {
            server_port: port,
            uuid: secret(uuid)?,
            flow,
            packet_encoding,
            tls,
        }),
        SourceFormat::SingBoxJson,
    )
    .map_err(|_| ImportError::new("invalid VLESS node"))
}

fn parse_json_hysteria(object: &Map<String, Value>) -> Result<Node, ImportError> {
    strict_keys(
        object,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "server_ports",
            "hop_interval",
            "password",
            "obfs",
            "tls",
        ],
    )?;
    let server = required_str(object, "server")?.to_owned();
    let ports = match (object.get("server_port"), object.get("server_ports")) {
        (Some(_), Some(_)) => {
            return Err(ImportError::new("use either server_port or server_ports"))
        }
        (Some(_), None) => PortSelection::single(required_port(object, "server_port")?)
            .map_err(|_| ImportError::new("invalid Hysteria2 port"))?,
        (None, Some(Value::Array(values))) => {
            let values = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ImportError::new("invalid Hysteria2 port range"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            PortSelection::ranges(values)
                .map_err(|_| ImportError::new("invalid Hysteria2 port range"))?
        }
        _ => return Err(ImportError::new("Hysteria2 port is required")),
    };
    let hop_interval = optional_str(object, "hop_interval")?.map(str::to_owned);
    if let Some(value) = &hop_interval {
        validate_hop_interval(value)
            .map_err(|_| ImportError::new("invalid Hysteria2 hop interval"))?;
    }
    let obfs = object.get("obfs").map(parse_json_obfs).transpose()?;
    let tls = parse_json_tls(object.get("tls"), false, false)?;
    let port = ports.primary_port();
    let name = json_name(object, "Hysteria2", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Hysteria2(Hysteria2Node {
            ports,
            hop_interval,
            password: secret(required_str(object, "password")?.to_owned())?,
            obfs,
            tls,
        }),
        SourceFormat::SingBoxJson,
    )
    .map_err(|_| ImportError::new("invalid Hysteria2 node"))
}

fn parse_json_naive(object: &Map<String, Value>) -> Result<Node, ImportError> {
    strict_keys(
        object,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "username",
            "password",
            "extra_headers",
            "quic",
            "tls",
        ],
    )?;
    let server = required_str(object, "server")?.to_owned();
    let port = required_port(object, "server_port")?;
    let username = optional_str(object, "username")?
        .map(|value| secret(value.to_owned()))
        .transpose()?;
    let password = optional_str(object, "password")?
        .map(|value| secret(value.to_owned()))
        .transpose()?;
    if username.is_none() != password.is_none() {
        return Err(ImportError::new(
            "Naive username and password must be supplied together",
        ));
    }
    let extra_headers = match object.get("extra_headers") {
        None => BTreeMap::new(),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                value
                    .as_str()
                    .map(|value| (key.clone(), value.to_owned()))
                    .ok_or_else(|| ImportError::new("invalid Naive extra headers"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(ImportError::new("invalid Naive extra headers")),
    };
    validate_headers(&extra_headers)
        .map_err(|_| ImportError::new("invalid Naive extra headers"))?;
    let quic = optional_bool(object, "quic")?.unwrap_or(false);
    let tls = parse_json_tls(object.get("tls"), false, true)?;
    if tls.insecure
        || !tls.alpn.is_empty()
        || !tls.certificate_public_key_sha256.is_empty()
        || tls.utls_fingerprint.is_some()
        || tls.reality.is_some()
    {
        return Err(ImportError::new(
            "Naive TLS contains fields unsupported by sing-box 1.13",
        ));
    }
    let name = json_name(object, "Naive", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Naive(NaiveNode {
            server_port: port,
            username,
            password,
            quic,
            extra_headers,
            tls,
        }),
        SourceFormat::SingBoxJson,
    )
    .map_err(|_| ImportError::new("invalid Naive node"))
}

fn parse_json_obfs(value: &Value) -> Result<HysteriaObfs, ImportError> {
    let object = value
        .as_object()
        .ok_or_else(|| ImportError::new("invalid Hysteria2 obfs"))?;
    strict_keys(object, &["type", "password"])?;
    if required_str(object, "type")? != "salamander" {
        return Err(ImportError::new("unsupported Hysteria2 obfuscation"));
    }
    Ok(HysteriaObfs {
        kind: HysteriaObfsKind::Salamander,
        password: secret(required_str(object, "password")?.to_owned())?,
    })
}

fn parse_json_tls(
    value: Option<&Value>,
    allow_reality: bool,
    required: bool,
) -> Result<TlsOptions, ImportError> {
    let Some(value) = value else {
        return if required {
            Err(ImportError::new("TLS configuration is required"))
        } else {
            Ok(TlsOptions::disabled())
        };
    };
    let object = value
        .as_object()
        .ok_or_else(|| ImportError::new("TLS must be an object"))?;
    strict_keys(
        object,
        &[
            "enabled",
            "server_name",
            "insecure",
            "alpn",
            "certificate_public_key_sha256",
            "utls",
            "reality",
            "ech",
        ],
    )?;
    let enabled = optional_bool(object, "enabled")?.unwrap_or(true);
    let server_name = optional_str(object, "server_name")?.map(str::to_owned);
    let insecure = optional_bool(object, "insecure")?.unwrap_or(false);
    let alpn = string_array(object.get("alpn"), "invalid TLS ALPN")?;
    let certificate_public_key_sha256 = string_array(
        object.get("certificate_public_key_sha256"),
        "invalid certificate public-key pin",
    )?
    .into_iter()
    .map(secret)
    .collect::<Result<_, _>>()?;
    let utls_fingerprint = match object.get("utls") {
        None => None,
        Some(Value::Object(value)) => {
            strict_keys(value, &["enabled", "fingerprint"])?;
            if !optional_bool(value, "enabled")?.unwrap_or(true) {
                None
            } else {
                Some(required_str(value, "fingerprint")?.to_owned())
            }
        }
        _ => return Err(ImportError::new("invalid uTLS configuration")),
    };
    let reality = match object.get("reality") {
        None => None,
        Some(Value::Object(value)) if allow_reality => {
            strict_keys(value, &["enabled", "public_key", "short_id"])?;
            if !optional_bool(value, "enabled")?.unwrap_or(true) {
                None
            } else {
                Some(RealityOptions {
                    public_key: secret(required_str(value, "public_key")?.to_owned())?,
                    short_id: Secret::new_allow_empty(
                        required_string_allow_empty(value, "short_id")?.to_owned(),
                    )
                    .map_err(|_| ImportError::new("REALITY short ID is invalid"))?,
                })
            }
        }
        Some(_) => return Err(ImportError::new("REALITY is unsupported for this protocol")),
    };
    let ech_config = match object.get("ech") {
        None => Vec::new(),
        Some(Value::Object(value)) => {
            strict_keys(value, &["enabled", "config"])?;
            if !optional_bool(value, "enabled")?.unwrap_or(true) {
                Vec::new()
            } else {
                string_array(value.get("config"), "invalid ECH config")?
                    .into_iter()
                    .map(secret)
                    .collect::<Result<_, _>>()?
            }
        }
        _ => return Err(ImportError::new("invalid ECH configuration")),
    };
    let tls = TlsOptions {
        enabled,
        server_name,
        insecure,
        alpn,
        certificate_public_key_sha256,
        ech_config,
        utls_fingerprint,
        reality,
    };
    tls.validate()
        .map_err(|_| ImportError::new("invalid TLS configuration"))?;
    if required && !tls.enabled {
        return Err(ImportError::new("TLS must be enabled"));
    }
    Ok(tls)
}

fn tls_from_query(query: &BTreeMap<String, String>) -> Result<TlsOptions, ImportError> {
    let server_name = query.get("sni").filter(|value| !value.is_empty()).cloned();
    let insecure = query
        .get("insecure")
        .map(|value| parse_bool_text(value))
        .transpose()?
        .unwrap_or(false);
    let alpn = query
        .get("alpn")
        .map(|value| value.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
    let ech_config = query
        .get("ech")
        .filter(|value| !value.is_empty())
        .map(|value| secret(value.clone()).map(|value| vec![value]))
        .transpose()?
        .unwrap_or_default();
    let utls_fingerprint = query.get("fp").filter(|value| !value.is_empty()).cloned();
    let tls = TlsOptions {
        enabled: true,
        server_name,
        insecure,
        alpn,
        certificate_public_key_sha256: Vec::new(),
        ech_config,
        utls_fingerprint,
        reality: None,
    };
    tls.validate()
        .map_err(|_| ImportError::new("invalid TLS options"))?;
    Ok(tls)
}

fn strict_query(url: &Url, allowed: &[&str]) -> Result<BTreeMap<String, String>, ImportError> {
    let mut result = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if !allowed.contains(&key.as_ref()) {
            return Err(ImportError::new("unsupported share-link parameter"));
        }
        if result
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(ImportError::new("duplicate share-link parameter"));
        }
    }
    Ok(result)
}

fn strict_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), ImportError> {
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(ImportError::new("unsupported field in imported outbound"))
    }
}

fn required_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ImportError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_LINE_BYTES)
        .ok_or_else(|| ImportError::new("required string field is missing or invalid"))
}

fn required_string_allow_empty<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, ImportError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_LINE_BYTES)
        .ok_or_else(|| ImportError::new("required string field is missing or invalid"))
}

fn optional_str<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, ImportError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|value| value.len() <= MAX_LINE_BYTES)
                .ok_or_else(|| ImportError::new("string field has an invalid type or size"))
        })
        .transpose()
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, ImportError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| ImportError::new("boolean field has an invalid type"))
        })
        .transpose()
}

fn required_port(object: &Map<String, Value>, key: &str) -> Result<u16, ImportError> {
    let value = object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| ImportError::new("port field is missing or invalid"))?;
    u16::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| ImportError::new("port is outside the allowed range"))
}

fn string_array(value: Option<&Value>, message: &'static str) -> Result<Vec<String>, ImportError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) if values.len() <= 32 => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.is_empty() && value.len() <= MAX_LINE_BYTES)
                    .map(str::to_owned)
                    .ok_or_else(|| ImportError::new(message))
            })
            .collect(),
        _ => Err(ImportError::new(message)),
    }
}

fn host(url: &Url) -> Result<String, ImportError> {
    url.host_str()
        .map(str::to_owned)
        .ok_or_else(|| ImportError::new("server address is required"))
}

fn require_authority_only(url: &Url) -> Result<(), ImportError> {
    if !matches!(url.path(), "" | "/") {
        return Err(ImportError::new("share-link path is unsupported"));
    }
    Ok(())
}

fn decode_component(value: &str) -> Result<String, ImportError> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| ImportError::new("invalid percent encoding"))?
        .into_owned();
    if decoded.len() > MAX_LINE_BYTES {
        return Err(ImportError::new("decoded field is too long"));
    }
    Ok(decoded)
}

fn optional_url_secret(value: &str) -> Result<Option<Secret>, ImportError> {
    let value = decode_component(value)?;
    if value.is_empty() {
        Ok(None)
    } else {
        secret(value).map(Some)
    }
}

fn secret(value: String) -> Result<Secret, ImportError> {
    Secret::new(value).map_err(|_| ImportError::new("secret field is invalid"))
}

fn required_secret(
    query: &BTreeMap<String, String>,
    key: &str,
    message: &'static str,
) -> Result<Secret, ImportError> {
    query
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ImportError::new(message))
        .and_then(secret)
}

fn display_name(url: &Url, protocol: &str, server: &str, port: u16) -> Result<String, ImportError> {
    match url.fragment() {
        Some(value) if !value.is_empty() => decode_component(value),
        _ => Ok(format!("{protocol} {server}:{port}")),
    }
}

fn json_name(
    object: &Map<String, Value>,
    protocol: &str,
    server: &str,
    port: u16,
) -> Result<String, ImportError> {
    Ok(optional_str(object, "tag")?
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{protocol} {server}:{port}")))
}

fn parse_header_extension(value: &str) -> Result<BTreeMap<String, String>, ImportError> {
    let mut result = BTreeMap::new();
    for line in value.split("\r\n") {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ImportError::new("invalid Naive extra header"))?;
        if result
            .insert(name.trim().to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(ImportError::new("duplicate Naive extra header"));
        }
    }
    Ok(result)
}

fn parse_bool_text(value: &str) -> Result<bool, ImportError> {
    match value {
        "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        _ => Err(ImportError::new("invalid boolean share-link parameter")),
    }
}

fn has_valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn finish_report(
    nodes: Vec<Node>,
    rejected: Vec<NodeRejection>,
    warnings: Vec<&'static str>,
) -> Result<ImportReport, ImportError> {
    if nodes.is_empty() {
        Err(ImportError::new(
            "subscription contains no valid supported nodes",
        ))
    } else {
        Ok(ImportReport {
            nodes,
            rejected,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn imports_vless_reality_vision_without_leaking_rejection_input() {
        let link = format!("vless://{UUID}@example.test:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2#Office");
        let report = import_subscription(link.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 1);
        assert_eq!(report.nodes[0].display_name(), "Office");
        assert_eq!(
            report.nodes[0].protocol_kind(),
            crate::domain::ProtocolKind::Vless
        );
        let empty_short_id = format!(
            "vless://{UUID}@example.test:443?encryption=none&security=reality&type=tcp&sni=cover.test&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789"
        );
        assert_eq!(
            import_subscription(empty_short_id.as_bytes())
                .unwrap()
                .nodes
                .len(),
            1
        );
    }

    #[test]
    fn imports_hysteria_and_naive_base64_once() {
        let links = "hysteria2://fixture-password@example.test:443?obfs=salamander&obfs-password=fixture-obfs&sni=example.test#HY2\nnaive+quic://fixture-user:fixture-pass@example.test:443#Naive";
        let encoded = general_purpose::STANDARD.encode(links);
        let report = import_subscription(encoded.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 2);
        assert!(report
            .nodes
            .iter()
            .all(|node| node.source_format() == SourceFormat::Base64List));
    }

    #[test]
    fn does_not_recursively_decode_base64() {
        let link = format!("vless://{UUID}@example.test:443?encryption=none&type=tcp");
        let twice = general_purpose::STANDARD.encode(general_purpose::STANDARD.encode(link));
        assert_eq!(
            import_subscription(twice.as_bytes())
                .unwrap_err()
                .to_string(),
            "decoded subscription is not a share-link list"
        );
    }

    #[test]
    fn strict_json_rejects_executable_or_detour_fields_per_node() {
        let json = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"safe","server":"example.test","server_port":443,"uuid":"{UUID}","detour":"command"}},{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}"}}]}}"#
        );
        let report = import_subscription(json.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 1);
        assert_eq!(
            report.rejected,
            vec![NodeRejection {
                index: 0,
                reason: "unsupported field in imported outbound"
            }]
        );
        assert!(!format!("{:?}", report.rejected).contains("command"));
    }

    #[test]
    fn imports_strict_json_protocol_shapes_and_port_ranges() {
        let json = format!(
            r#"[
                {{"type":"vless","tag":"Reality","server":"example.test","server_port":443,"uuid":"{UUID}","flow":"xtls-rprx-vision","packet_encoding":"xudp","tls":{{"enabled":true,"server_name":"cover.test","reality":{{"enabled":true,"public_key":"abcdefghijklmnopqrstuvwxyzABCDEFGH123456789","short_id":"a1b2"}}}}}},
                {{"type":"hysteria2","tag":"HY2","server":"example.test","server_ports":["2000:2010","8443"],"hop_interval":"30s","password":"fixture-hy2","obfs":{{"type":"salamander","password":"fixture-obfs"}},"tls":{{"enabled":true,"server_name":"example.test"}}}},
                {{"type":"naive","tag":"Naive","server":"example.test","server_port":443,"username":"fixture-user","password":"fixture-pass","extra_headers":{{"X-Fixture":"safe"}},"quic":true,"tls":{{"server_name":"example.test"}}}}
            ]"#
        );
        let report = import_subscription(json.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 3);
        assert!(report.rejected.is_empty());
    }

    #[test]
    fn rejects_naive_tls_options_not_supported_by_113() {
        let json = r#"{"type":"naive","server":"example.test","server_port":443,"username":"user","password":"pass","tls":{"server_name":"example.test","insecure":true}}"#;
        assert_eq!(
            import_subscription(json.as_bytes())
                .unwrap_err()
                .to_string(),
            "subscription contains no valid supported nodes"
        );
    }

    #[test]
    fn rejects_duplicate_query_and_header_injection() {
        let duplicate = format!("vless://{UUID}@example.test:443?security=none&security=tls");
        assert!(import_subscription(duplicate.as_bytes()).is_err());
        let naive = "naive+https://user:pass@example.test/?extra-headers=X-Test%3Ayes%0D%0AAuthorization%3Asecret";
        assert!(import_subscription(naive.as_bytes()).is_err());
        assert!(import_subscription(b"hysteria2://bad%zz@example.test:443").is_err());
        let ignored_tls = format!("vless://{UUID}@example.test:443?security=none&sni=ignored.test");
        assert!(import_subscription(ignored_tls.as_bytes()).is_err());
    }

    #[test]
    fn rejects_oversize_and_too_deep_inputs_before_model_use() {
        assert!(import_subscription(&vec![b'a'; MAX_INPUT_BYTES + 1]).is_err());
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 2),
            "]".repeat(MAX_JSON_DEPTH + 2)
        );
        assert_eq!(
            import_subscription(deep.as_bytes())
                .unwrap_err()
                .to_string(),
            "JSON nesting is too deep"
        );
    }

    #[test]
    fn imported_errors_never_include_credentials() {
        let bad = "hysteria2://unique-fixture-secret@example.test:443?unknown=unique-query-secret";
        let error = import_subscription(bad.as_bytes()).unwrap_err().to_string();
        assert!(!error.contains("unique-fixture-secret"));
        assert!(!error.contains("unique-query-secret"));
    }
}
