use std::{collections::BTreeMap, fmt, str};

use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use url::Url;

use crate::domain::{
    validate_headers, validate_hop_interval, Hysteria2Node, HysteriaObfs, HysteriaObfsKind,
    NaiveNode, Node, NodeProtocol, PacketEncoding, PortSelection, RealityOptions, Secret,
    SourceFormat, TlsOptions, VlessFlow, VlessNode, VlessTransport,
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
    if looks_like_clash_yaml(text) {
        return import_clash_yaml(text);
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
        match parse_share_link(line, source, index) {
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

fn parse_share_link(
    line: &str,
    source: SourceFormat,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
    let lower = line.to_ascii_lowercase();
    if !has_valid_percent_encoding(line) {
        return Err(ImportError::new("share link has invalid percent encoding"));
    }
    if lower.contains("%0d") || lower.contains("%0a") || line.chars().any(char::is_control) {
        return Err(ImportError::new("share link contains a control character"));
    }
    let (normalized, authority_ports) = normalize_hysteria_authority(line)?;
    let url = Url::parse(normalized.as_deref().unwrap_or(line))
        .map_err(|_| ImportError::new("malformed share link"))?;
    match url.scheme().to_ascii_lowercase().as_str() {
        "vless" => parse_vless_url(&url, source, source_ordinal),
        "hysteria2" | "hy2" => parse_hysteria_url(&url, source, source_ordinal, authority_ports),
        "naive+https" | "naive+quic" => parse_naive_url(&url, source, source_ordinal),
        _ => Err(ImportError::new("unsupported share-link scheme")),
    }
}

fn parse_vless_url(
    url: &Url,
    source: SourceFormat,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
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
            // `spx` is Xray's optional REALITY SpiderX hint. sing-box has no
            // corresponding client field, so accepting and discarding it is
            // the compatible translation for VLESS share links.
            "spx",
            "packetEncoding",
            "host",
            "path",
            "serviceName",
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
    let transport = parse_vless_query_transport(&query)?;
    let flow = match query.get("flow").map(String::as_str).unwrap_or("") {
        "" => None,
        "xtls-rprx-vision" => Some(VlessFlow::Vision),
        _ => return Err(ImportError::new("unsupported VLESS flow")),
    };
    let security = query.get("security").map(String::as_str).unwrap_or("none");
    let has_tls_parameters = ["sni", "alpn", "fp", "pbk", "sid", "spx"]
        .iter()
        .any(|key| query.contains_key(*key));
    if security == "none" && has_tls_parameters {
        return Err(ImportError::new(
            "TLS parameters are present while VLESS security is disabled",
        ));
    }
    if security == "tls"
        && ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.contains_key(*key))
    {
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
                spider_x: query
                    .get("spx")
                    .cloned()
                    .map(Secret::new_allow_empty)
                    .transpose()
                    .map_err(|_| ImportError::new("REALITY SpiderX path is invalid"))?,
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
            transport,
            tls,
        }),
        source,
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid VLESS node"))
}

fn parse_vless_query_transport(
    query: &BTreeMap<String, String>,
) -> Result<VlessTransport, ImportError> {
    match query.get("type").map(String::as_str).unwrap_or("tcp") {
        "" | "tcp" => {
            if ["host", "path", "serviceName"]
                .iter()
                .any(|key| query.contains_key(*key))
            {
                return Err(ImportError::new(
                    "VLESS transport parameters do not match TCP",
                ));
            }
            Ok(VlessTransport::Tcp)
        }
        "ws" => {
            if query.contains_key("serviceName") {
                return Err(ImportError::new(
                    "gRPC service name is invalid for WebSocket transport",
                ));
            }
            let path = query
                .get("path")
                .filter(|value| !value.is_empty())
                .cloned()
                .unwrap_or_else(|| "/".into());
            let host = query.get("host").filter(|value| !value.is_empty()).cloned();
            Ok(VlessTransport::WebSocket { path, host })
        }
        "grpc" => {
            if query.contains_key("host") || query.contains_key("path") {
                return Err(ImportError::new(
                    "WebSocket parameters are invalid for gRPC transport",
                ));
            }
            let service_name = query.get("serviceName").cloned().unwrap_or_default();
            Ok(VlessTransport::Grpc { service_name })
        }
        _ => Err(ImportError::new("unsupported VLESS transport")),
    }
}

fn parse_hysteria_url(
    url: &Url,
    source: SourceFormat,
    source_ordinal: usize,
    authority_ports: Option<PortSelection>,
) -> Result<Node, ImportError> {
    require_authority_only(url)?;
    let query = strict_query(
        url,
        &[
            "obfs",
            "obfs-password",
            "sni",
            "insecure",
            "alpn",
            "fp",
            "security",
            "ech",
            "pinSHA256",
        ],
    )?;
    if query
        .get("security")
        .is_some_and(|security| security != "tls")
    {
        return Err(ImportError::new("unsupported Hysteria2 security"));
    }
    if query.contains_key("pinSHA256") {
        return Err(ImportError::new(
            "Hysteria certificate fingerprint import is not supported",
        ));
    }
    let server = host(url)?;
    let ports = authority_ports.unwrap_or(
        PortSelection::single(url.port().unwrap_or(443))
            .map_err(|_| ImportError::new("invalid Hysteria2 port"))?,
    );
    let port = ports.primary_port();
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
    if query.contains_key("ech") {
        return Err(ImportError::new(
            "Hysteria2 URI ECH import is not supported safely",
        ));
    }
    let mut tls = tls_from_query(&query)?;
    // Hysteria2 runs over QUIC. sing-box only supports ECH from its custom TLS
    // options for QUIC, so an ecosystem `fp` hint is validated above but must
    // not be emitted as a uTLS configuration that the engine cannot apply.
    tls.utls_fingerprint = None;
    let name = display_name(url, "Hysteria2", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Hysteria2(Hysteria2Node {
            ports,
            hop_interval: None,
            password: secret(auth)?,
            obfs,
            tls,
        }),
        source,
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid Hysteria2 node"))
}

fn parse_naive_url(
    url: &Url,
    source: SourceFormat,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
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
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid Naive node"))
}

fn import_json(text: &str) -> Result<ImportReport, ImportError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let root = NoDuplicateJson::deserialize(&mut deserializer)
        .map_err(|_| ImportError::new("invalid sing-box JSON"))?
        .0;
    deserializer
        .end()
        .map_err(|_| ImportError::new("invalid sing-box JSON"))?;
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
        match parse_json_outbound(value, index) {
            Ok(node) => nodes.push(node),
            Err(error) => rejected.push(NodeRejection {
                index,
                reason: error.0,
            }),
        }
    }
    finish_report(nodes, rejected, warnings)
}

fn looks_like_clash_yaml(text: &str) -> bool {
    text.lines()
        .filter(|line| !line.starts_with(char::is_whitespace))
        .map(str::trim)
        .any(|line| line == "proxies:" || line.starts_with("proxies: "))
}

fn import_clash_yaml(text: &str) -> Result<ImportReport, ImportError> {
    use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_events: 50_000,
            max_aliases: 0,
            max_anchors: 0,
            max_recorded_anchor_events: 0,
            max_recorded_anchor_bytes: 0,
            max_depth: MAX_JSON_DEPTH,
            max_documents: 1,
            max_nodes: 10_000,
            max_total_scalar_bytes: MAX_INPUT_BYTES,
            max_total_comment_bytes: MAX_INPUT_BYTES,
            max_merge_keys: 0,
        },
        emit_comments: false,
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        reject_unsupported_tags: true,
    };
    let root: Value = serde_saphyr::from_str_with_options(text, options)
        .map_err(|_| ImportError::new("invalid Clash YAML"))?;
    if json_depth(&root) > MAX_JSON_DEPTH {
        return Err(ImportError::new("YAML nesting is too deep"));
    }
    let object = root
        .as_object()
        .ok_or_else(|| ImportError::new("Clash YAML must be an object"))?;
    strict_keys(object, &["proxies"])
        .map_err(|_| ImportError::new("unsupported top-level Clash field"))?;
    let proxies = object
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or_else(|| ImportError::new("Clash proxies must be an array"))?;
    if proxies.len() > MAX_NODES {
        return Err(ImportError::new("subscription contains too many nodes"));
    }
    let mut nodes = Vec::new();
    let mut rejected = Vec::new();
    for (index, proxy) in proxies.iter().enumerate() {
        let result = proxy
            .as_object()
            .ok_or_else(|| ImportError::new("Clash proxy must be an object"))
            .and_then(|object| match required_str(object, "type")? {
                "vless" => parse_clash_vless(object, index),
                "hysteria2" | "hy2" => parse_clash_hysteria(object, index),
                _ => Err(ImportError::new("unsupported Clash proxy type")),
            });
        match result {
            Ok(node) => nodes.push(node),
            Err(error) => rejected.push(NodeRejection {
                index,
                reason: error.0,
            }),
        }
    }
    finish_report(nodes, rejected, Vec::new())
}

fn parse_clash_vless(
    object: &Map<String, Value>,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
    strict_keys(
        object,
        &[
            "name",
            "type",
            "server",
            "port",
            "uuid",
            "network",
            "tls",
            "servername",
            "skip-cert-verify",
            "alpn",
            "client-fingerprint",
            "reality-opts",
            "ws-opts",
            "grpc-opts",
            "packet-encoding",
            "flow",
        ],
    )?;
    let server = required_str(object, "server")?.to_owned();
    let port = required_port(object, "port")?;
    let uuid = required_str(object, "uuid")?.to_owned();
    crate::domain::validate_uuid(&uuid).map_err(|_| ImportError::new("invalid VLESS UUID"))?;
    let network = optional_str(object, "network")?.unwrap_or("tcp");
    let transport = match network {
        "tcp" => {
            if object.contains_key("ws-opts") || object.contains_key("grpc-opts") {
                return Err(ImportError::new(
                    "Clash VLESS transport options do not match TCP",
                ));
            }
            VlessTransport::Tcp
        }
        "ws" => {
            if object.contains_key("grpc-opts") {
                return Err(ImportError::new("invalid Clash VLESS transport options"));
            }
            let options = object
                .get("ws-opts")
                .and_then(Value::as_object)
                .ok_or_else(|| ImportError::new("Clash VLESS ws-opts are required"))?;
            strict_keys(options, &["path", "headers"])?;
            let path = optional_str(options, "path")?.unwrap_or("/").to_owned();
            let host = match options.get("headers") {
                None => None,
                Some(Value::Object(headers)) => {
                    strict_keys(headers, &["Host"])?;
                    Some(required_str(headers, "Host")?.to_owned())
                }
                _ => return Err(ImportError::new("invalid Clash WebSocket headers")),
            };
            VlessTransport::WebSocket { path, host }
        }
        "grpc" => {
            if object.contains_key("ws-opts") {
                return Err(ImportError::new("invalid Clash VLESS transport options"));
            }
            let options = object
                .get("grpc-opts")
                .map(|value| {
                    value
                        .as_object()
                        .ok_or_else(|| ImportError::new("invalid Clash VLESS grpc-opts"))
                })
                .transpose()?;
            if let Some(options) = options {
                strict_keys(options, &["grpc-service-name"])?;
            }
            VlessTransport::Grpc {
                service_name: options
                    .map(|options| optional_str(options, "grpc-service-name"))
                    .transpose()?
                    .flatten()
                    .unwrap_or("")
                    .to_owned(),
            }
        }
        _ => return Err(ImportError::new("unsupported Clash VLESS transport")),
    };
    let flow = match optional_str(object, "flow")? {
        None | Some("") => None,
        Some("xtls-rprx-vision") => Some(VlessFlow::Vision),
        _ => return Err(ImportError::new("unsupported VLESS flow")),
    };
    let packet_encoding = match optional_str(object, "packet-encoding")? {
        None | Some("") => None,
        Some("packetaddr") => Some(PacketEncoding::PacketAddr),
        Some("xudp") => Some(PacketEncoding::Xudp),
        _ => return Err(ImportError::new("unsupported VLESS packet encoding")),
    };
    let reality = match object.get("reality-opts") {
        None => None,
        Some(Value::Object(value)) => {
            strict_keys(value, &["public-key", "short-id"])?;
            Some(RealityOptions {
                public_key: secret(required_str(value, "public-key")?.to_owned())?,
                short_id: Secret::new_allow_empty(
                    optional_str(value, "short-id")?.unwrap_or("").to_owned(),
                )
                .map_err(|_| ImportError::new("REALITY short ID is invalid"))?,
                spider_x: None,
            })
        }
        _ => return Err(ImportError::new("invalid Clash REALITY options")),
    };
    let tls_enabled = optional_bool(object, "tls")?.unwrap_or(false) || reality.is_some();
    let tls = TlsOptions {
        enabled: tls_enabled,
        server_name: optional_str(object, "servername")?.map(str::to_owned),
        insecure: optional_bool(object, "skip-cert-verify")?.unwrap_or(false),
        alpn: string_array(object.get("alpn"), "invalid TLS ALPN")?,
        certificate_public_key_sha256: Vec::new(),
        ech_config: Vec::new(),
        utls_fingerprint: optional_str(object, "client-fingerprint")?.map(str::to_owned),
        reality,
    };
    let name = required_str(object, "name")?.to_owned();
    Node::create(
        name,
        server,
        NodeProtocol::Vless(VlessNode {
            server_port: port,
            uuid: secret(uuid)?,
            flow,
            packet_encoding,
            transport,
            tls,
        }),
        SourceFormat::ClashYaml,
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid Clash VLESS node"))
}

fn parse_clash_hysteria(
    object: &Map<String, Value>,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
    strict_keys(
        object,
        &[
            "name",
            "type",
            "server",
            "port",
            "ports",
            "password",
            "obfs",
            "obfs-password",
            "sni",
            "skip-cert-verify",
            "alpn",
            "hop-interval",
        ],
    )?;
    let server = required_str(object, "server")?.to_owned();
    let ports = match (object.get("port"), object.get("ports")) {
        (Some(_), Some(Value::String(value))) => {
            required_port(object, "port")?;
            parse_clash_port_expression(value)?
        }
        (Some(_), None) => PortSelection::single(required_port(object, "port")?)
            .map_err(|_| ImportError::new("invalid Hysteria2 port"))?,
        (None, Some(Value::String(value))) => parse_clash_port_expression(value)?,
        _ => return Err(ImportError::new("Hysteria2 port is required")),
    };
    let hop_interval = match object.get("hop-interval") {
        None => None,
        Some(Value::Number(value)) => {
            let seconds = value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| (1..=3600).contains(value))
                .ok_or_else(|| ImportError::new("invalid Hysteria2 hop interval"))?;
            Some(format!("{seconds}s"))
        }
        Some(_) => return Err(ImportError::new("invalid Hysteria2 hop interval")),
    };
    let obfs = match optional_str(object, "obfs")? {
        None | Some("") => {
            if object.contains_key("obfs-password") {
                return Err(ImportError::new("Hysteria2 obfs password has no obfs type"));
            }
            None
        }
        Some("salamander") => Some(HysteriaObfs {
            kind: HysteriaObfsKind::Salamander,
            password: secret(required_str(object, "obfs-password")?.to_owned())?,
        }),
        _ => return Err(ImportError::new("unsupported Hysteria2 obfuscation")),
    };
    let tls = TlsOptions {
        enabled: true,
        server_name: optional_str(object, "sni")?.map(str::to_owned),
        insecure: optional_bool(object, "skip-cert-verify")?.unwrap_or(false),
        alpn: string_array(object.get("alpn"), "invalid TLS ALPN")?,
        certificate_public_key_sha256: Vec::new(),
        ech_config: Vec::new(),
        utls_fingerprint: None,
        reality: None,
    };
    let name = required_str(object, "name")?.to_owned();
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
        SourceFormat::ClashYaml,
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid Clash Hysteria2 node"))
}

fn parse_clash_port_expression(value: &str) -> Result<PortSelection, ImportError> {
    if value.is_empty() || value.len() > 1_024 {
        return Err(ImportError::new("invalid Hysteria2 port range"));
    }
    let values = value
        .split(',')
        .map(|part| {
            if let Some((start, end)) = part.split_once('-') {
                format!("{start}:{end}")
            } else {
                part.to_owned()
            }
        })
        .collect();
    PortSelection::ranges(values).map_err(|_| ImportError::new("invalid Hysteria2 port range"))
}

fn parse_json_outbound(value: &Value, source_ordinal: usize) -> Result<Node, ImportError> {
    let object = value
        .as_object()
        .ok_or_else(|| ImportError::new("outbound must be an object"))?;
    match required_str(object, "type")? {
        "vless" => parse_json_vless(object, source_ordinal),
        "hysteria2" => parse_json_hysteria(object, source_ordinal),
        "naive" => parse_json_naive(object, source_ordinal),
        _ => Err(ImportError::new("unsupported outbound type")),
    }
}

fn parse_json_vless(
    object: &Map<String, Value>,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
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
            "transport",
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
    let transport = parse_json_vless_transport(object.get("transport"))?;
    let name = json_name(object, "VLESS", &server, port)?;
    Node::create(
        name,
        server,
        NodeProtocol::Vless(VlessNode {
            server_port: port,
            uuid: secret(uuid)?,
            flow,
            packet_encoding,
            transport,
            tls,
        }),
        SourceFormat::SingBoxJson,
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid VLESS node"))
}

fn parse_json_vless_transport(value: Option<&Value>) -> Result<VlessTransport, ImportError> {
    let Some(value) = value else {
        return Ok(VlessTransport::Tcp);
    };
    let object = value
        .as_object()
        .ok_or_else(|| ImportError::new("VLESS transport must be an object"))?;
    match required_str(object, "type")? {
        "tcp" => {
            strict_keys(object, &["type"])?;
            Ok(VlessTransport::Tcp)
        }
        "ws" => {
            strict_keys(object, &["type", "path", "headers"])?;
            let path = optional_str(object, "path")?
                .filter(|value| !value.is_empty())
                .unwrap_or("/")
                .to_owned();
            let host = match object.get("headers") {
                None => None,
                Some(Value::Object(headers)) => {
                    strict_keys(headers, &["Host"])?;
                    Some(required_str(headers, "Host")?.to_owned())
                }
                _ => return Err(ImportError::new("invalid VLESS WebSocket headers")),
            };
            Ok(VlessTransport::WebSocket { path, host })
        }
        "grpc" => {
            strict_keys(object, &["type", "service_name"])?;
            Ok(VlessTransport::Grpc {
                service_name: optional_str(object, "service_name")?
                    .unwrap_or("")
                    .to_owned(),
            })
        }
        _ => Err(ImportError::new("unsupported VLESS transport")),
    }
}

fn parse_json_hysteria(
    object: &Map<String, Value>,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
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
        source_ordinal,
    )
    .map_err(|_| ImportError::new("invalid Hysteria2 node"))
}

fn parse_json_naive(
    object: &Map<String, Value>,
    source_ordinal: usize,
) -> Result<Node, ImportError> {
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
        source_ordinal,
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
                    spider_x: None,
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

fn normalize_hysteria_authority(
    line: &str,
) -> Result<(Option<String>, Option<PortSelection>), ImportError> {
    let Some((scheme, remainder)) = line.split_once("://") else {
        return Ok((None, None));
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "hysteria2" | "hy2") {
        return Ok((None, None));
    }
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    let port_start = if host_port.starts_with('[') {
        let close = host_port
            .find(']')
            .ok_or_else(|| ImportError::new("malformed Hysteria2 authority"))?;
        match host_port.as_bytes().get(close + 1) {
            Some(b':') => close + 2,
            None => return Ok((None, None)),
            _ => return Err(ImportError::new("malformed Hysteria2 authority")),
        }
    } else {
        host_port
            .rfind(':')
            .map(|index| index + 1)
            .unwrap_or(host_port.len())
    };
    if port_start == host_port.len() {
        return Ok((None, None));
    }
    let expression = &host_port[port_start..];
    if !expression.contains(',') && !expression.contains('-') {
        return Ok((None, None));
    }
    if expression.len() > 1_024 {
        return Err(ImportError::new("Hysteria2 port expression is too long"));
    }
    let mut ranges = Vec::new();
    for part in expression.split(',') {
        if part.is_empty() || ranges.len() >= 32 {
            return Err(ImportError::new("invalid Hysteria2 port range"));
        }
        let normalized = if let Some((start, end)) = part.split_once('-') {
            if end.contains('-') {
                return Err(ImportError::new("invalid Hysteria2 port range"));
            }
            format!("{start}:{end}")
        } else {
            part.to_owned()
        };
        ranges.push(normalized);
    }
    let ports = PortSelection::ranges(ranges)
        .map_err(|_| ImportError::new("invalid Hysteria2 port range"))?;
    let primary = ports.primary_port();
    let host_port_offset = authority.len() - host_port.len();
    let absolute_port_start = scheme.len() + 3 + host_port_offset + port_start;
    let absolute_port_end = scheme.len() + 3 + authority_end;
    let mut normalized = String::with_capacity(line.len());
    normalized.push_str(&line[..absolute_port_start]);
    normalized.push_str(&primary.to_string());
    normalized.push_str(&line[absolute_port_end..]);
    Ok((Some(normalized), Some(ports)))
}

struct NoDuplicateJson(Value);

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.to_owned()))
            }
            fn visit_string<E>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(value))
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<NoDuplicateJson>()? {
                    values.push(value.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    let value = map.next_value::<NoDuplicateJson>()?;
                    values.insert(key, value.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(JsonVisitor).map(Self)
    }
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
    mut warnings: Vec<&'static str>,
) -> Result<ImportReport, ImportError> {
    if nodes.is_empty() {
        Err(ImportError::new(
            "subscription contains no valid supported nodes",
        ))
    } else {
        if nodes.iter().any(Node::requires_insecure_approval)
            && !warnings.contains(&"insecure TLS nodes require explicit approval before use")
        {
            warnings.push("insecure TLS nodes require explicit approval before use");
        }
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
    fn imports_vless_reality_with_optional_xray_spider_x_hint() {
        let base = format!(
            "vless://{UUID}@example.test:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2#Office"
        );
        let with_spider_x = format!(
            "vless://{UUID}@example.test:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2&spx=%2Fprivate%3Ftoken%3Dfixture#Office"
        );
        let with_empty_spider_x = format!(
            "vless://{UUID}@example.test:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2&spx=#Office"
        );

        let baseline = import_subscription(base.as_bytes()).unwrap();
        for (link, expected) in [
            (with_spider_x, "/private?token=fixture"),
            (with_empty_spider_x, ""),
        ] {
            let report = import_subscription(link.as_bytes()).unwrap();
            assert_eq!(report.nodes.len(), 1);
            assert!(report.rejected.is_empty());
            assert_eq!(report.nodes[0].id(), baseline.nodes[0].id());
            let NodeProtocol::Vless(vless) = report.nodes[0].protocol() else {
                panic!("expected VLESS node");
            };
            assert_eq!(
                vless
                    .tls
                    .reality
                    .as_ref()
                    .and_then(|reality| reality.spider_x.as_ref())
                    .map(Secret::expose),
                Some(expected)
            );
        }

        let invalid_path = format!(
            "vless://{UUID}@example.test:443?encryption=none&security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2&spx=relative"
        );
        assert!(import_subscription(invalid_path.as_bytes()).is_err());

        for security in ["none", "tls"] {
            let misplaced = format!(
                "vless://{UUID}@example.test:443?encryption=none&security={security}&type=tcp&spx=%2F"
            );
            assert!(import_subscription(misplaced.as_bytes()).is_err());
        }
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
    fn imports_extended_hysteria_uri_without_emitting_quic_utls() {
        let link = "hysteria2://fixture-user:fixture-pass@example.test:443/?alpn=h3&fp=chrome&obfs=salamander&obfs-password=fixture-obfs&security=tls&sni=cover.test#HY2";
        let report = import_subscription(link.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 1);
        assert!(report.rejected.is_empty());

        let NodeProtocol::Hysteria2(node) = report.nodes[0].protocol() else {
            panic!("expected Hysteria2 node");
        };
        assert_eq!(node.password.expose(), "fixture-user:fixture-pass");
        assert_eq!(node.tls.alpn, vec!["h3"]);
        assert_eq!(node.tls.server_name.as_deref(), Some("cover.test"));
        assert!(node.tls.utls_fingerprint.is_none());
        assert!(matches!(
            node.obfs.as_ref().map(|obfs| obfs.kind),
            Some(HysteriaObfsKind::Salamander)
        ));
    }

    #[test]
    fn rejects_non_tls_hysteria_security_extension() {
        for security in ["", "none", "reality"] {
            let link =
                format!("hysteria2://fixture@example.test:443?security={security}&sni=cover.test");
            let report = import_subscription(link.as_bytes()).unwrap_err();
            assert_eq!(
                report.to_string(),
                "subscription contains no valid supported nodes"
            );
        }
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

    #[test]
    fn rejects_duplicate_json_keys_at_every_security_sensitive_depth() {
        let fixtures = [
            format!(
                r#"{{"type":"vless","type":"hysteria2","server":"example.test","server_port":443,"uuid":"{UUID}"}}"#
            ),
            format!(
                r#"{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}"#
            ),
            format!(
                r#"{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","tls":{{"enabled":true}},"tls":{{"enabled":false}}}}"#
            ),
            format!(
                r#"{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","tls":{{"enabled":true,"enabled":false}}}}"#
            ),
            format!(
                r#"{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","tls":{{"enabled":true,"insecure":false,"insecure":true}}}}"#
            ),
            format!(
                r#"{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","tls":{{"enabled":true,"reality":{{"enabled":true,"public_key":"abcdefghijklmnopqrstuvwxyzABCDEFGH123456789","public_key":"abcdefghijklmnopqrstuvwxyzABCDEFGH123456780","short_id":""}}}}}}"#
            ),
            r#"{"type":"naive","server":"example.test","server_port":443,"username":"user","password":"first","password":"second","tls":{"enabled":true}}"#.to_owned(),
        ];
        for fixture in fixtures {
            assert_eq!(
                import_subscription(fixture.as_bytes())
                    .unwrap_err()
                    .to_string(),
                "invalid sing-box JSON"
            );
        }
    }

    #[test]
    fn duplicate_nodes_have_unique_instance_ids_and_shared_update_key() {
        let input = format!(
            "vless://{UUID}@example.test:443?encryption=none&type=tcp#same\nvless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.test:443?encryption=none&type=tcp#same"
        );
        let nodes = import_subscription(input.as_bytes()).unwrap().nodes;
        assert_eq!(nodes[0].update_key(), nodes[1].update_key());
        assert_ne!(nodes[0].id(), nodes[1].id());
    }

    #[test]
    fn imports_vless_ws_grpc_and_hysteria_multiport() {
        let input = format!(
            "vless://{UUID}@example.test:443?security=tls&type=ws&path=%2Fsocket&host=cdn.test&sni=cover.test#WS\nvless://{UUID}@example.test:443?security=tls&type=grpc&serviceName=route&sni=cover.test#gRPC\nhysteria2://fixture@example.test:443,2000-2010?sni=example.test#HY2"
        );
        let nodes = import_subscription(input.as_bytes()).unwrap().nodes;
        assert_eq!(nodes.len(), 3);
        assert!(matches!(
            nodes[0].protocol(),
            NodeProtocol::Vless(VlessNode {
                transport: VlessTransport::WebSocket { .. },
                ..
            })
        ));
        assert!(matches!(
            nodes[1].protocol(),
            NodeProtocol::Vless(VlessNode {
                transport: VlessTransport::Grpc { .. },
                ..
            })
        ));
        assert!(matches!(
            nodes[2].protocol(),
            NodeProtocol::Hysteria2(Hysteria2Node {
                ports: PortSelection::Ranges(_),
                ..
            })
        ));
    }

    #[test]
    fn hysteria_uri_ech_and_pin_sha_fail_closed() {
        for parameter in ["ech=Zml4dHVyZQ==", "pinSHA256=fixture-pin"] {
            let input = format!(
                "hysteria2://fixture@example.test:443?sni=example.test&{parameter}#bad\nhysteria2://fixture@example.test:443?sni=example.test#good"
            );
            let report = import_subscription(input.as_bytes()).unwrap();
            assert_eq!(report.nodes.len(), 1);
            assert_eq!(report.rejected.len(), 1);
        }
    }

    #[test]
    fn imports_strict_clash_yaml_proxies_only() {
        let yaml = format!(
            "proxies:\n  - name: ws\n    type: vless\n    server: example.test\n    port: 443\n    uuid: {UUID}\n    network: ws\n    tls: true\n    servername: cover.test\n    ws-opts:\n      path: /socket\n      headers:\n        Host: cdn.test\n  - name: hy2\n    type: hysteria2\n    server: example.test\n    ports: 443,2000-2010\n    password: fixture\n    sni: example.test\n"
        );
        let report = import_subscription(yaml.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 2);
        assert!(report
            .nodes
            .iter()
            .all(|node| node.source_format() == SourceFormat::ClashYaml));
    }

    #[test]
    fn clash_yaml_rejects_duplicates_extensions_and_anchors() {
        let duplicate = "proxies:\n  - name: one\n    name: two\n    type: hysteria2\n    server: example.test\n    port: 443\n    password: fixture\n";
        assert_eq!(
            import_subscription(duplicate.as_bytes())
                .unwrap_err()
                .to_string(),
            "invalid Clash YAML"
        );
        let extra = "proxies: []\nrules: []\n";
        assert_eq!(
            import_subscription(extra.as_bytes())
                .unwrap_err()
                .to_string(),
            "unsupported top-level Clash field"
        );
        let anchor = "proxies: &nodes []\n";
        assert_eq!(
            import_subscription(anchor.as_bytes())
                .unwrap_err()
                .to_string(),
            "invalid Clash YAML"
        );
        let custom_tag = "proxies: !include fixture.yaml\n";
        assert_eq!(
            import_subscription(custom_tag.as_bytes())
                .unwrap_err()
                .to_string(),
            "invalid Clash YAML"
        );
        let multiple_documents = "---\nproxies: []\n---\nproxies: []\n";
        assert_eq!(
            import_subscription(multiple_documents.as_bytes())
                .unwrap_err()
                .to_string(),
            "invalid Clash YAML"
        );
    }

    #[test]
    fn imports_json_ws_and_grpc_transport_shapes() {
        let json = format!(
            r#"[{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","transport":{{"type":"ws","path":"/socket","headers":{{"Host":"cdn.test"}}}}}},{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","transport":{{"type":"grpc","service_name":"route"}}}}]"#
        );
        let report = import_subscription(json.as_bytes()).unwrap();
        assert_eq!(report.nodes.len(), 2);
        assert!(matches!(
            report.nodes[0].protocol(),
            NodeProtocol::Vless(VlessNode {
                transport: VlessTransport::WebSocket { .. },
                ..
            })
        ));
        assert!(matches!(
            report.nodes[1].protocol(),
            NodeProtocol::Vless(VlessNode {
                transport: VlessTransport::Grpc { .. },
                ..
            })
        ));
    }

    #[test]
    fn insecure_import_persists_warning_metadata() {
        let report = import_subscription(
            b"hysteria2://fixture@example.test:443?sni=example.test&insecure=1",
        )
        .unwrap();
        assert!(report.nodes[0].requires_insecure_approval());
        assert_eq!(
            report.nodes[0].security_warnings(),
            &[crate::domain::SecurityWarning::InsecureTlsVerification]
        );
        assert_eq!(
            report.warnings,
            vec!["insecure TLS nodes require explicit approval before use"]
        );
    }

    #[test]
    fn clash_hysteria_prefers_valid_ports_and_normalizes_fixed_hop_interval() {
        let yaml = "proxies:\n  - name: hopping\n    type: hysteria2\n    server: example.test\n    port: 443\n    ports: 2000-2010,8443\n    hop-interval: 15\n    password: fixture\n    sni: example.test\n";
        let node = import_subscription(yaml.as_bytes())
            .unwrap()
            .nodes
            .remove(0);
        assert!(matches!(
            node.protocol(),
            NodeProtocol::Hysteria2(Hysteria2Node {
                ports: PortSelection::Ranges(_),
                hop_interval: Some(value),
                ..
            }) if value == "15s"
        ));

        let invalid_range = "proxies:\n  - name: bad\n    type: hysteria2\n    server: example.test\n    port: 443\n    ports: 2000-2010\n    hop-interval: 15-30\n    password: fixture\n";
        assert!(import_subscription(invalid_range.as_bytes()).is_err());
        let invalid_fixed_port = "proxies:\n  - name: bad-port\n    type: hysteria2\n    server: example.test\n    port: 70000\n    ports: 2000-2010\n    password: fixture\n";
        assert!(import_subscription(invalid_fixed_port.as_bytes()).is_err());
    }

    #[test]
    fn grpc_service_name_is_optional_in_all_supported_formats() {
        let share =
            format!("vless://{UUID}@example.test:443?security=tls&type=grpc&sni=example.test");
        let json = format!(
            r#"{{"type":"vless","server":"example.test","server_port":443,"uuid":"{UUID}","transport":{{"type":"grpc"}}}}"#
        );
        let yaml = format!(
            "proxies:\n  - name: grpc\n    type: vless\n    server: example.test\n    port: 443\n    uuid: {UUID}\n    network: grpc\n"
        );
        for input in [share, json, yaml] {
            let node = import_subscription(input.as_bytes())
                .unwrap()
                .nodes
                .remove(0);
            assert!(matches!(
                node.protocol(),
                NodeProtocol::Vless(VlessNode {
                    transport: VlessTransport::Grpc { service_name },
                    ..
                }) if service_name.is_empty()
            ));
        }
    }

    #[test]
    fn websocket_host_accepts_http_authority_and_rejects_injection() {
        for host in ["cdn.test%3A8443", "%5B2001%3Adb8%3A%3A1%5D%3A443"] {
            let link = format!(
                "vless://{UUID}@example.test:443?security=tls&type=ws&host={host}&sni=example.test"
            );
            assert!(import_subscription(link.as_bytes()).is_ok());
        }
        for host in ["cdn.test%3Abad", "cdn.test%2Fevil", "user%40cdn.test"] {
            let link = format!(
                "vless://{UUID}@example.test:443?security=tls&type=ws&host={host}&sni=example.test"
            );
            assert!(import_subscription(link.as_bytes()).is_err());
        }
    }
}
