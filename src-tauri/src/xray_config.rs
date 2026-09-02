use std::fmt;

use serde_json::{json, Map, Value};

use crate::domain::{Node, NodeProtocol, PacketEncoding, Secret, VlessFlow, VlessTransport};

pub struct XrayBridgeRequest<'a> {
    pub node: &'a Node,
    pub listen_port: u16,
}

pub struct GeneratedXrayConfig(String);

impl GeneratedXrayConfig {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for GeneratedXrayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedXrayConfig([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayConfigError(&'static str);

impl fmt::Display for XrayConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for XrayConfigError {}

impl XrayConfigError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

/// Generates the private Xray v26.3.27 bridge used only for VLESS REALITY.
///
/// sing-box remains the public listener and route owner. This configuration has one
/// private loopback SOCKS inbound and one VLESS outbound, so it cannot fall back to a direct
/// route when REALITY authentication fails. The listener is bound to an unpublished,
/// process-owned loopback port; omitting SOCKS authentication also avoids client/server schema
/// differences around Xray account fields.
pub fn generate_xray_bridge_config(
    request: XrayBridgeRequest<'_>,
) -> Result<GeneratedXrayConfig, XrayConfigError> {
    if request.listen_port == 0 {
        return Err(XrayConfigError::new("Xray bridge port must be non-zero"));
    }
    let NodeProtocol::Vless(vless) = request.node.protocol() else {
        return Err(XrayConfigError::new(
            "Xray bridge requires a VLESS REALITY node",
        ));
    };
    let reality = vless
        .tls
        .reality
        .as_ref()
        .ok_or_else(|| XrayConfigError::new("Xray bridge requires a VLESS REALITY node"))?;
    if !vless.tls.enabled {
        return Err(XrayConfigError::new("VLESS REALITY requires TLS"));
    }
    if vless.tls.insecure
        || !vless.tls.alpn.is_empty()
        || !vless.tls.certificate_public_key_sha256.is_empty()
        || !vless.tls.ech_config.is_empty()
    {
        return Err(XrayConfigError::new(
            "VLESS REALITY TLS options cannot be represented by the pinned Xray schema",
        ));
    }

    let fingerprint = vless.tls.utls_fingerprint.as_deref().unwrap_or("chrome");
    let server_name = vless
        .tls
        .server_name
        .as_deref()
        .unwrap_or_else(|| request.node.server());
    let mut user = Map::new();
    user.insert("id".into(), json!(vless.uuid.expose()));
    user.insert("encryption".into(), json!("none"));
    if let Some(VlessFlow::Vision) = vless.flow {
        user.insert("flow".into(), json!("xtls-rprx-vision"));
    }

    let mut settings = Map::new();
    settings.insert(
        "vnext".into(),
        json!([{
            "address": request.node.server(),
            "port": vless.server_port,
            "users": [Value::Object(user)]
        }]),
    );
    if let Some(packet_encoding) = vless.packet_encoding {
        settings.insert(
            "packetEncoding".into(),
            json!(match packet_encoding {
                PacketEncoding::PacketAddr => "packetaddr",
                PacketEncoding::Xudp => "xudp",
            }),
        );
    }

    let mut stream = Map::new();
    stream.insert("security".into(), json!("reality"));
    stream.insert(
        "realitySettings".into(),
        json!({
            "serverName": server_name,
            "fingerprint": fingerprint,
            "publicKey": reality.public_key.expose(),
            "shortId": reality.short_id.expose(),
            "spiderX": reality
                .spider_x
                .as_ref()
                .map(Secret::expose)
                .unwrap_or("")
        }),
    );
    match &vless.transport {
        VlessTransport::Tcp => {
            stream.insert("network".into(), json!("tcp"));
        }
        VlessTransport::WebSocket { path, host } => {
            stream.insert("network".into(), json!("ws"));
            let mut websocket = Map::new();
            websocket.insert("path".into(), json!(path));
            if let Some(host) = host {
                websocket.insert("headers".into(), json!({ "Host": host }));
            }
            stream.insert("wsSettings".into(), Value::Object(websocket));
        }
        VlessTransport::Grpc { service_name } => {
            stream.insert("network".into(), json!("grpc"));
            stream.insert(
                "grpcSettings".into(),
                json!({ "serviceName": service_name }),
            );
        }
    }

    let root = json!({
        // Xray reports remote REALITY/VLESS handshake failures at Info. The launcher captures
        // XrayRun stdout into the same bounded, node-redacted diagnostic stream as stderr.
        "log": { "loglevel": "info" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": request.listen_port,
            "protocol": "socks",
            "tag": "bridge-in",
            "settings": {
                "auth": "noauth",
                "udp": true,
                "ip": "127.0.0.1"
            }
        }],
        "outbounds": [{
            "protocol": "vless",
            "tag": "selected",
            "settings": Value::Object(settings),
            "streamSettings": Value::Object(stream)
        }]
    });
    serde_json::to_string_pretty(&root)
        .map(GeneratedXrayConfig)
        .map_err(|_| XrayConfigError::new("could not serialize Xray configuration"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::import_subscription;

    fn node(link: &str) -> Node {
        import_subscription(link.as_bytes())
            .unwrap()
            .nodes
            .into_iter()
            .next()
            .unwrap()
    }

    fn generate(node: &Node) -> GeneratedXrayConfig {
        generate_xray_bridge_config(XrayBridgeRequest {
            node,
            listen_port: 19191,
        })
        .unwrap()
    }

    #[test]
    fn emits_exact_v26327_reality_bridge_shape() {
        let public_key = "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789";
        let node = node(&format!(
            "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&packetEncoding=xudp&sni=cover.test&fp=chrome&pbk={public_key}&sid=a1b2&spx=%2Fprivate%3Ftoken%3Dfixture#Reality"
        ));
        let generated = generate(&node);
        let value: Value = serde_json::from_str(generated.as_str()).unwrap();

        assert_eq!(
            value,
            json!({
                "log": { "loglevel": "info" },
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": 19191,
                    "protocol": "socks",
                    "tag": "bridge-in",
                    "settings": {
                        "auth": "noauth",
                        "udp": true,
                        "ip": "127.0.0.1"
                    }
                }],
                "outbounds": [{
                    "protocol": "vless",
                    "tag": "selected",
                    "settings": {
                        "vnext": [{
                            "address": "example.test",
                            "port": 443,
                            "users": [{
                                "id": "11111111-2222-3333-4444-555555555555",
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }]
                        }],
                        "packetEncoding": "xudp"
                    },
                    "streamSettings": {
                        "security": "reality",
                        "network": "tcp",
                        "realitySettings": {
                            "serverName": "cover.test",
                            "fingerprint": "chrome",
                            "publicKey": public_key,
                            "shortId": "a1b2",
                            "spiderX": "/private?token=fixture"
                        }
                    }
                }]
            })
        );
        assert!(value.pointer("/inbounds/0/settings/accounts").is_none());
        assert!(value.pointer("/inbounds/0/settings/users").is_none());
        let debug = format!("{generated:?}");
        assert!(!debug.contains("11111111-2222-3333-4444-555555555555"));
        assert!(!debug.contains(public_key));
        assert!(!debug.contains("/private?token=fixture"));
    }

    #[test]
    fn maps_websocket_and_grpc_transports_without_extra_outbounds() {
        let ws = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=ws&path=%2Fsocket&host=cdn.test&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2");
        let grpc = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=grpc&serviceName=route&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2");
        let ws_value: Value = serde_json::from_str(generate(&ws).as_str()).unwrap();
        let grpc_value: Value = serde_json::from_str(generate(&grpc).as_str()).unwrap();

        assert_eq!(
            ws_value
                .pointer("/outbounds/0/streamSettings/wsSettings/path")
                .and_then(Value::as_str),
            Some("/socket")
        );
        assert_eq!(
            ws_value
                .pointer("/outbounds/0/streamSettings/wsSettings/headers/Host")
                .and_then(Value::as_str),
            Some("cdn.test")
        );
        assert_eq!(
            grpc_value
                .pointer("/outbounds/0/streamSettings/grpcSettings/serviceName")
                .and_then(Value::as_str),
            Some("route")
        );
    }

    #[test]
    fn defaults_sparse_reality_client_fields_but_rejects_lossy_tls_mapping() {
        let sparse = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=");
        let sparse_value: Value = serde_json::from_str(generate(&sparse).as_str()).unwrap();
        assert_eq!(
            sparse_value
                .pointer("/outbounds/0/streamSettings/realitySettings/serverName")
                .and_then(Value::as_str),
            Some("example.test")
        );
        assert_eq!(
            sparse_value
                .pointer("/outbounds/0/streamSettings/realitySettings/fingerprint")
                .and_then(Value::as_str),
            Some("chrome")
        );

        let unsupported = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&alpn=h2&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2");
        assert!(generate_xray_bridge_config(XrayBridgeRequest {
            node: &unsupported,
            listen_port: 19191,
        })
        .is_err());

        for fingerprint in ["360", "qq"] {
            let link = format!(
                "vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp={fingerprint}&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2"
            );
            let value: Value = serde_json::from_str(generate(&node(&link)).as_str()).unwrap();
            assert_eq!(
                value
                    .pointer("/outbounds/0/streamSettings/realitySettings/fingerprint")
                    .and_then(Value::as_str),
                Some(fingerprint)
            );
        }
    }

    #[test]
    fn rejects_non_reality_and_zero_bridge_port() {
        let tls = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=tls&type=tcp&sni=cover.test");
        assert!(generate_xray_bridge_config(XrayBridgeRequest {
            node: &tls,
            listen_port: 19191,
        })
        .is_err());
        let reality = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2");
        assert!(generate_xray_bridge_config(XrayBridgeRequest {
            node: &reality,
            listen_port: 0,
        })
        .is_err());
    }
}
