use std::fmt;

use serde_json::{json, Map, Value};

use crate::domain::{Node, NodeProtocol, PacketEncoding, Secret, VlessFlow, VlessTransport};

pub struct XrayBridgeRequest<'a> {
    pub node: &'a Node,
    pub listen_port: u16,
    pub username: &'a str,
    pub password: &'a str,
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
/// authenticated loopback SOCKS inbound and one VLESS outbound, so it cannot fall back to a
/// direct route when REALITY authentication fails.
pub fn generate_xray_bridge_config(
    request: XrayBridgeRequest<'_>,
) -> Result<GeneratedXrayConfig, XrayConfigError> {
    if request.listen_port == 0 {
        return Err(XrayConfigError::new("Xray bridge port must be non-zero"));
    }
    let username = Secret::new(request.username.to_owned())
        .map_err(|_| XrayConfigError::new("invalid Xray bridge username"))?;
    let password = Secret::new(request.password.to_owned())
        .map_err(|_| XrayConfigError::new("invalid Xray bridge password"))?;
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
        "log": { "loglevel": "error" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": request.listen_port,
            "protocol": "socks",
            "tag": "bridge-in",
            "settings": {
                "auth": "password",
                "users": [{
                    "user": username.expose(),
                    "pass": password.expose()
                }],
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
            username: "fixture-bridge-user",
            password: "fixture-bridge-password",
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
            value.pointer("/inbounds/0/listen").and_then(Value::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(
            value
                .pointer("/inbounds/0/settings/auth")
                .and_then(Value::as_str),
            Some("password")
        );
        assert_eq!(
            value
                .pointer("/inbounds/0/settings/udp")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(value["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(
            value
                .pointer("/outbounds/0/settings/vnext/0/address")
                .and_then(Value::as_str),
            Some("example.test")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/settings/vnext/0/users/0/flow")
                .and_then(Value::as_str),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/settings/packetEncoding")
                .and_then(Value::as_str),
            Some("xudp")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/streamSettings/network")
                .and_then(Value::as_str),
            Some("tcp")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/streamSettings/security")
                .and_then(Value::as_str),
            Some("reality")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/streamSettings/realitySettings/publicKey")
                .and_then(Value::as_str),
            Some(public_key)
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/streamSettings/realitySettings/spiderX")
                .and_then(Value::as_str),
            Some("/private?token=fixture")
        );
        assert!(!format!("{generated:?}").contains("fixture-bridge-password"));
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
            username: "fixture",
            password: "fixture",
        })
        .is_err());
    }

    #[test]
    fn rejects_non_reality_and_invalid_bridge_credentials() {
        let tls = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=tls&type=tcp&sni=cover.test");
        assert!(generate_xray_bridge_config(XrayBridgeRequest {
            node: &tls,
            listen_port: 19191,
            username: "fixture",
            password: "fixture",
        })
        .is_err());
        let reality = node("vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&type=tcp&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2");
        for (port, username, password) in [
            (0, "fixture", "fixture"),
            (19191, "", "fixture"),
            (19191, "fixture", ""),
        ] {
            assert!(generate_xray_bridge_config(XrayBridgeRequest {
                node: &reality,
                listen_port: port,
                username,
                password,
            })
            .is_err());
        }
    }
}
