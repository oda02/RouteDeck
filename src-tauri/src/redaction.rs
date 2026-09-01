use std::{collections::BTreeSet, fmt};

use serde_json::Value;
use url::Url;

use crate::domain::{Node, NodeProtocol, Secret, TlsOptions, VlessTransport};

const REDACTED: &str = "[REDACTED]";
const OMITTED: &str = "[REDACTED: diagnostic omitted]";
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_SECRET_PATTERNS: usize = 128;
const MAX_PATTERN_BYTES: usize = 64 * 1024;
const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "auth",
    "password",
    "token",
    "uuid",
    "public_key",
    "short_id",
    "pbk",
    "sid",
    "spx",
    "spider_x",
    "spiderX",
    "ech",
    "obfs-password",
    "obfs_password",
    "subscription",
    "subscription_url",
    "certificate_public_key_sha256",
    "process_path",
    "canonical_exe_path",
];

#[derive(Default, Clone)]
pub struct Redactor {
    secrets: Vec<String>,
    saturated: bool,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Redactor([REDACTED])")
    }
}

impl Redactor {
    pub fn from_nodes(nodes: &[Node]) -> Self {
        let mut redactor = Self::default();
        for node in nodes {
            redactor.add_text(node.server());
            match node.protocol() {
                NodeProtocol::Vless(value) => {
                    redactor.add(&value.uuid);
                    redactor.add_tls(&value.tls);
                    match &value.transport {
                        VlessTransport::Tcp => {}
                        VlessTransport::WebSocket { path, host } => {
                            redactor.add_text(path);
                            if let Some(host) = host {
                                redactor.add_text(host);
                            }
                        }
                        VlessTransport::Grpc { service_name } => {
                            redactor.add_text(service_name);
                        }
                    }
                }
                NodeProtocol::Hysteria2(value) => {
                    redactor.add(&value.password);
                    if let Some(obfs) = &value.obfs {
                        redactor.add(&obfs.password);
                    }
                    redactor.add_tls(&value.tls);
                }
                NodeProtocol::Naive(value) => {
                    if let Some(username) = &value.username {
                        redactor.add(username);
                    }
                    if let Some(password) = &value.password {
                        redactor.add(password);
                    }
                    redactor.secrets.extend(
                        value
                            .extra_headers
                            .values()
                            .filter(|value| !value.is_empty())
                            .cloned(),
                    );
                    redactor.add_tls(&value.tls);
                }
            }
        }
        redactor.finish()
    }

    pub fn with_secret(mut self, value: &str) -> Self {
        self.add_text(value);
        self.finish()
    }

    pub fn redact(&self, input: &str) -> String {
        if self.saturated || input.len() > MAX_DIAGNOSTIC_BYTES {
            return OMITTED.into();
        }
        let mut output = redact_json(input).unwrap_or_else(|| redact_urls(input));
        if output.len() > MAX_DIAGNOSTIC_BYTES {
            return OMITTED.into();
        }
        output = redact_labeled_values(&output);
        if output.len() > MAX_DIAGNOSTIC_BYTES {
            return OMITTED.into();
        }
        for secret in &self.secrets {
            output = replace_ascii_case_insensitive(&output, secret, REDACTED);
            if output.len() > MAX_DIAGNOSTIC_BYTES {
                return OMITTED.into();
            }
            let encoded: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
            if encoded != *secret {
                output = replace_ascii_case_insensitive(&output, &encoded, REDACTED);
                if output.len() > MAX_DIAGNOSTIC_BYTES {
                    return OMITTED.into();
                }
            }
        }
        if output.len() > MAX_DIAGNOSTIC_BYTES {
            OMITTED.into()
        } else {
            output
        }
    }

    fn add(&mut self, secret: &Secret) {
        self.secrets.push(secret.expose().to_owned());
    }

    fn add_tls(&mut self, tls: &TlsOptions) {
        if let Some(server_name) = &tls.server_name {
            self.add_text(server_name);
        }
        for alpn in &tls.alpn {
            self.add_text(alpn);
        }
        self.secrets.extend(
            tls.certificate_public_key_sha256
                .iter()
                .chain(tls.ech_config.iter())
                .map(|secret| secret.expose().to_owned()),
        );
        if let Some(reality) = &tls.reality {
            self.add(&reality.public_key);
            self.add(&reality.short_id);
            if let Some(spider_x) = &reality.spider_x {
                self.add(spider_x);
            }
        }
    }

    fn add_text(&mut self, value: &str) {
        if value.is_empty() {
            return;
        }
        self.secrets.push(value.to_owned());
        let lowercase = value.to_lowercase();
        if lowercase != value {
            self.secrets.push(lowercase);
        }
    }

    fn finish(mut self) -> Self {
        let unique: BTreeSet<String> = self
            .secrets
            .into_iter()
            .filter(|secret| !secret.is_empty())
            .collect();
        self.secrets = unique.into_iter().collect();
        let pattern_bytes = self.secrets.iter().map(String::len).sum::<usize>();
        if self.secrets.len() > MAX_SECRET_PATTERNS || pattern_bytes > MAX_PATTERN_BYTES {
            self.secrets.clear();
            self.saturated = true;
            return self;
        }
        self.secrets
            .sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        self
    }
}

fn redact_json(input: &str) -> Option<String> {
    let mut value: Value = serde_json::from_str(input).ok()?;
    redact_json_value(&mut value, false);
    serde_json::to_string(&value).ok()
}

fn redact_json_value(value: &mut Value, parent_sensitive: bool) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let sensitive = is_sensitive_key(key);
                if sensitive {
                    *value = Value::String(REDACTED.into());
                } else {
                    redact_json_value(value, false);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value(value, parent_sensitive);
            }
        }
        Value::String(text) if parent_sensitive => *text = REDACTED.into(),
        Value::String(text) => *text = redact_urls(text),
        _ => {}
    }
}

fn redact_urls(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut start = 0;
    while let Some(relative) = input[start..].find("://") {
        let marker = start + relative;
        let token_start = input[start..marker]
            .rfind(|character: char| {
                character.is_whitespace() || matches!(character, '"' | '\'' | '<' | '(')
            })
            .map_or(start, |index| start + index + 1);
        let token_end = input[marker + 3..]
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '"' | '\'' | '<' | '>')
            })
            .map_or(input.len(), |index| marker + 3 + index);
        output.push_str(&input[start..token_start]);
        let token = &input[token_start..token_end];
        if let Ok(url) = Url::parse(token) {
            if is_sensitive_scheme(url.scheme())
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || !matches!(url.path(), "" | "/")
                || url.fragment().is_some()
            {
                output.push_str(url.scheme());
                output.push_str("://");
                if !url.username().is_empty() || url.password().is_some() {
                    output.push_str(REDACTED);
                    output.push('@');
                }
                output.push_str(url.host_str().unwrap_or(REDACTED));
                if let Some(port) = url.port() {
                    output.push(':');
                    output.push_str(&port.to_string());
                }
                if is_sensitive_scheme(url.scheme())
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                {
                    output.push('/');
                    output.push_str(REDACTED);
                }
            } else {
                output.push_str(token);
            }
        } else {
            output.push_str(REDACTED);
        }
        start = token_end;
    }
    output.push_str(&input[start..]);
    output
}

fn redact_labeled_values(input: &str) -> String {
    let mut output = input.to_owned();
    for key in SENSITIVE_KEYS {
        for separator in ['=', ':'] {
            output = redact_after_label(&output, key, separator);
        }
    }
    output
}

fn redact_after_label(input: &str, key: &str, separator: char) -> String {
    let lower = input.to_ascii_lowercase();
    let pattern = format!("{key}{separator}");
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = lower[offset..].find(&pattern) {
        let hit = offset + relative;
        let value_start = hit + pattern.len();
        output.push_str(&input[offset..value_start]);
        let whitespace = input[value_start..].len() - input[value_start..].trim_start().len();
        output.push_str(&input[value_start..value_start + whitespace]);
        let secret_start = value_start + whitespace;
        let secret_end = input[secret_start..]
            .find(|character: char| {
                character.is_whitespace() || matches!(character, ',' | ';' | '}' | ']' | '"')
            })
            .map_or(input.len(), |index| secret_start + index);
        if secret_start < secret_end {
            output.push_str(REDACTED);
        }
        offset = secret_end;
    }
    output.push_str(&input[offset..]);
    output
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = lower_input[offset..].find(&lower_needle) {
        let hit = offset + relative;
        output.push_str(&input[offset..hit]);
        output.push_str(replacement);
        offset = hit + needle.len();
    }
    output.push_str(&input[offset..]);
    output
}

fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEYS
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

fn is_sensitive_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "vless" | "hysteria2" | "hy2" | "naive+https" | "naive+quic"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::import_subscription;

    #[test]
    fn redacts_all_protocol_credentials_and_reality_material() {
        let links = b"vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&flow=xtls-rprx-vision&type=tcp&sni=cover.test&alpn=h2&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2&spx=%2Fprivate-spider%3Ftoken%3Dfixture\nvless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@ws-endpoint.test:443?security=tls&type=ws&sni=ws-cover.test&host=cdn-host.test&path=%2Fprivate-ws\nvless://ffffffff-1111-2222-3333-444444444444@grpc-endpoint.test:443?security=tls&type=grpc&sni=grpc-cover.test&serviceName=private-grpc\nhysteria2://fixture-password@hy-endpoint.test:443?obfs=salamander&obfs-password=fixture-obfs&sni=hy-cover.test\nnaive+https://fixture-user:fixture-pass@naive-endpoint.test:443";
        let nodes = import_subscription(links).unwrap().nodes;
        let redactor = Redactor::from_nodes(&nodes);
        let output = redactor.redact(str::from_utf8(links).unwrap());
        for secret in [
            "11111111",
            "fixture-password",
            "fixture-obfs",
            "fixture-user",
            "fixture-pass",
            "abcdefghijklmnopqrstuvwxyz",
            "a1b2",
            "private-spider",
        ] {
            assert!(!output.contains(secret), "secret fragment leaked: {secret}");
        }
        assert!(output.contains(REDACTED));
        let config_diagnostic = redactor.redact(
            "server=WS-ENDPOINT.TEST sni=ws-cover.test host=cdn-host.test path=/private-ws service=private-grpc alpn=h2",
        );
        for sensitive in [
            "WS-ENDPOINT.TEST",
            "ws-cover.test",
            "cdn-host.test",
            "/private-ws",
            "private-grpc",
            "h2",
        ] {
            assert!(!config_diagnostic.contains(sensitive));
        }
    }

    #[test]
    fn redacts_nested_json_by_key_and_urls_in_values() {
        let input = r#"{"outer":{"uuid":"fixture-uuid","password":"fixture-pass"},"message":"failed vless://fixture-uuid@example.test:443?pbk=fixture-key#name"}"#;
        let output = Redactor::default().redact(input);
        assert!(!output.contains("fixture-uuid"));
        assert!(!output.contains("fixture-pass"));
        assert!(!output.contains("fixture-key"));
    }

    #[test]
    fn redacts_known_plain_and_percent_encoded_secrets() {
        let redactor = Redactor::default().with_secret("fixture secret/value");
        assert!(!format!("{redactor:?}").contains("fixture"));
        let output = redactor.redact("password=fixture%20secret%2Fvalue and fixture secret/value");
        assert!(!output.contains("fixture"));
    }

    #[test]
    fn redacts_subscription_url_query_without_known_secret() {
        let output = Redactor::default().redact(
            "first https://one.test/path?token=one, second https://provider.test/sub/path?token=fixture-token",
        );
        assert!(!output.contains("token=one"));
        assert!(!output.contains("fixture-token"));
        assert!(!output.contains("/sub/path"));
        assert!(output.contains("provider.test"));
    }

    #[test]
    fn redacts_https_paths_fragments_and_adjacent_punctuation() {
        let output = Redactor::default().redact(
            "(https://provider.test/private/fixture-secret#fragment),; https://other.test/sub-token;",
        );
        assert!(!output.contains("fixture-secret"));
        assert!(!output.contains("fragment"));
        assert!(!output.contains("sub-token"));
        assert!(output.contains("provider.test"));
    }

    #[test]
    fn fails_closed_for_oversize_diagnostics_and_pattern_sets() {
        let oversized = "x".repeat(MAX_DIAGNOSTIC_BYTES + 1);
        assert_eq!(Redactor::default().redact(&oversized), OMITTED);
        let mut redactor = Redactor::default();
        for index in 0..=MAX_SECRET_PATTERNS {
            redactor = redactor.with_secret(&format!("secret-{index}"));
        }
        assert_eq!(redactor.redact("ordinary diagnostic"), OMITTED);
    }
}
