use std::{collections::BTreeSet, fmt};

use serde_json::Value;
use url::Url;

use crate::domain::{Node, NodeProtocol, Secret, TlsOptions};

const REDACTED: &str = "[REDACTED]";
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
            match node.protocol() {
                NodeProtocol::Vless(value) => {
                    redactor.add(&value.uuid);
                    redactor.add_tls(&value.tls);
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
        if !value.is_empty() {
            self.secrets.push(value.to_owned());
        }
        self.finish()
    }

    pub fn redact(&self, input: &str) -> String {
        let mut output = redact_json(input).unwrap_or_else(|| redact_urls(input));
        output = redact_labeled_values(&output);
        for secret in &self.secrets {
            output = output.replace(secret, REDACTED);
            let encoded: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
            if encoded != *secret {
                output = replace_ascii_case_insensitive(&output, &encoded, REDACTED);
            }
        }
        output
    }

    fn add(&mut self, secret: &Secret) {
        self.secrets.push(secret.expose().to_owned());
    }

    fn add_tls(&mut self, tls: &TlsOptions) {
        self.secrets.extend(
            tls.certificate_public_key_sha256
                .iter()
                .chain(tls.ech_config.iter())
                .map(|secret| secret.expose().to_owned()),
        );
        if let Some(reality) = &tls.reality {
            self.add(&reality.public_key);
            self.add(&reality.short_id);
        }
    }

    fn finish(mut self) -> Self {
        let unique: BTreeSet<String> = self
            .secrets
            .into_iter()
            .filter(|secret| !secret.is_empty())
            .collect();
        self.secrets = unique.into_iter().collect();
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
                character.is_whitespace() || matches!(character, '"' | '\'' | '>' | ')' | ',' | ';')
            })
            .map_or(input.len(), |index| marker + 3 + index);
        output.push_str(&input[start..token_start]);
        let token = &input[token_start..token_end];
        if let Ok(url) = Url::parse(token) {
            if is_sensitive_scheme(url.scheme())
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
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
        let links = b"vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&flow=xtls-rprx-vision&type=tcp&sni=cover.test&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2\nhysteria2://fixture-password@example.test:443?obfs=salamander&obfs-password=fixture-obfs&sni=example.test\nnaive+https://fixture-user:fixture-pass@example.test:443";
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
        ] {
            assert!(!output.contains(secret), "secret fragment leaked: {secret}");
        }
        assert!(output.contains(REDACTED));
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
}
