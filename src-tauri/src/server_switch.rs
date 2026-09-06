//! A bounded, authenticated control plane. The renderer supplies only a library node ID.
use std::{io::Read, time::Duration};

use reqwest::{blocking::Client, redirect::Policy};
use serde_json::{json, Value};

use crate::engine_runtime::RuntimeError;

pub(crate) const MAX_SWITCH_NODES: usize = 2000;

pub(crate) fn rejected() -> RuntimeError {
    RuntimeError::new(
        "server_switch",
        "Server switch configuration or control response was rejected",
    )
}

#[derive(Clone)]
pub(crate) struct SwitchControl {
    pub port: u16,
    pub secret: String,
}

#[derive(Clone, Copy)]
pub(crate) enum Selector {
    Selected,
    Candidate,
}

impl Selector {
    fn tag(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Candidate => "candidate",
        }
    }
}

pub(crate) fn node_tag(index: usize) -> String {
    format!("node-{index}")
}

pub(crate) trait SelectorControl: Send + Sync {
    fn select(
        &self,
        control: &SwitchControl,
        selector: Selector,
        index: usize,
    ) -> Result<(), RuntimeError>;
    fn current(&self, control: &SwitchControl, selector: Selector) -> Result<String, RuntimeError>;
}

pub(crate) struct ClashSelectorControl;

impl ClashSelectorControl {
    fn client() -> Result<Client, RuntimeError> {
        Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| rejected())
    }

    fn url(control: &SwitchControl, selector: Selector) -> Result<String, RuntimeError> {
        if control.port == 0
            || control.secret.len() != 48
            || !control.secret.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(rejected());
        }
        Ok(format!(
            "http://127.0.0.1:{}/proxies/{}",
            control.port,
            selector.tag()
        ))
    }
}

impl SelectorControl for ClashSelectorControl {
    fn select(
        &self,
        control: &SwitchControl,
        selector: Selector,
        index: usize,
    ) -> Result<(), RuntimeError> {
        if index >= MAX_SWITCH_NODES {
            return Err(rejected());
        }
        let response = Self::client()?
            .put(Self::url(control, selector)?)
            .bearer_auth(&control.secret)
            .header("content-type", "application/json")
            .body(json!({"name": node_tag(index)}).to_string())
            .send()
            .map_err(|_| rejected())?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(rejected());
        }
        Ok(())
    }

    fn current(&self, control: &SwitchControl, selector: Selector) -> Result<String, RuntimeError> {
        let mut response = Self::client()?
            .get(Self::url(control, selector)?)
            .bearer_auth(&control.secret)
            .send()
            .map_err(|_| rejected())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(rejected());
        }
        let mut bytes = Vec::new();
        // A selector response contains its complete member list (up to 2000 tags).
        (&mut response)
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| rejected())?;
        if bytes.len() > 128 * 1024 {
            return Err(rejected());
        }
        let root: Value = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
        let now = root
            .get("now")
            .and_then(Value::as_str)
            .ok_or_else(rejected)?;
        let index = now
            .strip_prefix("node-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(rejected)?;
        if index >= MAX_SWITCH_NODES || now != node_tag(index) {
            return Err(rejected());
        }
        Ok(now.to_owned())
    }
}

fn selector(tag: &str, tags: &[String]) -> Value {
    json!({"type":"selector", "tag":tag, "outbounds":tags,
        "default":tags[0], "interrupt_exist_connections":false})
}

/// Combine already generated single-node TUN configurations. Each native exit is
/// physically bound; loopback Xray bridges must never inherit that binding.
pub(crate) fn combine_configs(
    mut configs: Vec<Value>,
    control: &SwitchControl,
    candidate_port: u16,
    password: &str,
    upstream: &str,
) -> Result<Value, RuntimeError> {
    if configs.is_empty() || configs.len() > MAX_SWITCH_NODES {
        return Err(rejected());
    }
    let mut root = configs[0].clone();
    let tags: Vec<_> = (0..configs.len()).map(node_tag).collect();
    let mut exits = vec![
        selector("selected", &tags),
        selector("candidate", &tags),
        json!({"type":"direct", "tag":"direct", "bind_interface":upstream}),
    ];
    for (index, config) in configs.iter_mut().enumerate() {
        let mut exit = config["outbounds"][0].take();
        exit["tag"] = json!(tags[index]);
        if exit["type"] != "socks" {
            exit["bind_interface"] = json!(upstream);
        }
        exits.push(exit);
    }
    root["outbounds"] = json!(exits);
    root["route"]
        .as_object_mut()
        .ok_or_else(rejected)?
        .remove("default_interface");
    root["dns"]["servers"][0]["bind_interface"] = json!(upstream);
    root["inbounds"].as_array_mut().ok_or_else(rejected)?.push(json!({
        "type":"http", "tag":"candidate-in", "listen":"127.0.0.1", "listen_port":candidate_port,
        "users":[{"username":crate::runtime_constants::HEALTH_PROXY_USERNAME,"password":password}]
    }));
    root["route"]["rules"]
        .as_array_mut()
        .ok_or_else(rejected)?
        .insert(
            1,
            json!({"inbound":["candidate-in"],"action":"route","outbound":"candidate"}),
        );
    root["experimental"] = json!({"clash_api":{
        "external_controller":format!("127.0.0.1:{}",control.port), "secret":control.secret,
        "access_control_allow_origin":["http://routedeck.invalid"],
        "access_control_allow_private_network":false
    }});
    Ok(root)
}

/// Validate every new control-plane field before reducing to the existing closed
/// single-outbound helper validator. Nothing unvalidated is dropped during reduction.
pub(crate) fn split_config(
    mut root: Value,
    upstream: &str,
) -> Result<(Value, Vec<Value>), RuntimeError> {
    let api = root
        .pointer("/experimental/clash_api")
        .ok_or_else(rejected)?;
    let endpoint = api["external_controller"].as_str().ok_or_else(rejected)?;
    let port = endpoint
        .strip_prefix("127.0.0.1:")
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .ok_or_else(rejected)?;
    let control = SwitchControl {
        port,
        secret: api["secret"].as_str().ok_or_else(rejected)?.to_owned(),
    };
    ClashSelectorControl::url(&control, Selector::Selected)?;
    if endpoint != format!("127.0.0.1:{port}")
        || root["experimental"]
            != json!({"clash_api":{
                "external_controller":endpoint,"secret":control.secret,
                "access_control_allow_origin":["http://routedeck.invalid"],"access_control_allow_private_network":false
            }})
    {
        return Err(rejected());
    }
    root.as_object_mut()
        .ok_or_else(rejected)?
        .remove("experimental");
    let outbounds = root.get_mut("outbounds").ok_or_else(rejected)?.take();
    let outbounds = outbounds
        .as_array()
        .filter(|v| v.len() >= 4 && v.len() <= MAX_SWITCH_NODES + 3)
        .ok_or_else(rejected)?;
    let tags: Vec<_> = (0..outbounds.len() - 3).map(node_tag).collect();
    if outbounds[0] != selector("selected", &tags)
        || outbounds[1] != selector("candidate", &tags)
        || outbounds[2] != json!({"type":"direct","tag":"direct","bind_interface":upstream})
        || root["route"].get("default_interface").is_some()
        || root["dns"]["servers"][0]["bind_interface"] != upstream
    {
        return Err(rejected());
    }
    let inbounds = root
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(rejected)?;
    if inbounds.len() != 5 {
        return Err(rejected());
    }
    let candidate = inbounds.pop().ok_or_else(rejected)?;
    let health = inbounds
        .iter()
        .find(|v| v["tag"] == "health-in")
        .ok_or_else(rejected)?;
    let candidate_port = candidate["listen_port"]
        .as_u64()
        .filter(|p| *p > 0 && *p <= u16::MAX as u64)
        .ok_or_else(rejected)?;
    let mut ports = std::collections::HashSet::from([port as u64, candidate_port]);
    if ports.len() != 2 {
        return Err(rejected());
    }
    for inbound in inbounds.iter().filter(|v| v["type"] != "tun") {
        if !ports.insert(inbound["listen_port"].as_u64().ok_or_else(rejected)?) {
            return Err(rejected());
        }
    }
    if candidate
        != json!({"type":"http","tag":"candidate-in","listen":"127.0.0.1",
        "listen_port":candidate_port,"users":health["users"]})
    {
        return Err(rejected());
    }
    let rules = root
        .get_mut("route")
        .and_then(|route| route.get_mut("rules"))
        .and_then(Value::as_array_mut)
        .ok_or_else(rejected)?;
    if rules.get(1)
        != Some(&json!({"inbound":["candidate-in"],"action":"route","outbound":"candidate"}))
    {
        return Err(rejected());
    }
    rules.remove(1);
    let mut exits = Vec::new();
    for (index, original) in outbounds.iter().skip(3).enumerate() {
        if original["tag"] != tags[index]
            || !matches!(
                original["type"].as_str(),
                Some("vless" | "hysteria2" | "naive" | "socks")
            )
        {
            return Err(rejected());
        }
        let mut exit = original.clone();
        if exit["type"] == "socks" {
            if exit.get("bind_interface").is_some() {
                return Err(rejected());
            }
            let bridge_port = exit["server_port"].as_u64().ok_or_else(rejected)?;
            if !ports.insert(bridge_port) {
                return Err(rejected());
            }
        } else {
            if exit["bind_interface"] != upstream {
                return Err(rejected());
            }
            exit.as_object_mut()
                .ok_or_else(rejected)?
                .remove("bind_interface");
        }
        exit["tag"] = json!("selected");
        exits.push(exit);
    }
    Ok((root, exits))
}

pub(crate) fn single_config(base: &Value, exit: Value, upstream: &str) -> Value {
    let bridge = exit["type"] == "socks";
    let mut root = base.clone();
    let mut direct = json!({"type":"direct","tag":"direct"});
    if bridge {
        direct["bind_interface"] = json!(upstream);
    } else {
        root["route"]["default_interface"] = json!(upstream);
        if root["dns"]["servers"][0]["type"] == "local" {
            root["dns"]["servers"][0]
                .as_object_mut()
                .unwrap()
                .remove("bind_interface");
        }
    }
    root["outbounds"] = json!([exit, direct]);
    root
}
