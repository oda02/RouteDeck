use super::*;
use crate::server_switch::{self, Selector, SwitchControl};
use serde_json::{json, Value};

#[derive(Clone)]
pub(super) struct SwitchTarget {
    node_id: String,
    config_identity: String,
    naive_udp_over_tcp: bool,
}

pub(super) struct TunSwitchSession {
    pub control: SwitchControl,
    pub candidate_port: u16,
    candidate_route: HealthRoute,
    targets: Vec<SwitchTarget>,
    current: usize,
    pub uncertain: bool,
}

pub(super) struct PreparedTun {
    pub config: String,
    pub xray: Option<String>,
    pub bridges: Vec<LoopbackPortReservation>,
    pub reservations: Vec<LoopbackPortReservation>,
    pub switching: TunSwitchSession,
    pub redactor: Redactor,
}

impl ApplicationController {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_switchable_tun(
        &self,
        state: &State,
        selected: &Node,
        policy: &RoutePolicy,
        mode: CaptureMode,
        ports: crate::config::LocalPorts,
        password: &str,
        upstream: TunUpstream,
        naive_udp_over_tcp: bool,
    ) -> Result<PreparedTun, RuntimeError> {
        let control_port = LoopbackPortReservation::reserve()?;
        let candidate = LoopbackPortReservation::reserve()?;
        let control = SwitchControl {
            port: control_port.port(),
            secret: random_hex(24)?,
        };
        let mut nodes = vec![selected.clone()];
        nodes.extend(
            state
                .node_order
                .iter()
                .filter(|id| id.as_str() != selected.id())
                .filter_map(|id| state.nodes.get(id).map(|stored| stored.node.clone())),
        );
        let mut configs = Vec::new();
        let mut config_bytes = 0usize;
        let mut bridges = Vec::new();
        let mut targets = Vec::new();
        let mut xray_inbounds = Vec::new();
        let mut xray_outbounds = Vec::new();
        let mut xray_rules = Vec::new();
        for node in &nodes {
            let reality = matches!(node.protocol(), NodeProtocol::Vless(vless) if vless.tls.reality.is_some());
            let bridge = if reality {
                Some(LoopbackPortReservation::reserve()?)
            } else {
                None
            };
            let request = ConfigRequest {
                node,
                policy,
                mode: mode.clone(),
                ports,
                health_password: password.to_owned(),
                vpn_dns: None,
                insecure_approval: None,
                tun_upstream: Some(upstream.clone()),
                naive_udp_over_tcp,
            };
            let generated = match bridge.as_ref() {
                Some(bridge) => generate_socks_bridge_config(
                    request,
                    SocksBridge {
                        server_port: bridge.port(),
                    },
                ),
                None => generate_config(request),
            };
            // An unapproved or unrepresentable inactive profile cannot prevent the selected
            // valid profile starting. It is excluded, never silently altered or approved.
            let generated = match generated {
                Ok(config) => config,
                Err(_) if node.id() != selected.id() => continue,
                Err(error) => return Err(RuntimeError::new("generate_config", error.to_string())),
            };
            let tag = server_switch::node_tag(targets.len());
            if let Some(bridge) = bridge {
                let xray = generate_xray_bridge_config(XrayBridgeRequest {
                    node,
                    listen_port: bridge.port(),
                    tun_upstream: Some(upstream.clone()),
                });
                let xray = match xray {
                    Ok(config) => config,
                    Err(_) if node.id() != selected.id() => continue,
                    Err(error) => {
                        return Err(RuntimeError::new("generate_config", error.to_string()))
                    }
                };
                let mut xray: Value =
                    serde_json::from_str(xray.as_str()).map_err(|_| server_switch::rejected())?;
                xray["inbounds"][0]["tag"] = json!(tag);
                xray["outbounds"][0]["tag"] = json!(tag);
                xray_inbounds.push(xray["inbounds"][0].take());
                xray_outbounds.push(xray["outbounds"][0].take());
                xray_rules.push(json!({"type":"field","inboundTag":[tag],"outboundTag":tag}));
                bridges.push(bridge);
            }
            let mut config: Value =
                serde_json::from_str(generated.as_str()).map_err(|_| server_switch::rejected())?;
            if !configs.is_empty() {
                config = json!({"outbounds":[config["outbounds"][0].take()]});
            }
            config_bytes += config.to_string().len();
            if config_bytes as u64 > crate::tun_helper_protocol::MAX_CONFIG_BYTES {
                return Err(RuntimeError::new(
                    "generate_config",
                    "The server library exceeds the bounded TUN session configuration size",
                ));
            }
            configs.push(config);
            targets.push(SwitchTarget {
                node_id: node.id().to_owned(),
                config_identity: state
                    .nodes
                    .get(node.id())
                    .ok_or_else(server_switch::rejected)?
                    .config_identity
                    .clone(),
                naive_udp_over_tcp: naive_udp_over_tcp
                    && matches!(node.protocol(), NodeProtocol::Naive(_)),
            });
        }
        let root = server_switch::combine_configs(
            configs,
            &control,
            candidate.port(),
            password,
            &upstream.interface_alias,
        )?;
        let config = serde_json::to_string(&root).map_err(|_| server_switch::rejected())?;
        if config.len() as u64 > crate::tun_helper_protocol::MAX_CONFIG_BYTES {
            return Err(RuntimeError::new(
                "generate_config",
                "The server library exceeds the bounded TUN session configuration size",
            ));
        }
        let xray = (!bridges.is_empty()).then(|| {
            json!({"log":{"loglevel":"info"},
            "inbounds":xray_inbounds,"outbounds":xray_outbounds,
            "routing":{"rules":xray_rules}})
            .to_string()
        });
        let redactor = nodes.iter().fold(
            Redactor::from_nodes(&nodes)
                .with_secret(&control.secret)
                .with_secret(password),
            |redactor, node| redactor.with_secret(node.server()),
        );
        Ok(PreparedTun {
            config,
            xray,
            bridges,
            redactor,
            switching: TunSwitchSession {
                control,
                candidate_port: candidate.port(),
                candidate_route: HealthRoute::new(candidate.port(), password.to_owned()),
                targets,
                current: 0,
                uncertain: false,
            },
            reservations: vec![control_port, candidate],
        })
    }

    pub fn switch_tun_server(
        &self,
        session_id: &str,
        node_id: &str,
    ) -> Result<RuntimeStatus, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.lock_state();
        let error = |message| {
            PublicError::fixed(
                PublicErrorCode::ActiveSessionConflict,
                PublicErrorStage::Start,
                message,
            )
        };
        if state.shutting_down || state.recovery_required {
            return Err(error("The active session cannot accept a server switch"));
        }
        let stored = state
            .nodes
            .get(node_id)
            .ok_or_else(|| error("Selected server is no longer available"))?
            .clone();
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| error("There is no active TUN session"))?;
        if active.mode != RuntimeMode::Tun || active.session_id != session_id {
            return Err(error("The TUN session changed before the server switch"));
        }
        let switching = active
            .switching
            .as_ref()
            .ok_or_else(|| error("This TUN session does not support server switching"))?;
        if switching.uncertain {
            return Err(error("switch_server.uncertain"));
        }
        let index = switching
            .targets
            .iter()
            .position(|target| {
                target.node_id == node_id && target.config_identity == stored.config_identity
            })
            .ok_or_else(|| error("switch_server.not_prepared"))?;
        let control = switching.control.clone();
        let candidate_route = switching.candidate_route.clone();
        let candidate_port = switching.candidate_port;
        let previous = switching.current;
        let redactor = active.redactor.clone();
        let old_node = active.node_id.clone();
        // Discard a monitor proof that started before this attempt, including attempts
        // that later fail or leave control state uncertain.
        active.generation =
            random_hex(16).map_err(|_| error("Could not allocate a server switch generation"))?;
        let mut ownership_valid = false;
        let result = (|| {
            if !active.child.is_alive()? {
                return Err(server_switch::rejected());
            }
            self.services
                .listener
                .verify_owned_now(active.ports, active.child.as_mut())?;
            self.services
                .listener
                .verify_sidecar_owned_now(control.port, active.child.as_mut())?;
            self.services
                .listener
                .verify_sidecar_owned_now(candidate_port, active.child.as_mut())?;
            let before = active.child.tun_capture_snapshot()?;
            ownership_valid = true;
            // Candidate requests cannot change the selector that carries user traffic.
            self.services
                .selector
                .select(&control, Selector::Candidate, index)?;
            if self
                .services
                .selector
                .current(&control, Selector::Candidate)?
                != server_switch::node_tag(index)
            {
                return Err(server_switch::rejected());
            }
            self.services.prober.prove(&candidate_route)?;
            let switch = self
                .services
                .selector
                .select(&control, Selector::Selected, index);
            let selected = self.services.selector.current(&control, Selector::Selected);
            if selected.as_deref().ok() != Some(server_switch::node_tag(index).as_str()) {
                // A lost PUT reply is ambiguous. Restore and read back the old selection;
                // never restart TUN to hide an uncertain control-plane result.
                let _ = self
                    .services
                    .selector
                    .select(&control, Selector::Selected, previous);
                if self
                    .services
                    .selector
                    .current(&control, Selector::Selected)
                    .as_deref()
                    .ok()
                    != Some(server_switch::node_tag(previous).as_str())
                {
                    active.switching.as_mut().unwrap().uncertain = true;
                }
                return Err(switch.err().unwrap_or_else(server_switch::rejected));
            }
            let proof = self
                .services
                .prober
                .prove(&active.health_route)
                .and_then(|proof| {
                    ownership_valid = false;
                    let after = active.child.tun_capture_snapshot()?;
                    if before.interface_luid != after.interface_luid || !active.child.is_alive()? {
                        return Err(server_switch::rejected());
                    }
                    ownership_valid = true;
                    Ok(proof)
                });
            if proof.is_err() {
                let _ = self
                    .services
                    .selector
                    .select(&control, Selector::Selected, previous);
                if self
                    .services
                    .selector
                    .current(&control, Selector::Selected)
                    .as_deref()
                    .ok()
                    != Some(server_switch::node_tag(previous).as_str())
                {
                    active.switching.as_mut().unwrap().uncertain = true;
                }
            }
            proof
        })();
        match result {
            Ok(proof) => {
                let active = state.active.as_mut().unwrap();
                let switching = active.switching.as_mut().unwrap();
                switching.current = index;
                active.node_id = node_id.to_owned();
                active.config_identity = stored.config_identity;
                active.naive_udp_over_tcp = switching.targets[index].naive_udp_over_tcp;
                active.last_probe = Instant::now();
                active.consecutive_probe_failures = 0;
                state.status.steady_latency_ms = None;
                state.status.route_check_ms = Some(proof.latency_ms);
                Self::set_proof(
                    &mut state,
                    ProofKind::SelectedOutboundHttps,
                    ProofState::Passed,
                    Some(proof.latency_ms),
                );
                self.update_status(
                    &mut state,
                    RuntimePhase::TunReady,
                    Some(node_id.to_owned()),
                    None,
                );
                Ok(state.status.clone())
            }
            Err(failure) => {
                self.record_runtime_failure(&failure, &redactor);
                let public = public_runtime_error(failure, &redactor);
                if !ownership_valid
                    || state
                        .active
                        .as_ref()
                        .unwrap()
                        .switching
                        .as_ref()
                        .unwrap()
                        .uncertain
                {
                    if !ownership_valid {
                        Self::set_proof(
                            &mut state,
                            ProofKind::LocalScopeOwnership,
                            ProofState::Failed,
                            None,
                        );
                    }
                    Self::set_proof(
                        &mut state,
                        ProofKind::SelectedOutboundHttps,
                        ProofState::Failed,
                        None,
                    );
                    self.update_status(
                        &mut state,
                        RuntimePhase::Degraded,
                        Some(old_node),
                        Some(public.clone()),
                    );
                }
                Err(public)
            }
        }
    }
}
