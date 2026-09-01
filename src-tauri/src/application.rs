use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    config::{generate_config, CaptureMode, ConfigRequest},
    domain::{DefaultRoute, DnsPolicy, Ipv6Policy, LanPolicy, Node, ProtocolKind, RoutePolicy},
    engine_runtime::{
        random_hex, reconcile_stale_sessions, DiagnosticBuffer, EngineLauncher, ManagedChild,
        PortReservations, RuntimeError, SessionConfig, VerifiedEngineLauncher,
    },
    health::{
        HealthRoute, HttpsTrafficProber, ListenerVerifier, TcpListenerVerifier, TrafficProber,
    },
    redaction::Redactor,
    subscription::{import_subscription, ImportReport},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    Disconnected,
    Preparing,
    ValidatingConfig,
    StartingCore,
    VerifyingListener,
    ProvingTraffic,
    OutboundVerified,
    LocalProxyReady,
    Degraded,
    RollingBack,
    StoppingCore,
    DisconnectedWithError,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeScope {
    LocalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    LocalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    EngineConfig,
    EngineProcess,
    HttpListener,
    SocksListener,
    HealthListener,
    SelectedOutboundHttps,
    LocalScopeOwnership,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofState {
    NotRun,
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofRow {
    pub kind: ProofKind,
    pub state: ProofState,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub revision: u64,
    pub session_id: Option<String>,
    pub scope: RuntimeScope,
    pub mode: RuntimeMode,
    pub phase: RuntimePhase,
    pub node_id: Option<String>,
    pub ports: Option<PublicPorts>,
    pub route_check_ms: Option<u64>,
    pub engine_version: Option<String>,
    pub proofs: Vec<ProofRow>,
    pub error: Option<PublicError>,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            revision: 0,
            session_id: None,
            scope: RuntimeScope::LocalOnly,
            mode: RuntimeMode::LocalOnly,
            phase: RuntimePhase::Disconnected,
            node_id: None,
            ports: None,
            route_check_ms: None,
            engine_version: None,
            proofs: default_proofs(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicPorts {
    pub http: u16,
    pub socks: u16,
    pub health: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicErrorCode {
    ImportRejected,
    PreviewMissing,
    PreviewTokenInvalid,
    RecoveryRequired,
    ActiveSessionConflict,
    SessionChanged,
    NodeNotFound,
    RuntimeFailure,
    CommandFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicErrorStage {
    Import,
    SessionRecovery,
    Start,
    GenerateConfig,
    EngineLayout,
    EngineIntegrity,
    ConfigCheck,
    StartEngine,
    VerifyListeners,
    ProveTraffic,
    EngineProcess,
    StopEngine,
    SessionStorage,
    Random,
    Monitor,
    Command,
    Runtime,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicError {
    pub code: PublicErrorCode,
    pub stage: PublicErrorStage,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub preview_id: String,
    pub nodes: Vec<PreviewNode>,
    pub rejected: Vec<PreviewRejection>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewNode {
    pub id: String,
    pub display_name: String,
    pub protocol: ProtocolKind,
    pub insecure_tls: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewRejection {
    pub index: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmedImport {
    pub imported: usize,
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub status: RuntimeStatus,
    pub lines: Vec<String>,
}

pub(crate) trait EngineProvider: Send + Sync {
    fn create(&self) -> Result<Box<dyn EngineLauncher>, RuntimeError>;
}

struct FixedEngineProvider;

impl EngineProvider for FixedEngineProvider {
    fn create(&self) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
        Ok(Box::new(VerifiedEngineLauncher::resolve()?))
    }
}

struct RuntimeServices {
    engine: Arc<dyn EngineProvider>,
    listener: Arc<dyn ListenerVerifier>,
    prober: Arc<dyn TrafficProber>,
}

struct PendingImport {
    id: String,
    report: ImportReport,
}

#[derive(Clone)]
struct StoredNode {
    node: Node,
    config_identity: String,
}

struct ActiveSession {
    child: Box<dyn ManagedChild>,
    _config: SessionConfig,
    node_id: String,
    config_identity: String,
    session_id: String,
    default_route: DefaultRoute,
    ports: crate::config::LocalPorts,
    health_route: HealthRoute,
    engine_version: String,
    redactor: Redactor,
    last_probe: Instant,
    consecutive_probe_failures: u8,
    generation: String,
}

#[derive(Default)]
struct State {
    nodes: HashMap<String, StoredNode>,
    pending: Option<PendingImport>,
    active: Option<ActiveSession>,
    status: RuntimeStatus,
    recovery_required: bool,
    shutting_down: bool,
}

type EventSink = Arc<dyn Fn(RuntimeStatus) + Send + Sync>;

pub struct ApplicationController {
    state: Mutex<State>,
    operation: Mutex<()>,
    services: RuntimeServices,
    session_root: PathBuf,
    diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    event_sink: Mutex<Option<EventSink>>,
}

impl ApplicationController {
    pub fn production(
        session_root: PathBuf,
        event_sink: EventSink,
    ) -> Result<Arc<Self>, RuntimeError> {
        let recovery_error = reconcile_stale_sessions(&session_root).err();
        let controller = Arc::new(Self::with_services(
            session_root,
            event_sink,
            Arc::new(FixedEngineProvider),
            Arc::new(TcpListenerVerifier),
            Arc::new(HttpsTrafficProber),
        ));
        if let Some(error) = recovery_error {
            let public = public_runtime_error(error, &Redactor::default());
            let mut state = controller.lock_state();
            state.recovery_required = true;
            controller.update_status(
                &mut state,
                RuntimePhase::RecoveryRequired,
                None,
                Some(public),
            );
        }
        Self::spawn_monitor(&controller)?;
        Ok(controller)
    }

    fn spawn_monitor(controller: &Arc<Self>) -> Result<(), RuntimeError> {
        let weak: Weak<Self> = Arc::downgrade(controller);
        thread::Builder::new()
            .name("routedeck-health-monitor".into())
            .spawn(move || loop {
                thread::sleep(Duration::from_secs(1));
                let Some(controller) = weak.upgrade() else {
                    break;
                };
                controller.monitor_tick();
            })
            .map(|_| ())
            .map_err(|error| RuntimeError::new("monitor", error.to_string()))
    }

    fn with_services(
        session_root: PathBuf,
        event_sink: EventSink,
        engine: Arc<dyn EngineProvider>,
        listener: Arc<dyn ListenerVerifier>,
        prober: Arc<dyn TrafficProber>,
    ) -> Self {
        Self {
            state: Mutex::new(State::default()),
            operation: Mutex::new(()),
            services: RuntimeServices {
                engine,
                listener,
                prober,
            },
            session_root,
            diagnostics: Arc::new(Mutex::new(DiagnosticBuffer::default())),
            event_sink: Mutex::new(Some(event_sink)),
        }
    }

    pub fn preview_import_content(&self, content: String) -> Result<ImportPreview, PublicError> {
        let report = import_subscription(content.as_bytes()).map_err(|error| {
            PublicError::with_detail(
                PublicErrorCode::ImportRejected,
                PublicErrorStage::Import,
                "Subscription content was rejected",
                Redactor::default().redact(&error.to_string()),
            )
        })?;
        let preview_id =
            random_hex(16).map_err(|error| public_runtime_error(error, &Redactor::default()))?;
        let preview = preview_from_report(&preview_id, &report);
        let mut state = self.lock_state();
        state.pending = Some(PendingImport {
            id: preview_id,
            report,
        });
        Ok(preview)
    }

    pub fn discard_import_preview(&self, preview_id: &str) -> Result<(), PublicError> {
        let discarded = {
            let mut state = self.lock_state();
            let Some(pending) = state.pending.as_ref() else {
                return Ok(());
            };
            if !constant_time_token_eq(&pending.id, preview_id) {
                return Err(PublicError::fixed(
                    PublicErrorCode::PreviewTokenInvalid,
                    PublicErrorStage::Import,
                    "Import preview token is invalid",
                ));
            }
            state.pending.take()
        };
        drop(discarded);
        Ok(())
    }

    pub fn confirm_import(&self, preview_id: &str) -> Result<ConfirmedImport, PublicError> {
        let mut state = self.lock_state();
        let pending = state.pending.take().ok_or_else(|| {
            PublicError::fixed(
                PublicErrorCode::PreviewMissing,
                PublicErrorStage::Import,
                "No import preview is pending",
            )
        })?;
        if !constant_time_token_eq(&pending.id, preview_id) {
            state.pending = Some(pending);
            return Err(PublicError::fixed(
                PublicErrorCode::PreviewTokenInvalid,
                PublicErrorStage::Import,
                "Import preview token is invalid",
            ));
        }
        let prepared = pending
            .report
            .nodes
            .into_iter()
            .map(|node| {
                let node_id = node.id().to_owned();
                let config_identity = random_hex(16)
                    .map_err(|error| public_runtime_error(error, &Redactor::default()))?;
                Ok((
                    node_id,
                    StoredNode {
                        node,
                        config_identity,
                    },
                ))
            })
            .collect::<Result<Vec<_>, PublicError>>()?;
        let node_ids = prepared
            .iter()
            .map(|(node_id, _)| node_id.clone())
            .collect::<Vec<_>>();
        for (node_id, stored) in prepared {
            state.nodes.insert(node_id, stored);
        }
        Ok(ConfirmedImport {
            imported: node_ids.len(),
            node_ids,
        })
    }

    pub fn start_local_proxy(
        &self,
        node_id: &str,
        default_route: DefaultRoute,
    ) -> Result<RuntimeStatus, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.lock_state();
        if state.shutting_down {
            return Err(PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Start,
                "Application shutdown is in progress",
            ));
        }
        if state.recovery_required {
            return Err(PublicError::fixed(
                PublicErrorCode::RecoveryRequired,
                PublicErrorStage::SessionRecovery,
                "Review the preserved session data, then retry recovery",
            ));
        }
        let stored = state.nodes.get(node_id).cloned().ok_or_else(|| {
            PublicError::fixed(
                PublicErrorCode::NodeNotFound,
                PublicErrorStage::Start,
                "Selected node does not exist in the confirmed import",
            )
        })?;
        if state.active.is_some() {
            let exact = state.active.as_ref().is_some_and(|active| {
                active.node_id == node_id
                    && active.default_route == default_route
                    && active.config_identity == stored.config_identity
            });
            if !exact {
                return Err(PublicError::fixed(
                    PublicErrorCode::ActiveSessionConflict,
                    PublicErrorStage::Start,
                    "Stop the active local proxy before changing node, route, or node revision",
                ));
            }
            let route = {
                let active = state.active.as_mut().expect("active session disappeared");
                if !active.child.is_alive().unwrap_or(false) {
                    None
                } else {
                    Some(active.health_route.clone())
                }
            };
            drop(state);
            let validation = route.map(|route| self.services.prober.prove(&route));
            state = self.lock_state();
            if let Some(Ok(proof)) = validation {
                if !state.active.as_ref().is_some_and(|active| {
                    active.node_id == node_id
                        && active.default_route == default_route
                        && active.config_identity == stored.config_identity
                }) {
                    return Err(PublicError::fixed(
                        PublicErrorCode::SessionChanged,
                        PublicErrorStage::Start,
                        "Active session changed while traffic was being verified",
                    ));
                }
                let ownership_valid = state.active.as_mut().is_some_and(|active| {
                    active.child.is_alive().unwrap_or(false)
                        && self
                            .services
                            .listener
                            .verify_owned_now(active.ports, active.child.as_mut())
                            .is_ok()
                });
                if ownership_valid {
                    state.status.route_check_ms = Some(proof.latency_ms);
                    Self::set_proof(
                        &mut state,
                        ProofKind::SelectedOutboundHttps,
                        ProofState::Passed,
                        Some(proof.latency_ms),
                    );
                    Self::set_proof(
                        &mut state,
                        ProofKind::LocalScopeOwnership,
                        ProofState::Passed,
                        None,
                    );
                    self.update_status(
                        &mut state,
                        RuntimePhase::OutboundVerified,
                        Some(node_id.to_owned()),
                        None,
                    );
                    self.update_status(
                        &mut state,
                        RuntimePhase::LocalProxyReady,
                        Some(node_id.to_owned()),
                        None,
                    );
                    return Ok(state.status.clone());
                }
            }
            Self::set_proof(
                &mut state,
                ProofKind::SelectedOutboundHttps,
                ProofState::Failed,
                None,
            );
            Self::set_proof(
                &mut state,
                ProofKind::LocalScopeOwnership,
                ProofState::Failed,
                None,
            );
            self.update_status(
                &mut state,
                RuntimePhase::RollingBack,
                Some(node_id.to_owned()),
                None,
            );
            let stop_error = state
                .active
                .as_mut()
                .and_then(|active| active.child.stop().err());
            if let Some(error) = stop_error {
                let redactor = state
                    .active
                    .as_ref()
                    .map(|active| active.redactor.clone())
                    .unwrap_or_default();
                let public = public_runtime_error(error, &redactor);
                state.recovery_required = true;
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id.to_owned()),
                    Some(public.clone()),
                );
                return Err(public);
            }
            let stale = state.active.take();
            Self::clear_active_metadata(&mut state);
            drop(stale);
            if reconcile_stale_sessions(&self.session_root).is_err() {
                state.recovery_required = true;
                let public = PublicError::fixed(
                    PublicErrorCode::RecoveryRequired,
                    PublicErrorStage::SessionRecovery,
                    "Session data remains and requires review",
                );
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id.to_owned()),
                    Some(public.clone()),
                );
                return Err(public);
            }
        }
        let node = stored.node;
        let config_identity = stored.config_identity;
        let redactor = Redactor::from_nodes(std::slice::from_ref(&node)).with_secret(node.server());

        let result = self.start_locked(
            &mut state,
            &node,
            config_identity,
            default_route,
            redactor.clone(),
        );
        if let Err(error) = result {
            Self::mark_failed_proof(&mut state, error.stage());
            let safe = redactor.redact(error.message());
            self.diagnostics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("{}: {safe}", error.stage()));
            self.update_status(
                &mut state,
                RuntimePhase::RollingBack,
                Some(node_id.to_owned()),
                None,
            );
            let rollback_error = state
                .active
                .as_mut()
                .and_then(|active| active.child.stop().err());
            if let Some(rollback_error) = rollback_error {
                let public = public_runtime_error(rollback_error, &redactor);
                state.recovery_required = true;
                if let Some((ports, engine_version)) = state
                    .active
                    .as_ref()
                    .map(|active| (active.ports, active.engine_version.clone()))
                {
                    state.status.ports = Some(PublicPorts {
                        http: ports.http,
                        socks: ports.socks,
                        health: ports.health,
                    });
                    state.status.engine_version = Some(engine_version);
                }
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id.to_owned()),
                    Some(public.clone()),
                );
                return Err(public);
            }
            let failed = state.active.take();
            Self::clear_active_metadata(&mut state);
            drop(failed);
            let public = public_runtime_error(error, &redactor);
            if public.stage == PublicErrorStage::SessionRecovery
                || reconcile_stale_sessions(&self.session_root).is_err()
            {
                state.recovery_required = true;
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id.to_owned()),
                    Some(public.clone()),
                );
                return Err(public);
            }
            self.update_status(
                &mut state,
                RuntimePhase::DisconnectedWithError,
                Some(node_id.to_owned()),
                Some(public.clone()),
            );
            return Err(public);
        }
        Ok(state.status.clone())
    }

    fn start_locked(
        &self,
        state: &mut State,
        node: &Node,
        config_identity: String,
        default_route: DefaultRoute,
        redactor: Redactor,
    ) -> Result<(), RuntimeError> {
        let session_id = random_hex(16)?;
        state.status.session_id = Some(session_id.clone());
        state.status.proofs = default_proofs();
        self.update_status(
            state,
            RuntimePhase::Preparing,
            Some(node.id().to_owned()),
            None,
        );
        let reservations = PortReservations::reserve()?;
        let ports = reservations.ports();
        let password = random_hex(24)?;
        let policy = RoutePolicy {
            default: default_route,
            apps: Vec::new(),
            lan: LanPolicy::Direct,
            ipv6: Ipv6Policy::Enabled,
            dns: DnsPolicy::CurrentNetwork,
        };
        let generated = generate_config(ConfigRequest {
            node,
            policy: &policy,
            mode: CaptureMode::LocalProxy,
            ports,
            health_password: password.clone(),
            vpn_dns: None,
            insecure_approval: None,
        })
        .map_err(|error| RuntimeError::new("generate_config", error.to_string()))?;
        let session = SessionConfig::create(&self.session_root, generated.as_str())?;
        let process_redactor = redactor
            .clone()
            .with_secret(&password)
            .with_secret(&session.path().to_string_lossy());
        Self::set_proof(state, ProofKind::EngineConfig, ProofState::Pending, None);
        self.update_status(
            state,
            RuntimePhase::ValidatingConfig,
            Some(node.id().to_owned()),
            None,
        );
        let launcher = self.services.engine.create()?;
        let engine_version =
            launcher.check(&session, process_redactor.clone(), self.diagnostics.clone())?;
        let generation = random_hex(16)?;
        Self::set_proof(state, ProofKind::EngineConfig, ProofState::Passed, None);
        self.update_status(
            state,
            RuntimePhase::StartingCore,
            Some(node.id().to_owned()),
            None,
        );
        reservations.release();
        let child = launcher.start(&session, process_redactor, self.diagnostics.clone())?;
        let health_route = HealthRoute::new(ports.health, password);
        state.active = Some(ActiveSession {
            child,
            _config: session,
            node_id: node.id().to_owned(),
            config_identity,
            session_id,
            default_route,
            ports,
            health_route: health_route.clone(),
            engine_version: engine_version.clone(),
            redactor,
            last_probe: Instant::now(),
            consecutive_probe_failures: 0,
            generation,
        });
        Self::set_proof(state, ProofKind::EngineProcess, ProofState::Passed, None);
        for kind in [
            ProofKind::HttpListener,
            ProofKind::SocksListener,
            ProofKind::HealthListener,
        ] {
            Self::set_proof(state, kind, ProofState::Pending, None);
        }
        self.update_status(
            state,
            RuntimePhase::VerifyingListener,
            Some(node.id().to_owned()),
            None,
        );
        self.services.listener.wait_until_ready(
            ports,
            state
                .active
                .as_mut()
                .expect("provisional session disappeared")
                .child
                .as_mut(),
        )?;
        for kind in [
            ProofKind::HttpListener,
            ProofKind::SocksListener,
            ProofKind::HealthListener,
        ] {
            Self::set_proof(state, kind, ProofState::Passed, None);
        }
        Self::set_proof(
            state,
            ProofKind::SelectedOutboundHttps,
            ProofState::Pending,
            None,
        );
        self.update_status(
            state,
            RuntimePhase::ProvingTraffic,
            Some(node.id().to_owned()),
            None,
        );
        let proof = self.services.prober.prove(&health_route)?;
        Self::set_proof(
            state,
            ProofKind::SelectedOutboundHttps,
            ProofState::Passed,
            Some(proof.latency_ms),
        );
        let active = state
            .active
            .as_mut()
            .expect("provisional session disappeared");
        if !active.child.is_alive()? {
            return Err(RuntimeError::new(
                "prove_traffic",
                "sing-box exited immediately after traffic proof",
            ));
        }
        self.services
            .listener
            .verify_owned_now(ports, active.child.as_mut())?;
        Self::set_proof(
            state,
            ProofKind::LocalScopeOwnership,
            ProofState::Passed,
            None,
        );
        state.status.ports = Some(PublicPorts {
            http: ports.http,
            socks: ports.socks,
            health: ports.health,
        });
        state.status.route_check_ms = Some(proof.latency_ms);
        state.status.engine_version = Some(engine_version);
        self.update_status(
            state,
            RuntimePhase::OutboundVerified,
            Some(node.id().to_owned()),
            None,
        );
        self.update_status(
            state,
            RuntimePhase::LocalProxyReady,
            Some(node.id().to_owned()),
            None,
        );
        Ok(())
    }

    pub fn stop(&self) -> Result<RuntimeStatus, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.lock_state();
        if state.active.is_none() {
            if state.recovery_required {
                return Ok(state.status.clone());
            }
            self.reset_disconnected(&mut state);
            return Ok(state.status.clone());
        }
        let node_id = state.status.node_id.clone();
        self.update_status(
            &mut state,
            RuntimePhase::StoppingCore,
            node_id.clone(),
            None,
        );
        let stop_result = state
            .active
            .as_mut()
            .expect("active session disappeared")
            .child
            .stop();
        if let Err(error) = stop_result {
            let redactor = state
                .active
                .as_ref()
                .map(|active| active.redactor.clone())
                .unwrap_or_default();
            let public = public_runtime_error(error, &redactor);
            state.recovery_required = true;
            self.update_status(
                &mut state,
                RuntimePhase::RecoveryRequired,
                node_id,
                Some(public.clone()),
            );
            return Err(public);
        }
        let active = state.active.take();
        Self::clear_active_metadata(&mut state);
        drop(active);
        state.recovery_required = reconcile_stale_sessions(&self.session_root).is_err();
        if state.recovery_required {
            let public = PublicError::fixed(
                PublicErrorCode::RecoveryRequired,
                PublicErrorStage::SessionRecovery,
                "Session data remains and requires review",
            );
            self.update_status(
                &mut state,
                RuntimePhase::RecoveryRequired,
                node_id,
                Some(public.clone()),
            );
            return Err(public);
        }
        self.reset_disconnected(&mut state);
        Ok(state.status.clone())
    }

    pub fn retry_session_recovery(&self) -> Result<RuntimeStatus, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let state = self.lock_state();
            if !state.recovery_required {
                return Ok(state.status.clone());
            }
        }
        if let Err(error) = reconcile_stale_sessions(&self.session_root) {
            let public = public_runtime_error(error, &Redactor::default());
            let mut state = self.lock_state();
            state.recovery_required = true;
            self.update_status(
                &mut state,
                RuntimePhase::RecoveryRequired,
                None,
                Some(public.clone()),
            );
            return Err(public);
        }
        let mut state = self.lock_state();
        state.recovery_required = false;
        self.reset_disconnected(&mut state);
        Ok(state.status.clone())
    }

    pub fn status(&self) -> RuntimeStatus {
        self.lock_state().status.clone()
    }

    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            status: self.status(),
            lines: self
                .diagnostics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .snapshot(),
        }
    }

    pub fn shutdown(&self) {
        {
            let mut state = self.lock_state();
            if state.shutting_down {
                return;
            }
            state.shutting_down = true;
        }
        let _ = self.stop();
        let abandoned = {
            let mut state = self.lock_state();
            let active = state.active.take();
            Self::clear_active_metadata(&mut state);
            active
        };
        drop(abandoned);
        self.event_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }

    fn monitor_tick(&self) {
        struct ProbeSnapshot {
            generation: String,
            session_id: String,
            route: HealthRoute,
            redactor: Redactor,
            node_id: String,
        }

        let mut state = self.lock_state();
        let Some(active) = state.active.as_mut() else {
            return;
        };
        let process_error = match active.child.is_alive() {
            Ok(true) => None,
            Ok(false) => Some(PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::EngineProcess,
                "The local proxy process exited unexpectedly",
            )),
            Err(error) => Some(public_runtime_error(error, &active.redactor)),
        };
        if let Some(error) = process_error {
            let node_id = active.node_id.clone();
            let stale = state.active.take();
            Self::set_proof(
                &mut state,
                ProofKind::EngineProcess,
                ProofState::Failed,
                None,
            );
            Self::clear_active_metadata(&mut state);
            drop(stale);
            if reconcile_stale_sessions(&self.session_root).is_err() {
                state.recovery_required = true;
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id),
                    Some(PublicError::fixed(
                        PublicErrorCode::RecoveryRequired,
                        PublicErrorStage::SessionRecovery,
                        "Session data remains and requires review",
                    )),
                );
            } else {
                self.update_status(
                    &mut state,
                    RuntimePhase::DisconnectedWithError,
                    Some(node_id),
                    Some(error),
                );
            }
            return;
        }
        if active.last_probe.elapsed() < Duration::from_secs(10) {
            return;
        }
        active.last_probe = Instant::now();
        let snapshot = ProbeSnapshot {
            generation: active.generation.clone(),
            session_id: active.session_id.clone(),
            route: active.health_route.clone(),
            redactor: active.redactor.clone(),
            node_id: active.node_id.clone(),
        };
        drop(state);

        let proof = self.services.prober.prove(&snapshot.route);
        state = self.lock_state();
        let Some(active) = state.active.as_mut().filter(|active| {
            active.generation == snapshot.generation && active.session_id == snapshot.session_id
        }) else {
            return;
        };
        let ownership = if active.child.is_alive().unwrap_or(false) {
            self.services
                .listener
                .verify_owned_now(active.ports, active.child.as_mut())
        } else {
            Err(RuntimeError::new(
                "engine_process",
                "sing-box exited during traffic proof",
            ))
        };
        if let Err(error) = ownership {
            let public = public_runtime_error(error, &snapshot.redactor);
            let stale = state.active.take();
            Self::set_proof(
                &mut state,
                ProofKind::LocalScopeOwnership,
                ProofState::Failed,
                None,
            );
            Self::clear_active_metadata(&mut state);
            drop(stale);
            if reconcile_stale_sessions(&self.session_root).is_err() {
                state.recovery_required = true;
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(snapshot.node_id),
                    Some(PublicError::fixed(
                        PublicErrorCode::RecoveryRequired,
                        PublicErrorStage::SessionRecovery,
                        "Session data remains and requires review",
                    )),
                );
            } else {
                self.update_status(
                    &mut state,
                    RuntimePhase::DisconnectedWithError,
                    Some(snapshot.node_id),
                    Some(public),
                );
            }
            return;
        }
        match proof {
            Ok(proof) => {
                active.consecutive_probe_failures = 0;
                state.status.route_check_ms = Some(proof.latency_ms);
                Self::set_proof(
                    &mut state,
                    ProofKind::SelectedOutboundHttps,
                    ProofState::Passed,
                    Some(proof.latency_ms),
                );
                Self::set_proof(
                    &mut state,
                    ProofKind::LocalScopeOwnership,
                    ProofState::Passed,
                    None,
                );
                self.update_status(
                    &mut state,
                    RuntimePhase::OutboundVerified,
                    Some(snapshot.node_id.clone()),
                    None,
                );
                self.update_status(
                    &mut state,
                    RuntimePhase::LocalProxyReady,
                    Some(snapshot.node_id),
                    None,
                );
            }
            Err(error) => {
                active.consecutive_probe_failures =
                    active.consecutive_probe_failures.saturating_add(1);
                let threshold_reached = active.consecutive_probe_failures >= 2;
                Self::set_proof(
                    &mut state,
                    ProofKind::SelectedOutboundHttps,
                    ProofState::Failed,
                    None,
                );
                if threshold_reached {
                    let public = public_runtime_error(error, &snapshot.redactor);
                    self.update_status(
                        &mut state,
                        RuntimePhase::Degraded,
                        Some(snapshot.node_id),
                        Some(public),
                    );
                }
            }
        }
    }

    fn update_status(
        &self,
        state: &mut State,
        phase: RuntimePhase,
        node_id: Option<String>,
        error: Option<PublicError>,
    ) {
        state.status.phase = phase;
        state.status.node_id = node_id;
        state.status.error = error;
        if !matches!(
            phase,
            RuntimePhase::OutboundVerified | RuntimePhase::LocalProxyReady | RuntimePhase::Degraded
        ) {
            state.status.route_check_ms = None;
        }
        state.status.revision = state.status.revision.saturating_add(1);
        self.emit_status(state.status.clone());
    }

    fn clear_active_metadata(state: &mut State) {
        state.status.ports = None;
        state.status.route_check_ms = None;
        state.status.engine_version = None;
    }

    fn reset_disconnected(&self, state: &mut State) {
        Self::clear_active_metadata(state);
        state.status.session_id = None;
        state.status.proofs = default_proofs();
        self.update_status(state, RuntimePhase::Disconnected, None, None);
    }

    fn set_proof(
        state: &mut State,
        kind: ProofKind,
        proof_state: ProofState,
        latency_ms: Option<u64>,
    ) {
        if let Some(row) = state.status.proofs.iter_mut().find(|row| row.kind == kind) {
            row.state = proof_state;
            row.latency_ms = latency_ms;
        }
    }

    fn mark_failed_proof(state: &mut State, stage: &str) {
        match stage {
            "generate_config" | "session_storage" | "config_check" => {
                Self::set_proof(state, ProofKind::EngineConfig, ProofState::Failed, None);
            }
            "start_engine" | "engine_process" => {
                Self::set_proof(state, ProofKind::EngineProcess, ProofState::Failed, None);
            }
            "verify_listeners" => {
                for kind in [
                    ProofKind::HttpListener,
                    ProofKind::SocksListener,
                    ProofKind::HealthListener,
                    ProofKind::LocalScopeOwnership,
                ] {
                    Self::set_proof(state, kind, ProofState::Failed, None);
                }
            }
            "prove_traffic" => Self::set_proof(
                state,
                ProofKind::SelectedOutboundHttps,
                ProofState::Failed,
                None,
            ),
            _ => {}
        }
    }

    fn emit_status(&self, status: RuntimeStatus) {
        let sink = self
            .event_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(sink) = sink {
            sink(status);
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn preview_from_report(preview_id: &str, report: &ImportReport) -> ImportPreview {
    ImportPreview {
        preview_id: preview_id.to_owned(),
        nodes: report
            .nodes
            .iter()
            .map(|node| PreviewNode {
                id: node.id().to_owned(),
                display_name: node.display_name().to_owned(),
                protocol: node.protocol_kind(),
                insecure_tls: node.requires_insecure_approval(),
            })
            .collect(),
        rejected: report
            .rejected
            .iter()
            .map(|rejection| PreviewRejection {
                index: rejection.index,
                reason: rejection.reason.into(),
            })
            .collect(),
        warnings: report
            .warnings
            .iter()
            .map(|warning| (*warning).into())
            .collect(),
    }
}

fn default_proofs() -> Vec<ProofRow> {
    [
        ProofKind::EngineConfig,
        ProofKind::EngineProcess,
        ProofKind::HttpListener,
        ProofKind::SocksListener,
        ProofKind::HealthListener,
        ProofKind::SelectedOutboundHttps,
        ProofKind::LocalScopeOwnership,
    ]
    .into_iter()
    .map(|kind| ProofRow {
        kind,
        state: ProofState::NotRun,
        latency_ms: None,
    })
    .collect()
}

impl PublicError {
    fn fixed(code: PublicErrorCode, stage: PublicErrorStage, message: &'static str) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
            detail: None,
        }
    }

    fn with_detail(
        code: PublicErrorCode,
        stage: PublicErrorStage,
        message: &'static str,
        detail: String,
    ) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
            detail: Some(detail),
        }
    }
}

fn public_runtime_error(error: RuntimeError, redactor: &Redactor) -> PublicError {
    let stage = public_stage(error.stage());
    let detail = matches!(
        stage,
        PublicErrorStage::ConfigCheck
            | PublicErrorStage::VerifyListeners
            | PublicErrorStage::ProveTraffic
            | PublicErrorStage::EngineProcess
            | PublicErrorStage::StopEngine
    )
    .then(|| redactor.redact(error.message()));
    PublicError {
        code: PublicErrorCode::RuntimeFailure,
        stage,
        message: "The local proxy operation failed".into(),
        detail,
    }
}

fn public_stage(stage: &str) -> PublicErrorStage {
    match stage {
        "session_recovery" => PublicErrorStage::SessionRecovery,
        "generate_config" => PublicErrorStage::GenerateConfig,
        "engine_layout" => PublicErrorStage::EngineLayout,
        "engine_integrity" => PublicErrorStage::EngineIntegrity,
        "config_check" => PublicErrorStage::ConfigCheck,
        "start_engine" => PublicErrorStage::StartEngine,
        "verify_listeners" => PublicErrorStage::VerifyListeners,
        "prove_traffic" => PublicErrorStage::ProveTraffic,
        "engine_process" => PublicErrorStage::EngineProcess,
        "stop_engine" => PublicErrorStage::StopEngine,
        "session_storage" => PublicErrorStage::SessionStorage,
        "random" => PublicErrorStage::Random,
        "monitor" => PublicErrorStage::Monitor,
        _ => PublicErrorStage::Runtime,
    }
}

fn constant_time_token_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Condvar,
    };

    use super::*;
    use crate::health::ProofResult;

    const NODE: &str = "hysteria2://fixture-secret@example.test:443?sni=example.test#fixture";

    struct FakeProvider {
        check_fails: bool,
        stop_fails: bool,
        alive: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
    }

    impl EngineProvider for FakeProvider {
        fn create(&self) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
            Ok(Box::new(FakeLauncher {
                check_fails: self.check_fails,
                stop_fails: self.stop_fails,
                alive: self.alive.clone(),
                stops: self.stops.clone(),
            }))
        }
    }

    struct FakeLauncher {
        check_fails: bool,
        stop_fails: bool,
        alive: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
    }

    struct RecoveryFailProvider;

    impl EngineProvider for RecoveryFailProvider {
        fn create(&self) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
            Ok(Box::new(RecoveryFailLauncher))
        }
    }

    struct RecoveryFailLauncher;

    impl EngineLauncher for RecoveryFailLauncher {
        fn check(
            &self,
            _config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<String, RuntimeError> {
            Err(RuntimeError::new(
                "session_recovery",
                "injected incomplete secret cleanup",
            ))
        }

        fn start(
            &self,
            _config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<Box<dyn ManagedChild>, RuntimeError> {
            panic!("start must not run after recovery failure")
        }
    }

    impl EngineLauncher for FakeLauncher {
        fn check(
            &self,
            _config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<String, RuntimeError> {
            if self.check_fails {
                Err(RuntimeError::new(
                    "config_check",
                    "password=fixture-secret rejected",
                ))
            } else {
                Ok("fixture-engine".into())
            }
        }

        fn start(
            &self,
            _config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<Box<dyn ManagedChild>, RuntimeError> {
            self.alive.store(true, Ordering::SeqCst);
            Ok(Box::new(FakeChild {
                alive: self.alive.clone(),
                stops: self.stops.clone(),
                stop_fails: self.stop_fails,
            }))
        }
    }

    struct FakeChild {
        alive: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
        stop_fails: bool,
    }

    impl ManagedChild for FakeChild {
        fn pid(&self) -> u32 {
            std::process::id()
        }

        fn is_alive(&mut self) -> Result<bool, RuntimeError> {
            Ok(self.alive.load(Ordering::SeqCst))
        }

        fn stop(&mut self) -> Result<(), RuntimeError> {
            if self.stop_fails {
                return Err(RuntimeError::new(
                    "stop_engine",
                    "fixture process refused to stop",
                ));
            }
            if self.alive.swap(false, Ordering::SeqCst) {
                self.stops.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    struct FakeListener(bool);

    impl ListenerVerifier for FakeListener {
        fn wait_until_ready(
            &self,
            _ports: crate::config::LocalPorts,
            _child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            if self.0 {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "verify_listeners",
                    "fixture listener did not open",
                ))
            }
        }

        fn verify_owned_now(
            &self,
            _ports: crate::config::LocalPorts,
            child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            if self.0 && child.is_alive()? {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "verify_listeners",
                    "fixture listener ownership failed",
                ))
            }
        }
    }

    struct ToggleListener(Arc<AtomicBool>);

    impl ListenerVerifier for ToggleListener {
        fn wait_until_ready(
            &self,
            _ports: crate::config::LocalPorts,
            _child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            if self.0.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "verify_listeners",
                    "fixture listener did not open",
                ))
            }
        }

        fn verify_owned_now(
            &self,
            _ports: crate::config::LocalPorts,
            child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            if self.0.load(Ordering::SeqCst) && child.is_alive()? {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "verify_listeners",
                    "fixture listener ownership failed",
                ))
            }
        }
    }

    struct FakeProber(bool);

    impl TrafficProber for FakeProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            if self.0 {
                Ok(ProofResult { latency_ms: 42 })
            } else {
                Err(RuntimeError::new(
                    "prove_traffic",
                    "fixture selected outbound failed",
                ))
            }
        }
    }

    struct ToggleProber(Arc<AtomicBool>);

    impl TrafficProber for ToggleProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            if self.0.load(Ordering::SeqCst) {
                Ok(ProofResult { latency_ms: 42 })
            } else {
                Err(RuntimeError::new(
                    "prove_traffic",
                    "fixture selected outbound failed",
                ))
            }
        }
    }

    struct BlockingProber {
        calls: AtomicUsize,
        gate: Arc<(Mutex<(bool, bool)>, Condvar)>,
    }

    impl TrafficProber for BlockingProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
                let (lock, wake) = &*self.gate;
                let mut flags = lock.lock().unwrap();
                flags.0 = true;
                wake.notify_all();
                while !flags.1 {
                    flags = wake.wait(flags).unwrap();
                }
            }
            Ok(ProofResult { latency_ms: 42 })
        }
    }

    fn controller(
        check_fails: bool,
        listener: bool,
        proof: bool,
    ) -> (ApplicationController, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let alive = Arc::new(AtomicBool::new(false));
        let stops = Arc::new(AtomicUsize::new(0));
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        let controller = ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails,
                stop_fails: false,
                alive: alive.clone(),
                stops: stops.clone(),
            }),
            Arc::new(FakeListener(listener)),
            Arc::new(FakeProber(proof)),
        );
        (controller, stops, alive)
    }

    fn controller_with_prober(
        prober: Arc<dyn TrafficProber>,
    ) -> (ApplicationController, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let alive = Arc::new(AtomicBool::new(false));
        let stops = Arc::new(AtomicUsize::new(0));
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        let controller = ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails: false,
                alive: alive.clone(),
                stops: stops.clone(),
            }),
            Arc::new(FakeListener(true)),
            prober,
        );
        (controller, stops, alive)
    }

    fn controller_with_stop_failure() -> ApplicationController {
        let alive = Arc::new(AtomicBool::new(false));
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails: true,
                alive,
                stops: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(FakeListener(true)),
            Arc::new(FakeProber(true)),
        )
    }

    fn controller_with_start_rollback_failure(
        listener_ready: bool,
        proof_ready: bool,
    ) -> ApplicationController {
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails: true,
                alive: Arc::new(AtomicBool::new(false)),
                stops: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(FakeListener(listener_ready)),
            Arc::new(FakeProber(proof_ready)),
        )
    }

    fn controller_with_listener_toggle(
        listener: Arc<AtomicBool>,
    ) -> (ApplicationController, Arc<AtomicBool>) {
        let alive = Arc::new(AtomicBool::new(false));
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        let controller = ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails: false,
                alive: alive.clone(),
                stops: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleListener(listener)),
            Arc::new(FakeProber(true)),
        );
        (controller, alive)
    }

    fn controller_with_recovery_failure() -> ApplicationController {
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            Arc::new(RecoveryFailProvider),
            Arc::new(FakeListener(true)),
            Arc::new(FakeProber(true)),
        )
    }

    fn import_node(controller: &ApplicationController) -> String {
        let preview = controller.preview_import_content(NODE.into()).unwrap();
        let confirmed = controller.confirm_import(&preview.preview_id).unwrap();
        confirmed.node_ids[0].clone()
    }

    #[test]
    fn process_start_without_listener_never_turns_green_and_stops_child() {
        let (controller, stops, _) = controller(false, false, true);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::VerifyListeners);
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn incomplete_session_cleanup_enters_recovery_and_blocks_reconnect() {
        let controller = controller_with_recovery_failure();
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SessionRecovery);
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        let retry = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(retry.code, PublicErrorCode::RecoveryRequired);
    }

    #[test]
    fn check_failure_blocks_start_and_redacts_secrets() {
        let (controller, stops, _) = controller(true, true, true);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ConfigCheck);
        assert!(!error.message.contains("fixture-secret"));
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(controller
            .diagnostics()
            .lines
            .iter()
            .all(|line| !line.contains("fixture-secret")));
    }

    #[test]
    fn failed_forced_proxy_proof_never_turns_green() {
        let (controller, stops, _) = controller(false, true, false);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Direct)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert_ne!(controller.status().phase, RuntimePhase::LocalProxyReady);
    }

    #[test]
    fn successful_proof_is_the_only_path_to_local_proxy_ready_and_stop_is_idempotent() {
        let (controller, stops, _) = controller(false, true, true);
        let node = import_node(&controller);
        let status = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        assert_eq!(status.phase, RuntimePhase::LocalProxyReady);
        assert_eq!(status.scope, RuntimeScope::LocalOnly);
        assert_eq!(status.mode, RuntimeMode::LocalOnly);
        assert!(status.session_id.is_some());
        assert!(status
            .proofs
            .iter()
            .all(|proof| proof.state == ProofState::Passed));
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("\"phase\":\"connected\""));
        assert_eq!(status.route_check_ms, Some(42));
        assert_eq!(controller.stop().unwrap().phase, RuntimePhase::Disconnected);
        assert_eq!(controller.stop().unwrap().phase, RuntimePhase::Disconnected);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn import_confirmation_token_is_one_use() {
        let (controller, _, _) = controller(false, true, true);
        let preview = controller.preview_import_content(NODE.into()).unwrap();
        controller.confirm_import(&preview.preview_id).unwrap();
        assert!(controller.confirm_import(&preview.preview_id).is_err());
    }

    #[test]
    fn import_preview_discard_is_exact_and_idempotent() {
        let (controller, _, _) = controller(false, true, true);
        let preview = controller.preview_import_content(NODE.into()).unwrap();
        let mismatch = controller
            .discard_import_preview("00000000000000000000000000000000")
            .unwrap_err();
        assert_eq!(mismatch.code, PublicErrorCode::PreviewTokenInvalid);
        controller
            .discard_import_preview(&preview.preview_id)
            .unwrap();
        controller
            .discard_import_preview(&preview.preview_id)
            .unwrap();
        let missing = controller.confirm_import(&preview.preview_id).unwrap_err();
        assert_eq!(missing.code, PublicErrorCode::PreviewMissing);
    }

    #[test]
    fn import_preview_omits_raw_server_authority() {
        let (controller, _, _) = controller(false, true, true);
        let preview = controller.preview_import_content(NODE.into()).unwrap();
        let serialized = serde_json::to_string(&preview).unwrap();
        assert!(!serialized.contains("example.test"));
        assert!(serialized.contains("fixture"));
    }

    #[test]
    fn status_revision_is_monotonic_across_start_and_stop() {
        let (controller, _, _) = controller(false, true, true);
        let initial = controller.status().revision;
        let node = import_node(&controller);
        let started = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        assert!(started.revision > initial);
        let stopped = controller.stop().unwrap();
        assert!(stopped.revision > started.revision);
        assert!(stopped.session_id.is_none());
    }

    #[test]
    fn process_death_invalidates_connected_state_on_monitor_tick() {
        let (controller, _, alive) = controller(false, true, true);
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        alive.store(false, Ordering::SeqCst);
        controller.monitor_tick();
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert!(controller.status().error.is_some());
        assert!(controller.status().ports.is_none());
        assert!(controller.status().engine_version.is_none());
    }

    #[test]
    fn listener_ownership_loss_after_proof_invalidates_ready_state() {
        let listener = Arc::new(AtomicBool::new(true));
        let (controller, _) = controller_with_listener_toggle(listener.clone());
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        listener.store(false, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert!(controller.status().ports.is_none());
    }

    #[test]
    fn failed_stop_never_publishes_relinquished_listener_metadata() {
        let controller = controller_with_stop_failure();
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let error = controller.stop().unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::StopEngine);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::RecoveryRequired);
        assert!(status.ports.is_some());
        assert!(status.engine_version.is_some());
        let retry = controller
            .start_local_proxy(status.node_id.as_deref().unwrap(), DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(retry.code, PublicErrorCode::RecoveryRequired);
    }

    #[test]
    fn listener_failure_with_uncertain_rollback_retains_supervision() {
        let controller = controller_with_start_rollback_failure(false, true);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::StopEngine);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::RecoveryRequired);
        assert!(status.ports.is_some());
        assert!(controller.lock_state().active.is_some());
    }

    #[test]
    fn traffic_failure_with_uncertain_rollback_retains_supervision() {
        let controller = controller_with_start_rollback_failure(true, false);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::StopEngine);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::RecoveryRequired);
        assert!(status.ports.is_some());
        assert!(controller.lock_state().active.is_some());
    }

    #[test]
    fn failed_same_route_replacement_clears_old_listener_metadata() {
        let proof_enabled = Arc::new(AtomicBool::new(true));
        let (controller, _, _) =
            controller_with_prober(Arc::new(ToggleProber(proof_enabled.clone())));
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        assert!(controller.status().ports.is_some());
        proof_enabled.store(false, Ordering::SeqCst);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::DisconnectedWithError);
        assert!(status.ports.is_none());
        assert!(status.engine_version.is_none());
    }

    #[test]
    fn crash_data_preserves_ui_startup_and_blocks_only_connect_until_reviewed() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-recovery-controller-{}",
            random_hex(8).expect("test random")
        ));
        let stale = root.join("session-0123456789abcdef0123456789abcdef");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("config.json"), b"fixture-secret").unwrap();
        let controller = ApplicationController::production(root.clone(), Arc::new(|_| {})).unwrap();
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SessionRecovery);
        assert!(controller.retry_session_recovery().is_err());
        assert!(stale.join("config.json").exists());

        std::fs::remove_file(stale.join("config.json")).unwrap();
        std::fs::remove_dir(stale).unwrap();
        assert_eq!(
            controller.retry_session_recovery().unwrap().phase,
            RuntimePhase::Disconnected
        );
        drop(controller);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn periodic_proof_degrades_after_two_failures_and_recovers_on_success() {
        let proof_enabled = Arc::new(AtomicBool::new(true));
        let (controller, _, _) =
            controller_with_prober(Arc::new(ToggleProber(proof_enabled.clone())));
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        proof_enabled.store(false, Ordering::SeqCst);
        for expected_phase in [RuntimePhase::LocalProxyReady, RuntimePhase::Degraded] {
            controller.lock_state().active.as_mut().unwrap().last_probe =
                Instant::now() - Duration::from_secs(11);
            controller.monitor_tick();
            assert_eq!(controller.status().phase, expected_phase);
        }
        proof_enabled.store(true, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().phase, RuntimePhase::LocalProxyReady);
        assert!(controller.status().error.is_none());
    }

    #[test]
    fn periodic_network_probe_does_not_hold_controller_state_lock() {
        let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let (controller, _, _) = controller_with_prober(Arc::new(BlockingProber {
            calls: AtomicUsize::new(0),
            gate: gate.clone(),
        }));
        let controller = Arc::new(controller);
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);

        let monitor = {
            let controller = controller.clone();
            thread::spawn(move || controller.monitor_tick())
        };
        let (gate_lock, gate_wake) = &*gate;
        let mut flags = gate_lock.lock().unwrap();
        while !flags.0 {
            flags = gate_wake.wait(flags).unwrap();
        }
        drop(flags);

        let (status_tx, status_rx) = mpsc::channel();
        let status_controller = controller.clone();
        let status_thread = thread::spawn(move || {
            status_tx.send(status_controller.status()).unwrap();
        });
        let status_was_responsive = status_rx.recv_timeout(Duration::from_millis(500)).is_ok();

        let mut flags = gate_lock.lock().unwrap();
        flags.1 = true;
        gate_wake.notify_all();
        drop(flags);
        monitor.join().unwrap();
        status_thread.join().unwrap();
        assert!(status_was_responsive);
    }

    #[test]
    fn idempotency_requires_exact_route_identity() {
        let (controller, _, _) = controller(false, true, true);
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Direct)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::Start);
        assert_eq!(controller.status().phase, RuntimePhase::LocalProxyReady);
    }

    #[test]
    fn confirming_a_new_private_node_revision_never_reuses_a_ready_session() {
        let (controller, _, _) = controller(false, true, true);
        let node = import_node(&controller);
        let first = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let repeated = controller.preview_import_content(NODE.into()).unwrap();
        controller.confirm_import(&repeated.preview_id).unwrap();
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.code, PublicErrorCode::ActiveSessionConflict);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::LocalProxyReady);
        assert_eq!(status.session_id, first.session_id);
    }
}
