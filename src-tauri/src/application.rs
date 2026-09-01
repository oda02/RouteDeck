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
    Connected,
    Degraded,
    RollingBack,
    StoppingCore,
    DisconnectedWithError,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub phase: RuntimePhase,
    pub node_id: Option<String>,
    pub ports: Option<PublicPorts>,
    pub route_check_ms: Option<u64>,
    pub engine_version: Option<String>,
    pub error: Option<PublicError>,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            phase: RuntimePhase::Disconnected,
            node_id: None,
            ports: None,
            route_check_ms: None,
            engine_version: None,
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

#[derive(Debug, Clone, Serialize)]
pub struct PublicError {
    pub stage: String,
    pub message: String,
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
    pub server: String,
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

struct ActiveSession {
    child: Box<dyn ManagedChild>,
    _config: SessionConfig,
    node_id: String,
    default_route: DefaultRoute,
    health_route: HealthRoute,
    redactor: Redactor,
    last_probe: Instant,
    consecutive_probe_failures: u8,
    generation: String,
}

#[derive(Default)]
struct State {
    nodes: HashMap<String, Node>,
    pending: Option<PendingImport>,
    active: Option<ActiveSession>,
    status: RuntimeStatus,
    recovery_required: bool,
}

type EventSink = Arc<dyn Fn(RuntimeStatus) + Send + Sync>;

pub struct ApplicationController {
    state: Mutex<State>,
    operation: Mutex<()>,
    services: RuntimeServices,
    session_root: PathBuf,
    diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    event_sink: EventSink,
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
            let public = public_error(error);
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
            event_sink,
        }
    }

    pub fn import_preview(&self, input: String) -> Result<ImportPreview, PublicError> {
        let report = import_subscription(input.as_bytes()).map_err(|error| PublicError {
            stage: "import".into(),
            message: Redactor::default().redact(&error.to_string()),
        })?;
        let preview_id = random_hex(16).map_err(public_error)?;
        let preview = preview_from_report(&preview_id, &report);
        let mut state = self.lock_state();
        state.pending = Some(PendingImport {
            id: preview_id,
            report,
        });
        Ok(preview)
    }

    pub fn confirm_import(&self, preview_id: &str) -> Result<ConfirmedImport, PublicError> {
        let mut state = self.lock_state();
        let pending = state.pending.take().ok_or_else(|| PublicError {
            stage: "import".into(),
            message: "No import preview is pending".into(),
        })?;
        if !constant_time_token_eq(&pending.id, preview_id) {
            state.pending = Some(pending);
            return Err(PublicError {
                stage: "import".into(),
                message: "Import preview token is invalid".into(),
            });
        }
        let mut node_ids = Vec::with_capacity(pending.report.nodes.len());
        for node in pending.report.nodes {
            node_ids.push(node.id().to_owned());
            state.nodes.insert(node.id().to_owned(), node);
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
        if state.recovery_required {
            return Err(PublicError {
                stage: "session_recovery".into(),
                message: "Review and remove the preserved session data, then retry recovery".into(),
            });
        }
        if state.active.is_some() {
            let exact = state.active.as_ref().is_some_and(|active| {
                active.node_id == node_id && active.default_route == default_route
            });
            if !exact {
                return Err(PublicError {
                    stage: "start".into(),
                    message: "Stop the active local proxy before changing node or route".into(),
                });
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
                    active.node_id == node_id && active.default_route == default_route
                }) {
                    return Err(PublicError {
                        stage: "start".into(),
                        message: "Active session changed while traffic was being verified".into(),
                    });
                }
                state.status.route_check_ms = Some(proof.latency_ms);
                self.update_status(
                    &mut state,
                    RuntimePhase::Connected,
                    Some(node_id.to_owned()),
                    None,
                );
                return Ok(state.status.clone());
            }
            let stale = state.active.take();
            Self::clear_active_metadata(&mut state);
            self.update_status(
                &mut state,
                RuntimePhase::RollingBack,
                Some(node_id.to_owned()),
                None,
            );
            drop(state);
            if let Some(mut stale) = stale {
                if let Err(error) = stale.child.stop() {
                    let public = public_error(error);
                    state = self.lock_state();
                    self.update_status(
                        &mut state,
                        RuntimePhase::DisconnectedWithError,
                        Some(node_id.to_owned()),
                        Some(public.clone()),
                    );
                    return Err(public);
                }
            }
            state = self.lock_state();
        }
        let node = state
            .nodes
            .get(node_id)
            .cloned()
            .ok_or_else(|| PublicError {
                stage: "start".into(),
                message: "Selected node does not exist in the confirmed import".into(),
            })?;
        let redactor = Redactor::from_nodes(std::slice::from_ref(&node)).with_secret(node.server());

        let result = self.start_locked(&mut state, &node, default_route, redactor.clone());
        if let Err(error) = result {
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
            state.active.take();
            Self::clear_active_metadata(&mut state);
            self.update_status(
                &mut state,
                RuntimePhase::DisconnectedWithError,
                Some(node_id.to_owned()),
                Some(PublicError {
                    stage: error.stage().into(),
                    message: safe.clone(),
                }),
            );
            return Err(PublicError {
                stage: error.stage().into(),
                message: safe,
            });
        }
        Ok(state.status.clone())
    }

    fn start_locked(
        &self,
        state: &mut State,
        node: &Node,
        default_route: DefaultRoute,
        redactor: Redactor,
    ) -> Result<(), RuntimeError> {
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
            mode: CaptureMode::SystemProxy,
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
        self.update_status(
            state,
            RuntimePhase::ValidatingConfig,
            Some(node.id().to_owned()),
            None,
        );
        let launcher = self.services.engine.create()?;
        let engine_version = launcher.check(
            session.path(),
            process_redactor.clone(),
            self.diagnostics.clone(),
        )?;
        reservations.release();
        self.update_status(
            state,
            RuntimePhase::StartingCore,
            Some(node.id().to_owned()),
            None,
        );
        let mut child =
            launcher.start(session.path(), process_redactor, self.diagnostics.clone())?;
        self.update_status(
            state,
            RuntimePhase::VerifyingListener,
            Some(node.id().to_owned()),
            None,
        );
        if let Err(error) = self
            .services
            .listener
            .wait_until_ready(ports, child.as_mut())
        {
            let _ = child.stop();
            return Err(error);
        }
        self.update_status(
            state,
            RuntimePhase::ProvingTraffic,
            Some(node.id().to_owned()),
            None,
        );
        let health_route = HealthRoute::new(ports.health, password);
        let proof = match self.services.prober.prove(&health_route) {
            Ok(proof) => proof,
            Err(error) => {
                let _ = child.stop();
                return Err(error);
            }
        };
        if !child.is_alive()? {
            let _ = child.stop();
            return Err(RuntimeError::new(
                "prove_traffic",
                "sing-box exited immediately after traffic proof",
            ));
        }
        state.active = Some(ActiveSession {
            child,
            _config: session,
            node_id: node.id().to_owned(),
            default_route,
            health_route,
            redactor,
            last_probe: Instant::now(),
            consecutive_probe_failures: 0,
            generation: random_hex(16)?,
        });
        state.status.ports = Some(PublicPorts {
            http: ports.http,
            socks: ports.socks,
            health: ports.health,
        });
        state.status.route_check_ms = Some(proof.latency_ms);
        state.status.engine_version = Some(engine_version);
        self.update_status(
            state,
            RuntimePhase::Connected,
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
            state.status = RuntimeStatus::default();
            (self.event_sink)(state.status.clone());
            return Ok(state.status.clone());
        }
        let node_id = state.status.node_id.clone();
        self.update_status(
            &mut state,
            RuntimePhase::StoppingCore,
            node_id.clone(),
            None,
        );
        let mut active = state.active.take().expect("active session disappeared");
        Self::clear_active_metadata(&mut state);
        drop(state);
        let stop_result = active.child.stop();
        drop(active);
        state = self.lock_state();
        if let Err(error) = stop_result {
            let public = public_error(error);
            self.update_status(
                &mut state,
                RuntimePhase::DisconnectedWithError,
                node_id,
                Some(public.clone()),
            );
            return Err(public);
        }
        state.status = RuntimeStatus::default();
        (self.event_sink)(state.status.clone());
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
            let public = public_error(error);
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
        state.status = RuntimeStatus::default();
        (self.event_sink)(state.status.clone());
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

    fn monitor_tick(&self) {
        struct ProbeSnapshot {
            generation: String,
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
            Ok(false) => Some(PublicError {
                stage: "engine_process".into(),
                message: "sing-box exited unexpectedly".into(),
            }),
            Err(error) => Some(PublicError {
                stage: error.stage().into(),
                message: active.redactor.redact(error.message()),
            }),
        };
        if let Some(error) = process_error {
            let node_id = active.node_id.clone();
            let stale = state.active.take();
            Self::clear_active_metadata(&mut state);
            self.update_status(
                &mut state,
                RuntimePhase::Degraded,
                Some(node_id),
                Some(error),
            );
            drop(state);
            drop(stale);
            return;
        }
        if active.last_probe.elapsed() < Duration::from_secs(10) {
            return;
        }
        active.last_probe = Instant::now();
        let snapshot = ProbeSnapshot {
            generation: active.generation.clone(),
            route: active.health_route.clone(),
            redactor: active.redactor.clone(),
            node_id: active.node_id.clone(),
        };
        drop(state);

        let proof = self.services.prober.prove(&snapshot.route);
        state = self.lock_state();
        let Some(active) = state
            .active
            .as_mut()
            .filter(|active| active.generation == snapshot.generation)
        else {
            return;
        };
        match proof {
            Ok(proof) => {
                active.consecutive_probe_failures = 0;
                state.status.route_check_ms = Some(proof.latency_ms);
                self.update_status(
                    &mut state,
                    RuntimePhase::Connected,
                    Some(snapshot.node_id),
                    None,
                );
            }
            Err(error) => {
                active.consecutive_probe_failures =
                    active.consecutive_probe_failures.saturating_add(1);
                if active.consecutive_probe_failures >= 2 {
                    let public = PublicError {
                        stage: error.stage().into(),
                        message: snapshot.redactor.redact(error.message()),
                    };
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
        if phase != RuntimePhase::Connected {
            state.status.route_check_ms = None;
        }
        (self.event_sink)(state.status.clone());
    }

    fn clear_active_metadata(state: &mut State) {
        state.status.ports = None;
        state.status.route_check_ms = None;
        state.status.engine_version = None;
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
                server: node.server().to_owned(),
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

fn public_error(error: RuntimeError) -> PublicError {
    PublicError {
        stage: error.stage().into(),
        message: Redactor::default().redact(error.message()),
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
    use std::{
        path::Path,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc, Condvar,
        },
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

    impl EngineLauncher for FakeLauncher {
        fn check(
            &self,
            _config: &Path,
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
            _config: &Path,
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

    fn import_node(controller: &ApplicationController) -> String {
        let preview = controller.import_preview(NODE.into()).unwrap();
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
        assert_eq!(error.stage, "verify_listeners");
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn check_failure_blocks_start_and_redacts_secrets() {
        let (controller, stops, _) = controller(true, true, true);
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, "config_check");
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
        assert_eq!(error.stage, "prove_traffic");
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert_ne!(controller.status().phase, RuntimePhase::Connected);
    }

    #[test]
    fn successful_proof_is_the_only_path_to_connected_and_stop_is_idempotent() {
        let (controller, stops, _) = controller(false, true, true);
        let node = import_node(&controller);
        let status = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        assert_eq!(status.phase, RuntimePhase::Connected);
        assert_eq!(status.route_check_ms, Some(42));
        assert_eq!(controller.stop().unwrap().phase, RuntimePhase::Disconnected);
        assert_eq!(controller.stop().unwrap().phase, RuntimePhase::Disconnected);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn import_confirmation_token_is_one_use() {
        let (controller, _, _) = controller(false, true, true);
        let preview = controller.import_preview(NODE.into()).unwrap();
        controller.confirm_import(&preview.preview_id).unwrap();
        assert!(controller.confirm_import(&preview.preview_id).is_err());
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
        assert_eq!(controller.status().phase, RuntimePhase::Degraded);
        assert!(controller.status().error.is_some());
        assert!(controller.status().ports.is_none());
        assert!(controller.status().engine_version.is_none());
    }

    #[test]
    fn failed_stop_never_publishes_relinquished_listener_metadata() {
        let controller = controller_with_stop_failure();
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let error = controller.stop().unwrap_err();
        assert_eq!(error.stage, "stop_engine");
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::DisconnectedWithError);
        assert!(status.ports.is_none());
        assert!(status.engine_version.is_none());
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
        assert_eq!(error.stage, "prove_traffic");
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
        assert_eq!(error.stage, "session_recovery");
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
        for expected_phase in [RuntimePhase::Connected, RuntimePhase::Degraded] {
            controller.lock_state().active.as_mut().unwrap().last_probe =
                Instant::now() - Duration::from_secs(11);
            controller.monitor_tick();
            assert_eq!(controller.status().phase, expected_phase);
        }
        proof_enabled.store(true, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().phase, RuntimePhase::Connected);
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
        assert_eq!(error.stage, "start");
        assert_eq!(controller.status().phase, RuntimePhase::Connected);
    }
}
