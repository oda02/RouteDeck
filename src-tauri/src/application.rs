use std::{
    collections::{HashMap, VecDeque},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    app_instance::AppInstanceGuard,
    config::{
        default_tun_traffic_rules, generate_config, generate_socks_bridge_config,
        validate_tun_traffic_rules, CaptureMode, ConfigRequest, SocksBridge, TunSettings, TunStack,
        TunTrafficRule, TunUpstream,
    },
    domain::{
        AppRoute, AppRouteAction, DefaultRoute, DnsPolicy, Ipv6Policy, LanPolicy, Node,
        NodeProtocol, ProtocolKind, RoutePolicy,
    },
    engine_runtime::{
        random_hex, reconcile_stale_sessions, DiagnosticBuffer, EngineKind, EngineLauncher,
        LoopbackPortReservation, ManagedChild, PortReservations, RuntimeError, SessionConfig,
        TunCaptureSnapshot, VerifiedEngineLauncher,
    },
    health::{
        HealthRoute, HttpsTrafficProber, ListenerVerifier, TcpListenerVerifier, TrafficProber,
    },
    redaction::Redactor,
    subscription::{import_subscription, ImportReport},
    subscription_fetch::{
        HttpsSubscriptionFetcher, SubscriptionFetchError, SubscriptionFetchErrorKind,
        SubscriptionFetchStage, SubscriptionFetcher,
    },
    subscription_store::{
        valid_source_name, validate_sources, SourceKind, StoredSource, SubscriptionStore,
        LEGACY_SOURCE_ID, MAX_LIBRARY_NODES,
    },
    system_proxy::{
        SystemProxyControl, SystemProxyDiagnostics, SystemProxyManager, SystemProxyRestoreOutcome,
    },
    tun_helper::{reconcile_stale_tun_sessions, select_physical_upstream, TunUpstreamIdentity},
    xray_config::{generate_xray_bridge_config, XrayBridgeRequest},
};

#[cfg(windows)]
use crate::tun_helper::TunHelperLauncher;

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
    ApplyingSystemProxy,
    LocalProxyReady,
    SystemProxyReady,
    TunReady,
    RestoringSystemProxy,
    BlockedByConflict,
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
    SystemProxy,
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    LocalOnly,
    SystemProxy,
    Tun,
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
    SystemProxyOwnership,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofState {
    NotRun,
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steady_latency_ms: Option<u64>,
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
            steady_latency_ms: None,
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
    SubscriptionUrlInvalid,
    SubscriptionPolicyBlocked,
    SubscriptionFetchFailed,
    SubscriptionResponseTooLarge,
    SubscriptionFetchTimeout,
    SubscriptionInvalidEncoding,
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
    SubscriptionUrl,
    SubscriptionDns,
    SubscriptionFetch,
    SubscriptionResponse,
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
    SystemProxyPublish,
    SystemProxyRestore,
    SystemProxyOwnership,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<SourceKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_refreshable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_updated_at_ms: Option<u64>,
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
    pub system_proxy: SystemProxyDiagnostics,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SystemProxyRouting {
    pub default_route: DefaultRoute,
    #[serde(default)]
    pub naive_udp_over_tcp: bool,
    #[serde(default)]
    pub apps: Vec<SystemProxyAppRoute>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TunRouting {
    pub default_route: DefaultRoute,
    #[serde(default)]
    pub naive_udp_over_tcp: bool,
    #[serde(default)]
    pub apps: Vec<SystemProxyAppRoute>,
    #[serde(default)]
    pub stack: TunStack,
    #[serde(default = "default_tun_traffic_rules")]
    pub traffic_rules: Vec<TunTrafficRule>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SystemProxyAppRoute {
    pub process_path: String,
    pub process_name: Option<String>,
    pub route: AppRouteAction,
}

impl fmt::Debug for SystemProxyAppRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemProxyAppRoute")
            .field("process_path", &"[REDACTED]")
            .field("process_name", &self.process_name)
            .field("route", &self.route)
            .finish()
    }
}

impl SystemProxyRouting {
    fn into_policy(self) -> RoutePolicy {
        RoutePolicy {
            default: self.default_route,
            apps: self
                .apps
                .into_iter()
                .map(|app| AppRoute {
                    process_path: app.process_path,
                    process_name: app.process_name,
                    action: app.route,
                })
                .collect(),
            // Private destinations stay direct in both user-facing routing modes.
            lan: LanPolicy::Direct,
            ipv6: Ipv6Policy::Enabled,
            dns: DnsPolicy::CurrentNetwork,
        }
    }
}

impl TunRouting {
    fn into_policy(self) -> RoutePolicy {
        RoutePolicy {
            default: self.default_route,
            apps: self
                .apps
                .into_iter()
                .map(|app| AppRoute {
                    process_path: app.process_path,
                    process_name: app.process_name,
                    action: app.route,
                })
                .collect(),
            lan: LanPolicy::Direct,
            ipv6: Ipv6Policy::Enabled,
            dns: DnsPolicy::CurrentNetwork,
        }
    }
}

trait TunPrivilegeControl: Send + Sync {
    fn is_elevated(&self) -> Result<bool, RuntimeError>;
}

struct PlatformTunPrivilege;

impl TunPrivilegeControl for PlatformTunPrivilege {
    fn is_elevated(&self) -> Result<bool, RuntimeError> {
        #[cfg(windows)]
        {
            // The ordinary Tauri process intentionally stays at asInvoker. The fixed
            // native helper requests elevation only when its TUN launcher starts.
            Ok(true)
        }
        #[cfg(not(windows))]
        {
            Ok(false)
        }
    }
}

pub(crate) trait EngineProvider: Send + Sync {
    fn create(&self, kind: EngineKind) -> Result<Box<dyn EngineLauncher>, RuntimeError>;

    fn select_tun_upstream(&self) -> Result<TunUpstreamIdentity, RuntimeError> {
        #[cfg(test)]
        {
            Ok(TunUpstreamIdentity {
                interface_luid: 7,
                interface_index: 9,
                interface_alias: "Ethernet".into(),
                ipv4_dns_server: None,
            })
        }
        #[cfg(not(test))]
        {
            Err(RuntimeError::new(
                "tun_preflight",
                "TUN provider does not implement physical upstream selection",
            ))
        }
    }

    fn create_tun(
        &self,
        _upstream: TunUpstreamIdentity,
    ) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
        self.create(EngineKind::SingBox)
    }
}

struct FixedEngineProvider {
    expected_tun_helper_sha256: Option<&'static str>,
}

impl EngineProvider for FixedEngineProvider {
    fn create(&self, kind: EngineKind) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
        Ok(Box::new(VerifiedEngineLauncher::resolve_for(kind)?))
    }

    fn select_tun_upstream(&self) -> Result<TunUpstreamIdentity, RuntimeError> {
        select_physical_upstream()
    }

    fn create_tun(
        &self,
        upstream: TunUpstreamIdentity,
    ) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
        #[cfg(windows)]
        {
            Ok(Box::new(TunHelperLauncher::resolve(
                self.expected_tun_helper_sha256,
                upstream,
            )?))
        }
        #[cfg(not(windows))]
        {
            Err(RuntimeError::new(
                "start_engine",
                "TUN helper is available only on Windows",
            ))
        }
    }
}

struct ProvisionalChild(Option<Box<dyn ManagedChild>>);

impl ProvisionalChild {
    fn new(child: Box<dyn ManagedChild>) -> Self {
        Self(Some(child))
    }

    fn as_mut(&mut self) -> &mut dyn ManagedChild {
        self.0.as_deref_mut().expect("provisional child missing")
    }

    fn take(mut self) -> Box<dyn ManagedChild> {
        self.0.take().expect("provisional child missing")
    }
}

impl Drop for ProvisionalChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.stop();
        }
    }
}

struct RealityProcessPair {
    front: Box<dyn ManagedChild>,
    sidecar: Box<dyn ManagedChild>,
    sidecar_port: u16,
    listener: Arc<dyn ListenerVerifier>,
    _sidecar_config: SessionConfig,
}

impl ManagedChild for RealityProcessPair {
    fn pid(&self) -> u32 {
        self.front.pid()
    }

    fn is_alive(&mut self) -> Result<bool, RuntimeError> {
        if !self.front.is_alive()? || !self.sidecar.is_alive()? {
            return Ok(false);
        }
        self.listener
            .verify_sidecar_owned_now(self.sidecar_port, self.sidecar.as_mut())?;
        Ok(true)
    }

    fn stop(&mut self) -> Result<(), RuntimeError> {
        let front_result = self.front.stop();
        let sidecar_result = self.sidecar.stop();
        front_result.and(sidecar_result)
    }

    fn tun_capture_snapshot(&mut self) -> Result<TunCaptureSnapshot, RuntimeError> {
        self.front.tun_capture_snapshot()
    }
}

impl Drop for RealityProcessPair {
    fn drop(&mut self) {
        let _ = self.front.stop();
        let _ = self.sidecar.stop();
    }
}

struct RuntimeServices {
    recover_sessions: fn(&Path) -> Result<(), RuntimeError>,
    engine: Arc<dyn EngineProvider>,
    listener: Arc<dyn ListenerVerifier>,
    prober: Arc<dyn TrafficProber>,
    subscription_fetcher: Arc<dyn SubscriptionFetcher>,
    system_proxy: Arc<dyn SystemProxyControl>,
    tun_privilege: Arc<dyn TunPrivilegeControl>,
}

fn reconcile_all_sessions(root: &Path) -> Result<(), RuntimeError> {
    reconcile_stale_tun_sessions(root).and_then(|_| reconcile_stale_sessions(root))
}

struct PendingImport {
    report: ImportReport,
    source_content: String,
    source_kind: SourceKind,
    source_url: Option<String>,
}

const MAX_PENDING_IMPORT_PREVIEWS: usize = 4;

pub(crate) struct PreviewSlot {
    state: Arc<Mutex<State>>,
    active: bool,
}

impl PreviewSlot {
    fn reserve(state: &Arc<Mutex<State>>) -> Result<Self, PublicError> {
        let mut locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let occupied = locked.pending.len().saturating_add(locked.preview_inflight);
        if occupied >= MAX_PENDING_IMPORT_PREVIEWS {
            return Err(PublicError::fixed(
                PublicErrorCode::ImportRejected,
                PublicErrorStage::Import,
                "Too many import previews are awaiting processing, confirmation, or discard",
            ));
        }
        locked.preview_inflight += 1;
        drop(locked);
        Ok(Self {
            state: Arc::clone(state),
            active: true,
        })
    }

    fn commit(
        mut self,
        preview_id: String,
        report: ImportReport,
        source_content: String,
        source_kind: SourceKind,
        source_url: Option<String>,
    ) -> Result<(), PublicError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.preview_inflight = state.preview_inflight.saturating_sub(1);
        self.active = false;
        if state.pending.contains_key(&preview_id) {
            return Err(PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Import,
                "Could not allocate a unique import preview token",
            ));
        }
        state.pending.insert(
            preview_id,
            PendingImport {
                report,
                source_content,
                source_kind,
                source_url,
            },
        );
        Ok(())
    }
}

impl Drop for PreviewSlot {
    fn drop(&mut self) {
        if self.active {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.preview_inflight = state.preview_inflight.saturating_sub(1);
        }
    }
}

#[derive(Clone)]
struct StoredNode {
    node: Node,
    config_identity: String,
    source_id: String,
    source_name: String,
    source_kind: SourceKind,
}

struct ActiveSession {
    child: Box<dyn ManagedChild>,
    _config: SessionConfig,
    node_id: String,
    config_identity: String,
    session_id: String,
    mode: RuntimeMode,
    default_route: DefaultRoute,
    routing: RoutePolicy,
    tun_stack: Option<TunStack>,
    tun_traffic_rules: Option<Vec<TunTrafficRule>>,
    naive_udp_over_tcp: bool,
    system_proxy_requires_restore: bool,
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
    node_order: Vec<String>,
    sources: Vec<StoredSource>,
    pending: HashMap<String, PendingImport>,
    preview_inflight: usize,
    active: Option<ActiveSession>,
    status: RuntimeStatus,
    recovery_required: bool,
    shutting_down: bool,
}

type EventSink = Arc<dyn Fn(RuntimeStatus) + Send + Sync>;

pub struct ApplicationController {
    state: Arc<Mutex<State>>,
    published_status: Mutex<RuntimeStatus>,
    operation: Mutex<()>,
    services: RuntimeServices,
    session_root: PathBuf,
    subscription_store: Option<SubscriptionStore>,
    diagnostics: Arc<Mutex<DiagnosticBuffer>>,
    event_sink: Mutex<Option<EventSink>>,
    // Drop the lease after the session state and its owned child handles.
    _instance_guard: Option<AppInstanceGuard>,
}

impl ApplicationController {
    pub fn production(
        session_root: PathBuf,
        event_sink: EventSink,
        expected_tun_helper_sha256: Option<&'static str>,
    ) -> Result<Arc<Self>, RuntimeError> {
        let proxy_root = session_root
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| session_root.clone());
        let system_proxy: Arc<dyn SystemProxyControl> =
            Arc::new(SystemProxyManager::new(proxy_root));
        Self::production_with_system_proxy(
            session_root,
            event_sink,
            system_proxy,
            expected_tun_helper_sha256,
        )
    }

    fn production_with_system_proxy(
        session_root: PathBuf,
        event_sink: EventSink,
        system_proxy: Arc<dyn SystemProxyControl>,
        expected_tun_helper_sha256: Option<&'static str>,
    ) -> Result<Arc<Self>, RuntimeError> {
        Self::production_with_recovery(
            session_root,
            event_sink,
            system_proxy,
            expected_tun_helper_sha256,
            reconcile_all_sessions,
        )
    }

    fn production_with_recovery(
        session_root: PathBuf,
        event_sink: EventSink,
        system_proxy: Arc<dyn SystemProxyControl>,
        expected_tun_helper_sha256: Option<&'static str>,
        recover_sessions: fn(&Path) -> Result<(), RuntimeError>,
    ) -> Result<Arc<Self>, RuntimeError> {
        let instance_guard =
            AppInstanceGuard::acquire(session_root.parent().unwrap_or(&session_root))?;
        let engine_recovery_error = recover_sessions(&session_root).err();
        let proxy_recovery_error = system_proxy.reconcile_stale_journal().err();
        let subscription_store = SubscriptionStore::new(
            session_root
                .parent()
                .unwrap_or(&session_root)
                .join("subscription.json"),
        );
        let mut controller = Self::with_services_and_controls(
            session_root,
            event_sink,
            Arc::new(FixedEngineProvider {
                expected_tun_helper_sha256,
            }),
            Arc::new(TcpListenerVerifier),
            Arc::new(HttpsTrafficProber),
            Arc::new(HttpsSubscriptionFetcher),
            system_proxy,
        );
        controller.subscription_store = Some(subscription_store);
        controller.services.recover_sessions = recover_sessions;
        controller._instance_guard = Some(instance_guard);
        controller.restore_persisted_subscription();
        let controller = Arc::new(controller);
        if engine_recovery_error.is_some() || proxy_recovery_error.is_some() {
            let public = if let Some(error) = engine_recovery_error {
                public_runtime_error(error, &Redactor::default())
            } else {
                PublicError::fixed(
                    PublicErrorCode::RecoveryRequired,
                    PublicErrorStage::SystemProxyRestore,
                    "Windows System Proxy recovery requires attention",
                )
            };
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

    #[cfg(test)]
    fn with_services(
        session_root: PathBuf,
        event_sink: EventSink,
        engine: Arc<dyn EngineProvider>,
        listener: Arc<dyn ListenerVerifier>,
        prober: Arc<dyn TrafficProber>,
    ) -> Self {
        let proxy_root = session_root
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| session_root.clone());
        Self::with_services_and_fetcher(
            session_root,
            event_sink,
            engine,
            listener,
            prober,
            Arc::new(HttpsSubscriptionFetcher),
            Arc::new(SystemProxyManager::new(proxy_root)),
        )
    }

    #[cfg(test)]
    fn with_services_and_fetcher(
        session_root: PathBuf,
        event_sink: EventSink,
        engine: Arc<dyn EngineProvider>,
        listener: Arc<dyn ListenerVerifier>,
        prober: Arc<dyn TrafficProber>,
        subscription_fetcher: Arc<dyn SubscriptionFetcher>,
        system_proxy: Arc<dyn SystemProxyControl>,
    ) -> Self {
        let mut controller = Self::with_services_and_controls(
            session_root,
            event_sink,
            engine,
            listener,
            prober,
            subscription_fetcher,
            system_proxy,
        );
        // Unit fixtures own only their temporary files. Production TUN recovery
        // inspects host adapters and must never participate in these tests.
        controller.services.recover_sessions = reconcile_stale_sessions;
        controller
    }

    fn with_services_and_controls(
        session_root: PathBuf,
        event_sink: EventSink,
        engine: Arc<dyn EngineProvider>,
        listener: Arc<dyn ListenerVerifier>,
        prober: Arc<dyn TrafficProber>,
        subscription_fetcher: Arc<dyn SubscriptionFetcher>,
        system_proxy: Arc<dyn SystemProxyControl>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            published_status: Mutex::new(RuntimeStatus::default()),
            operation: Mutex::new(()),
            services: RuntimeServices {
                recover_sessions: reconcile_all_sessions,
                engine,
                listener,
                prober,
                subscription_fetcher,
                system_proxy,
                tun_privilege: Arc::new(PlatformTunPrivilege),
            },
            session_root,
            subscription_store: None,
            diagnostics: Arc::new(Mutex::new(DiagnosticBuffer::default())),
            event_sink: Mutex::new(Some(event_sink)),
            _instance_guard: None,
        }
    }

    fn restore_persisted_subscription(&self) {
        let Some(store) = &self.subscription_store else {
            return;
        };
        let restored = store.load().and_then(|sources| {
            sources
                .map(|sources| {
                    let mut nodes = Vec::new();
                    for source in &sources {
                        let report =
                            import_subscription(source.content.as_bytes()).map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "stored subscription content was rejected",
                                )
                            })?;
                        if nodes.len() + report.nodes.len() > MAX_LIBRARY_NODES {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "stored library contains too many nodes",
                            ));
                        }
                        nodes.extend(prepare_stored_nodes(report.nodes, source).map_err(|_| {
                            std::io::Error::other("could not restore stored subscription")
                        })?);
                    }
                    Ok((sources, nodes))
                })
                .transpose()
        });

        match restored {
            Ok(Some((sources, nodes))) => {
                let count = nodes.len();
                let node_order = nodes.iter().map(|(id, _)| id.clone()).collect();
                let mut state = self.lock_state();
                state.nodes = nodes.into_iter().collect();
                state.node_order = node_order;
                state.sources = sources;
                drop(state);
                self.diagnostics
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("subscription_storage: restored {count} nodes"));
            }
            Ok(None) => {}
            Err(_) => {
                self.diagnostics
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push("subscription_storage: stored subscription was ignored because it is invalid".into());
            }
        }
    }

    pub fn confirmed_nodes(&self) -> Vec<PreviewNode> {
        let state = self.lock_state();
        state
            .node_order
            .iter()
            .enumerate()
            .filter_map(|(index, id)| state.nodes.get(id).map(|stored| (index, stored)))
            .map(|(index, stored)| {
                let protocol = stored.node.protocol_kind();
                PreviewNode {
                    id: stored.node.id().to_owned(),
                    display_name: safe_preview_name(&stored.node, protocol, index),
                    protocol,
                    insecure_tls: stored.node.requires_insecure_approval(),
                    source_id: Some(stored.source_id.clone()),
                    source_name: Some(stored.source_name.clone()),
                    source_kind: Some(stored.source_kind),
                    source_refreshable: Some(
                        state
                            .sources
                            .iter()
                            .any(|source| source.id == stored.source_id && source.url.is_some()),
                    ),
                    source_updated_at_ms: state
                        .sources
                        .iter()
                        .find(|source| source.id == stored.source_id)
                        .and_then(|source| source.updated_at_ms),
                }
            })
            .collect()
    }

    pub fn preview_import_content(&self, content: String) -> Result<ImportPreview, PublicError> {
        let slot = self.reserve_preview_slot()?;
        self.preview_import_content_reserved(content, slot)
    }

    pub(crate) fn preview_import_content_reserved(
        &self,
        content: String,
        slot: PreviewSlot,
    ) -> Result<ImportPreview, PublicError> {
        let report = import_subscription(content.as_bytes()).map_err(|error| {
            PublicError::with_detail(
                PublicErrorCode::ImportRejected,
                PublicErrorStage::Import,
                "Subscription content was rejected",
                Redactor::default().redact(&error.to_string()),
            )
        })?;
        self.commit_import_preview(slot, report, content, SourceKind::Manual, None)
    }

    pub fn preview_import_url(&self, url: String) -> Result<ImportPreview, PublicError> {
        let slot = self.reserve_preview_slot()?;
        self.preview_import_url_reserved(url, slot)
    }

    pub(crate) fn reserve_preview_slot(&self) -> Result<PreviewSlot, PublicError> {
        PreviewSlot::reserve(&self.state)
    }

    pub(crate) fn preview_import_url_reserved(
        &self,
        url: String,
        slot: PreviewSlot,
    ) -> Result<ImportPreview, PublicError> {
        crate::subscription_fetch::validate_url(&url).map_err(public_subscription_fetch_error)?;
        let content = self
            .services
            .subscription_fetcher
            .fetch(&url)
            .map_err(public_subscription_fetch_error)?;
        let report = import_subscription(content.as_bytes()).map_err(|_| {
            PublicError::fixed(
                PublicErrorCode::ImportRejected,
                PublicErrorStage::Import,
                "subscription.content.rejected",
            )
        })?;
        self.commit_import_preview(slot, report, content, SourceKind::Subscription, Some(url))
    }

    fn commit_import_preview(
        &self,
        slot: PreviewSlot,
        report: ImportReport,
        source_content: String,
        source_kind: SourceKind,
        source_url: Option<String>,
    ) -> Result<ImportPreview, PublicError> {
        let preview_id =
            random_hex(16).map_err(|error| public_runtime_error(error, &Redactor::default()))?;
        let preview = preview_from_report(&preview_id, &report);
        slot.commit(preview_id, report, source_content, source_kind, source_url)?;
        Ok(preview)
    }

    pub fn discard_import_preview(&self, preview_id: &str) -> Result<(), PublicError> {
        let discarded = {
            let mut state = self.lock_state();
            matching_pending_key(&state.pending, preview_id)
                .and_then(|key| state.pending.remove(&key))
        };
        drop(discarded);
        Ok(())
    }

    pub fn confirm_import(&self, preview_id: &str) -> Result<ConfirmedImport, PublicError> {
        self.confirm_import_named(preview_id, None)
    }

    pub fn confirm_import_named(
        &self,
        preview_id: &str,
        source_name: Option<&str>,
    ) -> Result<ConfirmedImport, PublicError> {
        let mut state = self.lock_state();
        if state.recovery_required {
            return Err(PublicError::fixed(
                PublicErrorCode::RecoveryRequired,
                PublicErrorStage::Import,
                "Import is blocked until session recovery completes",
            ));
        }
        if state.active.is_some() {
            return Err(PublicError::fixed(
                PublicErrorCode::ActiveSessionConflict,
                PublicErrorStage::Import,
                "Stop the active local proxy before adding imported nodes",
            ));
        }
        if state.pending.is_empty() {
            return Err(PublicError::fixed(
                PublicErrorCode::PreviewMissing,
                PublicErrorStage::Import,
                "No import preview is pending",
            ));
        }
        let key = matching_pending_key(&state.pending, preview_id).ok_or_else(|| {
            PublicError::fixed(
                PublicErrorCode::PreviewTokenInvalid,
                PublicErrorStage::Import,
                "Import preview token is invalid",
            )
        })?;
        let pending = state.pending.get(&key).ok_or_else(|| {
            PublicError::fixed(
                PublicErrorCode::PreviewMissing,
                PublicErrorStage::Import,
                "No import preview is pending",
            )
        })?;
        if pending.report.nodes.is_empty() {
            return Err(source_import_error("subscription.content.rejected"));
        }
        let ordinal = state
            .sources
            .iter()
            .filter(|source| source.kind == pending.source_kind)
            .count()
            + 1;
        let source_name = match source_name.map(str::trim).filter(|name| !name.is_empty()) {
            Some(name)
                if valid_source_name(name)
                    && pending.report.nodes.iter().all(|node| {
                        Redactor::from_nodes(std::slice::from_ref(node)).redact(name) == name
                    }) =>
            {
                name.to_owned()
            }
            Some(_) => {
                return Err(PublicError::fixed(
                    PublicErrorCode::ImportRejected,
                    PublicErrorStage::Import,
                    "import.source_name.invalid",
                ))
            }
            None => match pending.source_kind {
                SourceKind::Subscription => format!("Подписка {ordinal}"),
                SourceKind::Manual => format!("Добавленные вручную {ordinal}"),
            },
        };
        let source = StoredSource {
            id: random_hex(16)
                .map_err(|error| public_runtime_error(error, &Redactor::default()))?,
            name: source_name,
            kind: pending.source_kind,
            content: pending.source_content.clone(),
            url: pending.source_url.clone(),
            updated_at_ms: Some(subscription_timestamp_ms()),
            revision: 0,
            node_ids: Vec::new(),
        };
        let mut sources = state.sources.clone();
        sources.push(source.clone());
        if validate_sources(&sources).is_err()
            || state.nodes.len() + pending.report.nodes.len() > MAX_LIBRARY_NODES
        {
            return Err(PublicError::fixed(
                PublicErrorCode::ImportRejected,
                PublicErrorStage::Import,
                "import.library.limit",
            ));
        }
        let prepared = prepare_stored_nodes(pending.report.nodes.clone(), &source)?;
        let node_ids = prepared
            .iter()
            .map(|(node_id, _)| node_id.clone())
            .collect::<Vec<_>>();
        if let Some(store) = &self.subscription_store {
            store.save(&sources).map_err(|_| {
                PublicError::fixed(
                    PublicErrorCode::RuntimeFailure,
                    PublicErrorStage::SessionStorage,
                    "Could not save the imported subscription",
                )
            })?;
        }
        state.pending.remove(&key);
        state.nodes.extend(prepared);
        state.node_order.extend(node_ids.clone());
        state.sources = sources;
        Ok(ConfirmedImport {
            imported: node_ids.len(),
            node_ids,
        })
    }

    pub fn refresh_source(
        &self,
        source_id: &str,
        url: Option<&str>,
    ) -> Result<ConfirmedImport, PublicError> {
        let slot = self.reserve_preview_slot()?;
        self.refresh_source_reserved(source_id, url, slot)
    }

    pub(crate) fn refresh_source_reserved(
        &self,
        source_id: &str,
        url: Option<&str>,
        _slot: PreviewSlot,
    ) -> Result<ConfirmedImport, PublicError> {
        validate_source_id(source_id)?;
        // Share the bounded fetch budget with previews. No state lock is held
        // during network I/O; a concurrent removal or refresh wins over this
        // stale snapshot and cannot be undone by the completed request.
        let original = {
            let state = self.lock_state();
            ensure_source_mutation_allowed(&state, source_id)?;
            state
                .sources
                .iter()
                .find(|source| source.id == source_id)
                .cloned()
                .ok_or_else(|| source_import_error("subscription.source_missing"))?
        };
        if original.kind != SourceKind::Subscription {
            return Err(source_import_error("subscription.refresh_manual"));
        }
        let url = url
            .or(original.url.as_deref())
            .ok_or_else(|| source_import_error("subscription.url_required"))?;
        crate::subscription_fetch::validate_url(url).map_err(public_subscription_fetch_error)?;
        let content = self
            .services
            .subscription_fetcher
            .fetch(url)
            .map_err(public_subscription_fetch_error)?;
        let report = import_subscription(content.as_bytes())
            .map_err(|_| source_import_error("subscription.content.rejected"))?;
        if report.nodes.is_empty() || !report.rejected.is_empty() {
            return Err(source_import_error("subscription.refresh_incomplete"));
        }
        let mut state = self.lock_state();
        ensure_source_mutation_allowed(&state, source_id)?;
        let index = state
            .sources
            .iter()
            .position(|source| source.id == source_id)
            .ok_or_else(|| source_import_error("subscription.source_changed"))?;
        if state.sources[index] != original {
            return Err(source_import_error("subscription.source_changed"));
        }
        let mut existing_ids: HashMap<String, VecDeque<String>> = HashMap::new();
        let mut old_count = 0;
        for id in &state.node_order {
            if let Some(stored) = state
                .nodes
                .get(id)
                .filter(|stored| stored.source_id == source_id)
            {
                old_count += 1;
                existing_ids
                    .entry(stored.node.update_key().to_owned())
                    .or_default()
                    .push_back(id.clone());
            }
        }
        let mut replacement = original.clone();
        replacement.node_ids = report
            .nodes
            .iter()
            .map(|node| {
                existing_ids
                    .get_mut(node.update_key())
                    .and_then(VecDeque::pop_front)
                    .map(Ok)
                    .unwrap_or_else(|| {
                        random_hex(16)
                            .map(|id| format!("{source_id}-{id}"))
                            .map_err(|error| public_runtime_error(error, &Redactor::default()))
                    })
            })
            .collect::<Result<_, _>>()?;
        replacement.content = content;
        replacement.url = Some(url.to_owned());
        replacement.updated_at_ms = Some(subscription_timestamp_ms());
        replacement.revision = original
            .revision
            .checked_add(1)
            .ok_or_else(|| source_import_error("subscription.source_changed"))?;
        let mut sources = state.sources.clone();
        sources[index] = replacement.clone();
        if validate_sources(&sources).is_err()
            || state.nodes.len() - old_count + report.nodes.len() > MAX_LIBRARY_NODES
        {
            return Err(source_import_error("import.library.limit"));
        }
        let prepared = prepare_stored_nodes(report.nodes, &replacement)?;
        let node_ids: Vec<_> = prepared.iter().map(|(id, _)| id.clone()).collect();
        if let Some(store) = &self.subscription_store {
            store.save(&sources).map_err(|_| source_storage_error())?;
        }
        let insertion = state
            .node_order
            .iter()
            .position(|id| {
                state
                    .nodes
                    .get(id)
                    .is_some_and(|stored| stored.source_id == source_id)
            })
            .unwrap_or(state.node_order.len());
        state
            .nodes
            .retain(|_, stored| stored.source_id != source_id);
        let mut order: Vec<_> = state
            .node_order
            .iter()
            .filter(|id| state.nodes.contains_key(*id))
            .cloned()
            .collect();
        order.splice(insertion..insertion, node_ids.clone());
        state.node_order = order;
        state.nodes.extend(prepared);
        state.sources = sources;
        Ok(ConfirmedImport {
            imported: node_ids.len(),
            node_ids,
        })
    }

    pub fn remove_source(&self, source_id: &str) -> Result<(), PublicError> {
        validate_source_id(source_id)?;
        let mut state = self.lock_state();
        ensure_source_mutation_allowed(&state, source_id)?;
        if !state.sources.iter().any(|source| source.id == source_id) {
            return Ok(());
        }
        let sources: Vec<_> = state
            .sources
            .iter()
            .filter(|source| source.id != source_id)
            .cloned()
            .collect();
        if let Some(store) = &self.subscription_store {
            store.save(&sources).map_err(|_| source_storage_error())?;
        }
        state
            .nodes
            .retain(|_, stored| stored.source_id != source_id);
        let order = state
            .node_order
            .iter()
            .filter(|id| state.nodes.contains_key(*id))
            .cloned()
            .collect();
        state.node_order = order;
        state.sources = sources;
        Ok(())
    }

    pub fn reset_local_state(&self) -> Result<(), PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.lock_state();
        if state.active.is_some() {
            return Err(PublicError::fixed(
                PublicErrorCode::ActiveSessionConflict,
                PublicErrorStage::SessionStorage,
                "Stop the active connection before resetting RouteDeck",
            ));
        }
        if let Some(store) = &self.subscription_store {
            store.clear().map_err(|_| {
                PublicError::fixed(
                    PublicErrorCode::RuntimeFailure,
                    PublicErrorStage::SessionStorage,
                    "Could not reset local RouteDeck data",
                )
            })?;
        }
        state.nodes.clear();
        state.node_order.clear();
        state.sources.clear();
        state.pending.clear();
        Ok(())
    }

    pub fn start_local_proxy(
        &self,
        node_id: &str,
        _default_route: DefaultRoute,
    ) -> Result<RuntimeStatus, PublicError> {
        let effective_route = DefaultRoute::Vpn;
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
                active.mode == RuntimeMode::LocalOnly
                    && active.node_id == node_id
                    && active.default_route == effective_route
                    && active.config_identity == stored.config_identity
            });
            if !exact {
                return Err(PublicError::fixed(
                    PublicErrorCode::ActiveSessionConflict,
                    PublicErrorStage::Start,
                    "Stop the active local proxy before changing node or node revision",
                ));
            }
            let route = {
                let active = state.active.as_mut().expect("active session disappeared");
                if !active.child.is_alive().unwrap_or(false) {
                    None
                } else {
                    Some((active.health_route.clone(), active.ports.http))
                }
            };
            drop(state);
            let validation = route.map(|(route, http_port)| {
                self.services
                    .prober
                    .prove(&route)
                    .and_then(|selected_proof| {
                        self.services
                            .prober
                            .prove_ordinary(http_port)
                            .map(|_| selected_proof)
                    })
            });
            state = self.lock_state();
            if let Some(Ok(proof)) = validation {
                if !state.active.as_ref().is_some_and(|active| {
                    active.mode == RuntimeMode::LocalOnly
                        && active.node_id == node_id
                        && active.default_route == effective_route
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
        let policy = RoutePolicy {
            default: DefaultRoute::Vpn,
            apps: Vec::new(),
            lan: LanPolicy::FollowDefault,
            ipv6: Ipv6Policy::Enabled,
            dns: DnsPolicy::CurrentNetwork,
        };

        self.begin_diagnostic_attempt();
        let result = self.start_locked(
            &mut state,
            &node,
            config_identity,
            policy,
            RuntimeMode::LocalOnly,
            None,
            None,
            false,
            redactor.clone(),
        );
        if let Err(error) = result {
            Self::mark_failed_proof(&mut state, error.stage());
            self.record_runtime_failure(&error, &redactor);
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

    pub fn start_system_proxy(
        &self,
        node_id: &str,
        routing: SystemProxyRouting,
    ) -> Result<RuntimeStatus, PublicError> {
        let requested_naive_udp_over_tcp = routing.naive_udp_over_tcp;
        let policy = routing.into_policy();
        policy.validate().map_err(|_| {
            PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Start,
                "Application routing rules are invalid",
            )
        })?;
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.lock_state();
        let naive_udp_over_tcp = requested_naive_udp_over_tcp
            && state
                .nodes
                .get(node_id)
                .is_some_and(|stored| matches!(stored.node.protocol(), NodeProtocol::Naive(_)));
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
                "Review preserved recovery data before reconnecting",
            ));
        }
        if state.active.is_some() {
            let exact = state.active.as_ref().is_some_and(|active| {
                active.mode == RuntimeMode::SystemProxy
                    && active.node_id == node_id
                    && active.routing == policy
                    && active.naive_udp_over_tcp == naive_udp_over_tcp
                    && state
                        .nodes
                        .get(node_id)
                        .is_some_and(|stored| active.config_identity == stored.config_identity)
            });
            if !exact {
                return Err(PublicError::fixed(
                    PublicErrorCode::ActiveSessionConflict,
                    PublicErrorStage::Start,
                    "Stop the active connection before changing System Proxy routing",
                ));
            }
            let route = {
                let active = state.active.as_mut().expect("active session disappeared");
                active
                    .child
                    .is_alive()
                    .unwrap_or(false)
                    .then(|| (active.health_route.clone(), active.ports.http))
            };
            drop(state);
            let proof = route.and_then(|(route, http_port)| {
                self.services
                    .prober
                    .prove(&route)
                    .and_then(|selected_proof| {
                        self.services
                            .prober
                            .prove_ordinary(http_port)
                            .map(|_| selected_proof)
                    })
                    .ok()
            });
            state = self.lock_state();
            let still_exact = state.active.as_ref().is_some_and(|active| {
                active.mode == RuntimeMode::SystemProxy
                    && active.node_id == node_id
                    && active.routing == policy
                    && active.naive_udp_over_tcp == naive_udp_over_tcp
            });
            if !still_exact {
                return Err(PublicError::fixed(
                    PublicErrorCode::SessionChanged,
                    PublicErrorStage::Start,
                    "Active session changed while traffic was being verified",
                ));
            }
            let listener_owned = state.active.as_mut().is_some_and(|active| {
                active.child.is_alive().unwrap_or(false)
                    && self
                        .services
                        .listener
                        .verify_owned_now(active.ports, active.child.as_mut())
                        .is_ok()
            });
            let proxy_owned = self.services.system_proxy.is_owned().unwrap_or(false);
            if let Some(proof) = proof.filter(|_| listener_owned && proxy_owned) {
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
                Self::set_proof(
                    &mut state,
                    ProofKind::SystemProxyOwnership,
                    ProofState::Passed,
                    None,
                );
                self.update_status(
                    &mut state,
                    RuntimePhase::SystemProxyReady,
                    Some(node_id.to_owned()),
                    None,
                );
                return Ok(state.status.clone());
            }
            let public = PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                if proxy_owned {
                    PublicErrorStage::ProveTraffic
                } else {
                    PublicErrorStage::SystemProxyOwnership
                },
                "The active System Proxy connection could not be verified",
            );
            self.update_status(
                &mut state,
                if proxy_owned {
                    RuntimePhase::Degraded
                } else {
                    RuntimePhase::BlockedByConflict
                },
                Some(node_id.to_owned()),
                Some(public.clone()),
            );
            return Err(public);
        }
        let stored = state.nodes.get(node_id).cloned().ok_or_else(|| {
            PublicError::fixed(
                PublicErrorCode::NodeNotFound,
                PublicErrorStage::Start,
                "Selected node does not exist in the confirmed import",
            )
        })?;
        let node = stored.node;
        let redactor = Redactor::from_nodes(std::slice::from_ref(&node)).with_secret(node.server());
        self.begin_diagnostic_attempt();
        let result = self.start_locked(
            &mut state,
            &node,
            stored.config_identity,
            policy,
            RuntimeMode::SystemProxy,
            None,
            None,
            naive_udp_over_tcp,
            redactor.clone(),
        );
        let Err(error) = result else {
            return Ok(state.status.clone());
        };

        let proxy_may_be_published = state
            .active
            .as_ref()
            .is_some_and(|active| active.system_proxy_requires_restore);
        Self::mark_failed_proof(&mut state, error.stage());
        self.record_runtime_failure(&error, &redactor);
        self.update_status(
            &mut state,
            RuntimePhase::RollingBack,
            Some(node_id.to_owned()),
            None,
        );
        if proxy_may_be_published {
            match self.services.system_proxy.restore_if_owned() {
                Ok(SystemProxyRestoreOutcome::Restored)
                | Ok(SystemProxyRestoreOutcome::ForeignPreserved) => {
                    if let Some(active) = state.active.as_mut() {
                        active.system_proxy_requires_restore = false;
                    }
                }
                Ok(SystemProxyRestoreOutcome::NoJournal) | Err(_) => {
                    state.recovery_required = true;
                    let public = PublicError::fixed(
                        PublicErrorCode::RecoveryRequired,
                        PublicErrorStage::SystemProxyRestore,
                        "Windows System Proxy could not be restored after startup failed",
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
        }
        if let Some(stop_error) = state
            .active
            .as_mut()
            .and_then(|active| active.child.stop().err())
        {
            let public = public_runtime_error(stop_error, &redactor);
            state.recovery_required = true;
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
        if reconcile_stale_sessions(&self.session_root).is_err() {
            state.recovery_required = true;
            self.update_status(
                &mut state,
                RuntimePhase::RecoveryRequired,
                Some(node_id.to_owned()),
                Some(public.clone()),
            );
        } else {
            self.update_status(
                &mut state,
                RuntimePhase::DisconnectedWithError,
                Some(node_id.to_owned()),
                Some(public.clone()),
            );
        }
        Err(public)
    }

    pub fn start_tun(
        &self,
        node_id: &str,
        routing: TunRouting,
    ) -> Result<RuntimeStatus, PublicError> {
        let stack = routing.stack;
        let traffic_rules = routing.traffic_rules.clone();
        let requested_naive_udp_over_tcp = routing.naive_udp_over_tcp;
        validate_tun_traffic_rules(&traffic_rules).map_err(|_| {
            PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Start,
                "TUN traffic rules are invalid",
            )
        })?;
        let policy = routing.into_policy();
        policy.validate().map_err(|_| {
            PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Start,
                "Application routing rules are invalid",
            )
        })?;
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let elevated = self.services.tun_privilege.is_elevated().map_err(|error| {
            PublicError::with_detail(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Start,
                "TUN availability could not be checked",
                Redactor::default().redact(error.message()),
            )
        })?;
        if !elevated {
            return Err(PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Start,
                "TUN requires RouteDeck to be run as administrator",
            ));
        }
        let mut state = self.lock_state();
        let naive_udp_over_tcp = requested_naive_udp_over_tcp
            && state
                .nodes
                .get(node_id)
                .is_some_and(|stored| matches!(stored.node.protocol(), NodeProtocol::Naive(_)));
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
                "Review preserved recovery data before reconnecting",
            ));
        }
        if state.active.is_some() {
            let exact = state.active.as_ref().is_some_and(|active| {
                active.mode == RuntimeMode::Tun
                    && active.node_id == node_id
                    && active.routing == policy
                    && active.tun_stack == Some(stack)
                    && active.tun_traffic_rules.as_deref() == Some(traffic_rules.as_slice())
                    && active.naive_udp_over_tcp == naive_udp_over_tcp
                    && state
                        .nodes
                        .get(node_id)
                        .is_some_and(|stored| active.config_identity == stored.config_identity)
            });
            if !exact {
                return Err(PublicError::fixed(
                    PublicErrorCode::ActiveSessionConflict,
                    PublicErrorStage::Start,
                    "Stop the active connection before changing TUN routing",
                ));
            }
            let verification = {
                let active = state.active.as_mut().expect("active session disappeared");
                if active.child.is_alive().unwrap_or(false) {
                    active
                        .child
                        .tun_capture_snapshot()
                        .ok()
                        .map(|before| (active.health_route.clone(), before))
                } else {
                    None
                }
            };
            drop(state);
            let proof = verification.and_then(|(route, before)| {
                self.services.prober.prove(&route).ok().and_then(|proof| {
                    self.services
                        .prober
                        .prove_tun_capture()
                        .ok()
                        .map(|_| (proof, before))
                })
            });
            state = self.lock_state();
            let still_exact = state.active.as_ref().is_some_and(|active| {
                active.mode == RuntimeMode::Tun
                    && active.node_id == node_id
                    && active.routing == policy
                    && active.tun_stack == Some(stack)
                    && active.tun_traffic_rules.as_deref() == Some(traffic_rules.as_slice())
                    && active.naive_udp_over_tcp == naive_udp_over_tcp
            });
            if !still_exact {
                return Err(PublicError::fixed(
                    PublicErrorCode::SessionChanged,
                    PublicErrorStage::Start,
                    "Active session changed while TUN traffic was being verified",
                ));
            }
            let ownership_and_capture = state.active.as_mut().is_some_and(|active| {
                active.child.is_alive().unwrap_or(false)
                    && self
                        .services
                        .listener
                        .verify_owned_now(active.ports, active.child.as_mut())
                        .is_ok()
                    && proof.as_ref().is_some_and(|(_, before)| {
                        active
                            .child
                            .tun_capture_snapshot()
                            .is_ok_and(|after| after.proves_traffic_since(*before))
                    })
            });
            if let Some((proof, _)) = proof.filter(|_| ownership_and_capture) {
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
                    RuntimePhase::TunReady,
                    Some(node_id.to_owned()),
                    None,
                );
                return Ok(state.status.clone());
            }
            let public = PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::ProveTraffic,
                "The active TUN connection could not be verified",
            );
            self.update_status(
                &mut state,
                RuntimePhase::RollingBack,
                Some(node_id.into()),
                None,
            );
            if let Some(error) = state
                .active
                .as_mut()
                .and_then(|active| active.child.stop().err())
            {
                let redactor = state
                    .active
                    .as_ref()
                    .map(|active| active.redactor.clone())
                    .unwrap_or_default();
                let stop = public_runtime_error(error, &redactor);
                state.recovery_required = true;
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id.to_owned()),
                    Some(stop.clone()),
                );
                return Err(stop);
            }
            let failed = state.active.take();
            Self::clear_active_metadata(&mut state);
            drop(failed);
            if reconcile_stale_sessions(&self.session_root).is_err() {
                state.recovery_required = true;
                self.update_status(
                    &mut state,
                    RuntimePhase::RecoveryRequired,
                    Some(node_id.to_owned()),
                    Some(public.clone()),
                );
            } else {
                self.update_status(
                    &mut state,
                    RuntimePhase::DisconnectedWithError,
                    Some(node_id.to_owned()),
                    Some(public.clone()),
                );
            }
            return Err(public);
        }
        let stored = state.nodes.get(node_id).cloned().ok_or_else(|| {
            PublicError::fixed(
                PublicErrorCode::NodeNotFound,
                PublicErrorStage::Start,
                "Selected node does not exist in the confirmed import",
            )
        })?;
        let node = stored.node;
        let redactor = Redactor::from_nodes(std::slice::from_ref(&node)).with_secret(node.server());
        self.begin_diagnostic_attempt();
        let result = self.start_locked(
            &mut state,
            &node,
            stored.config_identity,
            policy,
            RuntimeMode::Tun,
            Some(stack),
            Some(traffic_rules),
            naive_udp_over_tcp,
            redactor.clone(),
        );
        let Err(error) = result else {
            return Ok(state.status.clone());
        };

        Self::mark_failed_proof(&mut state, error.stage());
        self.record_runtime_failure(&error, &redactor);
        self.update_status(
            &mut state,
            RuntimePhase::RollingBack,
            Some(node_id.to_owned()),
            None,
        );
        if let Some(stop_error) = state
            .active
            .as_mut()
            .and_then(|active| active.child.stop().err())
        {
            self.record_runtime_failure(&stop_error, &redactor);
            let public = public_runtime_error(stop_error, &redactor);
            state.recovery_required = true;
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
        if reconcile_stale_sessions(&self.session_root).is_err() {
            state.recovery_required = true;
            self.update_status(
                &mut state,
                RuntimePhase::RecoveryRequired,
                Some(node_id.to_owned()),
                Some(public.clone()),
            );
        } else {
            self.update_status(
                &mut state,
                RuntimePhase::DisconnectedWithError,
                Some(node_id.to_owned()),
                Some(public.clone()),
            );
        }
        Err(public)
    }

    fn begin_diagnostic_attempt(&self) {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    fn record_runtime_failure(&self, error: &RuntimeError, redactor: &Redactor) {
        let line = format!("{}: {}", error.stage(), error.message());
        let safe = redactor.redact(&line);
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(safe);
    }

    fn start_locked(
        &self,
        state: &mut State,
        node: &Node,
        config_identity: String,
        policy: RoutePolicy,
        mode: RuntimeMode,
        tun_stack: Option<TunStack>,
        tun_traffic_rules: Option<Vec<TunTrafficRule>>,
        naive_udp_over_tcp: bool,
        redactor: Redactor,
    ) -> Result<(), RuntimeError> {
        let session_id = random_hex(16)?;
        state.status.scope = match mode {
            RuntimeMode::LocalOnly => RuntimeScope::LocalOnly,
            RuntimeMode::SystemProxy => RuntimeScope::SystemProxy,
            RuntimeMode::Tun => RuntimeScope::Tun,
        };
        state.status.mode = mode;
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
        let reality = matches!(
            node.protocol(),
            NodeProtocol::Vless(vless) if vless.tls.reality.is_some()
        );
        let capture_mode = match mode {
            RuntimeMode::LocalOnly => CaptureMode::LocalProxy,
            RuntimeMode::SystemProxy => CaptureMode::SystemProxy,
            RuntimeMode::Tun => CaptureMode::Tun(TunSettings {
                stack: tun_stack.unwrap_or_default(),
                traffic_rules: tun_traffic_rules
                    .clone()
                    .unwrap_or_else(default_tun_traffic_rules),
                ..TunSettings::default()
            }),
        };
        let tun_upstream_identity = if mode == RuntimeMode::Tun {
            Some(self.services.engine.select_tun_upstream()?)
        } else {
            None
        };
        if let Some(upstream) = &tun_upstream_identity {
            self.diagnostics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(
                    if upstream.ipv4_dns_server.is_some() {
                        "tun_dns=physical_ipv4_tcp"
                    } else {
                        "tun_dns=local_fallback_no_ipv4"
                    }
                    .into(),
                );
        }
        let tun_upstream = tun_upstream_identity.as_ref().map(|upstream| TunUpstream {
            interface_alias: upstream.interface_alias.clone(),
            ipv4_dns_server: upstream.ipv4_dns_server,
        });
        let request = || ConfigRequest {
            node,
            policy: &policy,
            mode: capture_mode.clone(),
            ports,
            health_password: password.clone(),
            vpn_dns: None,
            insecure_approval: None,
            tun_upstream: tun_upstream.clone(),
            naive_udp_over_tcp,
        };
        let mut bridge_reservation = None;
        let generated = if reality {
            let reservation = LoopbackPortReservation::reserve()?;
            let generated = generate_socks_bridge_config(
                request(),
                SocksBridge {
                    server_port: reservation.port(),
                },
            )
            .map_err(|error| RuntimeError::new("generate_config", error.to_string()))?;
            bridge_reservation = Some(reservation);
            generated
        } else {
            generate_config(request())
                .map_err(|error| RuntimeError::new("generate_config", error.to_string()))?
        };
        let session = SessionConfig::create(&self.session_root, generated.as_str())?;
        let mut process_redactor = redactor
            .clone()
            .with_secret(&password)
            .with_secret(&session.path().to_string_lossy());
        let sidecar_session = if let Some(reservation) = bridge_reservation.as_ref() {
            let generated = generate_xray_bridge_config(XrayBridgeRequest {
                node,
                listen_port: reservation.port(),
                tun_upstream: tun_upstream.clone(),
            })
            .map_err(|error| RuntimeError::new("generate_config", error.to_string()))?;
            let sidecar = SessionConfig::create(&self.session_root, generated.as_str())?;
            process_redactor = process_redactor.with_secret(&sidecar.path().to_string_lossy());
            Some(sidecar)
        } else {
            None
        };
        Self::set_proof(state, ProofKind::EngineConfig, ProofState::Pending, None);
        self.update_status(
            state,
            RuntimePhase::ValidatingConfig,
            Some(node.id().to_owned()),
            None,
        );
        let launcher = if mode == RuntimeMode::Tun {
            self.services.engine.create_tun(
                tun_upstream_identity
                    .clone()
                    .expect("TUN mode must have a selected physical upstream"),
            )?
        } else {
            self.services.engine.create(EngineKind::SingBox)?
        };
        let sing_box_version =
            launcher.check(&session, process_redactor.clone(), self.diagnostics.clone())?;
        let mut sidecar_launcher = if sidecar_session.is_some() {
            Some(self.services.engine.create(EngineKind::Xray)?)
        } else {
            None
        };
        let sidecar_version = if let (Some(launcher), Some(sidecar)) =
            (sidecar_launcher.as_ref(), sidecar_session.as_ref())
        {
            Some(launcher.check(sidecar, process_redactor.clone(), self.diagnostics.clone())?)
        } else {
            None
        };
        let engine_version = sidecar_version
            .map(|version| format!("sing-box {sing_box_version} + Xray {version}"))
            .unwrap_or(sing_box_version);
        let generation = random_hex(16)?;
        Self::set_proof(state, ProofKind::EngineConfig, ProofState::Passed, None);
        self.update_status(
            state,
            RuntimePhase::StartingCore,
            Some(node.id().to_owned()),
            None,
        );
        let sidecar = if let (Some(reservation), Some(sidecar), Some(launcher)) =
            (bridge_reservation, sidecar_session, sidecar_launcher.take())
        {
            let sidecar_port = reservation.port();
            reservation.release();
            let mut child = ProvisionalChild::new(launcher.start(
                &sidecar,
                process_redactor.clone(),
                self.diagnostics.clone(),
            )?);
            self.services
                .listener
                .wait_until_sidecar_ready(sidecar_port, child.as_mut())?;
            Some((child, sidecar, sidecar_port))
        } else {
            None
        };
        reservations.release();
        let front = ProvisionalChild::new(launcher.start(
            &session,
            process_redactor,
            self.diagnostics.clone(),
        )?);
        let child: Box<dyn ManagedChild> =
            if let Some((sidecar, sidecar_config, sidecar_port)) = sidecar {
                Box::new(RealityProcessPair {
                    front: front.take(),
                    sidecar: sidecar.take(),
                    sidecar_port,
                    listener: Arc::clone(&self.services.listener),
                    _sidecar_config: sidecar_config,
                })
            } else {
                front.take()
            };
        let health_route = HealthRoute::new(ports.health, password);
        state.active = Some(ActiveSession {
            child,
            _config: session,
            node_id: node.id().to_owned(),
            config_identity,
            session_id,
            mode,
            default_route: policy.default,
            routing: policy,
            tun_stack,
            tun_traffic_rules,
            naive_udp_over_tcp,
            system_proxy_requires_restore: false,
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
        // The private health route establishes that the selected outbound works. Local Proxy
        // and System Proxy additionally prove the ordinary HTTP ingress. TUN instead makes an
        // unproxied HTTPS request and requires the exact owned adapter counters to advance; a
        // loopback health-proxy success alone is never sufficient to publish TUN readiness.
        let selected_proof = self.services.prober.prove(&health_route)?;
        if matches!(mode, RuntimeMode::LocalOnly | RuntimeMode::SystemProxy) {
            self.services.prober.prove_ordinary(ports.http)?;
        } else if mode == RuntimeMode::Tun {
            // Selected outbound success and system capture are separate facts:
            // a later TUN failure must not leave the completed HTTPS proof pending.
            Self::set_proof(
                state,
                ProofKind::SelectedOutboundHttps,
                ProofState::Passed,
                Some(selected_proof.latency_ms),
            );
            Self::set_proof(
                state,
                ProofKind::LocalScopeOwnership,
                ProofState::Pending,
                None,
            );
            let active = state
                .active
                .as_mut()
                .expect("provisional TUN session disappeared");
            if let Err(error) =
                prove_tun_capture(self.services.prober.as_ref(), active.child.as_mut())
            {
                Self::set_proof(
                    state,
                    ProofKind::LocalScopeOwnership,
                    ProofState::Failed,
                    None,
                );
                return Err(error);
            }
        }
        Self::set_proof(
            state,
            ProofKind::SelectedOutboundHttps,
            ProofState::Passed,
            Some(selected_proof.latency_ms),
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
        state.status.route_check_ms = Some(selected_proof.latency_ms);
        state.status.engine_version = Some(engine_version);
        self.update_status(
            state,
            RuntimePhase::OutboundVerified,
            Some(node.id().to_owned()),
            None,
        );
        if mode == RuntimeMode::SystemProxy {
            Self::set_proof(
                state,
                ProofKind::SystemProxyOwnership,
                ProofState::Pending,
                None,
            );
            self.update_status(
                state,
                RuntimePhase::ApplyingSystemProxy,
                Some(node.id().to_owned()),
                None,
            );
            state
                .active
                .as_mut()
                .expect("active session disappeared")
                .system_proxy_requires_restore = true;
            if let Err(error) = self.services.system_proxy.publish_loopback(ports.http) {
                state
                    .active
                    .as_mut()
                    .expect("active session disappeared")
                    .system_proxy_requires_restore = error.may_have_changed();
                return Err(RuntimeError::new("system_proxy_publish", error.to_string()));
            }
            if !self
                .services
                .system_proxy
                .is_owned()
                .map_err(|error| RuntimeError::new("system_proxy_ownership", error.to_string()))?
            {
                return Err(RuntimeError::new(
                    "system_proxy_ownership",
                    "Windows System Proxy changed before readiness could be confirmed",
                ));
            }
            Self::set_proof(
                state,
                ProofKind::SystemProxyOwnership,
                ProofState::Passed,
                None,
            );
            // ApplyingSystemProxy intentionally clears the summary while WinINet
            // is being changed. Restore the already verified measurement before
            // publishing the final ready status so the IPC proof stays coherent.
            state.status.route_check_ms = Some(selected_proof.latency_ms);
            self.update_status(
                state,
                RuntimePhase::SystemProxyReady,
                Some(node.id().to_owned()),
                None,
            );
        } else if mode == RuntimeMode::Tun {
            self.update_status(
                state,
                RuntimePhase::TunReady,
                Some(node.id().to_owned()),
                None,
            );
        } else {
            self.update_status(
                state,
                RuntimePhase::LocalProxyReady,
                Some(node.id().to_owned()),
                None,
            );
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<RuntimeStatus, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.lock_state();
        self.stop_active_locked(&mut state, None)
    }

    // Every teardown path retains the session until restoration and explicit
    // child cleanup succeed. Dropping a child is never evidence of cleanup.
    fn stop_active_locked(
        &self,
        state: &mut State,
        terminal_failure: Option<PublicError>,
    ) -> Result<RuntimeStatus, PublicError> {
        if state.active.is_none() {
            if state.recovery_required {
                return Ok(state.status.clone());
            }
            self.reset_disconnected(state);
            return Ok(state.status.clone());
        }
        let node_id = state.status.node_id.clone();
        let system_proxy_requires_restore = state
            .active
            .as_ref()
            .is_some_and(|active| active.system_proxy_requires_restore);
        let mut proxy_conflict = None;
        if system_proxy_requires_restore {
            self.update_status(
                state,
                RuntimePhase::RestoringSystemProxy,
                node_id.clone(),
                None,
            );
            match self.services.system_proxy.restore_if_owned() {
                Ok(SystemProxyRestoreOutcome::Restored) => {
                    state
                        .active
                        .as_mut()
                        .expect("active session disappeared")
                        .system_proxy_requires_restore = false;
                    Self::set_proof(
                        state,
                        ProofKind::SystemProxyOwnership,
                        ProofState::Passed,
                        None,
                    );
                }
                Ok(SystemProxyRestoreOutcome::ForeignPreserved) => {
                    state
                        .active
                        .as_mut()
                        .expect("active session disappeared")
                        .system_proxy_requires_restore = false;
                    Self::set_proof(
                        state,
                        ProofKind::SystemProxyOwnership,
                        ProofState::Failed,
                        None,
                    );
                    proxy_conflict = Some(PublicError::fixed(
                        PublicErrorCode::RuntimeFailure,
                        PublicErrorStage::SystemProxyOwnership,
                        "Windows System Proxy was changed by another application and was preserved",
                    ));
                }
                Ok(SystemProxyRestoreOutcome::NoJournal) | Err(_) => {
                    state.recovery_required = true;
                    let public = PublicError::fixed(
                        PublicErrorCode::RecoveryRequired,
                        PublicErrorStage::SystemProxyRestore,
                        "Windows System Proxy ownership could not be restored safely",
                    );
                    self.update_status(
                        state,
                        RuntimePhase::RecoveryRequired,
                        node_id,
                        Some(public.clone()),
                    );
                    return Err(public);
                }
            }
        }
        self.update_status(state, RuntimePhase::StoppingCore, node_id.clone(), None);
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
                state,
                RuntimePhase::RecoveryRequired,
                node_id,
                Some(public.clone()),
            );
            return Err(public);
        }
        let active = state.active.take();
        Self::clear_active_metadata(state);
        drop(active);
        state.recovery_required = reconcile_stale_sessions(&self.session_root).is_err();
        if state.recovery_required {
            let public = PublicError::fixed(
                PublicErrorCode::RecoveryRequired,
                PublicErrorStage::SessionRecovery,
                "Session data remains and requires review",
            );
            self.update_status(
                state,
                RuntimePhase::RecoveryRequired,
                node_id,
                Some(public.clone()),
            );
            return Err(public);
        }
        if let Some(public) = proxy_conflict {
            state.status.session_id = None;
            self.update_status(
                state,
                RuntimePhase::DisconnectedWithError,
                node_id,
                Some(public.clone()),
            );
            return Err(public);
        }
        if let Some(error) = terminal_failure {
            // Cleanup succeeded, but retain the failed proof and attempted mode
            // for diagnostics. Do not publish a transient normal disconnect.
            self.update_status(
                state,
                RuntimePhase::DisconnectedWithError,
                node_id,
                Some(error),
            );
        } else {
            self.reset_disconnected(state);
        }
        Ok(state.status.clone())
    }

    pub fn retry_session_recovery(&self) -> Result<RuntimeStatus, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let mut state = self.lock_state();
            if !state.recovery_required {
                return Ok(state.status.clone());
            }
            if state.active.is_some() {
                return self.stop_active_locked(&mut state, None);
            }
        }
        if let Err(error) = (self.services.recover_sessions)(&self.session_root) {
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
        if self
            .services
            .system_proxy
            .reconcile_stale_journal()
            .is_err()
        {
            let public = PublicError::fixed(
                PublicErrorCode::RecoveryRequired,
                PublicErrorStage::SystemProxyRestore,
                "Windows System Proxy recovery still requires attention",
            );
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
        // Observation must not wait for UAC, engine validation or a network
        // proof holding the lifecycle state. Return the last complete revision.
        self.published_status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            status: self.status(),
            lines: self
                .diagnostics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .snapshot(),
            system_proxy: self.services.system_proxy.diagnostics(),
        }
    }

    pub fn clear_stale_system_proxy(&self, token: &str) -> Result<Diagnostics, PublicError> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let state = self.lock_state();
            let active_session_blocks_cleanup = state.active.as_ref().is_some_and(|active| {
                active.mode != RuntimeMode::Tun || state.status.phase != RuntimePhase::TunReady
            });
            if active_session_blocks_cleanup || state.shutting_down || state.recovery_required {
                return Err(PublicError::fixed(
                    PublicErrorCode::ActiveSessionConflict,
                    PublicErrorStage::SystemProxyRestore,
                    "Wait for RouteDeck to become stable and resolve session recovery before clearing a foreign System Proxy",
                ));
            }
        }
        self.services
            .system_proxy
            .clear_stale(token)
            .map_err(|error| PublicError {
                code: PublicErrorCode::CommandFailed,
                stage: PublicErrorStage::SystemProxyRestore,
                message: "Could not clear stale Windows System Proxy settings".into(),
                detail: Some(error.to_string()),
            })?;
        Ok(self.diagnostics())
    }

    pub fn shutdown(&self) -> bool {
        {
            let mut state = self.lock_state();
            if state.shutting_down {
                return state.active.is_none();
            }
            state.shutting_down = true;
        }
        let _ = self.stop();
        let safe_to_exit = {
            let mut state = self.lock_state();
            let safe = state.active.is_none();
            if !safe {
                // Let a later ExitRequested event retry the restore-before-stop sequence.
                state.shutting_down = false;
            }
            safe
        };
        if safe_to_exit {
            self.event_sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        }
        safe_to_exit
    }

    fn monitor_tick(&self) {
        struct ProbeSnapshot {
            generation: String,
            session_id: String,
            mode: RuntimeMode,
            route: HealthRoute,
            http_port: u16,
            redactor: Redactor,
            node_id: String,
            tun_before: Option<TunCaptureSnapshot>,
        }

        let mut state = self.lock_state();
        if state.recovery_required || state.status.phase == RuntimePhase::RecoveryRequired {
            return;
        }
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
            Self::set_proof(
                &mut state,
                ProofKind::EngineProcess,
                ProofState::Failed,
                None,
            );
            let _ = self.stop_active_locked(&mut state, Some(error));
            return;
        }
        if active.mode == RuntimeMode::SystemProxy {
            match self.services.system_proxy.is_owned() {
                Ok(true) => {}
                Ok(false) => {
                    let node_id = active.node_id.clone();
                    Self::set_proof(
                        &mut state,
                        ProofKind::SystemProxyOwnership,
                        ProofState::Failed,
                        None,
                    );
                    self.update_status(
                        &mut state,
                        RuntimePhase::BlockedByConflict,
                        Some(node_id),
                        Some(PublicError::fixed(
                            PublicErrorCode::RuntimeFailure,
                            PublicErrorStage::SystemProxyOwnership,
                            "Windows System Proxy was changed by another application",
                        )),
                    );
                    return;
                }
                Err(_) => {
                    let node_id = active.node_id.clone();
                    Self::set_proof(
                        &mut state,
                        ProofKind::SystemProxyOwnership,
                        ProofState::Failed,
                        None,
                    );
                    self.update_status(
                        &mut state,
                        RuntimePhase::Degraded,
                        Some(node_id),
                        Some(PublicError::fixed(
                            PublicErrorCode::RuntimeFailure,
                            PublicErrorStage::SystemProxyOwnership,
                            "Windows System Proxy ownership could not be checked",
                        )),
                    );
                    return;
                }
            }
        }
        if active.last_probe.elapsed() < Duration::from_secs(10) {
            return;
        }
        active.last_probe = Instant::now();
        let snapshot = ProbeSnapshot {
            generation: active.generation.clone(),
            session_id: active.session_id.clone(),
            mode: active.mode,
            route: active.health_route.clone(),
            http_port: active.ports.http,
            redactor: active.redactor.clone(),
            node_id: active.node_id.clone(),
            tun_before: (active.mode == RuntimeMode::Tun)
                .then(|| active.child.tun_capture_snapshot().ok())
                .flatten(),
        };
        drop(state);

        let proof = self
            .services
            .prober
            .prove(&snapshot.route)
            .and_then(|proof| {
                if matches!(
                    snapshot.mode,
                    RuntimeMode::LocalOnly | RuntimeMode::SystemProxy
                ) {
                    self.services
                        .prober
                        .prove_ordinary(snapshot.http_port)
                        .map(|_| proof)
                } else if snapshot.mode == RuntimeMode::Tun {
                    self.services.prober.prove_tun_capture().map(|_| proof)
                } else {
                    Ok(proof)
                }
            });
        state = self.lock_state();
        if state.recovery_required || state.status.phase == RuntimePhase::RecoveryRequired {
            return;
        }
        let Some(active) = state.active.as_mut().filter(|active| {
            active.generation == snapshot.generation && active.session_id == snapshot.session_id
        }) else {
            return;
        };
        let ownership = if active.child.is_alive().unwrap_or(false) {
            let listeners = self
                .services
                .listener
                .verify_owned_now(active.ports, active.child.as_mut());
            if snapshot.mode == RuntimeMode::Tun {
                listeners.and_then(|_| {
                    let before = snapshot.tun_before.ok_or_else(|| {
                        RuntimeError::new(
                            "tun_capture",
                            "the owned TUN capture snapshot was unavailable",
                        )
                    })?;
                    let after = active.child.tun_capture_snapshot()?;
                    if after.proves_traffic_since(before) {
                        Ok(())
                    } else {
                        Err(RuntimeError::new(
                            "tun_capture",
                            "periodic unproxied traffic did not traverse the owned TUN adapter",
                        ))
                    }
                })
            } else {
                listeners
            }
        } else {
            Err(RuntimeError::new(
                "engine_process",
                "sing-box exited during traffic proof",
            ))
        };
        if let Err(error) = ownership {
            let public = public_runtime_error(error, &snapshot.redactor);
            Self::set_proof(
                &mut state,
                ProofKind::LocalScopeOwnership,
                ProofState::Failed,
                None,
            );
            let _ = self.stop_active_locked(&mut state, Some(public));
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
                if snapshot.mode == RuntimeMode::SystemProxy {
                    Self::set_proof(
                        &mut state,
                        ProofKind::SystemProxyOwnership,
                        ProofState::Passed,
                        None,
                    );
                }
                if !matches!(
                    state.status.phase,
                    RuntimePhase::SystemProxyReady | RuntimePhase::TunReady
                ) {
                    self.update_status(
                        &mut state,
                        RuntimePhase::OutboundVerified,
                        Some(snapshot.node_id.clone()),
                        None,
                    );
                }
                self.update_status(
                    &mut state,
                    match snapshot.mode {
                        RuntimeMode::SystemProxy => RuntimePhase::SystemProxyReady,
                        RuntimeMode::Tun => RuntimePhase::TunReady,
                        RuntimeMode::LocalOnly => RuntimePhase::LocalProxyReady,
                    },
                    Some(snapshot.node_id),
                    None,
                );
                if matches!(snapshot.mode, RuntimeMode::SystemProxy | RuntimeMode::Tun) {
                    // Finish the original proof and TUN counter attribution first.
                    // Optional UX traffic must not help satisfy the cold proof.
                    drop(state);
                    let latency = self.services.prober.warm_latency(&snapshot.route);
                    state = self.lock_state();
                    if state.recovery_required
                        || state.status.error.is_some()
                        || !matches!(
                            state.status.phase,
                            RuntimePhase::SystemProxyReady | RuntimePhase::TunReady
                        )
                    {
                        return;
                    }
                    let Some(active) = state.active.as_mut().filter(|active| {
                        active.generation == snapshot.generation
                            && active.session_id == snapshot.session_id
                    }) else {
                        return;
                    };
                    let process_error = match active.child.is_alive() {
                        Ok(true) => None,
                        Ok(false) => Some(PublicError::fixed(
                            PublicErrorCode::RuntimeFailure,
                            PublicErrorStage::EngineProcess,
                            "The local proxy process exited during latency measurement",
                        )),
                        Err(error) => Some(public_runtime_error(error, &snapshot.redactor)),
                    };
                    if let Some(error) = process_error {
                        Self::set_proof(
                            &mut state,
                            ProofKind::EngineProcess,
                            ProofState::Failed,
                            None,
                        );
                        let _ = self.stop_active_locked(&mut state, Some(error));
                        return;
                    }
                    state.status.steady_latency_ms = latency;
                    state.status.revision = state.status.revision.saturating_add(1);
                    self.emit_status(state.status.clone());
                }
            }
            Err(error) => {
                active.consecutive_probe_failures =
                    active.consecutive_probe_failures.saturating_add(1);
                let threshold_reached = active.consecutive_probe_failures >= 2;
                let had_steady_latency = state.status.steady_latency_ms.take().is_some();
                if threshold_reached {
                    state.status.route_check_ms = None;
                    Self::set_proof(
                        &mut state,
                        ProofKind::SelectedOutboundHttps,
                        ProofState::Failed,
                        None,
                    );
                    let public = public_runtime_error(error, &snapshot.redactor);
                    self.update_status(
                        &mut state,
                        RuntimePhase::Degraded,
                        Some(snapshot.node_id),
                        Some(public),
                    );
                } else if had_steady_latency {
                    // Keep the existing one-failure readiness grace, but never
                    // display an old successful latency as a current sample.
                    state.status.revision = state.status.revision.saturating_add(1);
                    self.emit_status(state.status.clone());
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
        if state.status.error.is_some()
            || !matches!(
                phase,
                RuntimePhase::SystemProxyReady | RuntimePhase::TunReady
            )
        {
            state.status.steady_latency_ms = None;
        }
        if !matches!(
            phase,
            RuntimePhase::OutboundVerified
                | RuntimePhase::LocalProxyReady
                | RuntimePhase::SystemProxyReady
                | RuntimePhase::TunReady
                | RuntimePhase::Degraded
        ) {
            state.status.route_check_ms = None;
        }
        state.status.revision = state.status.revision.saturating_add(1);
        self.emit_status(state.status.clone());
    }

    fn clear_active_metadata(state: &mut State) {
        state.status.ports = None;
        state.status.route_check_ms = None;
        state.status.steady_latency_ms = None;
        state.status.engine_version = None;
    }

    fn reset_disconnected(&self, state: &mut State) {
        Self::clear_active_metadata(state);
        state.status.scope = RuntimeScope::LocalOnly;
        state.status.mode = RuntimeMode::LocalOnly;
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
            stage if is_safe_helper_start_stage(stage) => {
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
            "tun_capture" => Self::set_proof(
                state,
                ProofKind::LocalScopeOwnership,
                ProofState::Failed,
                None,
            ),
            "system_proxy_publish" | "system_proxy_ownership" => Self::set_proof(
                state,
                ProofKind::SystemProxyOwnership,
                ProofState::Failed,
                None,
            ),
            _ => {}
        }
    }

    fn emit_status(&self, status: RuntimeStatus) {
        *self
            .published_status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = status.clone();
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

fn public_subscription_fetch_error(error: SubscriptionFetchError) -> PublicError {
    let code = match error.kind() {
        SubscriptionFetchErrorKind::UrlInvalid => PublicErrorCode::SubscriptionUrlInvalid,
        SubscriptionFetchErrorKind::PolicyBlocked => PublicErrorCode::SubscriptionPolicyBlocked,
        SubscriptionFetchErrorKind::FetchFailed => PublicErrorCode::SubscriptionFetchFailed,
        SubscriptionFetchErrorKind::ResponseTooLarge => {
            PublicErrorCode::SubscriptionResponseTooLarge
        }
        SubscriptionFetchErrorKind::Timeout => PublicErrorCode::SubscriptionFetchTimeout,
        SubscriptionFetchErrorKind::InvalidEncoding => PublicErrorCode::SubscriptionInvalidEncoding,
    };
    let stage = match error.stage() {
        SubscriptionFetchStage::Url => PublicErrorStage::SubscriptionUrl,
        SubscriptionFetchStage::Dns => PublicErrorStage::SubscriptionDns,
        SubscriptionFetchStage::Fetch => PublicErrorStage::SubscriptionFetch,
        SubscriptionFetchStage::Response => PublicErrorStage::SubscriptionResponse,
    };
    let localization_key = match error.kind() {
        SubscriptionFetchErrorKind::UrlInvalid => "subscription.url.invalid",
        SubscriptionFetchErrorKind::PolicyBlocked => "subscription.policy_blocked",
        SubscriptionFetchErrorKind::FetchFailed => "subscription.fetch_failed",
        SubscriptionFetchErrorKind::ResponseTooLarge => "subscription.response_too_large",
        SubscriptionFetchErrorKind::Timeout => "subscription.timeout",
        SubscriptionFetchErrorKind::InvalidEncoding => "subscription.invalid_encoding",
    };
    PublicError::fixed(code, stage, localization_key)
}

fn subscription_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(8_640_000_000_000_000) as u64
}

fn source_import_error(message: &'static str) -> PublicError {
    PublicError::fixed(
        PublicErrorCode::ImportRejected,
        PublicErrorStage::Import,
        message,
    )
}

fn source_storage_error() -> PublicError {
    PublicError::fixed(
        PublicErrorCode::RuntimeFailure,
        PublicErrorStage::SessionStorage,
        "subscription.save_failed",
    )
}

fn validate_source_id(source_id: &str) -> Result<(), PublicError> {
    if source_id.len() != 32
        || !source_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(source_import_error("subscription.source_invalid"));
    }
    Ok(())
}

fn ensure_source_mutation_allowed(state: &State, source_id: &str) -> Result<(), PublicError> {
    if state.recovery_required || state.shutting_down {
        return Err(PublicError::fixed(
            PublicErrorCode::RecoveryRequired,
            PublicErrorStage::Import,
            "Import is blocked until session recovery completes",
        ));
    }
    if state
        .active
        .as_ref()
        .and_then(|active| state.nodes.get(&active.node_id))
        .is_some_and(|node| node.source_id == source_id)
    {
        return Err(PublicError::fixed(
            PublicErrorCode::ActiveSessionConflict,
            PublicErrorStage::Import,
            "Stop the active connection before changing its source",
        ));
    }
    Ok(())
}

fn prepare_stored_nodes(
    nodes: Vec<Node>,
    source: &StoredSource,
) -> Result<Vec<(String, StoredNode)>, PublicError> {
    if !source.node_ids.is_empty() && source.node_ids.len() != nodes.len() {
        return Err(source_import_error("subscription.content.rejected"));
    }
    let safe_source_name = if nodes.iter().all(|node| {
        Redactor::from_nodes(std::slice::from_ref(node)).redact(&source.name) == source.name
    }) {
        source.name.clone()
    } else {
        "Сохранённые серверы".into()
    };
    nodes
        .into_iter()
        .enumerate()
        .map(|(index, mut node)| {
            // Keep legacy IDs intact on migration; every new source owns a separate
            // namespace, including when the same endpoint is imported twice.
            if source.id != LEGACY_SOURCE_ID {
                node.id = format!("{}-{}", source.id, node.id());
            }
            if let Some(id) = source.node_ids.get(index) {
                node.id = id.clone();
            }
            let node_id = node.id().to_owned();
            let config_identity = random_hex(16)
                .map_err(|error| public_runtime_error(error, &Redactor::default()))?;
            Ok((
                node_id,
                StoredNode {
                    node,
                    config_identity,
                    source_id: source.id.clone(),
                    source_name: safe_source_name.clone(),
                    source_kind: source.kind,
                },
            ))
        })
        .collect()
}

fn preview_from_report(preview_id: &str, report: &ImportReport) -> ImportPreview {
    ImportPreview {
        preview_id: preview_id.to_owned(),
        nodes: report
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let protocol = node.protocol_kind();
                PreviewNode {
                    id: node.id().to_owned(),
                    display_name: safe_preview_name(node, protocol, index),
                    protocol,
                    insecure_tls: node.requires_insecure_approval(),
                    source_id: None,
                    source_name: None,
                    source_kind: None,
                    source_refreshable: None,
                    source_updated_at_ms: None,
                }
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

fn safe_preview_name(node: &Node, protocol: ProtocolKind, index: usize) -> String {
    let display_name = node.display_name();
    if display_name
        .to_lowercase()
        .contains(&node.server().to_lowercase())
    {
        let label = match protocol {
            ProtocolKind::Vless => "VLESS",
            ProtocolKind::Hysteria2 => "Hysteria2",
            ProtocolKind::Naive => "Naive",
        };
        format!("{label} server {}", index + 1)
    } else {
        display_name.to_owned()
    }
}

fn matching_pending_key(
    pending: &HashMap<String, PendingImport>,
    preview_id: &str,
) -> Option<String> {
    pending
        .keys()
        .find(|candidate| constant_time_token_eq(candidate, preview_id))
        .cloned()
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
        ProofKind::SystemProxyOwnership,
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

fn prove_tun_capture(
    prober: &dyn TrafficProber,
    child: &mut dyn ManagedChild,
) -> Result<crate::health::ProofResult, RuntimeError> {
    let before = child.tun_capture_snapshot()?;
    let proof = prober.prove_tun_capture()?;
    let after = child.tun_capture_snapshot()?;
    if !after.proves_traffic_since(before) {
        return Err(RuntimeError::new(
            "tun_capture",
            "the unproxied proof did not traverse the owned RouteDeck TUN adapter",
        ));
    }
    Ok(proof)
}

fn public_runtime_error(error: RuntimeError, redactor: &Redactor) -> PublicError {
    let stage = public_stage(error.stage());
    let detail = (is_safe_helper_start_stage(error.stage())
        || matches!(
            stage,
            PublicErrorStage::Start
                | PublicErrorStage::ConfigCheck
                | PublicErrorStage::VerifyListeners
                | PublicErrorStage::ProveTraffic
                | PublicErrorStage::EngineProcess
                | PublicErrorStage::StopEngine
                | PublicErrorStage::SystemProxyPublish
                | PublicErrorStage::SystemProxyRestore
                | PublicErrorStage::SystemProxyOwnership
        ))
    .then(|| redactor.redact(error.message()));
    PublicError {
        code: PublicErrorCode::RuntimeFailure,
        stage,
        message: "The RouteDeck connection operation failed".into(),
        detail,
    }
}

// These reviewed helper paths emit helper/Windows diagnostics, not arbitrary
// engine stderr; their detail still passes through the redactor. Keep this exact
// allowlist separate from generic start_engine errors, whose detail stays hidden.
fn is_safe_helper_start_stage(stage: &str) -> bool {
    matches!(
        stage,
        "tun_helper_pipe"
            | "tun_helper_protocol"
            | "tun_helper_identity"
            | "tun_helper_launch"
            | "tun_helper_start"
            | "tun_helper_exit"
    )
}

fn public_stage(stage: &str) -> PublicErrorStage {
    match stage {
        stage if is_safe_helper_start_stage(stage) => PublicErrorStage::StartEngine,
        "session_recovery" => PublicErrorStage::SessionRecovery,
        "tun_uac_cancelled" | "tun_preflight" => PublicErrorStage::Start,
        "generate_config" => PublicErrorStage::GenerateConfig,
        "engine_layout" => PublicErrorStage::EngineLayout,
        "engine_integrity" => PublicErrorStage::EngineIntegrity,
        "config_check" => PublicErrorStage::ConfigCheck,
        "start_engine" => PublicErrorStage::StartEngine,
        "verify_listeners" => PublicErrorStage::VerifyListeners,
        "prove_traffic" | "tun_capture" => PublicErrorStage::ProveTraffic,
        "engine_process" => PublicErrorStage::EngineProcess,
        "stop_engine" => PublicErrorStage::StopEngine,
        "system_proxy_publish" => PublicErrorStage::SystemProxyPublish,
        "system_proxy_restore" => PublicErrorStage::SystemProxyRestore,
        "system_proxy_ownership" => PublicErrorStage::SystemProxyOwnership,
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
        mpsc, Barrier, Condvar,
    };

    use super::*;
    use crate::health::ProofResult;
    use serde_json::Value;

    const NODE: &str = "hysteria2://fixture-secret@example.test:443?sni=example.test#fixture";
    const REALITY_NODE: &str = "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=cover.test&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyzABCDEFGH123456789&sid=a1b2#Reality";

    struct FakeProvider {
        check_fails: bool,
        stop_fails: bool,
        alive: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
    }

    struct FakeSystemProxy {
        alive: Arc<AtomicBool>,
        owned: AtomicBool,
        foreign: AtomicBool,
        fail_publish: AtomicBool,
        reject_publish_unchanged: AtomicBool,
        fail_restore: AtomicBool,
        publishes: AtomicUsize,
        restores: AtomicUsize,
        restore_saw_live_core: AtomicBool,
    }

    struct FakeTunPrivilege(bool);

    impl TunPrivilegeControl for FakeTunPrivilege {
        fn is_elevated(&self) -> Result<bool, RuntimeError> {
            Ok(self.0)
        }
    }

    impl FakeSystemProxy {
        fn new(alive: Arc<AtomicBool>) -> Self {
            Self {
                alive,
                owned: AtomicBool::new(false),
                foreign: AtomicBool::new(false),
                fail_publish: AtomicBool::new(false),
                reject_publish_unchanged: AtomicBool::new(false),
                fail_restore: AtomicBool::new(false),
                publishes: AtomicUsize::new(0),
                restores: AtomicUsize::new(0),
                restore_saw_live_core: AtomicBool::new(false),
            }
        }
    }

    impl SystemProxyControl for FakeSystemProxy {
        fn publish_loopback(
            &self,
            _http_port: u16,
        ) -> Result<(), crate::system_proxy::SystemProxyError> {
            assert!(self.alive.load(Ordering::SeqCst));
            self.publishes.fetch_add(1, Ordering::SeqCst);
            if self.reject_publish_unchanged.load(Ordering::SeqCst) {
                return Err(crate::system_proxy::SystemProxyError::Unchanged(
                    "fixture foreign proxy is active",
                ));
            }
            if self.fail_publish.load(Ordering::SeqCst) {
                return Err(crate::system_proxy::SystemProxyError::fixed(
                    "fixture publish failure",
                ));
            }
            self.owned.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn is_owned(&self) -> Result<bool, crate::system_proxy::SystemProxyError> {
            Ok(self.owned.load(Ordering::SeqCst) && !self.foreign.load(Ordering::SeqCst))
        }

        fn restore_if_owned(
            &self,
        ) -> Result<SystemProxyRestoreOutcome, crate::system_proxy::SystemProxyError> {
            self.restores.fetch_add(1, Ordering::SeqCst);
            self.restore_saw_live_core
                .store(self.alive.load(Ordering::SeqCst), Ordering::SeqCst);
            if self.fail_restore.load(Ordering::SeqCst) {
                return Err(crate::system_proxy::SystemProxyError::fixed(
                    "fixture restore failure",
                ));
            }
            if self.foreign.load(Ordering::SeqCst) {
                self.owned.store(false, Ordering::SeqCst);
                return Ok(SystemProxyRestoreOutcome::ForeignPreserved);
            }
            Ok(if self.owned.swap(false, Ordering::SeqCst) {
                SystemProxyRestoreOutcome::Restored
            } else {
                SystemProxyRestoreOutcome::NoJournal
            })
        }

        fn reconcile_stale_journal(
            &self,
        ) -> Result<SystemProxyRestoreOutcome, crate::system_proxy::SystemProxyError> {
            self.restore_if_owned()
        }
    }

    impl EngineProvider for FakeProvider {
        fn create(&self, _kind: EngineKind) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
            Ok(Box::new(FakeLauncher {
                check_fails: self.check_fails,
                stop_fails: self.stop_fails,
                alive: self.alive.clone(),
                stops: self.stops.clone(),
                tun: false,
            }))
        }

        fn create_tun(
            &self,
            _upstream: TunUpstreamIdentity,
        ) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
            Ok(Box::new(FakeLauncher {
                check_fails: self.check_fails,
                stop_fails: self.stop_fails,
                alive: self.alive.clone(),
                stops: self.stops.clone(),
                tun: true,
            }))
        }
    }

    struct FakeLauncher {
        check_fails: bool,
        stop_fails: bool,
        alive: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
        tun: bool,
    }

    struct RecoveryFailProvider;

    impl EngineProvider for RecoveryFailProvider {
        fn create(&self, _kind: EngineKind) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
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
                tun: self.tun,
                capture_calls: 0,
            }))
        }
    }

    struct FakeChild {
        alive: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
        stop_fails: bool,
        tun: bool,
        capture_calls: u64,
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

        fn tun_capture_snapshot(&mut self) -> Result<TunCaptureSnapshot, RuntimeError> {
            if !self.tun {
                return Err(RuntimeError::new(
                    "tun_capture",
                    "fixture is not a TUN child",
                ));
            }
            self.capture_calls = self.capture_calls.saturating_add(1);
            Ok(TunCaptureSnapshot {
                interface_luid: 7,
                in_octets: self.capture_calls * 1024,
                out_octets: self.capture_calls * 2048,
            })
        }
    }

    #[derive(Default)]
    struct BridgeObservation {
        sing_box: Option<u16>,
        xray: Option<u16>,
        sing_box_upstream: Option<String>,
        xray_upstream: Option<String>,
    }

    struct DualEngineProvider {
        events: Arc<Mutex<Vec<String>>>,
        observation: Arc<Mutex<BridgeObservation>>,
        sing_box_alive: Arc<AtomicBool>,
        xray_alive: Arc<AtomicBool>,
        fail_check: Option<EngineKind>,
        fail_start: Option<EngineKind>,
    }

    impl DualEngineProvider {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                observation: Arc::new(Mutex::new(BridgeObservation::default())),
                sing_box_alive: Arc::new(AtomicBool::new(false)),
                xray_alive: Arc::new(AtomicBool::new(false)),
                fail_check: None,
                fail_start: None,
            }
        }
    }

    impl EngineProvider for DualEngineProvider {
        fn create(&self, kind: EngineKind) -> Result<Box<dyn EngineLauncher>, RuntimeError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("create:{}", engine_label(kind)));
            Ok(Box::new(DualEngineLauncher {
                kind,
                events: Arc::clone(&self.events),
                observation: Arc::clone(&self.observation),
                alive: if kind == EngineKind::SingBox {
                    Arc::clone(&self.sing_box_alive)
                } else {
                    Arc::clone(&self.xray_alive)
                },
                fail_check: self.fail_check == Some(kind),
                fail_start: self.fail_start == Some(kind),
            }))
        }
    }

    struct DualEngineLauncher {
        kind: EngineKind,
        events: Arc<Mutex<Vec<String>>>,
        observation: Arc<Mutex<BridgeObservation>>,
        alive: Arc<AtomicBool>,
        fail_check: bool,
        fail_start: bool,
    }

    impl EngineLauncher for DualEngineLauncher {
        fn check(
            &self,
            config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<String, RuntimeError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("check:{}", engine_label(self.kind)));
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(config.path()).unwrap())
                    .expect("fixture config must be JSON");
            let bridge = if self.kind == EngineKind::SingBox {
                assert_eq!(value["outbounds"][0]["type"], "socks");
                assert!(value["outbounds"][0].get("username").is_none());
                assert!(value["outbounds"][0].get("password").is_none());
                value["outbounds"][0]["server_port"].as_u64().unwrap() as u16
            } else {
                assert_eq!(value["inbounds"][0]["settings"]["auth"], "noauth");
                assert!(value["inbounds"][0]["settings"].get("accounts").is_none());
                assert!(value["inbounds"][0]["settings"].get("users").is_none());
                value["inbounds"][0]["port"].as_u64().unwrap() as u16
            };
            let mut observation = self.observation.lock().unwrap();
            if self.kind == EngineKind::SingBox {
                observation.sing_box = Some(bridge);
                observation.sing_box_upstream = value
                    .pointer("/dns/servers/0/bind_interface")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            } else {
                observation.xray = Some(bridge);
                observation.xray_upstream = value
                    .pointer("/outbounds/0/streamSettings/sockopt/interface")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            if self.fail_check {
                Err(RuntimeError::new(
                    "config_check",
                    "fixture engine rejected its generated configuration",
                ))
            } else {
                Ok(match self.kind {
                    EngineKind::SingBox => "1.13.21",
                    EngineKind::Xray => "26.3.27",
                }
                .into())
            }
        }

        fn start(
            &self,
            _config: &SessionConfig,
            _redactor: Redactor,
            _diagnostics: Arc<Mutex<DiagnosticBuffer>>,
        ) -> Result<Box<dyn ManagedChild>, RuntimeError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("start:{}", engine_label(self.kind)));
            if self.fail_start {
                return Err(RuntimeError::new(
                    "start_engine",
                    "fixture engine refused to start",
                ));
            }
            self.alive.store(true, Ordering::SeqCst);
            Ok(Box::new(DualEngineChild {
                kind: self.kind,
                events: Arc::clone(&self.events),
                alive: Arc::clone(&self.alive),
            }))
        }
    }

    struct DualEngineChild {
        kind: EngineKind,
        events: Arc<Mutex<Vec<String>>>,
        alive: Arc<AtomicBool>,
    }

    impl ManagedChild for DualEngineChild {
        fn pid(&self) -> u32 {
            std::process::id()
        }

        fn is_alive(&mut self) -> Result<bool, RuntimeError> {
            Ok(self.alive.load(Ordering::SeqCst))
        }

        fn stop(&mut self) -> Result<(), RuntimeError> {
            if self.alive.swap(false, Ordering::SeqCst) {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("stop:{}", engine_label(self.kind)));
            }
            Ok(())
        }
    }

    fn engine_label(kind: EngineKind) -> &'static str {
        match kind {
            EngineKind::SingBox => "sing-box",
            EngineKind::Xray => "xray",
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

        fn wait_until_sidecar_ready(
            &self,
            _port: u16,
            child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            if self.0 && child.is_alive()? {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "verify_listeners",
                    "fixture sidecar listener did not open",
                ))
            }
        }

        fn verify_sidecar_owned_now(
            &self,
            port: u16,
            child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            self.wait_until_sidecar_ready(port, child)
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

        fn wait_until_sidecar_ready(
            &self,
            _port: u16,
            child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            if self.0.load(Ordering::SeqCst) && child.is_alive()? {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    "verify_listeners",
                    "fixture sidecar listener did not open",
                ))
            }
        }

        fn verify_sidecar_owned_now(
            &self,
            port: u16,
            child: &mut dyn ManagedChild,
        ) -> Result<(), RuntimeError> {
            self.wait_until_sidecar_ready(port, child)
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

        fn prove_tun_capture(&self) -> Result<ProofResult, RuntimeError> {
            self.prove(&HealthRoute::new(1, String::new()))
        }
    }

    struct SecretFailProber;

    impl TrafficProber for SecretFailProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            Err(RuntimeError::new(
                "prove_traffic",
                "fixture selected outbound password=fixture-secret failed",
            ))
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

    struct OrdinaryFailProber;

    impl TrafficProber for OrdinaryFailProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            Ok(ProofResult { latency_ms: 21 })
        }

        fn prove_ordinary(&self, _http_port: u16) -> Result<ProofResult, RuntimeError> {
            Err(RuntimeError::new(
                "prove_traffic",
                "fixture ordinary proxy route failed",
            ))
        }
    }

    struct DistinctLatencyProber;

    struct WarmFixtureProber {
        cold_enabled: Arc<AtomicBool>,
        warm_enabled: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
        gate: Option<(Arc<Barrier>, Arc<Barrier>)>,
    }

    impl TrafficProber for WarmFixtureProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            if self.cold_enabled.load(Ordering::SeqCst) {
                Ok(ProofResult { latency_ms: 420 })
            } else {
                Err(RuntimeError::new(
                    "prove_traffic",
                    "fixture cold proof failed",
                ))
            }
        }

        fn warm_latency(&self, _route: &HealthRoute) -> Option<u64> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some((entered, release)) = &self.gate {
                entered.wait();
                release.wait();
            }
            self.warm_enabled.load(Ordering::SeqCst).then_some(17)
        }
    }

    impl TrafficProber for DistinctLatencyProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            Ok(ProofResult { latency_ms: 17 })
        }

        fn prove_ordinary(&self, _http_port: u16) -> Result<ProofResult, RuntimeError> {
            Ok(ProofResult { latency_ms: 91 })
        }
    }

    struct BlockingProber {
        calls: AtomicUsize,
        gate: Arc<(Mutex<(bool, bool)>, Condvar)>,
    }

    struct FakeSubscriptionFetcher {
        result: Result<String, SubscriptionFetchError>,
    }

    impl SubscriptionFetcher for FakeSubscriptionFetcher {
        fn fetch(&self, _raw_url: &str) -> Result<String, SubscriptionFetchError> {
            self.result.clone()
        }
    }

    struct BlockingSubscriptionFetcher {
        ready: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl SubscriptionFetcher for BlockingSubscriptionFetcher {
        fn fetch(&self, _raw_url: &str) -> Result<String, SubscriptionFetchError> {
            self.ready.wait();
            self.release.wait();
            Ok(NODE.into())
        }
    }

    impl TrafficProber for BlockingProber {
        fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
            // Startup proves both the private health inbound and the ordinary HTTP inbound.
            if self.calls.fetch_add(1, Ordering::SeqCst) > 1 {
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

    fn controller_with_system_proxy(
        prober: Arc<dyn TrafficProber>,
    ) -> (
        ApplicationController,
        Arc<FakeSystemProxy>,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
    ) {
        controller_with_system_proxy_stop_behavior(prober, false)
    }

    fn controller_with_system_proxy_stop_behavior(
        prober: Arc<dyn TrafficProber>,
        stop_fails: bool,
    ) -> (
        ApplicationController,
        Arc<FakeSystemProxy>,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
    ) {
        let alive = Arc::new(AtomicBool::new(false));
        let stops = Arc::new(AtomicUsize::new(0));
        let proxy = Arc::new(FakeSystemProxy::new(alive.clone()));
        let root = std::env::temp_dir().join(format!(
            "routedeck-system-proxy-test-{}",
            random_hex(8).expect("test random")
        ));
        let controller = ApplicationController::with_services_and_controls(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails,
                alive: alive.clone(),
                stops: stops.clone(),
            }),
            Arc::new(FakeListener(true)),
            prober,
            Arc::new(HttpsSubscriptionFetcher),
            proxy.clone(),
        );
        (controller, proxy, stops, alive)
    }

    fn controller_with_tun(
        elevated: bool,
        proof: bool,
        stop_fails: bool,
    ) -> (ApplicationController, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let alive = Arc::new(AtomicBool::new(false));
        let stops = Arc::new(AtomicUsize::new(0));
        let proxy = Arc::new(FakeSystemProxy::new(alive.clone()));
        let root = std::env::temp_dir().join(format!(
            "routedeck-tun-test-{}",
            random_hex(8).expect("test random")
        ));
        let mut controller = ApplicationController::with_services_and_controls(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails,
                alive: alive.clone(),
                stops: stops.clone(),
            }),
            Arc::new(FakeListener(true)),
            Arc::new(FakeProber(proof)),
            Arc::new(HttpsSubscriptionFetcher),
            proxy,
        );
        controller.services.tun_privilege = Arc::new(FakeTunPrivilege(elevated));
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

    fn controller_with_fetcher(fetcher: Arc<dyn SubscriptionFetcher>) -> ApplicationController {
        let root = std::env::temp_dir().join(format!(
            "routedeck-test-{}",
            random_hex(8).expect("test random")
        ));
        ApplicationController::with_services_and_fetcher(
            root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails: false,
                alive: Arc::new(AtomicBool::new(false)),
                stops: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(FakeListener(true)),
            Arc::new(FakeProber(true)),
            fetcher,
            Arc::new(SystemProxyManager::new(std::env::temp_dir().join(format!(
                "routedeck-fetch-proxy-test-{}",
                random_hex(8).expect("test random")
            )))),
        )
    }

    fn controller_with_dual_provider(
        provider: Arc<DualEngineProvider>,
        listener_ready: bool,
    ) -> ApplicationController {
        let root = std::env::temp_dir().join(format!(
            "routedeck-reality-test-{}",
            random_hex(8).expect("test random")
        ));
        ApplicationController::with_services(
            root,
            Arc::new(|_| {}),
            provider,
            Arc::new(FakeListener(listener_ready)),
            Arc::new(FakeProber(true)),
        )
    }

    fn import_node(controller: &ApplicationController) -> String {
        import_node_from(controller, NODE)
    }

    fn import_node_from(controller: &ApplicationController, link: &str) -> String {
        let preview = controller.preview_import_content(link.into()).unwrap();
        let confirmed = controller.confirm_import(&preview.preview_id).unwrap();
        confirmed.node_ids[0].clone()
    }

    fn controller_at(session_root: PathBuf) -> ApplicationController {
        let alive = Arc::new(AtomicBool::new(false));
        let subscription_store =
            SubscriptionStore::new(session_root.with_extension("subscription.json"));
        let mut controller = ApplicationController::with_services_and_controls(
            session_root,
            Arc::new(|_| {}),
            Arc::new(FakeProvider {
                check_fails: false,
                stop_fails: false,
                alive: alive.clone(),
                stops: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(FakeListener(true)),
            Arc::new(FakeProber(true)),
            Arc::new(HttpsSubscriptionFetcher),
            Arc::new(FakeSystemProxy::new(alive)),
        );
        controller.subscription_store = Some(subscription_store);
        controller.restore_persisted_subscription();
        controller
    }

    #[test]
    fn confirmed_subscription_is_restored_after_controller_restart() {
        let session_root = std::env::temp_dir().join(format!(
            "routedeck-persistence-test-{}",
            random_hex(8).expect("test random")
        ));
        let persisted_path = session_root.with_extension("subscription.json");
        let expected_id = {
            let controller = controller_at(session_root.clone());
            let id = import_node(&controller);
            assert_eq!(controller.confirmed_nodes().len(), 1);
            id
        };

        let restored = controller_at(session_root).confirmed_nodes();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].id, expected_id);
        assert_eq!(restored[0].display_name, "fixture");
        std::fs::remove_file(persisted_path).unwrap();
    }

    #[test]
    fn multiple_sources_keep_independent_ids_order_and_names_after_restart() {
        let session_root =
            std::env::temp_dir().join(format!("routedeck-library-test-{}", random_hex(8).unwrap()));
        let persisted_path = session_root.with_extension("subscription.json");
        let controller = controller_at(session_root.clone());
        for name in ["Личный сервер", "Резервный сервер"] {
            let preview = controller.preview_import_content(NODE.into()).unwrap();
            let serialized = serde_json::to_value(&preview).unwrap();
            assert!(serialized["nodes"][0].get("sourceId").is_none());
            controller
                .confirm_import_named(&preview.preview_id, Some(name))
                .unwrap();
        }
        let nodes = controller.confirmed_nodes();
        assert_eq!(nodes.len(), 2);
        assert_ne!(nodes[0].id, nodes[1].id);
        assert_ne!(nodes[0].source_id, nodes[1].source_id);
        assert_eq!(nodes[0].source_name.as_deref(), Some("Личный сервер"));
        assert_eq!(nodes[1].source_name.as_deref(), Some("Резервный сервер"));
        assert_eq!(nodes[0].source_kind, Some(SourceKind::Manual));
        drop(controller);
        assert_eq!(
            serde_json::to_value(controller_at(session_root).confirmed_nodes()).unwrap(),
            serde_json::to_value(nodes).unwrap()
        );
        std::fs::remove_file(persisted_path).unwrap();
    }

    #[test]
    fn legacy_subscription_is_retained_when_a_new_source_is_added() {
        let session_root = std::env::temp_dir().join(format!(
            "routedeck-legacy-library-test-{}",
            random_hex(8).unwrap()
        ));
        let persisted_path = session_root.with_extension("subscription.json");
        std::fs::write(
            &persisted_path,
            serde_json::to_vec(&serde_json::json!({"version": 1, "content": NODE})).unwrap(),
        )
        .unwrap();
        let controller = controller_at(session_root.clone());
        let original_id = import_subscription(NODE.as_bytes()).unwrap().nodes[0]
            .id()
            .to_owned();
        assert_eq!(controller.confirmed_nodes()[0].id, original_id);
        assert_eq!(
            controller.confirmed_nodes()[0].source_id.as_deref(),
            Some(LEGACY_SOURCE_ID)
        );
        let new_id = import_node(&controller);
        assert_ne!(new_id, original_id);
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&persisted_path).unwrap()).unwrap();
        assert_eq!(stored["version"], 3);
        assert_eq!(stored["sources"].as_array().unwrap().len(), 2);
        drop(controller);
        let restored = controller_at(session_root).confirmed_nodes();
        assert_eq!(restored[0].id, original_id);
        assert_eq!(restored[1].id, new_id);
        std::fs::remove_file(persisted_path).unwrap();
    }

    #[test]
    fn source_kind_is_bound_to_preview_origin_and_source_name_errors_are_secret_free() {
        let controller = controller_with_fetcher(Arc::new(FakeSubscriptionFetcher {
            result: Ok(NODE.into()),
        }));
        let preview = controller
            .preview_import_url("https://provider.test/private-token".into())
            .unwrap();
        for name in [
            "https://provider.test/private-token",
            "user:secret@host",
            "example.test",
            "password=private-token",
            "bad\nname",
        ] {
            let error = controller
                .confirm_import_named(&preview.preview_id, Some(name))
                .unwrap_err();
            assert_eq!(error.message, "import.source_name.invalid");
            assert!(error.detail.is_none());
            assert!(controller.confirmed_nodes().is_empty());
            assert!(controller
                .lock_state()
                .pending
                .contains_key(&preview.preview_id));
        }
        controller
            .confirm_import_named(&preview.preview_id, Some("Моя подписка"))
            .unwrap();
        import_node(&controller);
        let nodes = controller.confirmed_nodes();
        assert_eq!(nodes[0].source_kind, Some(SourceKind::Subscription));
        assert_eq!(nodes[1].source_kind, Some(SourceKind::Manual));
        let public = serde_json::to_string(&nodes).unwrap();
        assert!(!public.contains("private-token"));
        assert!(!public.contains("example.test"));
    }

    #[test]
    fn additive_library_node_limit_preserves_existing_data_and_preview() {
        let (controller, _, _) = controller(false, true, true);
        let content = std::iter::repeat_n(NODE, MAX_LIBRARY_NODES)
            .collect::<Vec<_>>()
            .join("\n");
        let preview = controller.preview_import_content(content).unwrap();
        assert_eq!(
            controller
                .confirm_import(&preview.preview_id)
                .unwrap()
                .imported,
            MAX_LIBRARY_NODES
        );
        let overflow = controller.preview_import_content(NODE.into()).unwrap();
        let error = controller.confirm_import(&overflow.preview_id).unwrap_err();
        assert_eq!(error.message, "import.library.limit");
        assert_eq!(controller.confirmed_nodes().len(), MAX_LIBRARY_NODES);
        assert_eq!(controller.lock_state().sources.len(), 1);
        assert!(controller
            .lock_state()
            .pending
            .contains_key(&overflow.preview_id));
    }

    #[test]
    fn corrupt_subscription_does_not_block_startup_or_later_replacement() {
        let session_root = std::env::temp_dir().join(format!(
            "routedeck-corrupt-persistence-test-{}",
            random_hex(8).expect("test random")
        ));
        let persisted_path = session_root.with_extension("subscription.json");
        std::fs::write(&persisted_path, b"{broken").unwrap();

        {
            let controller = controller_at(session_root.clone());
            assert!(controller.confirmed_nodes().is_empty());
            assert!(controller
                .diagnostics()
                .lines
                .iter()
                .any(|line| line.contains("stored subscription was ignored")));
            import_node(&controller);
        }

        assert_eq!(controller_at(session_root).confirmed_nodes().len(), 1);
        std::fs::remove_file(persisted_path).unwrap();
    }

    #[test]
    fn reset_removes_confirmed_nodes_from_memory_and_persistent_storage() {
        let session_root = std::env::temp_dir().join(format!(
            "routedeck-reset-persistence-test-{}",
            random_hex(8).expect("test random")
        ));
        let persisted_path = session_root.with_extension("subscription.json");
        {
            let controller = controller_at(session_root.clone());
            import_node(&controller);
            assert_eq!(controller.confirmed_nodes().len(), 1);

            controller.reset_local_state().unwrap();
            assert!(controller.confirmed_nodes().is_empty());
            assert!(!persisted_path.exists());
            controller.reset_local_state().unwrap();
        }

        assert!(controller_at(session_root).confirmed_nodes().is_empty());
    }

    #[test]
    fn failed_persistent_add_keeps_preview_retryable_and_old_nodes_atomic() {
        let session_root = std::env::temp_dir().join(format!(
            "routedeck-transactional-persistence-test-{}",
            random_hex(8).expect("test random")
        ));
        let persisted_path = session_root.with_extension("subscription.json");
        let blocked_path = session_root.with_extension("blocked");
        let mut controller = controller_at(session_root.clone());
        let old_node = import_node(&controller);
        let replacement = controller
            .preview_import_content(REALITY_NODE.into())
            .unwrap();
        std::fs::create_dir(&blocked_path).unwrap();
        controller.subscription_store = Some(SubscriptionStore::new(blocked_path.clone()));

        let error = controller
            .confirm_import(&replacement.preview_id)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SessionStorage);
        assert_eq!(controller.confirmed_nodes()[0].id, old_node);
        assert!(controller
            .lock_state()
            .pending
            .contains_key(&replacement.preview_id));
        assert_eq!(
            controller_at(session_root.clone()).confirmed_nodes()[0].id,
            old_node
        );

        controller.subscription_store = Some(SubscriptionStore::new(persisted_path.clone()));
        let confirmed = controller.confirm_import(&replacement.preview_id).unwrap();
        assert_ne!(confirmed.node_ids[0], replacement.nodes[0].id);
        let nodes = controller.confirmed_nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].id, old_node);
        assert_eq!(nodes[1].id, confirmed.node_ids[0]);
        assert_eq!(controller.lock_state().sources.len(), 2);
        assert_eq!(
            controller_at(session_root)
                .confirmed_nodes()
                .iter()
                .map(|node| &node.id)
                .collect::<Vec<_>>(),
            nodes.iter().map(|node| &node.id).collect::<Vec<_>>()
        );

        std::fs::remove_file(persisted_path).unwrap();
        std::fs::remove_dir(blocked_path).unwrap();
    }

    struct MutableSubscriptionFetcher {
        result: Mutex<Result<String, SubscriptionFetchError>>,
        calls: AtomicUsize,
    }

    impl SubscriptionFetcher for MutableSubscriptionFetcher {
        fn fetch(&self, _url: &str) -> Result<String, SubscriptionFetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.lock().unwrap().clone()
        }
    }

    fn refresh_fixture(
        content: &str,
    ) -> (
        ApplicationController,
        Arc<MutableSubscriptionFetcher>,
        String,
    ) {
        let fetcher = Arc::new(MutableSubscriptionFetcher {
            result: Mutex::new(Ok(content.into())),
            calls: AtomicUsize::new(0),
        });
        let controller = controller_with_fetcher(fetcher.clone());
        let preview = controller
            .preview_import_url("https://provider.test/private-fixture-token".into())
            .unwrap();
        controller
            .confirm_import_named(&preview.preview_id, Some("Мои серверы"))
            .unwrap();
        let source_id = controller.confirmed_nodes()[0].source_id.clone().unwrap();
        (controller, fetcher, source_id)
    }

    #[test]
    fn refresh_url_is_private_and_only_subscription_groups_are_refreshable() {
        let (controller, _, source_id) = refresh_fixture(NODE);
        import_node(&controller);
        let nodes = controller.confirmed_nodes();
        assert_eq!(nodes[0].source_refreshable, Some(true));
        assert!(nodes[0].source_updated_at_ms.is_some());
        assert_eq!(nodes[1].source_refreshable, Some(false));
        let state = controller.lock_state();
        assert!(state.sources[0]
            .url
            .as_ref()
            .unwrap()
            .contains("private-fixture-token"));
        assert!(!format!("{:?}", state.sources).contains("private-fixture-token"));
        drop(state);
        let public = serde_json::to_string(&nodes).unwrap();
        assert!(!public.contains("provider.test"));
        assert!(!public.contains("private-fixture-token"));
        assert_eq!(nodes[0].source_id.as_deref(), Some(source_id.as_str()));
    }

    struct ExactUrlSubscriptionFetcher {
        expected_url: &'static str,
        calls: AtomicUsize,
    }

    impl SubscriptionFetcher for ExactUrlSubscriptionFetcher {
        fn fetch(&self, raw_url: &str) -> Result<String, SubscriptionFetchError> {
            assert_eq!(raw_url, self.expected_url);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NODE.into())
        }
    }

    #[test]
    fn initial_url_import_retains_refresh_url_through_confirmation_save_and_restart() {
        const FIXTURE_URL: &str = "https://provider.test/subscription?token=fixture-only";
        let root = std::env::temp_dir().join(format!(
            "routedeck-url-import-roundtrip-{}",
            random_hex(8).unwrap()
        ));
        let path = root.with_extension("subscription.json");
        let fetcher = Arc::new(ExactUrlSubscriptionFetcher {
            expected_url: FIXTURE_URL,
            calls: AtomicUsize::new(0),
        });
        let mut controller = controller_at(root.clone());
        controller.services.subscription_fetcher = fetcher.clone();
        let preview = controller.preview_import_url(FIXTURE_URL.into()).unwrap();
        assert!(!serde_json::to_string(&preview)
            .unwrap()
            .contains("fixture-only"));
        let imported = controller
            .confirm_import_named(&preview.preview_id, Some("Подписка"))
            .unwrap();
        let source_id = controller.confirmed_nodes()[0].source_id.clone().unwrap();
        assert_eq!(
            controller.confirmed_nodes()[0].source_refreshable,
            Some(true)
        );
        drop(controller);

        let mut controller = controller_at(root.clone());
        controller.services.subscription_fetcher = fetcher.clone();
        assert_eq!(
            controller.confirmed_nodes()[0].source_refreshable,
            Some(true)
        );
        assert_eq!(
            controller
                .refresh_source(&source_id, None)
                .unwrap()
                .node_ids,
            imported.node_ids
        );
        drop(controller);

        let mut controller = controller_at(root);
        controller.services.subscription_fetcher = fetcher.clone();
        assert_eq!(
            controller
                .refresh_source(&source_id, None)
                .unwrap()
                .node_ids,
            imported.node_ids
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 3);
        assert!(!serde_json::to_string(&controller.confirmed_nodes())
            .unwrap()
            .contains("fixture-only"));
        drop(controller);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn migrated_v2_subscription_needs_url_once_and_reuses_it_after_restart() {
        const FIXTURE_URL: &str = "https://provider.test/legacy?token=fixture-only";
        const SOURCE_ID: &str = "1234567890abcdef1234567890abcdef";
        let root = std::env::temp_dir().join(format!(
            "routedeck-v2-refresh-roundtrip-{}",
            random_hex(8).unwrap()
        ));
        let path = root.with_extension("subscription.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "sources": [{ "id": SOURCE_ID, "name": "Старая подписка",
                    "kind": "subscription", "content": NODE }]
            }))
            .unwrap(),
        )
        .unwrap();
        let fetcher = Arc::new(ExactUrlSubscriptionFetcher {
            expected_url: FIXTURE_URL,
            calls: AtomicUsize::new(0),
        });
        let mut controller = controller_at(root.clone());
        controller.services.subscription_fetcher = fetcher.clone();
        let original_node_id = controller.confirmed_nodes()[0].id.clone();
        assert_eq!(
            controller.confirmed_nodes()[0].source_refreshable,
            Some(false)
        );
        assert_eq!(
            controller
                .refresh_source(SOURCE_ID, None)
                .unwrap_err()
                .message,
            "subscription.url_required"
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            controller
                .refresh_source(SOURCE_ID, Some(FIXTURE_URL))
                .unwrap()
                .node_ids,
            vec![original_node_id.clone()]
        );
        drop(controller);

        let mut controller = controller_at(root);
        controller.services.subscription_fetcher = fetcher.clone();
        assert_eq!(
            controller.confirmed_nodes()[0].source_refreshable,
            Some(true)
        );
        assert_eq!(
            controller.confirmed_nodes()[0].source_name.as_deref(),
            Some("Старая подписка")
        );
        assert_eq!(
            controller.refresh_source(SOURCE_ID, None).unwrap().node_ids,
            vec![original_node_id]
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
        drop(controller);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn refresh_reorders_and_rotates_credentials_without_changing_existing_ids_after_restart() {
        let second = NODE.replace("example.test", "second.test");
        let (mut controller, fetcher, source_id) = refresh_fixture(&format!("{NODE}\n{second}"));
        let other_id = import_node(&controller);
        let before = controller.confirmed_nodes();
        let other_identity = controller.lock_state().nodes[&other_id]
            .config_identity
            .clone();
        let old_identity = controller.lock_state().nodes[&before[0].id]
            .config_identity
            .clone();
        let path = controller.session_root.with_extension("subscription.json");
        controller.subscription_store = Some(SubscriptionStore::new(path.clone()));
        let third = NODE.replace("example.test", "third.test");
        let changed = NODE.replace("fixture-secret", "rotated-fixture-secret");
        *fetcher.result.lock().unwrap() = Ok(format!("{second}\n{changed}\n{third}"));
        let refreshed = controller.refresh_source(&source_id, None).unwrap();
        assert_eq!(refreshed.imported, 3);
        assert_eq!(refreshed.node_ids[0], before[1].id);
        assert_eq!(refreshed.node_ids[1], before[0].id);
        let after = controller.confirmed_nodes();
        assert_eq!(after[3].id, other_id);
        assert_eq!(after[0].source_name.as_deref(), Some("Мои серверы"));
        assert_eq!(
            controller.lock_state().nodes[&other_id].config_identity,
            other_identity
        );
        assert_ne!(
            controller.lock_state().nodes[&before[0].id].config_identity,
            old_identity
        );
        assert_eq!(controller.lock_state().sources[0].revision, 1);
        let restored = controller_at(controller.session_root.clone()).confirmed_nodes();
        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::to_value(restored).unwrap()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn refresh_preserves_duplicate_occurrence_ids_and_can_run_beside_another_active_group() {
        let (controller, fetcher, source_id) = refresh_fixture(&format!("{NODE}\n{NODE}"));
        let other = import_node(&controller);
        let before = controller.confirmed_nodes();
        controller
            .start_local_proxy(&other, DefaultRoute::Vpn)
            .unwrap();
        *fetcher.result.lock().unwrap() = Ok(format!("{NODE}\n{NODE}"));
        let refreshed = controller.refresh_source(&source_id, None).unwrap();
        assert_eq!(
            refreshed.node_ids,
            vec![before[0].id.clone(), before[1].id.clone()]
        );
        assert_ne!(refreshed.node_ids[0], refreshed.node_ids[1]);
        assert_eq!(
            controller.lock_state().active.as_ref().unwrap().node_id,
            other
        );
        controller.remove_source(&source_id).unwrap();
        assert_eq!(controller.confirmed_nodes().len(), 1);
        controller.stop().unwrap();
    }

    #[test]
    fn refresh_and_remove_refuse_the_active_group_without_fetching_or_changing_state() {
        let (controller, fetcher, source_id) = refresh_fixture(NODE);
        let before = serde_json::to_value(controller.confirmed_nodes()).unwrap();
        let node = controller.confirmed_nodes()[0].id.clone();
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        assert_eq!(
            controller
                .refresh_source(&source_id, None)
                .unwrap_err()
                .code,
            PublicErrorCode::ActiveSessionConflict
        );
        assert_eq!(
            controller.remove_source(&source_id).unwrap_err().code,
            PublicErrorCode::ActiveSessionConflict
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            serde_json::to_value(controller.confirmed_nodes()).unwrap(),
            before
        );
        controller.stop().unwrap();
    }

    #[test]
    fn refresh_rejects_empty_partial_or_failed_responses_without_losing_saved_nodes() {
        let (controller, fetcher, source_id) = refresh_fixture(NODE);
        let before = serde_json::to_value(controller.confirmed_nodes()).unwrap();
        for result in [
            Ok(String::new()),
            Ok(format!("{NODE}\nnaive+https://broken:70000")),
            Ok("not a subscription".into()),
            Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::Timeout,
                SubscriptionFetchStage::Fetch,
            )),
        ] {
            *fetcher.result.lock().unwrap() = result;
            assert!(controller.refresh_source(&source_id, None).is_err());
            assert_eq!(
                serde_json::to_value(controller.confirmed_nodes()).unwrap(),
                before
            );
            assert_eq!(controller.lock_state().sources[0].revision, 0);
            assert_eq!(controller.lock_state().preview_inflight, 0);
        }
    }

    #[test]
    fn refresh_and_remove_save_failure_leave_memory_and_disk_unchanged() {
        let (mut controller, fetcher, source_id) = refresh_fixture(NODE);
        let path = controller.session_root.with_extension("subscription.json");
        let store = SubscriptionStore::new(path.clone());
        store.save(&controller.lock_state().sources).unwrap();
        let disk_before = std::fs::read(&path).unwrap();
        let before = serde_json::to_value(controller.confirmed_nodes()).unwrap();
        let blocked = controller.session_root.with_extension("blocked");
        std::fs::create_dir(&blocked).unwrap();
        controller.subscription_store = Some(SubscriptionStore::new(blocked.clone()));
        *fetcher.result.lock().unwrap() = Ok(NODE.replace("example.test", "replacement.test"));
        assert_eq!(
            controller
                .refresh_source(&source_id, None)
                .unwrap_err()
                .stage,
            PublicErrorStage::SessionStorage
        );
        assert!(controller.remove_source(&source_id).is_err());
        assert_eq!(
            serde_json::to_value(controller.confirmed_nodes()).unwrap(),
            before
        );
        assert_eq!(std::fs::read(&path).unwrap(), disk_before);
        controller.subscription_store = Some(SubscriptionStore::new(path.clone()));
        controller.remove_source(&source_id).unwrap();
        controller.remove_source(&source_id).unwrap();
        assert!(controller.confirmed_nodes().is_empty());
        assert!(controller_at(controller.session_root.clone())
            .confirmed_nodes()
            .is_empty());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(blocked).unwrap();
    }

    #[test]
    fn legacy_subscription_refresh_accepts_a_new_url_and_manual_sources_cannot_refresh() {
        let (controller, fetcher, source_id) = refresh_fixture(NODE);
        controller.lock_state().sources[0].url = None;
        assert_eq!(
            controller.confirmed_nodes()[0].source_refreshable,
            Some(false)
        );
        assert_eq!(
            controller
                .refresh_source(&source_id, None)
                .unwrap_err()
                .message,
            "subscription.url_required"
        );
        controller
            .refresh_source(
                &source_id,
                Some("https://replacement-provider.test/fixture"),
            )
            .unwrap();
        assert_eq!(
            controller.confirmed_nodes()[0].source_refreshable,
            Some(true)
        );
        assert_eq!(
            controller.lock_state().sources[0].url.as_deref(),
            Some("https://replacement-provider.test/fixture")
        );
        import_node(&controller);
        let manual_id = controller.confirmed_nodes()[1].source_id.clone().unwrap();
        assert_eq!(
            controller
                .refresh_source(&manual_id, Some("https://provider.test/fixture"))
                .unwrap_err()
                .message,
            "subscription.refresh_manual"
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_hostile_source_ids_and_urls_are_rejected_before_fetch_without_secret_errors() {
        let (controller, fetcher, source_id) = refresh_fixture(NODE);
        for url in [
            "http://provider.test/secret",
            "file:///secret",
            "https://127.0.0.1/secret",
            "https://localhost/secret",
            "https://user:secret@provider.test/",
            "https://provider.test/#secret",
        ] {
            let error = controller
                .refresh_source(&source_id, Some(url))
                .unwrap_err();
            assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
        }
        assert!(controller
            .refresh_source(
                &source_id,
                Some(&format!("https://provider.test/{}", "a".repeat(4096)))
            )
            .is_err());
        for id in ["../private-secret", "", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"] {
            assert!(controller.refresh_source(id, None).is_err());
            assert!(controller.remove_source(id).is_err());
        }
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(controller.lock_state().preview_inflight, 0);
        assert_eq!(controller.confirmed_nodes().len(), 1);
    }

    #[test]
    fn deleted_source_is_not_resurrected_by_an_inflight_refresh() {
        let (mut controller, _, source_id) = refresh_fixture(NODE);
        let ready = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        controller.services.subscription_fetcher = Arc::new(BlockingSubscriptionFetcher {
            ready: ready.clone(),
            release: release.clone(),
        });
        let controller = Arc::new(controller);
        let worker_controller = controller.clone();
        let worker_id = source_id.clone();
        let worker = thread::spawn(move || worker_controller.refresh_source(&worker_id, None));
        ready.wait();
        controller.remove_source(&source_id).unwrap();
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap_err().message,
            "subscription.source_changed"
        );
        assert!(controller.confirmed_nodes().is_empty());
        assert_eq!(controller.lock_state().preview_inflight, 0);
    }

    #[test]
    fn refresh_is_bounded_by_the_shared_import_fetch_budget() {
        let (controller, fetcher, source_id) = refresh_fixture(NODE);
        let slots: Vec<_> = (0..MAX_PENDING_IMPORT_PREVIEWS)
            .map(|_| controller.reserve_preview_slot().unwrap())
            .collect();
        assert!(controller.refresh_source(&source_id, None).is_err());
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        drop(slots);
        controller.refresh_source(&source_id, None).unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_cannot_replace_a_source_that_became_active_during_fetch() {
        let (mut controller, _, source_id) = refresh_fixture(NODE);
        let before = controller.confirmed_nodes()[0].id.clone();
        let ready = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        controller.services.subscription_fetcher = Arc::new(BlockingSubscriptionFetcher {
            ready: ready.clone(),
            release: release.clone(),
        });
        let controller = Arc::new(controller);
        let worker_controller = controller.clone();
        let worker_id = source_id.clone();
        let worker = thread::spawn(move || worker_controller.refresh_source(&worker_id, None));
        ready.wait();
        controller
            .start_local_proxy(&before, DefaultRoute::Vpn)
            .unwrap();
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap_err().code,
            PublicErrorCode::ActiveSessionConflict
        );
        assert_eq!(controller.lock_state().sources[0].revision, 0);
        assert_eq!(
            controller.lock_state().active.as_ref().unwrap().node_id,
            before
        );
        controller.stop().unwrap();
    }

    #[test]
    fn restored_source_id_mapping_must_match_the_parsed_nodes() {
        let (mut controller, _, _) = refresh_fixture(NODE);
        let path = controller.session_root.with_extension("subscription.json");
        let mut sources = controller.lock_state().sources.clone();
        sources[0].node_ids = vec![
            format!("{}-{}", sources[0].id, "a".repeat(32)),
            format!("{}-{}", sources[0].id, "b".repeat(32)),
        ];
        let store = SubscriptionStore::new(path.clone());
        store.save(&sources).unwrap();
        controller.subscription_store = Some(store);
        assert!(controller_at(controller.session_root.clone())
            .confirmed_nodes()
            .is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn only_one_concurrent_refresh_can_commit_the_same_source_revision() {
        let (mut controller, _, source_id) = refresh_fixture(NODE);
        let ready = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(3));
        controller.services.subscription_fetcher = Arc::new(BlockingSubscriptionFetcher {
            ready: ready.clone(),
            release: release.clone(),
        });
        let controller = Arc::new(controller);
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let controller = controller.clone();
                let source_id = source_id.clone();
                thread::spawn(move || controller.refresh_source(&source_id, None))
            })
            .collect();
        ready.wait();
        release.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .find_map(|result| result.as_ref().err())
                .unwrap()
                .message,
            "subscription.source_changed"
        );
        assert_eq!(controller.lock_state().sources[0].revision, 1);
        assert_eq!(controller.lock_state().preview_inflight, 0);
    }

    #[test]
    fn reality_uses_matching_private_bridge_and_ordered_dual_process_lifecycle() {
        let provider = Arc::new(DualEngineProvider::new());
        let controller = controller_with_dual_provider(Arc::clone(&provider), true);
        let node = import_node_from(&controller, REALITY_NODE);

        let status = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        assert_eq!(status.phase, RuntimePhase::LocalProxyReady);
        assert_eq!(
            status.engine_version.as_deref(),
            Some("sing-box 1.13.21 + Xray 26.3.27")
        );
        let observation = provider.observation.lock().unwrap();
        assert_eq!(observation.sing_box, observation.xray);
        assert!(observation.sing_box.unwrap() > 0);
        drop(observation);

        let events = provider.events.lock().unwrap().clone();
        let xray_start = events
            .iter()
            .position(|event| event == "start:xray")
            .unwrap();
        let sing_box_start = events
            .iter()
            .position(|event| event == "start:sing-box")
            .unwrap();
        assert!(xray_start < sing_box_start);

        controller.stop().unwrap();
        let events = provider.events.lock().unwrap();
        let sing_box_stop = events
            .iter()
            .position(|event| event == "stop:sing-box")
            .unwrap();
        let xray_stop = events
            .iter()
            .position(|event| event == "stop:xray")
            .unwrap();
        assert!(sing_box_stop < xray_stop);
        assert!(!provider.sing_box_alive.load(Ordering::SeqCst));
        assert!(!provider.xray_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn reality_tun_populates_the_same_physical_upstream_in_both_engine_configs() {
        let provider = Arc::new(DualEngineProvider::new());
        let controller = controller_with_dual_provider(Arc::clone(&provider), true);
        let node = import_node_from(&controller, REALITY_NODE);

        let error = controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        let observation = provider.observation.lock().unwrap();
        assert_eq!(observation.sing_box_upstream.as_deref(), Some("Ethernet"));
        assert_eq!(observation.xray_upstream.as_deref(), Some("Ethernet"));
    }

    #[test]
    fn reality_xray_check_failure_starts_neither_process() {
        let mut configured = DualEngineProvider::new();
        configured.fail_check = Some(EngineKind::Xray);
        let provider = Arc::new(configured);
        let controller = controller_with_dual_provider(Arc::clone(&provider), true);
        let node = import_node_from(&controller, REALITY_NODE);

        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ConfigCheck);
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        let events = provider.events.lock().unwrap();
        assert!(events.iter().all(|event| !event.starts_with("start:")));
        assert!(!provider.sing_box_alive.load(Ordering::SeqCst));
        assert!(!provider.xray_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn reality_sidecar_listener_failure_stops_xray_before_front_starts() {
        let provider = Arc::new(DualEngineProvider::new());
        let controller = controller_with_dual_provider(Arc::clone(&provider), false);
        let node = import_node_from(&controller, REALITY_NODE);

        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::VerifyListeners);
        let events = provider.events.lock().unwrap();
        assert!(events.iter().any(|event| event == "start:xray"));
        assert!(events.iter().any(|event| event == "stop:xray"));
        assert!(events.iter().all(|event| event != "start:sing-box"));
        assert!(!provider.xray_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn reality_front_start_failure_rolls_back_live_xray() {
        let mut configured = DualEngineProvider::new();
        configured.fail_start = Some(EngineKind::SingBox);
        let provider = Arc::new(configured);
        let controller = controller_with_dual_provider(Arc::clone(&provider), true);
        let node = import_node_from(&controller, REALITY_NODE);

        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::StartEngine);
        let events = provider.events.lock().unwrap();
        let xray_start = events
            .iter()
            .position(|event| event == "start:xray")
            .unwrap();
        let sing_box_start = events
            .iter()
            .position(|event| event == "start:sing-box")
            .unwrap();
        let xray_stop = events
            .iter()
            .position(|event| event == "stop:xray")
            .unwrap();
        assert!(xray_start < sing_box_start && sing_box_start < xray_stop);
        assert!(!provider.xray_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn reality_sidecar_death_invalidates_and_tears_down_front_session() {
        let provider = Arc::new(DualEngineProvider::new());
        let controller = controller_with_dual_provider(Arc::clone(&provider), true);
        let node = import_node_from(&controller, REALITY_NODE);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();

        provider.xray_alive.store(false, Ordering::SeqCst);
        controller.monitor_tick();
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert!(!provider.sing_box_alive.load(Ordering::SeqCst));
        assert!(provider
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "stop:sing-box"));
    }

    #[test]
    fn reality_stop_attempts_sidecar_cleanup_when_front_stop_fails() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-reality-stop-test-{}",
            random_hex(8).expect("test random")
        ));
        let front_alive = Arc::new(AtomicBool::new(true));
        let sidecar_alive = Arc::new(AtomicBool::new(true));
        let front_stops = Arc::new(AtomicUsize::new(0));
        let sidecar_stops = Arc::new(AtomicUsize::new(0));
        let sidecar_config = SessionConfig::create(&root, "{}").unwrap();
        let mut pair = RealityProcessPair {
            front: Box::new(FakeChild {
                alive: Arc::clone(&front_alive),
                stops: front_stops,
                stop_fails: true,
                tun: false,
                capture_calls: 0,
            }),
            sidecar: Box::new(FakeChild {
                alive: Arc::clone(&sidecar_alive),
                stops: Arc::clone(&sidecar_stops),
                stop_fails: false,
                tun: false,
                capture_calls: 0,
            }),
            sidecar_port: 1,
            listener: Arc::new(FakeListener(true)),
            _sidecar_config: sidecar_config,
        };

        let error = pair.stop().unwrap_err();

        assert_eq!(error.stage(), "stop_engine");
        assert!(front_alive.load(Ordering::SeqCst));
        assert!(!sidecar_alive.load(Ordering::SeqCst));
        assert_eq!(sidecar_stops.load(Ordering::SeqCst), 1);
        drop(pair);
        let _ = std::fs::remove_dir(root);
    }

    #[test]
    fn reality_stop_preserves_front_error_when_both_processes_fail() {
        struct FailingStopChild {
            message: &'static str,
            attempts: Arc<AtomicUsize>,
        }

        impl ManagedChild for FailingStopChild {
            fn pid(&self) -> u32 {
                std::process::id()
            }

            fn is_alive(&mut self) -> Result<bool, RuntimeError> {
                Ok(true)
            }

            fn stop(&mut self) -> Result<(), RuntimeError> {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                Err(RuntimeError::new("stop_engine", self.message))
            }
        }

        let root = std::env::temp_dir().join(format!(
            "routedeck-reality-double-stop-test-{}",
            random_hex(8).expect("test random")
        ));
        let front_attempts = Arc::new(AtomicUsize::new(0));
        let sidecar_attempts = Arc::new(AtomicUsize::new(0));
        let sidecar_config = SessionConfig::create(&root, "{}").unwrap();
        let mut pair = RealityProcessPair {
            front: Box::new(FailingStopChild {
                message: "front stop failed",
                attempts: Arc::clone(&front_attempts),
            }),
            sidecar: Box::new(FailingStopChild {
                message: "sidecar stop failed",
                attempts: Arc::clone(&sidecar_attempts),
            }),
            sidecar_port: 1,
            listener: Arc::new(FakeListener(true)),
            _sidecar_config: sidecar_config,
        };

        let error = pair.stop().unwrap_err();

        assert_eq!(error.stage(), "stop_engine");
        assert_eq!(error.message(), "front stop failed");
        assert_eq!(front_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(sidecar_attempts.load(Ordering::SeqCst), 1);
        drop(pair);
        let _ = std::fs::remove_dir(root);
    }

    #[test]
    fn reality_system_proxy_restores_windows_before_stopping_both_engines() {
        let provider = Arc::new(DualEngineProvider::new());
        let proxy = Arc::new(FakeSystemProxy::new(Arc::clone(&provider.sing_box_alive)));
        let root = std::env::temp_dir().join(format!(
            "routedeck-reality-system-proxy-test-{}",
            random_hex(8).expect("test random")
        ));
        let controller = ApplicationController::with_services_and_controls(
            root,
            Arc::new(|_| {}),
            provider.clone(),
            Arc::new(FakeListener(true)),
            Arc::new(FakeProber(true)),
            Arc::new(HttpsSubscriptionFetcher),
            proxy.clone(),
        );
        let node = import_node_from(&controller, REALITY_NODE);

        let status = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        assert_eq!(status.phase, RuntimePhase::SystemProxyReady);
        controller.stop().unwrap();
        assert!(proxy.restore_saw_live_core.load(Ordering::SeqCst));
        assert!(!provider.sing_box_alive.load(Ordering::SeqCst));
        assert!(!provider.xray_alive.load(Ordering::SeqCst));
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
    fn private_health_success_cannot_hide_ordinary_proxy_failure() {
        let (controller, stops, _) = controller_with_prober(Arc::new(OrdinaryFailProber));
        let node = import_node(&controller);
        let error = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert_ne!(controller.status().phase, RuntimePhase::LocalProxyReady);
        assert_eq!(controller.status().route_check_ms, None);
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
        assert!(status.proofs.iter().all(|proof| {
            proof.state == ProofState::Passed
                || (proof.kind == ProofKind::SystemProxyOwnership
                    && proof.state == ProofState::NotRun)
        }));
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
        controller
            .discard_import_preview("00000000000000000000000000000000")
            .unwrap();
        assert_eq!(controller.lock_state().pending.len(), 1);
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
    fn repeated_discard_does_not_touch_another_pending_preview() {
        let (controller, _, _) = controller(false, true, true);
        let first = controller.preview_import_content(NODE.into()).unwrap();
        let second = controller
            .preview_import_content(
                "hysteria2://second-secret@second.test:443?sni=cover.test#second".into(),
            )
            .unwrap();
        controller
            .discard_import_preview(&first.preview_id)
            .unwrap();
        controller
            .discard_import_preview(&first.preview_id)
            .unwrap();
        assert!(controller
            .lock_state()
            .pending
            .contains_key(&second.preview_id));
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
    fn import_preview_masks_authority_fallbacks_without_user_labels() {
        let (controller, _, _) = controller(false, true, true);
        for content in [
            "hysteria2://fixture-secret@raw-share-authority.test:443?sni=cover.test",
            r#"{"type":"hysteria2","server":"raw-json-authority.test","server_port":443,"password":"fixture-secret","tls":{"enabled":true,"server_name":"cover.test"}}"#,
        ] {
            let preview = controller.preview_import_content(content.into()).unwrap();
            let serialized = serde_json::to_string(&preview).unwrap();
            assert!(!serialized.contains("raw-share-authority.test"));
            assert!(!serialized.contains("raw-json-authority.test"));
            assert_eq!(preview.nodes[0].display_name, "Hysteria2 server 1");
            controller
                .discard_import_preview(&preview.preview_id)
                .unwrap();
        }
    }

    #[test]
    fn pending_previews_are_token_indexed_and_bounded() {
        let (controller, _, _) = controller(false, true, true);
        let mut previews = Vec::new();
        for index in 0..MAX_PENDING_IMPORT_PREVIEWS {
            previews.push(
                controller
                    .preview_import_content(format!(
                        "hysteria2://fixture-{index}@server-{index}.test:443?sni=cover.test"
                    ))
                    .unwrap(),
            );
        }
        assert_eq!(
            controller.lock_state().pending.len(),
            MAX_PENDING_IMPORT_PREVIEWS
        );
        let overflow = controller.preview_import_content(NODE.into()).unwrap_err();
        assert_eq!(overflow.code, PublicErrorCode::ImportRejected);
        controller
            .discard_import_preview(&previews[1].preview_id)
            .unwrap();
        assert!(
            controller
                .confirm_import(&previews[0].preview_id)
                .unwrap()
                .imported
                > 0
        );
        assert_eq!(
            controller.lock_state().pending.len(),
            MAX_PENDING_IMPORT_PREVIEWS - 2
        );
    }

    #[test]
    fn inflight_preview_slots_reject_overload_before_parsing() {
        let (controller, _, _) = controller(false, true, true);
        let controller = Arc::new(controller);
        let ready = Arc::new(Barrier::new(MAX_PENDING_IMPORT_PREVIEWS + 1));
        let release = Arc::new(Barrier::new(MAX_PENDING_IMPORT_PREVIEWS + 1));
        let reserved = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..MAX_PENDING_IMPORT_PREVIEWS {
            let controller = controller.clone();
            let ready = ready.clone();
            let release = release.clone();
            let reserved = reserved.clone();
            workers.push(thread::spawn(move || {
                let _slot = PreviewSlot::reserve(&controller.state).unwrap();
                reserved.fetch_add(1, Ordering::SeqCst);
                ready.wait();
                release.wait();
            }));
        }
        ready.wait();
        assert_eq!(reserved.load(Ordering::SeqCst), MAX_PENDING_IMPORT_PREVIEWS);
        assert_eq!(
            controller.lock_state().preview_inflight,
            MAX_PENDING_IMPORT_PREVIEWS
        );
        let overload = controller.preview_import_content(NODE.into()).unwrap_err();
        assert_eq!(overload.code, PublicErrorCode::ImportRejected);
        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(controller.lock_state().preview_inflight, 0);
        let preview = controller.preview_import_content(NODE.into()).unwrap();
        controller
            .discard_import_preview(&preview.preview_id)
            .unwrap();
        assert!(controller
            .preview_import_content("not a subscription".into())
            .is_err());
        assert_eq!(controller.lock_state().preview_inflight, 0);
    }

    #[test]
    fn url_preview_reserves_slot_before_network_work_and_commits_masked_report() {
        let ready = Arc::new(Barrier::new(MAX_PENDING_IMPORT_PREVIEWS + 1));
        let release = Arc::new(Barrier::new(MAX_PENDING_IMPORT_PREVIEWS + 1));
        let controller = Arc::new(controller_with_fetcher(Arc::new(
            BlockingSubscriptionFetcher {
                ready: ready.clone(),
                release: release.clone(),
            },
        )));
        let mut workers = Vec::new();
        for index in 0..MAX_PENDING_IMPORT_PREVIEWS {
            let controller = controller.clone();
            workers.push(thread::spawn(move || {
                controller.preview_import_url(format!(
                    "https://subscriptions.test/list?token=secret-{index}"
                ))
            }));
        }
        ready.wait();
        assert_eq!(
            controller.lock_state().preview_inflight,
            MAX_PENDING_IMPORT_PREVIEWS
        );
        let overload = controller
            .preview_import_url("https://subscriptions.test/overflow?token=secret".into())
            .unwrap_err();
        assert_eq!(overload.code, PublicErrorCode::ImportRejected);
        release.wait();
        let previews = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(controller.lock_state().preview_inflight, 0);
        assert_eq!(
            controller.lock_state().pending.len(),
            MAX_PENDING_IMPORT_PREVIEWS
        );
        for preview in previews {
            let serialized = serde_json::to_string(&preview).unwrap();
            assert!(!serialized.contains("example.test"));
            assert!(!serialized.contains("subscriptions.test"));
            controller
                .discard_import_preview(&preview.preview_id)
                .unwrap();
        }
    }

    #[test]
    fn url_fetch_errors_emit_only_finite_localization_contract() {
        let cases = [(
            SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::PolicyBlocked,
                SubscriptionFetchStage::Dns,
            ),
            PublicErrorCode::SubscriptionPolicyBlocked,
            PublicErrorStage::SubscriptionDns,
            "subscription.policy_blocked",
        )];
        for (error, code, stage, message) in cases {
            let controller =
                controller_with_fetcher(Arc::new(FakeSubscriptionFetcher { result: Err(error) }));
            let raw_url = "https://secret-host.test/list?token=never-emit";
            let public = controller.preview_import_url(raw_url.into()).unwrap_err();
            assert_eq!(public.code, code);
            assert_eq!(public.stage, stage);
            assert_eq!(public.message, message);
            assert!(public.detail.is_none());
            let serialized = serde_json::to_string(&public).unwrap();
            assert!(!serialized.contains("never-emit"));
            assert!(!serialized.contains("secret-host"));
            assert_eq!(controller.lock_state().preview_inflight, 0);
            assert!(controller.lock_state().pending.is_empty());
        }
    }

    #[test]
    fn concurrent_preview_results_can_be_resolved_out_of_order() {
        let (controller, _, _) = controller(false, true, true);
        let controller = Arc::new(controller);
        let first = {
            let controller = controller.clone();
            thread::spawn(move || {
                controller
                    .preview_import_content(
                        "hysteria2://first-secret@first.test:443?sni=cover.test#first".into(),
                    )
                    .unwrap()
            })
        };
        let second = {
            let controller = controller.clone();
            thread::spawn(move || {
                controller
                    .preview_import_content(
                        "hysteria2://second-secret@second.test:443?sni=cover.test#second".into(),
                    )
                    .unwrap()
            })
        };
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!(controller.lock_state().pending.len(), 2);
        assert_eq!(
            controller
                .confirm_import(&second.preview_id)
                .unwrap()
                .imported,
            1
        );
        controller
            .discard_import_preview(&first.preview_id)
            .unwrap();
        assert!(controller.lock_state().pending.is_empty());
    }

    #[test]
    fn confirmed_import_adds_nodes_without_invalidating_previous_nodes() {
        let (controller, _, _) = controller(false, true, true);
        let obsolete = import_node(&controller);
        let replacement = controller
            .preview_import_content(
                "hysteria2://replacement-secret@replacement.test:443?sni=cover.test#replacement"
                    .into(),
            )
            .unwrap();
        let confirmed = controller.confirm_import(&replacement.preview_id).unwrap();
        assert_eq!(controller.lock_state().nodes.len(), 2);
        assert_ne!(confirmed.node_ids[0], obsolete);
        let status = controller
            .start_local_proxy(&obsolete, DefaultRoute::Vpn)
            .unwrap();
        assert_eq!(status.node_id.as_deref(), Some(obsolete.as_str()));
        controller.stop().unwrap();
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
        assert!(controller.status().proofs.iter().any(|proof| {
            proof.kind == ProofKind::EngineProcess && proof.state == ProofState::Failed
        }));
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
        assert!(controller.status().proofs.iter().any(|proof| {
            proof.kind == ProofKind::LocalScopeOwnership && proof.state == ProofState::Failed
        }));
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
    fn recovery_required_is_sticky_across_monitor_ticks() {
        let controller = controller_with_stop_failure();
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        controller.stop().unwrap_err();
        let before = controller.status();
        {
            let mut state = controller.lock_state();
            state.active.as_mut().unwrap().last_probe = Instant::now() - Duration::from_secs(11);
        }
        controller.monitor_tick();
        let after = controller.status();
        assert_eq!(after.phase, RuntimePhase::RecoveryRequired);
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.proofs, before.proofs);
        assert!(controller.lock_state().active.is_some());
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
    fn crash_data_preserves_ui_startup_and_blocks_import_replacement_until_reviewed() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-recovery-controller-{}",
            random_hex(8).expect("test random")
        ));
        let sessions = root.join("sessions");
        let stale = sessions.join("session-0123456789abcdef0123456789abcdef");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("config.json"), b"fixture-secret").unwrap();
        let proxy = Arc::new(FakeSystemProxy::new(Arc::new(AtomicBool::new(false))));
        let controller = ApplicationController::production_with_recovery(
            sessions.clone(),
            Arc::new(|_| {}),
            proxy,
            None,
            reconcile_stale_sessions,
        )
        .unwrap();
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        let preview = controller.preview_import_content(NODE.into()).unwrap();
        let error = controller.confirm_import(&preview.preview_id).unwrap_err();
        assert_eq!(error.code, PublicErrorCode::RecoveryRequired);
        assert_eq!(error.stage, PublicErrorStage::Import);
        assert!(controller.retry_session_recovery().is_err());
        assert!(stale.join("config.json").exists());

        std::fs::remove_file(stale.join("config.json")).unwrap();
        std::fs::remove_dir(stale).unwrap();
        assert_eq!(
            controller.retry_session_recovery().unwrap().phase,
            RuntimePhase::Disconnected
        );
        assert_eq!(
            controller
                .confirm_import(&preview.preview_id)
                .unwrap()
                .imported,
            1
        );
        drop(controller);
        std::fs::remove_file(root.join("controller.lock")).unwrap();
        std::fs::remove_file(root.join("subscription.json")).unwrap();
        std::fs::remove_dir(sessions).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn second_instance_is_rejected_before_any_startup_recovery() {
        let root = std::env::temp_dir().join(format!(
            "routedeck-instance-controller-{}",
            random_hex(8).unwrap()
        ));
        let proxy = Arc::new(FakeSystemProxy::new(Arc::new(AtomicBool::new(false))));
        let first = ApplicationController::production_with_recovery(
            root.join("sessions"),
            Arc::new(|_| {}),
            proxy.clone(),
            None,
            reconcile_stale_sessions,
        )
        .unwrap();
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        let second = ApplicationController::production_with_recovery(
            root.join("sessions"),
            Arc::new(|_| {}),
            proxy.clone(),
            None,
            reconcile_stale_sessions,
        );
        assert!(matches!(second, Err(error) if error.stage() == "app_instance"));
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        drop(first);
        std::fs::remove_file(root.join("controller.lock")).unwrap();
        if root.join("sessions").exists() {
            std::fs::remove_dir(root.join("sessions")).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn periodic_proof_degrades_after_two_failures_and_recovers_on_success() {
        let proof_enabled = Arc::new(AtomicBool::new(true));
        let (controller, stops, alive) =
            controller_with_prober(Arc::new(ToggleProber(proof_enabled.clone())));
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let ready = controller.status();
        let original_session = controller
            .lock_state()
            .active
            .as_ref()
            .unwrap()
            .session_id
            .clone();
        proof_enabled.store(false, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        let first_failure = controller.status();
        assert_eq!(first_failure.phase, RuntimePhase::LocalProxyReady);
        assert_eq!(first_failure.revision, ready.revision);
        assert_eq!(first_failure.proofs, ready.proofs);
        assert_eq!(first_failure.route_check_ms, ready.route_check_ms);

        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        let degraded = controller.status();
        assert_eq!(degraded.phase, RuntimePhase::Degraded);
        assert!(degraded.revision > ready.revision);
        assert_eq!(degraded.route_check_ms, None);
        assert_eq!(
            degraded
                .proofs
                .iter()
                .find(|proof| proof.kind == ProofKind::SelectedOutboundHttps)
                .unwrap()
                .state,
            ProofState::Failed
        );
        proof_enabled.store(true, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().phase, RuntimePhase::LocalProxyReady);
        assert!(controller.status().error.is_none());
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(
            controller.lock_state().active.as_ref().unwrap().session_id,
            original_session
        );
    }

    #[test]
    fn optional_warm_latency_never_replaces_or_degrades_the_cold_proof() {
        let cold_enabled = Arc::new(AtomicBool::new(true));
        let warm_enabled = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let (controller, _, _, _) = controller_with_system_proxy(Arc::new(WarmFixtureProber {
            cold_enabled: cold_enabled.clone(),
            warm_enabled: warm_enabled.clone(),
            calls: calls.clone(),
            gate: None,
        }));
        let node = import_node(&controller);
        let startup = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        assert_eq!(startup.steady_latency_ms, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        let measured = controller.status();
        assert_eq!(measured.steady_latency_ms, Some(17));
        assert_eq!(measured.route_check_ms, Some(420));
        assert_eq!(
            measured
                .proofs
                .iter()
                .find(|proof| proof.kind == ProofKind::SelectedOutboundHttps)
                .unwrap()
                .latency_ms,
            Some(420)
        );
        warm_enabled.store(false, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().steady_latency_ms, None);
        assert_eq!(controller.status().phase, RuntimePhase::SystemProxyReady);
        assert_eq!(controller.status().proofs, measured.proofs);
        warm_enabled.store(true, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().steady_latency_ms, Some(17));
        let warm_calls = calls.load(Ordering::SeqCst);
        cold_enabled.store(false, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().steady_latency_ms, None);
        assert_eq!(controller.status().phase, RuntimePhase::SystemProxyReady);
        assert_eq!(calls.load(Ordering::SeqCst), warm_calls);
        controller.stop().unwrap();
        assert_eq!(controller.status().steady_latency_ms, None);
    }

    #[test]
    fn warm_latency_is_outside_state_lock_and_cannot_publish_into_a_replacement_session() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (controller, _, _, _) = controller_with_system_proxy(Arc::new(WarmFixtureProber {
            cold_enabled: Arc::new(AtomicBool::new(true)),
            warm_enabled: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            gate: Some((entered.clone(), release.clone())),
        }));
        let controller = Arc::new(controller);
        let node = import_node(&controller);
        let initial = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        let monitor_controller = controller.clone();
        let monitor = thread::spawn(move || monitor_controller.monitor_tick());
        entered.wait();
        // Both observation and teardown must finish while the network sample is blocked.
        assert_eq!(controller.status().phase, RuntimePhase::SystemProxyReady);
        controller.stop().unwrap();
        let replacement = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        assert_ne!(replacement.session_id, initial.session_id);
        release.wait();
        monitor.join().unwrap();
        assert_eq!(controller.status().session_id, replacement.session_id);
        assert_eq!(controller.status().steady_latency_ms, None);
        controller.stop().unwrap();
    }

    #[test]
    fn healthy_same_session_refresh_keeps_previous_warm_sample_until_replacement() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (controller, _, _, _) = controller_with_system_proxy(Arc::new(WarmFixtureProber {
            cold_enabled: Arc::new(AtomicBool::new(true)),
            warm_enabled: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            gate: Some((entered.clone(), release.clone())),
        }));
        let controller = Arc::new(controller);
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        {
            let mut state = controller.lock_state();
            state.status.steady_latency_ms = Some(29);
            state.active.as_mut().unwrap().last_probe = Instant::now() - Duration::from_secs(11);
        }
        let monitor_controller = controller.clone();
        let monitor = thread::spawn(move || monitor_controller.monitor_tick());
        entered.wait();
        assert_eq!(controller.status().phase, RuntimePhase::SystemProxyReady);
        assert_eq!(controller.status().steady_latency_ms, Some(29));
        release.wait();
        monitor.join().unwrap();
        assert_eq!(controller.status().steady_latency_ms, Some(17));
        controller.stop().unwrap();
    }

    #[test]
    fn process_death_during_optional_latency_uses_existing_owned_cleanup_path() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (controller, _, _, alive) = controller_with_system_proxy(Arc::new(WarmFixtureProber {
            cold_enabled: Arc::new(AtomicBool::new(true)),
            warm_enabled: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            gate: Some((entered.clone(), release.clone())),
        }));
        let controller = Arc::new(controller);
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        let monitor_controller = controller.clone();
        let monitor = thread::spawn(move || monitor_controller.monitor_tick());
        entered.wait();
        alive.store(false, Ordering::SeqCst);
        release.wait();
        monitor.join().unwrap();
        assert_ne!(controller.status().phase, RuntimePhase::SystemProxyReady);
        assert_eq!(controller.status().steady_latency_ms, None);
        assert!(controller.status().error.is_some());
    }

    #[test]
    fn steady_latency_is_omitted_by_default_and_cleared_on_transitions_and_errors() {
        assert!(serde_json::to_value(RuntimeStatus::default())
            .unwrap()
            .get("steadyLatencyMs")
            .is_none());
        let (controller, _, _) = controller(false, true, true);
        let mut state = controller.lock_state();
        state.status.steady_latency_ms = Some(17);
        assert_eq!(
            serde_json::to_value(&state.status).unwrap()["steadyLatencyMs"],
            17
        );
        controller.update_status(&mut state, RuntimePhase::Preparing, None, None);
        assert_eq!(state.status.steady_latency_ms, None);
        state.status.steady_latency_ms = Some(17);
        controller.update_status(
            &mut state,
            RuntimePhase::SystemProxyReady,
            None,
            Some(PublicError::fixed(
                PublicErrorCode::RuntimeFailure,
                PublicErrorStage::Monitor,
                "fixture error",
            )),
        );
        assert_eq!(state.status.steady_latency_ms, None);
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
    fn renderer_route_draft_is_ignored_for_local_proxy() {
        let (controller, _, _) = controller(false, true, true);
        let node = import_node(&controller);
        controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let status = controller
            .start_local_proxy(&node, DefaultRoute::Direct)
            .unwrap();
        assert_eq!(status.phase, RuntimePhase::LocalProxyReady);
        assert_eq!(
            controller
                .lock_state()
                .active
                .as_ref()
                .unwrap()
                .default_route,
            DefaultRoute::Vpn
        );
    }

    #[test]
    fn startup_status_and_diagnostics_do_not_wait_for_the_engine_proof() {
        let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let (controller, _, _) = controller_with_prober(Arc::new(BlockingProber {
            calls: AtomicUsize::new(2),
            gate: gate.clone(),
        }));
        let controller = Arc::new(controller);
        let node = import_node(&controller);
        let start_controller = controller.clone();
        let start =
            thread::spawn(move || start_controller.start_local_proxy(&node, DefaultRoute::Vpn));
        let (lock, wake) = &*gate;
        let mut flags = lock.lock().unwrap();
        while !flags.0 {
            flags = wake.wait(flags).unwrap();
        }
        drop(flags);

        let (tx, rx) = mpsc::channel();
        let observer = controller.clone();
        let observation = thread::spawn(move || {
            tx.send((observer.status(), observer.diagnostics().status))
                .unwrap();
        });
        let observed = rx.recv_timeout(Duration::from_millis(500));
        // Always release the worker before asserting, including on regression.
        let mut flags = lock.lock().unwrap();
        flags.1 = true;
        wake.notify_all();
        drop(flags);
        let ready = start.join().unwrap().unwrap();
        observation.join().unwrap();

        let (status, diagnostics) =
            observed.expect("startup observation blocked on lifecycle state");
        assert_eq!(status.phase, RuntimePhase::ProvingTraffic);
        assert_eq!(diagnostics.revision, status.revision);
        assert!(ready.revision > status.revision);
        assert_eq!(controller.status().revision, ready.revision);
        let stopped = controller.stop().unwrap();
        assert_eq!(controller.status().revision, stopped.revision);
        assert_eq!(controller.status().phase, RuntimePhase::Disconnected);
    }

    fn system_routing(default_route: DefaultRoute) -> SystemProxyRouting {
        SystemProxyRouting {
            default_route,
            naive_udp_over_tcp: false,
            apps: vec![SystemProxyAppRoute {
                process_path: r"C:\Program Files\Browser\browser.exe".into(),
                process_name: Some("browser.exe".into()),
                route: if default_route == DefaultRoute::Direct {
                    AppRouteAction::Vpn
                } else {
                    AppRouteAction::Direct
                },
            }],
        }
    }

    fn tun_routing(default_route: DefaultRoute) -> TunRouting {
        TunRouting {
            default_route,
            naive_udp_over_tcp: false,
            stack: TunStack::default(),
            traffic_rules: default_tun_traffic_rules(),
            apps: vec![SystemProxyAppRoute {
                process_path: r"C:\Program Files\Browser\browser.exe".into(),
                process_name: Some("browser.exe".into()),
                route: if default_route == DefaultRoute::Direct {
                    AppRouteAction::Vpn
                } else {
                    AppRouteAction::Direct
                },
            }],
        }
    }

    #[test]
    fn routing_defaults_are_closed_and_backward_compatible() {
        let legacy: TunRouting = serde_json::from_value(serde_json::json!({
            "defaultRoute": "vpn",
            "apps": []
        }))
        .unwrap();
        assert_eq!(legacy.stack, TunStack::Gvisor);
        assert!(!legacy.naive_udp_over_tcp);
        assert_eq!(legacy.traffic_rules, default_tun_traffic_rules());
        let gvisor: TunRouting = serde_json::from_value(serde_json::json!({
            "defaultRoute": "vpn",
            "apps": [],
            "stack": "gvisor"
        }))
        .unwrap();
        assert_eq!(gvisor.stack, TunStack::Gvisor);
        assert_eq!(gvisor.traffic_rules, default_tun_traffic_rules());
        let disabled: TunRouting = serde_json::from_value(serde_json::json!({
            "defaultRoute": "vpn",
            "apps": [],
            "trafficRules": []
        }))
        .unwrap();
        assert!(disabled.traffic_rules.is_empty());
        let explicit_system: TunRouting = serde_json::from_value(serde_json::json!({
            "defaultRoute": "vpn", "apps": [], "stack": "system",
            "naiveUdpOverTcp": true
        }))
        .unwrap();
        assert_eq!(explicit_system.stack, TunStack::System);
        assert!(explicit_system.naive_udp_over_tcp);
        let system_proxy: SystemProxyRouting = serde_json::from_value(serde_json::json!({
            "defaultRoute": "vpn", "apps": []
        }))
        .unwrap();
        assert!(!system_proxy.naive_udp_over_tcp);
        for stack in ["mixed", "Gvisor", ""] {
            assert!(serde_json::from_value::<TunRouting>(serde_json::json!({
                "defaultRoute": "vpn",
                "apps": [],
                "stack": stack
            }))
            .is_err());
        }
        for traffic_rule in [
            serde_json::json!({"network":"icmp","port":443,"action":"block"}),
            serde_json::json!({"network":"UDP","port":443,"action":"block"}),
            serde_json::json!({"network":"udp","port":443,"action":"reject"}),
            serde_json::json!({"network":"udp","port":443,"action":"Block"}),
            serde_json::json!({"network":"udp","port":"443","action":"block"}),
            serde_json::json!({"network":"udp","port":65536,"action":"block"}),
            serde_json::json!({"network":"udp","port":443,"action":"block","extra":true}),
        ] {
            assert!(serde_json::from_value::<TunRouting>(serde_json::json!({
                "defaultRoute": "vpn",
                "apps": [],
                "trafficRules": [traffic_rule]
            }))
            .is_err());
        }
    }

    #[test]
    fn invalid_tun_traffic_rules_fail_before_privilege_or_runtime_work() {
        let (controller, stops, alive) = controller_with_tun(false, true, false);
        let node = import_node(&controller);
        for rules in [
            vec![TunTrafficRule {
                network: crate::config::TunTrafficNetwork::Udp,
                port: 53,
                action: crate::config::TunTrafficAction::Block,
            }],
            vec![default_tun_traffic_rules()[0].clone(); 33],
        ] {
            let mut routing = tun_routing(DefaultRoute::Vpn);
            routing.traffic_rules = rules;
            let error = controller.start_tun(&node, routing).unwrap_err();
            assert_eq!(error.stage, PublicErrorStage::Start);
            assert_eq!(error.message, "TUN traffic rules are invalid");
        }
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(controller.status().phase, RuntimePhase::Disconnected);
    }

    #[test]
    fn active_tun_traffic_rule_change_requires_stop_before_restart() {
        let (controller, stops, _) = controller_with_tun(true, true, false);
        let node = import_node(&controller);
        controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap();
        let mut disabled = tun_routing(DefaultRoute::Vpn);
        disabled.traffic_rules.clear();
        let error = controller.start_tun(&node, disabled).unwrap_err();
        assert_eq!(error.code, PublicErrorCode::ActiveSessionConflict);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        controller.stop().unwrap();
    }

    #[test]
    fn active_tun_stack_change_requires_stop_before_restart() {
        let (controller, stops, _) = controller_with_tun(true, true, false);
        let node = import_node(&controller);
        let mut system = tun_routing(DefaultRoute::Vpn);
        system.stack = TunStack::System;
        controller.start_tun(&node, system).unwrap();
        assert_eq!(
            controller.lock_state().active.as_ref().unwrap().tun_stack,
            Some(TunStack::System)
        );

        let error = controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap_err();
        assert_eq!(error.code, PublicErrorCode::ActiveSessionConflict);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        controller.stop().unwrap();
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn active_naive_udp_over_tcp_change_requires_restart_and_non_naive_ignores_it() {
        let (controller, stops, _) = controller_with_tun(true, true, false);
        let naive = import_node_from(
            &controller,
            "naive+https://fixture-user:fixture-pass@example.test:443",
        );
        controller
            .start_tun(&naive, tun_routing(DefaultRoute::Vpn))
            .unwrap();
        assert!(
            !controller
                .lock_state()
                .active
                .as_ref()
                .unwrap()
                .naive_udp_over_tcp
        );
        let mut enabled = tun_routing(DefaultRoute::Vpn);
        enabled.naive_udp_over_tcp = true;
        let error = controller.start_tun(&naive, enabled).unwrap_err();
        assert_eq!(error.code, PublicErrorCode::ActiveSessionConflict);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        controller.stop().unwrap();

        let non_naive = import_node(&controller);
        controller
            .start_tun(&non_naive, tun_routing(DefaultRoute::Vpn))
            .unwrap();
        let mut ignored = tun_routing(DefaultRoute::Vpn);
        ignored.naive_udp_over_tcp = true;
        controller.start_tun(&non_naive, ignored).unwrap();
        assert!(
            !controller
                .lock_state()
                .active
                .as_ref()
                .unwrap()
                .naive_udp_over_tcp
        );
        controller.stop().unwrap();
    }

    #[test]
    fn foreign_proxy_cleanup_gate_preserves_active_tun_and_blocks_transitions() {
        let (controller, stops, alive) = controller_with_tun(true, true, false);
        let node = import_node(&controller);
        controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap();
        // The fixture proxy backend refuses cleanup. Reaching that backend in
        // a stable TUN session demonstrates that the lifecycle gate permits it;
        // no platform settings are read or changed by this test.
        let error = controller
            .clear_stale_system_proxy(&"a".repeat(64))
            .unwrap_err();
        assert_eq!(error.code, PublicErrorCode::CommandFailed);
        for phase in [RuntimePhase::StartingCore, RuntimePhase::RecoveryRequired] {
            controller.lock_state().status.phase = phase;
            let error = controller
                .clear_stale_system_proxy(&"a".repeat(64))
                .unwrap_err();
            assert_eq!(error.code, PublicErrorCode::ActiveSessionConflict);
        }
        controller.lock_state().status.phase = RuntimePhase::TunReady;
        controller.lock_state().shutting_down = true;
        assert_eq!(
            controller
                .clear_stale_system_proxy(&"a".repeat(64))
                .unwrap_err()
                .code,
            PublicErrorCode::ActiveSessionConflict
        );
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
    }

    #[test]
    fn tun_start_requires_elevation_before_starting_an_engine() {
        let (controller, stops, alive) = controller_with_tun(false, true, false);
        let node = import_node(&controller);

        let error = controller
            .start_tun(&node, tun_routing(DefaultRoute::Direct))
            .unwrap_err();

        assert_eq!(error.stage, PublicErrorStage::Start);
        assert!(error.message.contains("administrator"));
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(controller.status().phase, RuntimePhase::Disconnected);
    }

    #[test]
    fn cancelled_tun_uac_is_reported_as_a_safe_start_cancellation() {
        let public = public_runtime_error(
            RuntimeError::new("tun_uac_cancelled", "TUN permission request was cancelled"),
            &Redactor::default(),
        );

        assert_eq!(public.code, PublicErrorCode::RuntimeFailure);
        assert_eq!(public.stage, PublicErrorStage::Start);
        assert_eq!(
            public.detail.as_deref(),
            Some("TUN permission request was cancelled")
        );
    }

    #[test]
    fn helper_start_failures_preserve_redacted_detail_and_fail_only_engine_proof() {
        for stage in [
            "tun_helper_pipe",
            "tun_helper_protocol",
            "tun_helper_identity",
            "tun_helper_launch",
            "tun_helper_start",
            "tun_helper_exit",
        ] {
            let (controller, _, _) = controller_with_tun(true, true, false);
            let mut state = controller.lock_state();
            ApplicationController::set_proof(
                &mut state,
                ProofKind::EngineConfig,
                ProofState::Passed,
                None,
            );
            ApplicationController::mark_failed_proof(&mut state, stage);
            let proof = |kind| {
                state
                    .status
                    .proofs
                    .iter()
                    .find(|row| row.kind == kind)
                    .unwrap()
                    .state
            };
            assert_eq!(proof(ProofKind::EngineProcess), ProofState::Failed);
            assert_eq!(proof(ProofKind::EngineConfig), ProofState::Passed);
            assert_eq!(proof(ProofKind::SelectedOutboundHttps), ProofState::NotRun);
            assert_eq!(proof(ProofKind::LocalScopeOwnership), ProofState::NotRun);

            let public = public_runtime_error(
                RuntimeError::new(
                    stage,
                    "fixed helper failure (Windows error 232); password=fixture-secret",
                ),
                &Redactor::default().with_secret("fixture-secret"),
            );
            assert_eq!(public.stage, PublicErrorStage::StartEngine);
            let detail = public.detail.unwrap();
            assert!(detail.contains("Windows error 232"));
            assert!(!detail.contains("fixture-secret"));
        }
        for stage in ["start_engine", "tun_helper_unreviewed"] {
            let public = public_runtime_error(
                RuntimeError::new(stage, "arbitrary raw process stderr"),
                &Redactor::default(),
            );
            assert!(public.detail.is_none());
        }
    }

    #[test]
    fn tun_capture_failure_preserves_successful_selected_https_proof() {
        struct CaptureFailProber;
        impl TrafficProber for CaptureFailProber {
            fn prove(&self, _route: &HealthRoute) -> Result<ProofResult, RuntimeError> {
                Ok(ProofResult { latency_ms: 42 })
            }
            fn prove_tun_capture(&self) -> Result<ProofResult, RuntimeError> {
                Err(RuntimeError::new(
                    "tun_capture",
                    "fixture TUN capture failed",
                ))
            }
        }
        let (mut controller, stops, alive) = controller_with_tun(true, true, false);
        controller.services.prober = Arc::new(CaptureFailProber);
        let node = import_node(&controller);
        let error = controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::DisconnectedWithError);
        let selected = status
            .proofs
            .iter()
            .find(|row| row.kind == ProofKind::SelectedOutboundHttps)
            .unwrap();
        assert_eq!(selected.state, ProofState::Passed);
        assert_eq!(selected.latency_ms, Some(42));
        assert_eq!(
            status
                .proofs
                .iter()
                .find(|row| row.kind == ProofKind::LocalScopeOwnership)
                .unwrap()
                .state,
            ProofState::Failed
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(
            controller.diagnostics().lines,
            vec![
                "tun_dns=local_fallback_no_ipv4",
                "tun_capture: fixture TUN capture failed"
            ]
        );
    }

    #[test]
    fn tun_failed_start_retains_first_error_and_separate_cleanup_failure() {
        let (controller, _, _) = controller_with_tun(true, false, true);
        let node = import_node(&controller);
        let error = controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::StopEngine);
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        assert_eq!(
            controller.diagnostics().lines,
            vec![
                "tun_dns=local_fallback_no_ipv4",
                "prove_traffic: fixture selected outbound failed",
                "stop_engine: fixture process refused to stop",
            ]
        );
    }

    #[test]
    fn tun_start_applies_default_and_app_routes_then_stops_only_the_owned_engine() {
        let (controller, stops, alive) = controller_with_tun(true, true, false);
        let node = import_node(&controller);

        let status = controller
            .start_tun(&node, tun_routing(DefaultRoute::Direct))
            .unwrap();

        assert_eq!(status.scope, RuntimeScope::Tun);
        assert_eq!(status.mode, RuntimeMode::Tun);
        assert_eq!(status.phase, RuntimePhase::TunReady);
        assert_eq!(status.route_check_ms, Some(42));
        let state = controller.lock_state();
        let active = state.active.as_ref().unwrap();
        assert_eq!(active.routing.default, DefaultRoute::Direct);
        assert_eq!(active.routing.apps.len(), 1);
        assert_eq!(active.routing.apps[0].action, AppRouteAction::Vpn);
        assert_eq!(active.tun_stack, Some(TunStack::Gvisor));
        drop(state);
        assert!(alive.load(Ordering::SeqCst));

        let stopped = controller.stop().unwrap();
        assert_eq!(stopped.phase, RuntimePhase::Disconnected);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn tun_start_failure_rolls_back_the_owned_engine() {
        let (controller, stops, alive) = controller_with_tun(true, false, false);
        let node = import_node(&controller);
        controller
            .diagnostics
            .lock()
            .unwrap()
            .push("stale attempt".into());

        let error = controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap_err();

        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(
            controller.diagnostics().lines,
            vec![
                "tun_dns=local_fallback_no_ipv4",
                "prove_traffic: fixture selected outbound failed"
            ]
        );
    }

    #[test]
    fn local_health_success_cannot_substitute_for_owned_tun_counter_progress() {
        struct StaticTunChild;

        impl ManagedChild for StaticTunChild {
            fn pid(&self) -> u32 {
                std::process::id()
            }

            fn is_alive(&mut self) -> Result<bool, RuntimeError> {
                Ok(true)
            }

            fn stop(&mut self) -> Result<(), RuntimeError> {
                Ok(())
            }

            fn tun_capture_snapshot(&mut self) -> Result<TunCaptureSnapshot, RuntimeError> {
                Ok(TunCaptureSnapshot {
                    interface_luid: 7,
                    in_octets: 1024,
                    out_octets: 2048,
                })
            }
        }

        let error = prove_tun_capture(&FakeProber(true), &mut StaticTunChild).unwrap_err();
        assert_eq!(error.stage(), "tun_capture");
        assert!(error.message().contains("did not traverse"));
    }

    #[test]
    fn system_proxy_start_failure_records_only_the_current_redacted_attempt() {
        let (controller, _proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(SecretFailProber));
        let node = import_node(&controller);
        controller
            .diagnostics
            .lock()
            .unwrap()
            .push("stale attempt".into());

        let error = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap_err();

        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
        let lines = controller.diagnostics().lines;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("prove_traffic: "));
        assert!(!lines[0].contains("fixture-secret"));
        assert!(!lines[0].contains("stale attempt"));
    }

    #[test]
    fn tun_stop_failure_keeps_session_for_an_honest_recovery_state() {
        let (controller, stops, alive) = controller_with_tun(true, true, true);
        let node = import_node(&controller);
        controller
            .start_tun(&node, tun_routing(DefaultRoute::Vpn))
            .unwrap();

        let error = controller.stop().unwrap_err();

        assert_eq!(error.stage, PublicErrorStage::StopEngine);
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
        assert!(controller.lock_state().active.is_some());
    }

    #[test]
    fn system_proxy_refuses_to_publish_when_ordinary_proxy_route_fails() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(OrdinaryFailProber));
        let node = import_node(&controller);

        let error = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Direct))
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::ProveTraffic);
        assert_eq!(proxy.publishes.load(Ordering::SeqCst), 0);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
    }

    #[test]
    fn system_proxy_applies_saved_direct_default_and_application_exception() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);

        let status = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Direct))
            .unwrap();
        assert_eq!(status.scope, RuntimeScope::SystemProxy);
        assert_eq!(status.mode, RuntimeMode::SystemProxy);
        assert_eq!(status.phase, RuntimePhase::SystemProxyReady);
        assert_eq!(status.route_check_ms, Some(42));
        assert!(status.proofs.iter().any(|proof| {
            proof.kind == ProofKind::SelectedOutboundHttps
                && proof.state == ProofState::Passed
                && proof.latency_ms == status.route_check_ms
        }));
        assert_eq!(proxy.publishes.load(Ordering::SeqCst), 1);
        assert!(status.proofs.iter().any(|proof| {
            proof.kind == ProofKind::SystemProxyOwnership && proof.state == ProofState::Passed
        }));
        let state = controller.lock_state();
        let active = state.active.as_ref().unwrap();
        assert_eq!(active.routing.default, DefaultRoute::Direct);
        assert_eq!(active.routing.apps.len(), 1);
        assert_eq!(
            active.routing.apps[0].process_path,
            r"C:\Program Files\Browser\browser.exe"
        );
        assert_eq!(active.routing.apps[0].action, AppRouteAction::Vpn);
        assert_eq!(active.routing.lan, LanPolicy::Direct);
        drop(state);

        controller.stop().unwrap();
        assert!(proxy.restore_saw_live_core.load(Ordering::SeqCst));
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn system_proxy_reports_selected_health_latency_not_direct_ingress_latency() {
        let (controller, _proxy, _stops, _alive) =
            controller_with_system_proxy(Arc::new(DistinctLatencyProber));
        let node = import_node(&controller);

        let status = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Direct))
            .unwrap();

        assert_eq!(status.route_check_ms, Some(17));
        assert!(status.proofs.iter().any(|proof| {
            proof.kind == ProofKind::SelectedOutboundHttps
                && proof.state == ProofState::Passed
                && proof.latency_ms == Some(17)
        }));
    }

    #[test]
    fn repeated_identical_system_proxy_start_reuses_the_verified_session() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        let first = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Direct))
            .unwrap();

        let second = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Direct))
            .unwrap();

        assert_eq!(second.session_id, first.session_id);
        assert_eq!(proxy.publishes.load(Ordering::SeqCst), 1);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
    }

    #[test]
    fn system_proxy_stop_preserves_foreign_state_and_reports_conflict() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        proxy.foreign.store(true, Ordering::SeqCst);

        let error = controller.stop().unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SystemProxyOwnership);
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn system_proxy_restore_failure_keeps_the_live_core_available_for_recovery() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        proxy.fail_restore.store(true, Ordering::SeqCst);

        let error = controller.stop().unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SystemProxyRestore);
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
    }

    #[test]
    fn monitor_listener_loss_retains_live_proxy_until_restore_can_be_retried() {
        let (mut controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let listener = Arc::new(AtomicBool::new(true));
        controller.services.listener = Arc::new(ToggleListener(listener.clone()));
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        let original = controller.status();
        listener.store(false, Ordering::SeqCst);
        proxy.fail_restore.store(true, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);

        controller.monitor_tick();

        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        let ports = |status: RuntimeStatus| {
            status
                .ports
                .map(|ports| (ports.http, ports.socks, ports.health))
        };
        assert_eq!(ports(controller.status()), ports(original.clone()));
        assert_eq!(controller.status().session_id, original.session_id);
        assert!(controller.lock_state().active.is_some());
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
        assert!(proxy.restore_saw_live_core.load(Ordering::SeqCst));
        assert!(controller.retry_session_recovery().is_err());
        assert!(controller.lock_state().active.is_some());

        proxy.fail_restore.store(false, Ordering::SeqCst);
        assert_eq!(
            controller.retry_session_recovery().unwrap().phase,
            RuntimePhase::Disconnected
        );
        assert!(controller.lock_state().active.is_none());
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn monitor_process_death_keeps_recovery_handle_when_proxy_restore_fails() {
        let (controller, proxy, _, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        alive.store(false, Ordering::SeqCst);
        proxy.fail_restore.store(true, Ordering::SeqCst);
        controller.monitor_tick();
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        assert!(controller.lock_state().active.is_some());
        proxy.fail_restore.store(false, Ordering::SeqCst);
        assert_eq!(
            controller.retry_session_recovery().unwrap().phase,
            RuntimePhase::Disconnected
        );
        assert!(controller.lock_state().active.is_none());
    }

    #[test]
    fn monitor_cleanup_failure_retains_child_and_does_not_restore_proxy_twice() {
        let (mut controller, proxy, stops, alive) =
            controller_with_system_proxy_stop_behavior(Arc::new(FakeProber(true)), true);
        let listener = Arc::new(AtomicBool::new(true));
        controller.services.listener = Arc::new(ToggleListener(listener.clone()));
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        listener.store(false, Ordering::SeqCst);
        controller.lock_state().active.as_mut().unwrap().last_probe =
            Instant::now() - Duration::from_secs(11);
        controller.monitor_tick();
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        assert!(controller.lock_state().active.is_some());
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        assert!(controller.retry_session_recovery().is_err());
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        assert!(controller.lock_state().active.is_some());
    }

    #[test]
    fn ambiguous_system_proxy_publish_failure_keeps_the_core_alive() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        proxy.fail_publish.store(true, Ordering::SeqCst);

        let error = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Direct))
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SystemProxyRestore);
        assert_eq!(controller.status().phase, RuntimePhase::RecoveryRequired);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
    }

    #[test]
    fn rejected_foreign_proxy_publish_stops_local_core_without_attempting_restore() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        proxy.reject_publish_unchanged.store(true, Ordering::SeqCst);
        let error = controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap_err();
        assert_eq!(error.stage, PublicErrorStage::SystemProxyPublish);
        assert_eq!(
            controller.status().phase,
            RuntimePhase::DisconnectedWithError
        );
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 0);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
        assert!(controller.lock_state().active.is_none());
    }

    #[test]
    fn shutdown_is_prevented_until_system_proxy_restore_succeeds() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy(Arc::new(FakeProber(true)));
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();
        proxy.fail_restore.store(true, Ordering::SeqCst);

        assert!(!controller.shutdown());
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));

        proxy.fail_restore.store(false, Ordering::SeqCst);
        assert!(controller.shutdown());
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn stop_retry_does_not_restore_system_proxy_twice_after_core_stop_failure() {
        let (controller, proxy, stops, alive) =
            controller_with_system_proxy_stop_behavior(Arc::new(FakeProber(true)), true);
        let node = import_node(&controller);
        controller
            .start_system_proxy(&node, system_routing(DefaultRoute::Vpn))
            .unwrap();

        assert_eq!(
            controller.stop().unwrap_err().stage,
            PublicErrorStage::StopEngine
        );
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        assert!(alive.load(Ordering::SeqCst));

        assert_eq!(
            controller.stop().unwrap_err().stage,
            PublicErrorStage::StopEngine
        );
        assert_eq!(proxy.restores.load(Ordering::SeqCst), 1);
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
    }

    #[test]
    fn confirming_a_new_private_node_revision_never_reuses_a_ready_session() {
        let (controller, _, _) = controller(false, true, true);
        let node = import_node(&controller);
        let first = controller
            .start_local_proxy(&node, DefaultRoute::Vpn)
            .unwrap();
        let repeated = controller.preview_import_content(NODE.into()).unwrap();
        let error = controller.confirm_import(&repeated.preview_id).unwrap_err();
        assert_eq!(error.code, PublicErrorCode::ActiveSessionConflict);
        let status = controller.status();
        assert_eq!(status.phase, RuntimePhase::LocalProxyReady);
        assert_eq!(status.session_id, first.session_id);
        assert!(controller
            .lock_state()
            .pending
            .contains_key(&repeated.preview_id));
    }
}
