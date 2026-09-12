import { defaultTrafficRules, RouteDeckError } from "./model.ts";
import type {
  AppNotice,
  ConnectionMode,
  ConnectionPhase,
  ConnectionProof,
  ControllerSnapshot,
  Protocol,
  RouteDeckController,
  RoutingConfig,
  RunningApplication,
  Server,
  SettingsConfig,
  SubscriptionImportSource,
  SubscriptionPreview,
  TunPathChoice,
} from "./model.ts";
import {
  ContractViolation,
  RuntimeRevisionGate,
  isVerifiedLocalReady,
  isVerifiedSystemProxyReady,
  isVerifiedTunReady,
  parseConfirmedImport,
  parseConfirmedNodes,
  parseDiagnostics,
  parseImportPreview,
  parsePublicError,
  parseRunningApplications,
  parseRuntimeStatus,
  parseUnitResponse,
  type ImportPreviewDto,
  type ConfirmedNodeDto,
  type ProofStateDto,
  type PublicErrorDto,
  type RuntimePhaseDto,
  type RuntimeProofDto,
  type RuntimeStatusDto,
} from "./tauriContract.ts";

const RUNTIME_EVENT = "routedeck://runtime-phase";
const ROUTING_STORAGE_KEY = "routedeck.routing.v1";
const PREFERENCES_STORAGE_KEY = "routedeck.preferences.v1";
const SELECTION_STORAGE_KEY = "routedeck.selection.v1";

function loadSelection(): { selectedServerId: string; mode: ConnectionMode } {
  const fallback = { selectedServerId: "", mode: "proxy" as const };
  try {
    const raw = typeof window === "undefined" ? null : window.localStorage.getItem(SELECTION_STORAGE_KEY);
    if (!raw || raw.length > 1024) return fallback;
    const value = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1
      || Object.keys(value).some((key) => !["version", "selectedServerId", "mode"].includes(key))
      || typeof value.selectedServerId !== "string" || value.selectedServerId.length > 256
      || !/^[a-zA-Z0-9._:-]*$/.test(value.selectedServerId)
      || !["proxy", "tun"].includes(value.mode)) return fallback;
    return { selectedServerId: value.selectedServerId, mode: value.mode };
  } catch { return fallback; }
}

function saveSelection(selectedServerId: string, mode: ConnectionMode): void {
  try {
    if (typeof window !== "undefined") window.localStorage.setItem(SELECTION_STORAGE_KEY, JSON.stringify({ version: 1, selectedServerId, mode }));
  } catch { throw new RouteDeckError("preferences-save-failed"); }
}

export interface TauriTransport {
  invoke(command: string, arguments_?: Record<string, unknown>): Promise<unknown>;
  listen(event: string, handler: (payload: unknown) => void): Promise<() => void>;
}

export type TauriTransportLoader = () => Promise<TauriTransport>;

export const loadTauriTransport: TauriTransportLoader = async () => {
  const [{ invoke }, { listen }] = await Promise.all([
    import("@tauri-apps/api/core"),
    import("@tauri-apps/api/event"),
  ]);
  return {
    invoke: (command, arguments_) => invoke(command, arguments_),
    listen: async (event, handler) => listen(event, (message) => handler(message.payload)),
  };
};

const emptyProofs = (): ConnectionProof[] => [
  { id: "config", label: "Конфигурация", state: "idle", summary: "Не проверялась" },
  { id: "core", label: "Ядро", state: "idle", summary: "Не запущено" },
  { id: "local-ingress", label: "Локальный прокси", state: "idle", summary: "Не проверялся" },
  { id: "windows-mode", label: "Прокси Windows", state: "idle", summary: "Не включён" },
  { id: "outbound-proof", label: "Доступность интернета", state: "idle", summary: "Не проверялся" },
  { id: "egress-ip", label: "VPN IP", state: "skipped", summary: "Пока не измеряется" },
];

const defaultSettings = (): SettingsConfig => ({
  startMinimized: false,
  closeBehavior: "tray",
  httpPort: 2080,
  socksPort: 2081,
  proxyConflictPolicy: "never-overwrite",
  theme: "dark",
  subscriptionRefreshHours: 0,
});

export function validatedRouting(value: unknown): RoutingConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RouteDeckError("invalid-routing");
  const candidate = value as Partial<RoutingConfig>;
  if (Object.keys(candidate).some((key) => !["defaultRoute", "tunStack", "naiveUdpOverTcp", "trafficRules", "apps"].includes(key))
    || (candidate.defaultRoute !== "direct" && candidate.defaultRoute !== "vpn")
    || (candidate.tunStack !== undefined && candidate.tunStack !== "system" && candidate.tunStack !== "gvisor")
    || (candidate.naiveUdpOverTcp !== undefined && typeof candidate.naiveUdpOverTcp !== "boolean")
    || !Array.isArray(candidate.apps) || candidate.apps.length > 256) throw new RouteDeckError("invalid-routing");
  const validText = (text: unknown, maxBytes: number): text is string => typeof text === "string" && Boolean(text.trim())
    && !/[\u0000-\u001f\u007f-\u009f]/.test(text) && new TextEncoder().encode(text).length <= maxBytes;
  const apps = candidate.apps.map((app) => {
    if (!app || typeof app !== "object" || Array.isArray(app) || Object.keys(app).some((key) => !["id", "name", "path", "route"].includes(key))
      || !validText(app.id, 4096) || !validText(app.name, 260) || !validText(app.path, 4096) || !/[\\/]/.test(app.path)
      || !["inherit", "direct", "vpn"].includes(app.route)) throw new RouteDeckError("invalid-routing");
    return { id: app.id, name: app.name.trim(), path: app.path.trim().replaceAll("/", "\\"), route: app.route };
  });
  if (new Set(apps.map((app) => app.id)).size !== apps.length || new Set(apps.map((app) => app.path.toLocaleLowerCase("en-US"))).size !== apps.length) throw new RouteDeckError("invalid-routing");
  // Missing means migration from an older version; an explicitly empty list
  // must stay empty so removing the compatibility rule survives a restart.
  const rawRules = candidate.trafficRules === undefined ? defaultTrafficRules() : candidate.trafficRules;
  if (!Array.isArray(rawRules) || rawRules.length > 32) throw new RouteDeckError("invalid-routing");
  const trafficRules = rawRules.map((rule) => {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)
      || Object.keys(rule).some((key) => !["id", "enabled", "network", "port", "action"].includes(key))
      || !validText(rule.id, 128) || typeof rule.enabled !== "boolean"
      || !["tcp", "udp"].includes(rule.network) || !Number.isInteger(rule.port)
      || rule.port < 1 || rule.port > 65535 || rule.port === 53
      || !["block", "direct", "vpn"].includes(rule.action)) throw new RouteDeckError("invalid-routing");
    return { id: rule.id, enabled: rule.enabled, network: rule.network, port: rule.port, action: rule.action };
  });
  if (new Set(trafficRules.map((rule) => rule.id)).size !== trafficRules.length) throw new RouteDeckError("invalid-routing");
  return { defaultRoute: candidate.defaultRoute, tunStack: candidate.tunStack ?? "gvisor", naiveUdpOverTcp: candidate.naiveUdpOverTcp ?? false, trafficRules, apps };
}

export function activeTrafficRules(routing: RoutingConfig) {
  return routing.trafficRules.filter((rule) => rule.enabled).map(({ network, port, action }) => ({ network, port, action }));
}

export function effectiveTunKey(routing: RoutingConfig): string {
  return JSON.stringify([routing.tunStack, activeTrafficRules(routing)]);
}

export function effectiveRoutingKey(routing: RoutingConfig): string {
  return JSON.stringify([routing.defaultRoute, routing.apps.filter((app) => app.route !== "inherit").map((app) => [app.path, app.route]).sort((a, b) => a[0].localeCompare(b[0]))]);
}

function loadRouting(): RoutingConfig {
  if (typeof window === "undefined") return { defaultRoute: "direct", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [] };
  try {
    const stored = window.localStorage.getItem(ROUTING_STORAGE_KEY);
    if (!stored || stored.length > 3_000_000) return { defaultRoute: "direct", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [] };
    return validatedRouting(JSON.parse(stored));
  } catch {
    return { defaultRoute: "direct", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [] };
  }
}

function loadSettings(): SettingsConfig {
  const fallback = defaultSettings();
  if (typeof window === "undefined") return fallback;
  try {
    const stored = window.localStorage.getItem(PREFERENCES_STORAGE_KEY);
    if (!stored || stored.length > 256) return fallback;
    const value = JSON.parse(stored);
    if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1
      || Object.keys(value).some((key) => !["version", "theme", "subscriptionRefreshHours"].includes(key))
      || !["dark", "light", "system"].includes(value.theme) || ![0, 6, 24].includes(value.subscriptionRefreshHours)) return fallback;
    return { ...fallback, theme: value.theme, subscriptionRefreshHours: value.subscriptionRefreshHours };
  } catch { return fallback; }
}

const initialTauriSnapshot = (): ControllerSnapshot => ({
  isDemo: false,
  runtimeScope: "system-proxy",
  backendAvailable: true,
  phase: "disconnected",
  mode: loadSelection().mode,
  selectedServerId: loadSelection().selectedServerId,
  servers: [],
  proofs: emptyProofs(),
  notice: {
    id: "backend-initializing",
    kind: "info",
    title: "Запускаем RouteDeck",
    body: "Подготавливаем подключение.",
  },
  routing: loadRouting(),
  settings: loadSettings(),
  environment: {
    otherVpnDetected: false,
    systemProxyOwner: "none",
    physicalAdapters: [],
  },
  diagnostics: {
    running: false,
    steps: emptyProofs(),
    sanitizedLog: [],
    systemProxy: { state: "unavailable", endpoint: null, detail: "Состояние ещё не проверено.", cleanupToken: null },
  },
  subscriptionName: "Подписка не импортирована",
  subscriptionUpdatedAt: "—",
});

export function runtimePhaseToConnectionPhase(phase: RuntimePhaseDto): ConnectionPhase {
  switch (phase) {
    case "disconnected":
      return "disconnected";
    case "preparing":
    case "validating_config":
      return "validating-config";
    case "starting_core":
      return "starting-core";
    case "verifying_listener":
      return "checking-local-ingress";
    case "proving_traffic":
      return "verifying-outbound";
    case "outbound_verified":
      return "verifying-outbound";
    case "applying_system_proxy":
      return "applying-windows-mode";
    case "local_proxy_ready":
      return "degraded";
    case "system_proxy_ready":
    case "tun_ready":
      return "connected";
    case "degraded":
      return "degraded";
    case "restoring_system_proxy":
    case "rolling_back":
    case "stopping_core":
      return "disconnecting";
    case "blocked_by_conflict":
      return "blocked-by-conflict";
    case "disconnected_with_error":
    case "recovery_required":
      return "failed";
  }
}

function uiProofState(state: ProofStateDto): ConnectionProof["state"] {
  switch (state) {
    case "not_run": return "idle";
    case "pending": return "running";
    case "passed": return "pass";
    case "failed": return "fail";
  }
}

function proofByKind(status: RuntimeStatusDto, kind: RuntimeProofDto["kind"]): RuntimeProofDto | undefined {
  return status.proofs.find((proof) => proof.kind === kind);
}

function proofSummary(state: ConnectionProof["state"], pass: string): string {
  switch (state) {
    case "pass": return pass;
    case "running": return "Проверяется…";
    case "fail": return "Проверка не пройдена";
    case "warn": return "Требует внимания";
    case "skipped": return "Недоступно";
    case "idle": return "Не проверялось";
  }
}

function projectSingleProof(
  status: RuntimeStatusDto,
  kind: RuntimeProofDto["kind"],
  id: ConnectionProof["id"],
  label: string,
  pass: string,
  value?: string,
): ConnectionProof {
  const backendProof = proofByKind(status, kind);
  const state = backendProof ? uiProofState(backendProof.state) : "idle";
  return {
    id,
    label,
    state,
    summary: proofSummary(state, pass),
    value,
    durationMs: backendProof?.latencyMs,
  };
}

function projectIngressProof(status: RuntimeStatusDto): ConnectionProof {
  const members = ["http_listener", "socks_listener", "health_listener"]
    .map((kind) => proofByKind(status, kind as RuntimeProofDto["kind"]))
    .filter((proof): proof is RuntimeProofDto => Boolean(proof));
  let state: ConnectionProof["state"] = "idle";
  if (members.some((proof) => proof.state === "failed")) state = "fail";
  else if (members.some((proof) => proof.state === "pending")) state = "running";
  else if (members.length === 3 && members.every((proof) => proof.state === "passed")) state = "pass";
  const value = status.ports ? `HTTP 127.0.0.1:${status.ports.http} · SOCKS 127.0.0.1:${status.ports.socks}` : undefined;
  return {
    id: "local-ingress",
    label: "Локальный прокси",
    state,
    summary: proofSummary(state, "Локальный прокси работает"),
    value,
    durationMs: Math.max(0, ...members.map((proof) => proof.latencyMs ?? 0)) || undefined,
  };
}

export function projectRuntimeProofs(status: RuntimeStatusDto): ConnectionProof[] {
  const config = projectSingleProof(status, "engine_config", "config", "Конфигурация", "Ядро приняло конфигурацию");
  const core = projectSingleProof(status, "engine_process", "core", "Ядро", "Прокси-ядро запущено", status.engineVersion);
  const ingress = projectIngressProof(status);
  const outbound = projectSingleProof(
    status,
    "selected_outbound_https",
    "outbound-proof",
    "Доступность интернета",
    "Полный HTTPS-запрос через VPN выполнен",
    status.routeCheckMs === undefined ? undefined : `${status.routeCheckMs} мс`,
  );
  const windowsProxy = status.scope === "tun"
    ? projectSingleProof(status, "local_scope_ownership", "windows-mode", "TUN", "TUN включён")
    : projectSingleProof(
      status,
      "system_proxy_ownership",
      "windows-mode",
      "Прокси Windows",
      "Системный прокси включён",
      status.scope === "system_proxy" && status.ports ? `127.0.0.1:${status.ports.http}` : undefined,
    );
  return [
    config,
    core,
    ingress,
    windowsProxy,
    outbound,
    {
      id: "egress-ip",
      label: "VPN egress IP",
      state: "skipped",
      summary: "Не измерялся",
    },
  ];
}

function runtimeNotice(status: RuntimeStatusDto): AppNotice | undefined {
  if (isVerifiedSystemProxyReady(status) || isVerifiedTunReady(status)) return undefined;
  if (isVerifiedLocalReady(status)) {
    const endpoint = status.ports ? `127.0.0.1:${status.ports.http}` : "локальном порту";
    return {
      id: "local-proxy-only",
      kind: "warning",
      title: "Локальный прокси проверен, но режим Windows не применён",
      body: `Трафик через выбранный сервер подтверждён на ${endpoint}. Системный прокси и TUN пока не включены, поэтому обычные приложения продолжают использовать прежний маршрут.`,
      redactedDetail: "Обычные приложения продолжат использовать прежний маршрут, пока системный прокси не включён.",
    };
  }
  if (status.phase === "blocked_by_conflict" || status.error?.stage === "system_proxy_ownership") {
    return {
      id: "system-proxy-conflict",
      kind: "error",
      title: "Прокси Windows изменён другой программой",
      body: "RouteDeck сохранил её настройки. Остановите другой VPN или прокси, затем отключите RouteDeck и подключитесь снова.",
    };
  }
  if (status.phase === "recovery_required") {
    if (status.error?.stage === "system_proxy_restore" && status.ports) {
      return {
        id: "system-proxy-recovery-required",
        kind: "error",
        title: "Не удалось вернуть настройки прокси Windows",
        body: "Локальный прокси пока остаётся запущенным. Устраните конфликт с другой VPN-программой и нажмите «Повторить».",
      };
    }
    if (status.error?.stage === "session_recovery") {
      return {
        id: "session-recovery-required",
        kind: "error",
        title: "Осталась незавершённая сессия",
        body: "RouteDeck не запускает новое подключение, пока состояние предыдущей сессии не будет восстановлено. Нажмите «Повторить».",
      };
    }
    return {
      id: "session-recovery-required",
      kind: "error",
      title: "Не удалось завершить предыдущую операцию",
      body: "RouteDeck сохранил текущее состояние для повторной попытки. Нажмите «Повторить» или откройте диагностику.",
    };
  }
  if (status.error) {
    return {
      id: `runtime-${status.error.code}`,
      kind: "error",
      title: "Подключение требует внимания",
      body: "RouteDeck не смог завершить операцию. Повторите попытку или откройте диагностику.",
      redactedDetail: status.error.detail,
    };
  }
  return undefined;
}

function protocolName(protocol: ImportPreviewDto["nodes"][number]["protocol"]): Protocol {
  switch (protocol) {
    case "vless": return "VLESS";
    case "hysteria2": return "Hysteria2";
    case "naive": return "Naive";
  }
}

function projectConfirmedNodes(nodes: readonly ConfirmedNodeDto[]): Server[] {
  return nodes.map((node) => ({
    id: node.id,
    name: node.displayName,
    country: "—",
    protocol: protocolName(node.protocol),
    detail: node.insecureTls ? "Отключена проверка TLS" : "Импортировано",
    source: node.sourceName ?? "Подписка",
    sourceId: node.sourceId,
    sourceKind: node.sourceKind,
    sourceRefreshable: node.sourceRefreshable,
    sourceUpdatedAtMs: node.sourceUpdatedAtMs,
    latencyState: "unavailable",
  }));
}

function projectRuntimeLatency(servers: readonly Server[], status: RuntimeStatusDto): Server[] {
  const latencyMs = isVerifiedSystemProxyReady(status) || isVerifiedTunReady(status)
    ? status.steadyLatencyMs
    : undefined;
  return servers.map((server) => latencyMs !== undefined && server.id === status.nodeId
    ? {
      ...server,
      latencyState: "ready",
      latencyMs,
      checkedAt: undefined,
    }
    : {
      ...server,
      latencyState: "unavailable",
      latencyMs: undefined,
      checkedAt: undefined,
    });
}

function routeDeckErrorFromBackend(error: PublicErrorDto): RouteDeckError {
  if (error.code === "runtime_failure" && error.stage === "start"
    && error.detail === "TUN permission request was cancelled") {
    return new RouteDeckError("tun-uac-cancelled");
  }
  if (error.code === "runtime_failure" && error.stage === "start"
    && error.message === "TUN requires RouteDeck to be run as administrator") {
    return new RouteDeckError("tun-admin-required");
  }
  switch (error.code) {
    case "import_rejected":
      if (error.message === "import.source_name.invalid") return new RouteDeckError("invalid-source-name");
      if (error.message === "import.library.limit") return new RouteDeckError("server-library-full");
      if (error.message === "subscription.url_required") return new RouteDeckError("invalid-subscription-url");
      if (error.message === "subscription.refresh_manual") return new RouteDeckError("capability-unavailable");
      if (error.message === "subscription.refresh_incomplete") return new RouteDeckError("subscription-refresh-incomplete");
      if (["subscription.source_missing", "subscription.source_changed", "subscription.source_invalid"].includes(error.message)) return new RouteDeckError("source-changed");
      return new RouteDeckError("subscription-import-rejected");
    case "active_session_conflict":
      if (error.message === "switch_server.not_prepared") return new RouteDeckError("server-switch-not-prepared");
      if (error.message === "switch_server.uncertain") return new RouteDeckError("server-switch-uncertain");
      if (error.stage === "import") return new RouteDeckError("import-requires-disconnect");
      return new RouteDeckError("runtime-failure", error.detail);
    case "preview_missing":
    case "preview_token_invalid":
      return new RouteDeckError("stale-subscription-preview");
    case "node_not_found":
      return new RouteDeckError("node-not-selected");
    case "subscription_url_invalid":
      return new RouteDeckError("invalid-subscription-url");
    case "subscription_policy_blocked":
      return new RouteDeckError("subscription-policy-blocked");
    case "subscription_fetch_failed":
      return new RouteDeckError("subscription-fetch-failed");
    case "subscription_response_too_large":
      return new RouteDeckError("subscription-response-too-large");
    case "subscription_fetch_timeout":
      return new RouteDeckError("subscription-fetch-timeout");
    case "subscription_invalid_encoding":
      return new RouteDeckError("subscription-invalid-encoding");
    default:
      return new RouteDeckError("runtime-failure", error.detail);
  }
}

export class TauriController implements RouteDeckController {
  private snapshot = initialTauriSnapshot();
  private readonly listeners = new Set<() => void>();
  private readonly revisions = new RuntimeRevisionGate();
  private readonly initialization: Promise<void>;
  private transport?: TauriTransport;
  private unlisten?: () => void;
  private disposed = false;
  private boundaryFailed = false;
  private runtime?: RuntimeStatusDto;
  private pendingImport?: { dto: ImportPreviewDto; projected: SubscriptionPreview };
  private importGeneration = 0;
  private confirmingImport = false;
  private beforeUnload?: () => void;
  // One queue owns all lifecycle mutations; desired state may change while IPC
  // is awaiting UAC or a network probe. Every start re-reads the latest intent.
  private operationTail: Promise<void> = Promise.resolve();
  private queuedOperations = 0;
  private wantsConnection = false;
  private intentRevision = 0;
  private routingRevision = 0;
  private runtimeRoutingRevision = 0;
  private diagnosticsGeneration = 0;
  private proxyCleanupPending = false;

  constructor(loader: TauriTransportLoader = loadTauriTransport) {
    if (typeof window !== "undefined") {
      this.beforeUnload = () => this.dispose();
      window.addEventListener("beforeunload", this.beforeUnload, { once: true });
    }
    this.initialization = this.initialize(loader);
  }

  private async initialize(loader: TauriTransportLoader): Promise<void> {
    try {
      const transport = await loader();
      if (this.disposed) return;
      this.transport = transport;
      const unlisten = await transport.listen(RUNTIME_EVENT, (payload) => this.receiveRuntime(payload));
      if (this.disposed) {
        unlisten();
        return;
      }
      this.unlisten = unlisten;
      // Listen first. If an event wins this race, RuntimeRevisionGate rejects
      // the older invoke snapshot instead of regressing the UI.
      const status = parseRuntimeStatus(await transport.invoke("runtime_status"));
      this.acceptRuntime(status);
      const restoredNodes = parseConfirmedNodes(await transport.invoke("confirmed_nodes"));
      if (this.disposed || this.boundaryFailed) return;
      const authoritativeStatus = this.runtime ?? status;
      if (this.intentRevision === 0) {
        this.wantsConnection = this.hasRuntimeSession();
        if (this.hasRuntimeSession()) this.publish({ mode: authoritativeStatus.mode === "tun" ? "tun" : "proxy" });
      }
      const servers = projectRuntimeLatency(projectConfirmedNodes(restoredNodes), authoritativeStatus);
      const activeNodeId = this.runtime?.nodeId;
      this.publish({
        servers,
        selectedServerId: activeNodeId && servers.some((server) => server.id === activeNodeId)
          ? activeNodeId
          : servers.some((server) => server.id === this.snapshot.selectedServerId) ? this.snapshot.selectedServerId : servers[0]?.id ?? "",
        subscriptionName: servers.length > 0 ? "Подписка" : "Подписка не импортирована",
        subscriptionUpdatedAt: servers.length > 0 ? "сохранена" : "—",
      });
      if (!this.boundaryFailed && this.snapshot.notice?.id === "backend-initializing") {
        this.publish({ notice: runtimeNotice(authoritativeStatus) });
      }
    } catch (error) {
      this.failBoundary(error instanceof ContractViolation ? "backend-response-invalid" : "backend-unavailable");
    }
  }

  ready = async (): Promise<void> => this.initialization;

  private publish(update: Partial<ControllerSnapshot>): void {
    this.snapshot = { ...this.snapshot, ...update };
    this.listeners.forEach((listener) => listener());
  }

  private receiveRuntime(payload: unknown): void {
    if (this.boundaryFailed || this.disposed) return;
    try {
      this.acceptRuntime(parseRuntimeStatus(payload));
    } catch {
      this.failBoundary("backend-response-invalid");
    }
  }

  private acceptRuntime(status: RuntimeStatusDto): void {
    if (this.boundaryFailed || !this.revisions.accept(status)) return;
    this.diagnosticsGeneration += 1;
    this.runtime = status;
    if (this.queuedOperations === 0 && ["disconnected", "disconnected_with_error", "recovery_required", "blocked_by_conflict"].includes(status.phase)) this.wantsConnection = false;
    const activeMode = status.phase !== "disconnected" && status.phase !== "disconnected_with_error" && status.mode !== "local_only"
      ? status.mode === "tun" ? "tun" : "proxy"
      : undefined;
    this.publish({
      backendAvailable: true,
      activeMode,
      activeServerId: activeMode ? status.nodeId : undefined,
      routingPending: this.hasRuntimeSession() && this.routingRevision !== this.runtimeRoutingRevision,
      servers: projectRuntimeLatency(this.snapshot.servers, status),
      runtimeScope: status.scope === "tun"
        ? "tun"
        : status.scope === "system_proxy"
          ? "system-proxy"
          : status.phase === "disconnected"
            ? this.snapshot.mode === "tun" ? "tun" : "system-proxy"
            : "local-only",
      phase: runtimePhaseToConnectionPhase(status.phase),
      proofs: projectRuntimeProofs(status),
      notice: runtimeNotice(status),
      diagnostics: this.snapshot.diagnostics.systemProxy.cleanupToken
        ? { ...this.snapshot.diagnostics, systemProxy: { ...this.snapshot.diagnostics.systemProxy, cleanupToken: null } }
        : this.snapshot.diagnostics,
    });
  }

  private failBoundary(code: "backend-unavailable" | "backend-response-invalid"): void {
    this.boundaryFailed = true;
    this.publish({
      backendAvailable: false,
      phase: "failed",
      proofs: emptyProofs().map((proof) => ({ ...proof, state: "skipped", summary: "Не удалось проверить" })),
      notice: {
        id: code,
        kind: "error",
        title: code === "backend-response-invalid" ? "Не удалось обновить состояние" : "RouteDeck недоступен",
        body: code === "backend-response-invalid"
          ? "Не удалось прочитать состояние подключения. Перезапустите RouteDeck."
          : "Управление подключением сейчас недоступно. Перезапустите RouteDeck.",
        redactedDetail: "Перезапустите RouteDeck и повторите попытку.",
      },
    });
  }

  private async requireTransport(): Promise<TauriTransport> {
    await this.initialization;
    if (this.boundaryFailed || !this.transport || this.disposed) throw new RouteDeckError("backend-unavailable");
    return this.transport;
  }

  private invokeError(error: unknown): RouteDeckError {
    try {
      return routeDeckErrorFromBackend(parsePublicError(error));
    } catch (contractError) {
      if (contractError instanceof ContractViolation) {
        this.failBoundary("backend-response-invalid");
        return new RouteDeckError("backend-response-invalid");
      }
      return new RouteDeckError("runtime-failure");
    }
  }

  private async invokeStatus(command: string, arguments_?: Record<string, unknown>): Promise<void> {
    const transport = await this.requireTransport();
    let raw: unknown;
    try {
      raw = await transport.invoke(command, arguments_);
    } catch (error) {
      throw this.invokeError(error);
    }
    try {
      this.acceptRuntime(parseRuntimeStatus(raw));
    } catch (error) {
      if (error instanceof ContractViolation) this.failBoundary("backend-response-invalid");
      throw new RouteDeckError("backend-response-invalid");
    }
  }

  getSnapshot = (): ControllerSnapshot => this.snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private hasRuntimeSession(): boolean {
    return Boolean(this.runtime && this.runtime.phase !== "disconnected" && this.runtime.phase !== "disconnected_with_error");
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    this.queuedOperations += 1;
    this.publish({ switching: true });
    const result = this.operationTail.then(operation);
    this.operationTail = result.catch(() => undefined);
    return result.finally(() => {
      this.queuedOperations -= 1;
      this.publish({ switching: this.queuedOperations > 0 });
    });
  }

  private async stopRuntime(): Promise<void> {
    const command = this.runtime?.mode === "tun"
      ? "stop_tun"
      : this.runtime?.mode === "local_only" ? "stop_local_proxy" : "stop_system_proxy";
    await this.invokeStatus(command);
    // A successful IPC is insufficient: recovery-required and retained listeners
    // must never be followed by a second runtime.
    if (this.runtime?.phase !== "disconnected") throw new RouteDeckError("runtime-failure");
  }

  private async reconcileConnection(): Promise<void> {
    await this.requireTransport();
    try {
      for (;;) {
        if (!this.wantsConnection) {
          if (this.hasRuntimeSession()) await this.stopRuntime();
          return;
        }
        if (this.runtime?.phase === "recovery_required" || this.runtime?.phase === "blocked_by_conflict") {
          throw new RouteDeckError("runtime-failure");
        }
        const mode = this.snapshot.mode;
        const nodeId = this.snapshot.selectedServerId;
        if (!nodeId || !this.snapshot.servers.some((server) => server.id === nodeId)) throw new RouteDeckError("node-not-selected");
        const expectedMode = mode === "tun" ? "tun" : "system_proxy";
        if (this.hasRuntimeSession()) {
          if (this.runtime?.nodeId === nodeId && this.runtime.mode === expectedMode
            && this.routingRevision === this.runtimeRoutingRevision
            && (isVerifiedSystemProxyReady(this.runtime) || isVerifiedTunReady(this.runtime) || isVerifiedLocalReady(this.runtime) || this.runtime.phase === "degraded")) return;
          if (mode === "tun" && this.runtime?.mode === "tun" && this.runtime.sessionId
            && this.routingRevision === this.runtimeRoutingRevision) {
            const sessionId = this.runtime.sessionId;
            try {
              await this.invokeStatus("switch_tun_server", { sessionId, nodeId });
              if (this.runtime?.sessionId !== sessionId || this.runtime.nodeId !== nodeId || !isVerifiedTunReady(this.runtime)) {
                throw new RouteDeckError("runtime-failure");
              }
            } catch (error) {
              // A failed candidate leaves the old session serving traffic. Never fall
              // back to stop/start; a newer selection may still be tried normally.
              if (this.wantsConnection && this.snapshot.selectedServerId !== nodeId) continue;
              if (error instanceof RouteDeckError && error.code === "runtime-failure") {
                throw new RouteDeckError("server-switch-failed", error.redactedDetail);
              }
              throw error;
            }
            continue;
          }
          await this.stopRuntime();
          continue;
        }
        const started = await this.startSelectedRuntime();
        if (!this.runtime || this.runtime.nodeId !== started.nodeId || this.runtime.mode !== started.mode
          || !(isVerifiedSystemProxyReady(this.runtime) || isVerifiedTunReady(this.runtime))) throw new RouteDeckError("runtime-failure");
        // Selection/disconnect may have changed during start. Reconcile again,
        // without a transient UI claim that the requested new server is active.
      }
    } catch (error) {
      const cancelled = !this.wantsConnection;
      if (!(this.runtime?.mode === "tun" && this.hasRuntimeSession())) this.wantsConnection = false;
      if (cancelled && this.hasRuntimeSession()) await this.stopRuntime();
      throw error;
    }
  }

  setMode = async (mode: ConnectionMode): Promise<void> => {
    if (mode !== "proxy" && mode !== "tun") throw new RouteDeckError("capability-unavailable");
    if (this.boundaryFailed || !this.snapshot.backendAvailable) throw new RouteDeckError("backend-unavailable");
    if (this.snapshot.mode === mode) return;
    saveSelection(this.snapshot.selectedServerId, mode);
    this.intentRevision += 1;
    this.publish({ mode, notice: undefined });
    if (this.wantsConnection || this.hasRuntimeSession() || this.queuedOperations > 0) await this.enqueue(() => this.reconcileConnection());
  };

  selectServer = async (serverId: string): Promise<void> => {
    if (!this.snapshot.servers.some((server) => server.id === serverId)) throw new RouteDeckError("node-not-selected");
    if (this.snapshot.selectedServerId === serverId) return;
    saveSelection(serverId, this.snapshot.mode);
    this.intentRevision += 1;
    this.publish({ selectedServerId: serverId });
    if (this.wantsConnection || this.hasRuntimeSession() || this.queuedOperations > 0) await this.enqueue(() => this.reconcileConnection());
  };

  connect = async (_tunPath?: TunPathChoice): Promise<void> => {
    this.intentRevision += 1;
    this.wantsConnection = true;
    await this.enqueue(() => this.reconcileConnection());
  };

  private async startSelectedRuntime(): Promise<{ nodeId: string; mode: "tun" | "system_proxy" }> {
    // Check the trust boundary before interpreting any optimistic UI state.
    await this.requireTransport();
    if (!this.snapshot.selectedServerId) throw new RouteDeckError("node-not-selected");
    const nodeId = this.snapshot.selectedServerId;
    const mode = this.snapshot.mode === "tun" ? "tun" : "system_proxy";
    const routingRevision = this.routingRevision;
    await this.invokeStatus(mode === "tun" ? "start_tun" : "start_system_proxy", {
      nodeId,
      routing: {
        defaultRoute: this.snapshot.routing.defaultRoute,
        ...(this.snapshot.routing.naiveUdpOverTcp ? { naiveUdpOverTcp: true } : {}),
        ...(mode === "tun" ? { stack: this.snapshot.routing.tunStack, trafficRules: activeTrafficRules(this.snapshot.routing) } : {}),
        apps: this.snapshot.routing.apps
          .filter((app) => app.route !== "inherit")
          .map((app) => ({
            processPath: app.path,
            processName: app.path.split(/[\\/]/).at(-1) || undefined,
            route: app.route,
          })),
      },
    });
    this.runtimeRoutingRevision = routingRevision;
    this.publish({ routingPending: this.hasRuntimeSession() && this.routingRevision !== routingRevision });
    return { nodeId, mode };
  }

  disconnect = async (): Promise<void> => {
    this.intentRevision += 1;
    this.wantsConnection = false;
    await this.enqueue(async () => {
      await this.requireTransport();
      if (this.hasRuntimeSession()) await this.stopRuntime();
    });
  };

  retry = async (): Promise<void> => {
    if (this.runtime?.phase === "recovery_required") {
      this.wantsConnection = false;
      this.intentRevision += 1;
      await this.enqueue(() => this.invokeStatus("retry_session_recovery"));
      return;
    }
    this.intentRevision += 1;
    this.wantsConnection = true;
    await this.enqueue(async () => {
      try {
        await this.requireTransport();
        // Explicit Retry must re-establish an unhealthy/blocked session; ordinary
        // idempotent Connect intentionally keeps a matching runtime running.
        if (this.hasRuntimeSession()) await this.stopRuntime();
        await this.reconcileConnection();
      } catch (error) {
        this.wantsConnection = false;
        throw error;
      }
    });
  };

  dismissNotice = (): void => {
    if (!this.boundaryFailed) this.publish({ notice: undefined });
  };

  refreshServers = async (): Promise<void> => {
    throw new RouteDeckError("capability-unavailable");
  };

  private async reloadSources(sourceId: string, removed: boolean, expectedIds: string[] = []): Promise<void> {
    const transport = await this.requireTransport();
    let raw;
    try { raw = await transport.invoke("confirmed_nodes"); }
    catch { throw new RouteDeckError("library-reload-failed"); }
    let nodes: ConfirmedNodeDto[];
    try {
      nodes = parseConfirmedNodes(raw);
      const ids = new Set(nodes.map((node) => node.id));
      if (expectedIds.some((id) => !ids.has(id))
        || this.snapshot.servers.some((server) => server.sourceId !== sourceId && !ids.has(server.id))
        || (removed && nodes.some((node) => node.sourceId === sourceId))) throw new ContractViolation();
    } catch {
      this.failBoundary("backend-response-invalid");
      throw new RouteDeckError("backend-response-invalid");
    }
    const previous = this.snapshot.servers.find((server) => server.id === this.snapshot.selectedServerId);
    const servers = projectRuntimeLatency(projectConfirmedNodes(nodes), this.runtime!);
    const selected = servers.find((server) => server.id === this.snapshot.selectedServerId)
      ?? (!removed && previous?.sourceId === sourceId ? servers.find((server) => server.sourceId === sourceId && server.name === previous.name) ?? servers.find((server) => server.sourceId === sourceId) : undefined)
      ?? servers[0];
    this.publish({ servers, selectedServerId: selected?.id ?? "", subscriptionName: "Мои серверы", subscriptionUpdatedAt: "только что" });
  }

  refreshSource = async (sourceId: string, url?: string, background = false): Promise<void> => {
    await this.enqueue(async () => {
      const transport = await this.requireTransport();
      const source = this.snapshot.servers.find((server) => server.sourceId === sourceId);
      // Scheduled refreshes are opportunistic. Recheck inside the lifecycle queue
      // because Connect may have been clicked since the timer inspected state.
      if (background && (this.wantsConnection || this.hasRuntimeSession() || !source?.sourceRefreshable || source.sourceKind !== "subscription")) return;
      if (!source || source.sourceKind !== "subscription") throw new RouteDeckError("capability-unavailable");
      if (!source.sourceRefreshable && !url?.trim()) throw new RouteDeckError("invalid-subscription-url");
      const affectsActive = this.snapshot.servers.some((server) => server.sourceId === sourceId && server.id === this.runtime?.nodeId) && this.hasRuntimeSession();
      if (affectsActive) {
        try { await this.stopRuntime(); }
        catch (error) { this.wantsConnection = false; throw error; }
      }
      let raw;
      try {
        const pending = transport.invoke("refresh_source", { sourceId, ...(url?.trim() ? { url: url.trim() } : {}) });
        url = undefined;
        raw = await pending;
      } catch (error) {
        url = undefined;
        const failure = this.invokeError(error);
        // The backend retains the old source on a failed fetch. Restore it only
        // after a verified stop and only while the user still wants a connection.
        if (affectsActive && this.wantsConnection) await this.reconcileConnection();
        throw failure;
      }
      let confirmed;
      try { confirmed = parseConfirmedImport(raw); }
      catch { this.failBoundary("backend-response-invalid"); this.wantsConnection = false; throw new RouteDeckError("backend-response-invalid"); }
      try { await this.reloadSources(sourceId, false, confirmed.nodeIds); }
      catch (error) { this.wantsConnection = false; throw error; }
      if (affectsActive) await this.reconcileConnection();
    });
  };

  removeSource = async (sourceId: string): Promise<void> => {
    await this.enqueue(async () => {
      const transport = await this.requireTransport();
      const affectsActive = this.snapshot.servers.some((server) => server.sourceId === sourceId && server.id === this.runtime?.nodeId) && this.hasRuntimeSession();
      if (affectsActive) {
        this.wantsConnection = false;
        this.intentRevision += 1;
        await this.stopRuntime();
      }
      let raw;
      try { raw = await transport.invoke("remove_source", { sourceId }); }
      catch (error) { throw this.invokeError(error); }
      try { parseUnitResponse(raw); }
      catch { this.failBoundary("backend-response-invalid"); throw new RouteDeckError("backend-response-invalid"); }
      await this.reloadSources(sourceId, true);
    });
  };

  previewSubscription = async (source: SubscriptionImportSource): Promise<SubscriptionPreview> => {
    if (this.confirmingImport) throw new RouteDeckError("stale-subscription-preview");
    const generation = this.invalidatePendingImport();
    if (!source.value.trim()) throw new RouteDeckError("empty-subscription-source");
    const sourceType = source.type;
    const transport = await this.requireTransport();
    // Initialization can take long enough for the dialog to be closed or the
    // import method to change. Never send a secret-bearing IPC after that.
    if (generation !== this.importGeneration) {
      source = { type: "clipboard", value: "" };
      throw new RouteDeckError("stale-subscription-preview");
    }
    let raw: unknown;
    try {
      const pending = sourceType === "url"
        ? transport.invoke("preview_import_url", { url: source.value })
        : transport.invoke("preview_import_content", { content: source.value });
      // Drop the controller stack's reference as soon as IPC owns the request.
      // Neither URL nor raw share content is retained in controller state.
      source = { type: "clipboard", value: "" };
      raw = await pending;
    } catch (error) {
      source = { type: "clipboard", value: "" };
      throw this.invokeError(error);
    }
    let dto: ImportPreviewDto;
    try {
      dto = parseImportPreview(raw);
    } catch {
      this.failBoundary("backend-response-invalid");
      throw new RouteDeckError("backend-response-invalid");
    }
    if (generation !== this.importGeneration) {
      await this.discardPreviewToken(dto.previewId);
      throw new RouteDeckError("stale-subscription-preview");
    }
    const counts = new Map<Protocol, number>();
    dto.nodes.forEach((node) => {
      const protocol = protocolName(node.protocol);
      counts.set(protocol, (counts.get(protocol) ?? 0) + 1);
    });
    const projected: SubscriptionPreview = {
      token: dto.previewId,
      sourceLabel: sourceType === "clipboard" ? "Буфер обмена" : "HTTPS-подписка",
      supported: (["VLESS", "Hysteria2", "Naive"] as const)
        .map((protocol) => ({ protocol, count: counts.get(protocol) ?? 0 }))
        .filter((entry) => entry.count > 0),
      unsupportedCount: dto.rejected.length,
      nodeNames: dto.nodes.map((node) => node.displayName),
    };
    this.pendingImport = { dto, projected };
    return projected;
  };

  private invalidatePendingImport(): number {
    const previewId = this.pendingImport?.dto.previewId;
    this.importGeneration += 1;
    this.pendingImport = undefined;
    if (previewId) void this.discardPreviewToken(previewId);
    return this.importGeneration;
  }

  private async discardPreviewToken(previewId: string): Promise<void> {
    const transport = this.transport;
    if (!transport || this.disposed) return;
    try {
      parseUnitResponse(await transport.invoke("discard_import_preview", { previewId }));
    } catch (error) {
      // Cleanup is best-effort: an already consumed/expired token is harmless.
      // A malformed successful response is still a trust-boundary failure.
      if (error instanceof ContractViolation && !this.disposed) this.failBoundary("backend-response-invalid");
    }
  }

  cancelImportPreview = (): void => {
    // confirm_import consumes the token and updates the backend atomically. Once
    // it has started, cancellation would only hide an outcome we must reconcile.
    if (this.confirmingImport) return;
    this.invalidatePendingImport();
  };

  commitSubscription = async (preview: SubscriptionPreview, sourceName?: string): Promise<void> => {
    const pending = this.pendingImport;
    if (this.confirmingImport || !pending || preview.token !== pending.projected.token) throw new RouteDeckError("stale-subscription-preview");
    const generation = ++this.importGeneration;
    this.confirmingImport = true;
    try {
      const transport = await this.requireTransport();
      let raw: unknown;
      try {
        raw = await transport.invoke("confirm_import", { previewId: preview.token, ...(sourceName?.trim() ? { sourceName: sourceName.trim() } : {}) });
      } catch (error) {
        throw this.invokeError(error);
      }
      let confirmed;
      try {
        confirmed = parseConfirmedImport(raw);
      } catch {
        this.failBoundary("backend-response-invalid");
        throw new RouteDeckError("backend-response-invalid");
      }
      if (confirmed.imported !== pending.dto.nodes.length) {
        this.failBoundary("backend-response-invalid");
        throw new RouteDeckError("backend-response-invalid");
      }
      if (generation !== this.importGeneration) throw new RouteDeckError("stale-subscription-preview");
      this.pendingImport = undefined;
      let nodes: ConfirmedNodeDto[];
      try {
        raw = await transport.invoke("confirmed_nodes");
      } catch (error) {
        throw new RouteDeckError("library-reload-failed");
      }
      try {
        nodes = parseConfirmedNodes(raw);
        const ids = new Set(nodes.map((node) => node.id));
        if (confirmed.nodeIds.some((id) => !ids.has(id)) || this.snapshot.servers.some((server) => !ids.has(server.id))) throw new ContractViolation();
      } catch {
        this.failBoundary("backend-response-invalid");
        throw new RouteDeckError("backend-response-invalid");
      }
      if (generation !== this.importGeneration) throw new RouteDeckError("stale-subscription-preview");
      const servers = projectConfirmedNodes(nodes);
      this.pendingImport = undefined;
      this.publish({
        servers,
        selectedServerId: servers.some((server) => server.id === this.snapshot.selectedServerId) ? this.snapshot.selectedServerId : servers[0]?.id ?? "",
        subscriptionName: "Мои серверы",
        subscriptionUpdatedAt: "только что",
      });
    } finally {
      this.confirmingImport = false;
    }
  };

  listRunningApplications = async (): Promise<RunningApplication[]> => {
    const transport = await this.requireTransport();
    let raw: unknown;
    try {
      raw = await transport.invoke("list_running_applications");
    } catch (error) {
      throw this.invokeError(error);
    }
    try {
      return parseRunningApplications(raw);
    } catch {
      this.failBoundary("backend-response-invalid");
      throw new RouteDeckError("backend-response-invalid");
    }
  };

  applyRouting = async (routing: RoutingConfig): Promise<void> => {
    // Persist before restarting. A failed write cannot disrupt a working session;
    // a failed restart must not discard the user's successfully saved edits.
    const saved = validatedRouting(routing);
    const tunChanged = effectiveTunKey(saved) !== effectiveTunKey(this.snapshot.routing);
    const tunUsesPolicy = this.runtime?.mode === "tun" || (this.wantsConnection && this.snapshot.mode === "tun");
    const naiveChanged = saved.naiveUdpOverTcp !== this.snapshot.routing.naiveUdpOverTcp
      && this.snapshot.servers.some((server) => server.protocol === "Naive" && (tunUsesPolicy || server.id === this.runtime?.nodeId || server.id === this.snapshot.selectedServerId));
    const changesRuntime = effectiveRoutingKey(saved) !== effectiveRoutingKey(this.snapshot.routing) || (tunChanged && tunUsesPolicy) || naiveChanged;
    try {
      if (typeof window !== "undefined") window.localStorage.setItem(ROUTING_STORAGE_KEY, JSON.stringify(saved));
    } catch {
      throw new RouteDeckError("preferences-save-failed");
    }
    if (changesRuntime) this.routingRevision += 1;
    this.publish({ routing: saved, routingPending: this.hasRuntimeSession() && this.routingRevision !== this.runtimeRoutingRevision });
    if (changesRuntime && (this.wantsConnection || this.hasRuntimeSession() || this.queuedOperations > 0)) await this.enqueue(() => this.reconcileConnection());
  };

  saveSettings = async (settings: SettingsConfig): Promise<void> => {
    if (!settings || !["dark", "light", "system"].includes(settings.theme) || ![0, 6, 24].includes(settings.subscriptionRefreshHours)) throw new RouteDeckError("preferences-save-failed");
    const supported = new Set(["theme", "subscriptionRefreshHours"]);
    if (Object.keys(settings).some((key) => !supported.has(key) && settings[key as keyof SettingsConfig] !== this.snapshot.settings[key as keyof SettingsConfig])) throw new RouteDeckError("capability-unavailable");
    const saved = { ...this.snapshot.settings, theme: settings.theme, subscriptionRefreshHours: settings.subscriptionRefreshHours };
    try {
      if (typeof window !== "undefined") window.localStorage.setItem(PREFERENCES_STORAGE_KEY, JSON.stringify({ version: 1, theme: saved.theme, subscriptionRefreshHours: saved.subscriptionRefreshHours }));
    } catch { throw new RouteDeckError("preferences-save-failed"); }
    this.publish({ settings: saved });
  };

  runDiagnostics = async (): Promise<void> => {
    const transport = await this.requireTransport();
    const generation = ++this.diagnosticsGeneration;
    this.publish({ diagnostics: { ...this.snapshot.diagnostics, running: true, systemProxy: { ...this.snapshot.diagnostics.systemProxy, cleanupToken: null } } });
    try {
      let raw: unknown;
      try {
        raw = await transport.invoke("runtime_diagnostics");
      } catch (error) {
        throw this.invokeError(error);
      }
      let diagnostics;
      try { diagnostics = parseDiagnostics(raw); }
      catch {
        this.failBoundary("backend-response-invalid");
        throw new RouteDeckError("backend-response-invalid");
      }
      if (generation !== this.diagnosticsGeneration) return;
      this.acceptRuntime(diagnostics.status);
      this.publish({
        diagnostics: {
          running: false,
          snapshotReceivedAt: new Intl.DateTimeFormat("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date()),
          steps: projectRuntimeProofs(diagnostics.status),
          sanitizedLog: diagnostics.lines,
          systemProxy: diagnostics.systemProxy,
        },
      });
    } catch (error) {
      if (error instanceof RouteDeckError) throw error;
      this.failBoundary("backend-response-invalid");
      throw new RouteDeckError("backend-response-invalid");
    } finally {
      if (this.snapshot.diagnostics.running) {
        this.publish({ diagnostics: { ...this.snapshot.diagnostics, running: false } });
      }
    }
  };

  clearStaleSystemProxy = async (token: string): Promise<void> => {
    if (this.proxyCleanupPending) throw new RouteDeckError("capability-unavailable");
    if (!/^[a-f0-9]{64}$/.test(token) || this.snapshot.diagnostics.systemProxy.state !== "stale" || this.snapshot.diagnostics.systemProxy.cleanupToken !== token) {
      throw new RouteDeckError("backend-response-invalid");
    }
    this.proxyCleanupPending = true;
    ++this.diagnosticsGeneration;
    try {
      const transport = await this.requireTransport();
      let raw: unknown;
      try {
        raw = await transport.invoke("clear_stale_system_proxy", { token });
      } catch (error) {
        throw this.invokeError(error);
      }
      let diagnostics;
      try { diagnostics = parseDiagnostics(raw); }
      catch {
        this.failBoundary("backend-response-invalid");
        throw new RouteDeckError("backend-response-invalid");
      }
      this.acceptRuntime(diagnostics.status);
      this.publish({ diagnostics: {
        running: false,
        snapshotReceivedAt: new Intl.DateTimeFormat("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date()),
        steps: projectRuntimeProofs(diagnostics.status),
        sanitizedLog: diagnostics.lines,
        systemProxy: diagnostics.systemProxy,
      } });
    } finally {
      this.proxyCleanupPending = false;
      // Cleanup attempts consume their observation token, including failed attempts.
      if (this.snapshot.diagnostics.systemProxy.cleanupToken === token) {
        this.publish({ diagnostics: { ...this.snapshot.diagnostics, systemProxy: { ...this.snapshot.diagnostics.systemProxy, cleanupToken: null } } });
      }
    }
  };

  resetLocalState = async (): Promise<void> => {
    this.wantsConnection = false;
    this.intentRevision += 1;
    await this.enqueue(async () => {
      await this.requireTransport();
      if (this.hasRuntimeSession()) await this.stopRuntime();
      this.cancelImportPreview();
      const transport = await this.requireTransport();
      try {
        parseUnitResponse(await transport.invoke("reset_local_state"));
      } catch (error) {
        throw this.invokeError(error);
      }
      if (typeof window !== "undefined") {
        window.localStorage.removeItem(ROUTING_STORAGE_KEY);
        window.localStorage.removeItem(PREFERENCES_STORAGE_KEY);
        window.localStorage.removeItem(SELECTION_STORAGE_KEY);
      }
      this.routingRevision = 0;
      this.runtimeRoutingRevision = 0;
      this.publish({
        phase: "disconnected",
        selectedServerId: "",
        servers: [],
        proofs: emptyProofs(),
        notice: undefined,
        routing: { defaultRoute: "direct", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [] },
        routingPending: false,
        settings: defaultSettings(),
        subscriptionName: "Подписка не импортирована",
        subscriptionUpdatedAt: "—",
      });
    });
  };

  getSanitizedReport = (): string => {
    const selected = this.snapshot.servers.find((server) => server.id === this.snapshot.selectedServerId);
    return [
      "RouteDeck diagnostic report (sanitized)",
      `phase=${this.snapshot.phase}`,
      `runtimeScope=${this.snapshot.runtimeScope}`,
      `serverProtocol=${selected?.protocol ?? "unknown"}`,
      `tunStackPreference=${this.snapshot.routing.tunStack}`,
      `naiveUdpOverTcpPreference=${this.snapshot.routing.naiveUdpOverTcp}`,
      `tunTrafficRulesEnabled=${activeTrafficRules(this.snapshot.routing).length}`,
      `systemProxyState=${this.snapshot.diagnostics.systemProxy.state}`,
      `systemProxyEndpoint=${this.snapshot.diagnostics.systemProxy.endpoint ?? "not-reported"}`,
      ...this.snapshot.diagnostics.sanitizedLog,
    ].join("\n");
  };

  dispose = (): void => {
    if (this.disposed) return;
    const previewId = this.pendingImport?.dto.previewId;
    this.pendingImport = undefined;
    this.importGeneration += 1;
    if (previewId && !this.confirmingImport) void this.discardPreviewToken(previewId);
    this.disposed = true;
    this.unlisten?.();
    this.unlisten = undefined;
    if (this.beforeUnload && typeof window !== "undefined") {
      window.removeEventListener("beforeunload", this.beforeUnload);
    }
    this.listeners.clear();
  };
}
