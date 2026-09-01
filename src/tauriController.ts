import { RouteDeckError } from "./model.ts";
import type {
  AppNotice,
  ConnectionMode,
  ConnectionPhase,
  ConnectionProof,
  ControllerSnapshot,
  Protocol,
  RouteDeckController,
  RoutingConfig,
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
  parseConfirmedImport,
  parseDiagnostics,
  parseImportPreview,
  parsePublicError,
  parseRuntimeStatus,
  parseUnitResponse,
  type ImportPreviewDto,
  type ProofStateDto,
  type PublicErrorDto,
  type RuntimePhaseDto,
  type RuntimeProofDto,
  type RuntimeStatusDto,
} from "./tauriContract.ts";

const RUNTIME_EVENT = "routedeck://runtime-phase";

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
  { id: "windows-mode", label: "Режим Windows", state: "skipped", summary: "Не применён: доступен только локальный прокси" },
  { id: "outbound-proof", label: "VPN-маршрут", state: "idle", summary: "Не проверялся" },
  { id: "egress-ip", label: "VPN egress IP", state: "skipped", summary: "Backend пока не измеряет egress IP" },
];

const defaultSettings = (): SettingsConfig => ({
  startMinimized: false,
  closeBehavior: "tray",
  httpPort: 2080,
  socksPort: 2081,
  proxyConflictPolicy: "never-overwrite",
  theme: "dark",
});

const initialTauriSnapshot = (): ControllerSnapshot => ({
  isDemo: false,
  runtimeScope: "local-only",
  backendAvailable: true,
  phase: "disconnected",
  mode: "proxy",
  selectedServerId: "",
  servers: [],
  proofs: emptyProofs(),
  notice: {
    id: "backend-initializing",
    kind: "info",
    title: "Проверяем backend RouteDeck",
    body: "Подключаемся к локальному контроллеру и сверяем его состояние.",
  },
  routing: { defaultRoute: "direct", apps: [] },
  settings: defaultSettings(),
  environment: {
    otherVpnDetected: false,
    systemProxyOwner: "none",
    physicalAdapters: [],
  },
  diagnostics: {
    running: false,
    steps: emptyProofs(),
    sanitizedLog: [],
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
    case "local_proxy_ready":
    case "degraded":
      // The backend has proved only its explicit local proxy. It has not applied
      // or proved Windows System Proxy/TUN, so global Connected is forbidden.
      return "degraded";
    case "rolling_back":
    case "stopping_core":
      return "disconnecting";
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
    summary: proofSummary(state, "Локальные listeners принадлежат sing-box"),
    value,
    durationMs: Math.max(0, ...members.map((proof) => proof.latencyMs ?? 0)) || undefined,
  };
}

export function projectRuntimeProofs(status: RuntimeStatusDto): ConnectionProof[] {
  const config = projectSingleProof(status, "engine_config", "config", "Конфигурация", "sing-box принял конфигурацию");
  const core = projectSingleProof(status, "engine_process", "core", "Ядро", "Процесс sing-box запущен", status.engineVersion);
  const ingress = projectIngressProof(status);
  const outbound = projectSingleProof(
    status,
    "selected_outbound_https",
    "outbound-proof",
    "VPN-маршрут",
    "HTTPS через выбранный outbound подтверждён",
    status.routeCheckMs === undefined ? undefined : `${status.routeCheckMs} мс`,
  );
  return [
    config,
    core,
    ingress,
    {
      id: "windows-mode",
      label: "Режим Windows",
      state: "skipped",
      summary: "Не применён: backend работает только локально",
    },
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
  if (isVerifiedLocalReady(status)) {
    const endpoint = status.ports ? `127.0.0.1:${status.ports.http}` : "локальном порту";
    return {
      id: "local-proxy-only",
      kind: "warning",
      title: "Локальный прокси проверен, но режим Windows не применён",
      body: `Трафик через выбранный сервер подтверждён на ${endpoint}. Системный прокси и TUN пока не включены, поэтому обычные приложения продолжают использовать прежний маршрут.`,
      redactedDetail: "Это локальная проверка outbound, а не подтверждение системной маршрутизации.",
    };
  }
  if (status.phase === "recovery_required") {
    return {
      id: "session-recovery-required",
      kind: "error",
      title: "Нужно проверить сохранённую сессию",
      body: "Backend обнаружил незавершённое локальное состояние и безопасно заблокировал новый запуск.",
      redactedDetail: "Технические пути и содержимое конфигурации скрыты.",
    };
  }
  if (status.error) {
    return {
      id: `runtime-${status.error.code}`,
      kind: "error",
      title: "Локальный прокси требует внимания",
      body: "Backend остановил или ограничил сессию. Секретные технические сведения скрыты; откройте безопасную диагностику.",
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

function routeDeckErrorFromBackend(error: PublicErrorDto): RouteDeckError {
  switch (error.code) {
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
      return new RouteDeckError("runtime-failure");
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
      if (!this.boundaryFailed && this.snapshot.notice?.id === "backend-initializing") {
        this.publish({ notice: runtimeNotice(status) });
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
    this.runtime = status;
    this.publish({
      backendAvailable: true,
      phase: runtimePhaseToConnectionPhase(status.phase),
      proofs: projectRuntimeProofs(status),
      notice: runtimeNotice(status),
    });
  }

  private failBoundary(code: "backend-unavailable" | "backend-response-invalid"): void {
    this.boundaryFailed = true;
    this.publish({
      backendAvailable: false,
      phase: "failed",
      proofs: emptyProofs().map((proof) => ({ ...proof, state: "skipped", summary: "Backend недоступен" })),
      notice: {
        id: code,
        kind: "error",
        title: code === "backend-response-invalid" ? "Backend вернул неожиданные данные" : "Backend RouteDeck недоступен",
        body: "Действия с сетью безопасно заблокированы. RouteDeck не использует непроверенное состояние.",
        redactedDetail: "Подробности ответа скрыты, чтобы не вывести секретные данные.",
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

  setMode = (mode: ConnectionMode): void => {
    if (this.boundaryFailed || !this.snapshot.backendAvailable) return;
    if (this.snapshot.phase !== "disconnected" && this.snapshot.phase !== "failed") return;
    this.publish({ mode, notice: undefined });
  };

  selectServer = (serverId: string): void => {
    if (this.snapshot.servers.some((server) => server.id === serverId)) {
      this.publish({ selectedServerId: serverId });
    }
  };

  connect = async (_tunPath?: TunPathChoice): Promise<void> => {
    // Check the trust boundary before interpreting any optimistic UI state.
    await this.requireTransport();
    if (this.snapshot.mode === "tun") throw new RouteDeckError("capability-unavailable");
    if (!this.snapshot.selectedServerId) throw new RouteDeckError("node-not-selected");
    await this.invokeStatus("start_local_proxy", {
      nodeId: this.snapshot.selectedServerId,
      defaultRoute: this.snapshot.routing.defaultRoute,
    });
  };

  disconnect = async (): Promise<void> => this.invokeStatus("stop_local_proxy");

  retry = async (): Promise<void> => {
    if (this.runtime?.phase === "recovery_required") {
      await this.invokeStatus("retry_session_recovery");
      return;
    }
    await this.connect();
  };

  dismissNotice = (): void => {
    if (!this.boundaryFailed) this.publish({ notice: undefined });
  };

  refreshServers = async (): Promise<void> => {
    throw new RouteDeckError("capability-unavailable");
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
      sourceLabel: sourceType === "clipboard" ? "Буфер обмена · скрыто" : "HTTPS-подписка · адрес скрыт",
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

  commitSubscription = async (preview: SubscriptionPreview): Promise<void> => {
    const pending = this.pendingImport;
    if (this.confirmingImport || !pending || preview.token !== pending.projected.token) throw new RouteDeckError("stale-subscription-preview");
    const generation = ++this.importGeneration;
    this.confirmingImport = true;
    try {
      const transport = await this.requireTransport();
      let raw: unknown;
      try {
        raw = await transport.invoke("confirm_import", { previewId: preview.token });
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
      const previewIds = new Set(pending.dto.nodes.map((node) => node.id));
      if (confirmed.nodeIds.some((id) => !previewIds.has(id))) {
        this.failBoundary("backend-response-invalid");
        throw new RouteDeckError("backend-response-invalid");
      }
      if (generation !== this.importGeneration) throw new RouteDeckError("stale-subscription-preview");
      const confirmedIds = new Set(confirmed.nodeIds);
      const servers: Server[] = pending.dto.nodes
        .filter((node) => confirmedIds.has(node.id))
        .map((node) => ({
          id: node.id,
          name: node.displayName,
          country: "—",
          protocol: protocolName(node.protocol),
          detail: node.insecureTls ? "Требует отдельного подтверждения небезопасного TLS" : "Проверено строгим импортом",
          source: "Локальный импорт",
          latencyState: "unavailable",
        }));
      this.pendingImport = undefined;
      this.publish({
        servers,
        selectedServerId: servers[0]?.id ?? "",
        subscriptionName: "Локальный импорт",
        subscriptionUpdatedAt: "только что",
      });
    } finally {
      this.confirmingImport = false;
    }
  };

  applyRouting = async (_routing: RoutingConfig): Promise<void> => {
    throw new RouteDeckError("capability-unavailable");
  };

  saveSettings = async (_settings: SettingsConfig): Promise<void> => {
    throw new RouteDeckError("capability-unavailable");
  };

  runDiagnostics = async (): Promise<void> => {
    const transport = await this.requireTransport();
    this.publish({ diagnostics: { ...this.snapshot.diagnostics, running: true } });
    try {
      let raw: unknown;
      try {
        raw = await transport.invoke("runtime_diagnostics");
      } catch (error) {
        throw this.invokeError(error);
      }
      const diagnostics = parseDiagnostics(raw);
      this.acceptRuntime(diagnostics.status);
      this.publish({
        diagnostics: {
          running: false,
          snapshotReceivedAt: new Intl.DateTimeFormat("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date()),
          steps: projectRuntimeProofs(diagnostics.status),
          sanitizedLog: diagnostics.lines,
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

  resetLocalState = async (): Promise<void> => {
    if (this.runtime && this.runtime.phase !== "disconnected") await this.disconnect();
    this.cancelImportPreview();
    this.publish({
      phase: "disconnected",
      selectedServerId: "",
      servers: [],
      proofs: emptyProofs(),
      notice: undefined,
      routing: { defaultRoute: "direct", apps: [] },
      settings: defaultSettings(),
      subscriptionName: "Подписка не импортирована",
      subscriptionUpdatedAt: "—",
    });
  };

  getSanitizedReport = (): string => {
    const selected = this.snapshot.servers.find((server) => server.id === this.snapshot.selectedServerId);
    return [
      "RouteDeck diagnostic report (sanitized)",
      `phase=${this.snapshot.phase}`,
      "runtimeScope=local_only",
      `serverProtocol=${selected?.protocol ?? "unknown"}`,
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
