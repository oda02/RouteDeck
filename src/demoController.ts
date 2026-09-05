import { defaultTrafficRules, RouteDeckError } from "./model";
import { effectiveRoutingKey, effectiveTunKey, validatedRouting } from "./tauriController";
import type {
  AppNotice,
  ConnectionMode,
  ConnectionPhase,
  ConnectionProof,
  ControllerSnapshot,
  ProofId,
  ProofState,
  RouteDeckController,
  RoutingConfig,
  Server,
  SettingsConfig,
  SubscriptionImportSource,
  SubscriptionPreview,
  TunPathChoice,
} from "./model";

const wait = (milliseconds: number) =>
  new Promise<void>((resolve) => window.setTimeout(resolve, milliseconds));

const now = () =>
  new Intl.DateTimeFormat("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date());

const baseProofs = (): ConnectionProof[] => [
  { id: "config", label: "Конфигурация", state: "idle", summary: "Не проверялась" },
  { id: "core", label: "Ядро", state: "idle", summary: "Не запущено" },
  { id: "local-ingress", label: "Локальный прокси", state: "idle", summary: "Не проверялся" },
  { id: "windows-mode", label: "Режим Windows", state: "idle", summary: "Не применён" },
  { id: "outbound-proof", label: "Доступность интернета", state: "idle", summary: "Не проверялся" },
  { id: "egress-ip", label: "VPN egress IP", state: "skipped", summary: "Не проверялся" },
];

const demoProofs = (): ConnectionProof[] => baseProofs().map((proof) =>
  proof.id === "egress-ip"
    ? { ...proof, summary: "Последний: 203.0.113.42 (демо)" }
    : proof,
);

const initialSnapshot: ControllerSnapshot = {
  isDemo: true,
  runtimeScope: "demo",
  backendAvailable: false,
  phase: "disconnected",
  mode: "proxy",
  selectedServerId: "nl-vless",
  servers: [
    {
      id: "nl-vless",
      name: "Amsterdam Edge",
      country: "NL",
      protocol: "VLESS",
      detail: "Reality · Vision",
      source: "DEMO profile",
      latencyState: "ready",
      latencyMs: 84,
      checkedAt: "14:32",
    },
    {
      id: "de-hy2",
      name: "Frankfurt Fast",
      country: "DE",
      protocol: "Hysteria2",
      detail: "QUIC · TLS",
      source: "DEMO profile",
      latencyState: "ready",
      latencyMs: 121,
      checkedAt: "14:31",
    },
    {
      id: "fi-naive",
      name: "Helsinki Quiet",
      country: "FI",
      protocol: "Naive",
      detail: "HTTPS · Cronet",
      source: "DEMO profile",
      latencyState: "unavailable",
    },
    {
      id: "se-hy2",
      name: "Stockholm North",
      country: "SE",
      protocol: "Hysteria2",
      detail: "QUIC · TLS",
      source: "DEMO profile",
      latencyState: "ready",
      latencyMs: 96,
      checkedAt: "14:30",
    },
    {
      id: "us-vless",
      name: "New York Relay",
      country: "US",
      protocol: "VLESS",
      detail: "Reality · Vision",
      source: "DEMO profile",
      latencyState: "timeout",
      checkedAt: "14:29",
    },
  ],
  proofs: /* @__PURE__ */ demoProofs(),
  routing: {
    defaultRoute: "direct",
    tunStack: "gvisor", naiveUdpOverTcp: false,
    trafficRules: defaultTrafficRules(),
    apps: [
      {
        id: "firefox",
        name: "Firefox",
        path: "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        route: "vpn",
      },
      {
        id: "telegram",
        name: "Telegram",
        path: "C:\\Users\\User\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
        route: "vpn",
      },
      {
        id: "spotify",
        name: "Spotify",
        path: "C:\\Users\\User\\AppData\\Roaming\\Spotify\\Spotify.exe",
        route: "direct",
      },
    ],
  },
  settings: {
    startMinimized: false,
    closeBehavior: "tray",
    httpPort: 2080,
    socksPort: 2081,
    proxyConflictPolicy: "never-overwrite",
    theme: "dark",
    subscriptionRefreshHours: 0,
  },
  environment: {
    otherVpnDetected: false,
    otherVpnName: "Активный VPN",
    systemProxyOwner: "none",
    externalProxyEndpoint: "127.0.0.1:10808",
    physicalAdapters: [
      { id: "wifi-intel", label: "Wi-Fi · Intel AX211" },
      { id: "ethernet-realtek", label: "Ethernet · Realtek PCIe" },
    ],
  },
  diagnostics: {
    running: false,
    steps: baseProofs(),
    sanitizedLog: [
      "Контроллер готов; системные вызовы не выполнялись.",
      "Обнаружен внешний владелец системного прокси: loopback:10808.",
      "Секреты и адрес подписки удалены из отчёта.",
    ],
    systemProxy: { state: "stale", endpoint: "127.0.0.1:10808", detail: "Прокси Windows включён, но локальный порт не отвечает.", cleanupToken: "d".repeat(64) },
  },
  subscriptionName: "DEMO provider",
  subscriptionUpdatedAt: "12 мин назад",
};

class DevelopmentDemoController implements RouteDeckController {
  private snapshot: ControllerSnapshot = { ...initialSnapshot, servers: initialSnapshot.servers.map((server) => ({ ...server,
    source: server.protocol === "Naive" ? "Личные серверы" : "Demo subscription",
    sourceId: server.protocol === "Naive" ? "demo-manual" : "demo-subscription",
    sourceKind: server.protocol === "Naive" ? "manual" : "subscription",
    sourceRefreshable: server.protocol !== "Naive", sourceUpdatedAtMs: Date.now(),
  })) };
  private readonly listeners = new Set<() => void>();
  private operation = 0;
  private lifecycleTail: Promise<void> = Promise.resolve();
  private wantsConnection = false;
  private pendingOperations = 0;
  private routingRevision = 0;
  private activeRoutingRevision = 0;

  private enqueue(operation: () => Promise<void>): Promise<void> {
    this.pendingOperations += 1;
    this.publish({ switching: true });
    const result = this.lifecycleTail.then(operation);
    this.lifecycleTail = result.catch(() => undefined);
    return result.finally(() => { this.pendingOperations -= 1; this.publish({ switching: this.pendingOperations > 0 }); });
  }

  private async reconcile(tunPath?: TunPathChoice): Promise<void> {
    for (;;) {
      if (!this.wantsConnection) { await this.stopDemo(); return; }
      if (this.snapshot.phase === "connected" && this.snapshot.activeMode === this.snapshot.mode && this.snapshot.activeServerId === this.snapshot.selectedServerId && this.routingRevision === this.activeRoutingRevision) return;
      if (this.snapshot.phase !== "disconnected") await this.stopDemo();
      if (!this.wantsConnection) return;
      await this.startDemo(tunPath);
      if (this.snapshot.phase !== "connected") { this.wantsConnection = false; return; }
    }
  }

  getSnapshot = () => this.snapshot;

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private publish(update: Partial<ControllerSnapshot>) {
    this.snapshot = { ...this.snapshot, ...update };
    this.listeners.forEach((listener) => listener());
  }

  private setPhase(phase: ConnectionPhase) {
    this.publish({ phase });
  }

  private updateProof(id: ProofId, state: ProofState, summary: string, value?: string, durationMs?: number) {
    const proofs = this.snapshot.proofs.map((proof) =>
      proof.id === id
        ? { ...proof, state, summary, value, durationMs, checkedAt: state === "running" ? undefined : now() }
        : proof,
    );
    this.publish({ proofs });
  }

  private setNotice(notice?: AppNotice) {
    this.publish({ notice });
  }

  setMode = async (mode: ConnectionMode) => {
    this.publish({ mode, notice: undefined });
    if (this.wantsConnection || this.pendingOperations) await this.enqueue(() => this.reconcile());
  };

  selectServer = async (serverId: string) => {
    if (!this.snapshot.servers.some((server) => server.id === serverId)) return;
    this.publish({ selectedServerId: serverId });
    if (this.wantsConnection || this.pendingOperations) await this.enqueue(() => this.reconcile());
  };

  connect = async (tunPath?: TunPathChoice) => {
    this.wantsConnection = true;
    await this.enqueue(() => this.reconcile(tunPath));
  };

  private startDemo = async (tunPath?: TunPathChoice) => {
    if (!["disconnected", "failed", "blocked-by-conflict", "degraded"].includes(this.snapshot.phase)) return;
    const token = ++this.operation;
    const activeServerId = this.snapshot.selectedServerId;
    const activeMode = this.snapshot.mode;
    const routingRevision = this.routingRevision;
    const isCurrent = () => token === this.operation;
    this.publish({ proofs: demoProofs(), notice: undefined });

    const step = async (
      phase: ConnectionPhase,
      id: ProofId,
      pending: string,
      done: string,
      value?: string,
    ) => {
      this.setPhase(phase);
      this.updateProof(id, "running", pending);
      await wait(260);
      if (!isCurrent()) return false;
      this.updateProof(id, "pass", done, value, 42);
      return true;
    };

    if (!(await step("validating-config", "config", "Проверяем конфигурацию…", "sing-box принял конфигурацию"))) return;
    if (!(await step("starting-core", "core", "Запускаем sing-box…", "Ядро запущено", "PID demo"))) return;
    if (!(await step("checking-local-ingress", "local-ingress", "Проверяем локальный порт…", "HTTP ingress отвечает", "127.0.0.1:2080"))) return;

    if (this.snapshot.mode === "proxy" && this.snapshot.environment.systemProxyOwner === "external") {
      this.setPhase("applying-windows-mode");
      this.updateProof("windows-mode", "fail", "Системный прокси занят другим клиентом", this.snapshot.environment.externalProxyEndpoint);
      this.updateProof("outbound-proof", "running", "Проверяем выбранный outbound через локальный ingress…");
      await wait(260);
      if (!isCurrent()) return;
      this.updateProof("outbound-proof", "pass", "Выбранный outbound отвечает", "HTTPS · 842 ms", 842);
      this.updateProof("egress-ip", "pass", "IP через выбранный outbound", "203.0.113.42 (демо)", 118);
      this.setPhase("blocked-by-conflict");
      this.setNotice({
        id: "proxy-owner-conflict",
        kind: "error",
        title: "Не удалось применить системный прокси",
        body: `Другой клиент использует ${this.snapshot.environment.externalProxyEndpoint}. Локальный прокси RouteDeck работает на 127.0.0.1:2080, но приложения Windows пока его не используют.`,
        redactedDetail: "RouteDeck не перезаписывает чужое состояние автоматически. Отключите системный прокси в другом клиенте и повторите проверку.",
      });
      return;
    }

    if (this.snapshot.mode === "tun" && this.snapshot.environment.otherVpnDetected && !tunPath) {
      this.setPhase("failed");
      this.updateProof("windows-mode", "fail", "Не выбран путь сосуществования с другим VPN");
      this.setNotice({
        id: "tun-path-required",
        kind: "warning",
        title: "Нужно выбрать путь для TUN",
        body: "Другой VPN активен. Выберите вложенный маршрут или проверенный физический адаптер перед запросом UAC.",
      });
      return;
    }

    const modeValue =
      this.snapshot.mode === "proxy"
        ? "HTTP 127.0.0.1:2080"
        : tunPath?.type === "physical"
          ? "TUN · физический адаптер"
          : "TUN · через текущий VPN";
    if (!(await step("applying-windows-mode", "windows-mode", "Применяем выбранный режим…", "Режим активен", modeValue))) return;
    if (!(await step("verifying-outbound", "outbound-proof", "Проверяем HTTPS через выбранный сервер…", "Маршрут подтверждён", "HTTPS · 842 ms"))) return;
    this.updateProof("egress-ip", "pass", "IP через выбранный outbound", "203.0.113.42 (демо)", 118);
    this.setPhase("connected");
    this.activeRoutingRevision = routingRevision;
    this.publish({ activeServerId, activeMode, routingPending: this.routingRevision !== routingRevision });
  };

  disconnect = async () => {
    this.wantsConnection = false;
    await this.enqueue(() => this.stopDemo());
  };

  private stopDemo = async () => {
    if (this.snapshot.phase === "disconnected" || this.snapshot.phase === "disconnecting") return;
    ++this.operation;
    this.setPhase("disconnecting");
    await wait(320);
    this.publish({ phase: "disconnected", activeMode: undefined, activeServerId: undefined, routingPending: false, proofs: demoProofs(), notice: undefined });
  };

  retry = async () => this.connect();

  dismissNotice = () => this.setNotice(undefined);

  refreshServers = async () => {
    this.publish({
      servers: this.snapshot.servers.map((server) => ({ ...server, latencyState: "pending" })),
    });
    await wait(420);
    this.publish({
      servers: this.snapshot.servers.map((server, index) => ({
        ...server,
        latencyState: index === 2 ? "unavailable" : index === 4 ? "timeout" : "ready",
        latencyMs: index === 2 || index === 4 ? undefined : [88, 126, 0, 99][index],
        checkedAt: now(),
      })),
      subscriptionUpdatedAt: "только что",
    });
  };

  refreshSource = async (sourceId: string, _url?: string, background = false) => {
    await this.enqueue(async () => {
      if (background && (this.wantsConnection || this.snapshot.phase !== "disconnected" || !this.snapshot.servers.some((server) => server.sourceId === sourceId && server.sourceRefreshable))) return;
      const active = this.snapshot.servers.find((server) => server.id === this.snapshot.activeServerId)?.sourceId === sourceId;
      if (active) await this.stopDemo();
      await wait(420);
      this.publish({ servers: this.snapshot.servers.map((server) => server.sourceId === sourceId ? { ...server, sourceUpdatedAtMs: Date.now() } : server) });
      if (active) await this.reconcile();
    });
  };

  removeSource = async (sourceId: string) => {
    await this.enqueue(async () => {
      if (this.snapshot.servers.find((server) => server.id === this.snapshot.activeServerId)?.sourceId === sourceId) {
        this.wantsConnection = false;
        await this.stopDemo();
      }
      const servers = this.snapshot.servers.filter((server) => server.sourceId !== sourceId);
      this.publish({ servers, selectedServerId: servers.some((server) => server.id === this.snapshot.selectedServerId) ? this.snapshot.selectedServerId : servers[0]?.id ?? "" });
    });
  };

  previewSubscription = async (source: SubscriptionImportSource): Promise<SubscriptionPreview> => {
    await wait(350);
    let sourceLabel = "Буфер обмена";
    if (source.type === "url") {
      let parsed: URL;
      try {
        parsed = new URL(source.value);
      } catch {
        throw new RouteDeckError("invalid-subscription-url");
      }
      if (parsed.protocol !== "https:") throw new RouteDeckError("insecure-subscription-url");
      sourceLabel = `${parsed.hostname}/••••`;
    } else if (!source.value.trim()) {
      throw new RouteDeckError("empty-subscription-source");
    }
    return {
      token: `dev-preview-${Date.now()}`,
      sourceLabel,
      supported: [
        { protocol: "VLESS", count: 4 },
        { protocol: "Hysteria2", count: 3 },
        { protocol: "Naive", count: 1 },
      ],
      unsupportedCount: 2,
      nodeNames: ["Amsterdam Edge", "Frankfurt Fast", "Helsinki Quiet"],
    };
  };

  cancelImportPreview = () => undefined;

  commitSubscription = async (preview: SubscriptionPreview, sourceName?: string) => {
    if (!preview.token.startsWith("dev-preview-")) throw new RouteDeckError("stale-subscription-preview");
    await wait(280);
    const sourceId = preview.token;
    const added = preview.nodeNames.map((name, index): Server => ({
      id: `${sourceId}-${index}`, name, country: "—", protocol: preview.supported[index % preview.supported.length]?.protocol ?? "Naive",
      detail: "Демо", source: sourceName?.trim() || "Импортировано вручную", sourceId,
      sourceKind: preview.sourceLabel === "Буфер обмена" ? "manual" : "subscription", sourceRefreshable: preview.sourceLabel !== "Буфер обмена", sourceUpdatedAtMs: Date.now(), latencyState: "unavailable",
    }));
    this.publish({ servers: [...this.snapshot.servers, ...added], subscriptionName: "Мои серверы", subscriptionUpdatedAt: "только что" });
  };

  listRunningApplications = async () => this.snapshot.routing.apps.map((app) => ({
    processName: app.path.split(/[\\/]/).at(-1) ?? app.name,
    executablePath: app.path,
    displayName: app.name,
  }));

  applyRouting = async (routing: RoutingConfig) => {
    const saved = validatedRouting(routing);
    const tunChanged = effectiveTunKey(saved) !== effectiveTunKey(this.snapshot.routing);
    const naiveChanged = saved.naiveUdpOverTcp !== this.snapshot.routing.naiveUdpOverTcp
      && this.snapshot.servers.some((server) => server.protocol === "Naive" && (server.id === this.snapshot.activeServerId || server.id === this.snapshot.selectedServerId));
    const changed = effectiveRoutingKey(saved) !== effectiveRoutingKey(this.snapshot.routing)
      || (tunChanged && (this.snapshot.activeMode === "tun" || (this.wantsConnection && this.snapshot.mode === "tun"))) || naiveChanged;
    if (changed) this.routingRevision += 1;
    this.publish({ routing: saved, routingPending: this.snapshot.phase === "connected" && this.routingRevision !== this.activeRoutingRevision });
    if (changed && (this.wantsConnection || this.pendingOperations)) await this.enqueue(() => this.reconcile());
  };

  saveSettings = async (settings: SettingsConfig) => {
    if (!["dark", "light", "system"].includes(settings.theme) || ![0, 6, 24].includes(settings.subscriptionRefreshHours)) throw new RouteDeckError("preferences-save-failed");
    this.publish({ settings: { ...this.snapshot.settings, theme: settings.theme, subscriptionRefreshHours: settings.subscriptionRefreshHours } });
  };

  runDiagnostics = async () => {
    this.publish({
      diagnostics: { ...this.snapshot.diagnostics, running: true, steps: demoProofs() },
    });
    await wait(480);
    const steps: ConnectionProof[] = [
      { id: "config", label: "Конфигурация", state: "pass", summary: "Структура корректна", checkedAt: now(), durationMs: 18 },
      { id: "core", label: "Ядро", state: "pass", summary: "Mock-контроллер отвечает", checkedAt: now(), durationMs: 22 },
      { id: "local-ingress", label: "Локальный ingress", state: "pass", summary: "HTTP 127.0.0.1:2080", checkedAt: now(), durationMs: 12 },
      { id: "windows-mode", label: "Режим Windows", state: "warn", summary: "Обнаружен внешний прокси", value: "loopback:10808", checkedAt: now(), durationMs: 7 },
      { id: "outbound-proof", label: "Доступность интернета", state: "pass", summary: "Выбранный outbound подтверждён", checkedAt: now(), durationMs: 842 },
      { id: "egress-ip", label: "VPN egress IP", state: "warn", summary: "Демо-значение", value: "203.0.113.42", checkedAt: now(), durationMs: 118 },
    ];
    this.publish({
      diagnostics: {
        ...this.snapshot.diagnostics,
        running: false,
        snapshotReceivedAt: now(),
        steps,
      },
    });
  };

  clearStaleSystemProxy = async (token: string) => {
    if (token !== this.snapshot.diagnostics.systemProxy.cleanupToken) throw new RouteDeckError("backend-response-invalid");
    await wait(220);
    this.publish({ diagnostics: { ...this.snapshot.diagnostics, snapshotReceivedAt: now(), systemProxy: { state: "disabled", endpoint: null, detail: "Прокси Windows отключён.", cleanupToken: null } } });
  };

  resetLocalState = async () => {
    ++this.operation;
    await wait(220);
    this.publish({
      phase: "disconnected",
      mode: "proxy",
      proofs: demoProofs(),
      notice: undefined,
      routing: initialSnapshot.routing,
      settings: initialSnapshot.settings,
    });
  };

  getSanitizedReport = () => {
    const selected = this.snapshot.servers.find((server) => server.id === this.snapshot.selectedServerId);
    return [
      "RouteDeck diagnostic report (sanitized)",
      `phase=${this.snapshot.phase}`,
      `mode=${this.snapshot.mode}`,
      `server=${selected?.protocol ?? "unknown"}/${selected?.country ?? "unknown"}`,
      `systemProxyOwner=${this.snapshot.environment.systemProxyOwner}`,
      ...this.snapshot.diagnostics.sanitizedLog,
    ].join("\n");
  };
}

export function createDevelopmentDemoController(): RouteDeckController {
  return new DevelopmentDemoController();
}
