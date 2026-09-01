import { RouteDeckError } from "./model";
import { hasTauriIpc, selectControllerRuntime } from "./runtimeSelection";
import { TauriController } from "./tauriController";
import type { ConnectionProof, ControllerSnapshot, RouteDeckController } from "./model";

const baseProofs = (): ConnectionProof[] => [
  { id: "config", label: "Конфигурация", state: "idle", summary: "Не проверялась" },
  { id: "core", label: "Ядро", state: "idle", summary: "Не запущено" },
  { id: "local-ingress", label: "Локальный прокси", state: "idle", summary: "Не проверялся" },
  { id: "windows-mode", label: "Режим Windows", state: "idle", summary: "Не применён" },
  { id: "outbound-proof", label: "VPN-маршрут", state: "idle", summary: "Не проверялся" },
  { id: "egress-ip", label: "VPN egress IP", state: "skipped", summary: "Не проверялся" },
];

class BackendUnavailableController implements RouteDeckController {
  private readonly snapshot: ControllerSnapshot = {
    isDemo: false,
    runtimeScope: "unavailable",
    backendAvailable: false,
    phase: "failed",
    mode: "proxy",
    selectedServerId: "",
    servers: [],
    proofs: baseProofs(),
    notice: {
      id: "backend-unavailable",
      kind: "error",
      title: "Backend RouteDeck пока недоступен",
      body: "Интерфейс запущен без Tauri-адаптера. Соединение, импорт и изменения Windows заблокированы.",
      redactedDetail: "Production работает fail-closed: ни одно синтетическое состояние не может стать подключённым.",
    },
    routing: { defaultRoute: "direct", apps: [] },
    settings: {
      startMinimized: false,
      closeBehavior: "tray",
      httpPort: 2080,
      socksPort: 2081,
      proxyConflictPolicy: "never-overwrite",
      theme: "dark",
    },
    environment: {
      otherVpnDetected: false,
      systemProxyOwner: "none",
      physicalAdapters: [],
    },
    subscriptionName: "Backend не подключён",
    subscriptionUpdatedAt: "—",
    diagnostics: {
      running: false,
      steps: baseProofs().map((proof) => ({ ...proof, state: "skipped", summary: "Backend недоступен" })),
      sanitizedLog: ["Tauri adapter is not bound; production actions are disabled."],
    },
  };
  private readonly listeners = new Set<() => void>();

  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };
  private unavailable(): never {
    throw new RouteDeckError("backend-unavailable");
  }
  setMode = () => this.unavailable();
  selectServer = () => this.unavailable();
  connect = async () => this.unavailable();
  disconnect = async () => this.unavailable();
  retry = async () => this.unavailable();
  dismissNotice = () => undefined;
  refreshServers = async () => this.unavailable();
  previewSubscription = async () => this.unavailable();
  cancelImportPreview = () => undefined;
  commitSubscription = async () => this.unavailable();
  applyRouting = async () => this.unavailable();
  saveSettings = async () => this.unavailable();
  runDiagnostics = async () => this.unavailable();
  resetLocalState = async () => this.unavailable();
  getSanitizedReport = () => "RouteDeck production report\nbackend=unavailable\nstatus=fail-closed";
}

const explicitDemo = ["1", "true"].includes(import.meta.env.VITE_ROUTEDECK_DEMO?.toLowerCase() ?? "");
const runtimeKind = selectControllerRuntime({
  explicitDemo,
  isDevelopment: import.meta.env.DEV,
  tauriIpcAvailable: hasTauriIpc(typeof window === "undefined" ? undefined : window),
});

async function createController(): Promise<RouteDeckController> {
  if (import.meta.env.DEV && runtimeKind === "demo") {
    const { createDevelopmentDemoController } = await import("./demoController");
    return createDevelopmentDemoController();
  }
  return runtimeKind === "tauri" ? new TauriController() : new BackendUnavailableController();
}

export const controller: RouteDeckController = await createController();
