export const destinations = ["home", "servers", "routing", "settings", "diagnostics"] as const;

export type Destination = (typeof destinations)[number];
export type ConnectionMode = "proxy" | "tun";
export type ConnectionPhase =
  | "disconnected"
  | "validating-config"
  | "starting-core"
  | "checking-local-ingress"
  | "applying-windows-mode"
  | "verifying-outbound"
  | "connected"
  | "degraded"
  | "disconnecting"
  | "blocked-by-conflict"
  | "failed";

export type ProofState = "idle" | "running" | "pass" | "warn" | "fail" | "skipped";
export type ProofId =
  | "config"
  | "core"
  | "local-ingress"
  | "windows-mode"
  | "outbound-proof"
  | "egress-ip";

export interface ConnectionProof {
  id: ProofId;
  label: string;
  state: ProofState;
  summary: string;
  value?: string;
  checkedAt?: string;
  durationMs?: number;
}

export type Protocol = "VLESS" | "Hysteria2" | "Naive";
export type LatencyState = "ready" | "pending" | "timeout" | "unavailable";

export interface Server {
  id: string;
  name: string;
  country: string;
  protocol: Protocol;
  detail: string;
  source: string;
  latencyState: LatencyState;
  latencyMs?: number;
  checkedAt?: string;
}

export type DefaultRoute = "direct" | "vpn";
export type AppRouteChoice = "inherit" | "direct" | "vpn";

export interface AppRule {
  id: string;
  name: string;
  path: string;
  route: AppRouteChoice;
}

export interface RoutingConfig {
  defaultRoute: DefaultRoute;
  apps: AppRule[];
}

export type ThemePreference = "dark" | "light" | "system";
export type CloseBehavior = "tray" | "exit";
export type ProxyConflictPolicy = "never-overwrite" | "ask";

export interface SettingsConfig {
  startMinimized: boolean;
  closeBehavior: CloseBehavior;
  httpPort: number;
  socksPort: number;
  proxyConflictPolicy: ProxyConflictPolicy;
  theme: ThemePreference;
}

export type NoticeKind = "info" | "warning" | "error" | "success";

export interface AppNotice {
  id: string;
  kind: NoticeKind;
  title: string;
  body: string;
  detail?: string;
}

export interface EnvironmentInfo {
  otherVpnDetected: boolean;
  otherVpnName?: string;
  systemProxyOwner: "none" | "routedeck" | "external";
  externalProxyEndpoint?: string;
  physicalAdapters: Array<{ id: string; label: string }>;
}

export type TunPathChoice =
  | { type: "nested" }
  | { type: "physical"; adapterId: string };

export interface DiagnosticsState {
  running: boolean;
  lastRunAt?: string;
  durationMs?: number;
  steps: ConnectionProof[];
  sanitizedLog: string[];
}

export interface ControllerSnapshot {
  phase: ConnectionPhase;
  mode: ConnectionMode;
  selectedServerId: string;
  servers: Server[];
  proofs: ConnectionProof[];
  notice?: AppNotice;
  routing: RoutingConfig;
  settings: SettingsConfig;
  environment: EnvironmentInfo;
  diagnostics: DiagnosticsState;
  subscriptionName: string;
  subscriptionUpdatedAt: string;
}

export interface RouteDeckController {
  getSnapshot: () => ControllerSnapshot;
  subscribe: (listener: () => void) => () => void;
  setMode: (mode: ConnectionMode) => void;
  selectServer: (serverId: string) => void;
  connect: (tunPath?: TunPathChoice) => Promise<void>;
  disconnect: () => Promise<void>;
  retry: () => Promise<void>;
  dismissNotice: () => void;
  refreshServers: () => Promise<void>;
  importSubscription: (source: string) => Promise<void>;
  applyRouting: (routing: RoutingConfig) => Promise<void>;
  saveSettings: (settings: SettingsConfig) => Promise<void>;
  runDiagnostics: () => Promise<void>;
  resetLocalState: () => Promise<void>;
  getSanitizedReport: () => string;
}
