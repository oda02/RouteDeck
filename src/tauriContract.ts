const runtimePhases = [
  "disconnected",
  "preparing",
  "validating_config",
  "starting_core",
  "verifying_listener",
  "proving_traffic",
  "outbound_verified",
  "applying_system_proxy",
  "local_proxy_ready",
  "system_proxy_ready",
  "tun_ready",
  "restoring_system_proxy",
  "blocked_by_conflict",
  "degraded",
  "rolling_back",
  "stopping_core",
  "disconnected_with_error",
  "recovery_required",
] as const;

const proofKinds = [
  "engine_config",
  "engine_process",
  "http_listener",
  "socks_listener",
  "health_listener",
  "selected_outbound_https",
  "local_scope_ownership",
  "system_proxy_ownership",
] as const;

const proofStates = ["not_run", "pending", "passed", "failed"] as const;
const publicErrorCodes = [
  "import_rejected",
  "preview_missing",
  "preview_token_invalid",
  "recovery_required",
  "active_session_conflict",
  "session_changed",
  "node_not_found",
  "runtime_failure",
  "command_failed",
  "subscription_url_invalid",
  "subscription_policy_blocked",
  "subscription_fetch_failed",
  "subscription_response_too_large",
  "subscription_fetch_timeout",
  "subscription_invalid_encoding",
] as const;
const publicErrorStages = [
  "import",
  "session_recovery",
  "start",
  "generate_config",
  "engine_layout",
  "engine_integrity",
  "config_check",
  "start_engine",
  "verify_listeners",
  "prove_traffic",
  "engine_process",
  "stop_engine",
  "system_proxy_publish",
  "system_proxy_restore",
  "system_proxy_ownership",
  "session_storage",
  "random",
  "monitor",
  "command",
  "runtime",
  "subscription_url",
  "subscription_dns",
  "subscription_fetch",
  "subscription_response",
] as const;
const protocols = ["vless", "hysteria2", "naive"] as const;

export type RuntimePhaseDto = (typeof runtimePhases)[number];
export type ProofKindDto = (typeof proofKinds)[number];
export type ProofStateDto = (typeof proofStates)[number];
export type PublicErrorCodeDto = (typeof publicErrorCodes)[number];
export type PublicErrorStageDto = (typeof publicErrorStages)[number];
export type ProtocolDto = (typeof protocols)[number];

export interface PublicErrorDto {
  code: PublicErrorCodeDto;
  stage: PublicErrorStageDto;
  message: string;
  detail?: string;
}

export interface RuntimeProofDto {
  kind: ProofKindDto;
  state: ProofStateDto;
  latencyMs?: number;
}

export interface RuntimeStatusDto {
  revision: number;
  sessionId?: string;
  scope: "local_only" | "system_proxy" | "tun";
  mode: "local_only" | "system_proxy" | "tun";
  phase: RuntimePhaseDto;
  nodeId?: string;
  ports?: { http: number; socks: number; health: number };
  routeCheckMs?: number;
  steadyLatencyMs?: number;
  engineVersion?: string;
  proofs: RuntimeProofDto[];
  error?: PublicErrorDto;
}

export interface RunningApplicationDto {
  processName: string;
  executablePath: string;
  displayName: string;
}

export interface ImportPreviewDto {
  previewId: string;
  nodes: Array<{
    id: string;
    displayName: string;
    protocol: ProtocolDto;
    insecureTls: boolean;
  }>;
  rejected: Array<{ index: number; reason: string }>;
  warnings: string[];
}

export type ConfirmedNodeDto = ImportPreviewDto["nodes"][number] & {
  sourceId?: string;
  sourceName?: string;
  sourceKind?: "manual" | "subscription";
  sourceRefreshable?: boolean;
  sourceUpdatedAtMs?: number;
};

export interface ConfirmedImportDto {
  imported: number;
  nodeIds: string[];
}

export interface DiagnosticsDto {
  status: RuntimeStatusDto;
  lines: string[];
  systemProxy: SystemProxyDiagnosticDto;
}

export interface SystemProxyDiagnosticDto {
  state: "disabled" | "owned" | "foreignActive" | "stale" | "conflict" | "unavailable";
  endpoint: string | null;
  detail: string;
  cleanupToken: string | null;
}

export class ContractViolation extends Error {
  constructor() {
    super("backend response did not match the RouteDeck IPC contract");
    this.name = "ContractViolation";
  }
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ContractViolation();
  return value as Record<string, unknown>;
}

function exactKeys(input: Record<string, unknown>, allowed: readonly string[], required: readonly string[] = allowed): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(input).some((key) => !allowedSet.has(key))) throw new ContractViolation();
  if (required.some((key) => !(key in input))) throw new ContractViolation();
}

function finiteInteger(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new ContractViolation();
  }
  return value as number;
}

function boundedString(value: unknown, maximum: number, allowEmpty = false): string {
  if (typeof value !== "string" || value.length > maximum || (!allowEmpty && value.length === 0)) {
    throw new ContractViolation();
  }
  return value;
}

function optionalString(value: unknown, maximum: number): string | undefined {
  if (value === undefined || value === null) return undefined;
  return boundedString(value, maximum);
}

function optionalIdentifier(value: unknown, maximum: number): string | undefined {
  const text = optionalString(value, maximum);
  if (text === undefined) return undefined;
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new ContractViolation();
  return text;
}

function member<const T extends readonly string[]>(value: unknown, allowed: T): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) throw new ContractViolation();
  return value as T[number];
}

function optionalDuration(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  return finiteInteger(value, 0, 24 * 60 * 60 * 1000);
}

export function parsePublicError(value: unknown): PublicErrorDto {
  const input = record(value);
  exactKeys(input, ["code", "stage", "message", "detail"], ["code", "stage", "message"]);
  const error: PublicErrorDto = {
    code: member(input.code, publicErrorCodes),
    stage: member(input.stage, publicErrorStages),
    message: boundedString(input.message, 4096),
    detail: optionalString(input.detail, 8192),
  };
  const subscriptionContracts: Partial<Record<PublicErrorCodeDto, { message: string; stages: PublicErrorStageDto[] }>> = {
    subscription_url_invalid: { message: "subscription.url.invalid", stages: ["subscription_url"] },
    subscription_policy_blocked: { message: "subscription.policy_blocked", stages: ["subscription_url", "subscription_dns"] },
    subscription_fetch_failed: { message: "subscription.fetch_failed", stages: ["subscription_dns", "subscription_fetch"] },
    subscription_response_too_large: { message: "subscription.response_too_large", stages: ["subscription_response"] },
    subscription_fetch_timeout: { message: "subscription.timeout", stages: ["subscription_dns", "subscription_fetch"] },
    subscription_invalid_encoding: { message: "subscription.invalid_encoding", stages: ["subscription_response"] },
  };
  const subscriptionContract = subscriptionContracts[error.code];
  if (subscriptionContract) {
    if (error.message !== subscriptionContract.message || !subscriptionContract.stages.includes(error.stage)) {
      throw new ContractViolation();
    }
    if (input.detail !== undefined && input.detail !== null) throw new ContractViolation();
  }
  return error;
}

export function parseRuntimeStatus(value: unknown): RuntimeStatusDto {
  const input = record(value);
  exactKeys(
    input,
    ["revision", "sessionId", "scope", "mode", "phase", "nodeId", "ports", "routeCheckMs", "steadyLatencyMs", "engineVersion", "proofs", "error"],
    ["revision", "scope", "mode", "phase", "proofs"],
  );
  if (!Array.isArray(input.proofs) || input.proofs.length > proofKinds.length) throw new ContractViolation();
  const proofs = input.proofs.map((entry): RuntimeProofDto => {
    const proof = record(entry);
    exactKeys(proof, ["kind", "state", "latencyMs"], ["kind", "state"]);
    return {
      kind: member(proof.kind, proofKinds),
      state: member(proof.state, proofStates),
      latencyMs: optionalDuration(proof.latencyMs),
    };
  });
  const seen = new Set(proofs.map((proof) => proof.kind));
  if (seen.size !== proofs.length || proofs.length !== proofKinds.length) throw new ContractViolation();

  let ports: RuntimeStatusDto["ports"];
  if (input.ports !== undefined && input.ports !== null) {
    const rawPorts = record(input.ports);
    exactKeys(rawPorts, ["http", "socks", "health"]);
    ports = {
      http: finiteInteger(rawPorts.http, 1, 65535),
      socks: finiteInteger(rawPorts.socks, 1, 65535),
      health: finiteInteger(rawPorts.health, 1, 65535),
    };
    if (new Set([ports.http, ports.socks, ports.health]).size !== 3) throw new ContractViolation();
  }

  const status: RuntimeStatusDto = {
    revision: finiteInteger(input.revision),
    sessionId: optionalIdentifier(input.sessionId, 256),
    scope: member(input.scope, ["local_only", "system_proxy", "tun"] as const),
    mode: member(input.mode, ["local_only", "system_proxy", "tun"] as const),
    phase: member(input.phase, runtimePhases),
    nodeId: optionalIdentifier(input.nodeId, 256),
    ports,
    routeCheckMs: optionalDuration(input.routeCheckMs),
    steadyLatencyMs: optionalDuration(input.steadyLatencyMs),
    engineVersion: optionalString(input.engineVersion, 128),
    proofs,
    error: input.error === undefined || input.error === null ? undefined : parsePublicError(input.error),
  };
  validateRuntimeRelationships(status);
  return status;
}

const readyProofKinds = [
  "engine_config",
  "engine_process",
  "http_listener",
  "socks_listener",
  "health_listener",
  "selected_outbound_https",
  "local_scope_ownership",
] as const;

const allProofKinds = [...readyProofKinds, "system_proxy_ownership"] as const;

function validateRuntimeRelationships(status: RuntimeStatusDto): void {
  if (status.scope !== status.mode) throw new ContractViolation();
  if (status.steadyLatencyMs !== undefined && (!["system_proxy_ready", "tun_ready"].includes(status.phase)
    || status.error || status.routeCheckMs === undefined || !status.sessionId || !status.nodeId)) throw new ContractViolation();
  const systemOnlyPhases: RuntimePhaseDto[] = [
    "applying_system_proxy",
    "system_proxy_ready",
    "restoring_system_proxy",
    "blocked_by_conflict",
  ];
  if (systemOnlyPhases.includes(status.phase) && status.scope !== "system_proxy") throw new ContractViolation();
  if (status.phase === "tun_ready" && status.scope !== "tun") throw new ContractViolation();
  for (const proof of status.proofs) {
    if (proof.latencyMs !== undefined && proof.state !== "passed") throw new ContractViolation();
    if (proof.kind !== "selected_outbound_https" && proof.latencyMs !== undefined) throw new ContractViolation();
  }

  if (status.phase === "disconnected") {
    if (status.scope !== "local_only" || status.mode !== "local_only") throw new ContractViolation();
    if (status.sessionId || status.nodeId || status.ports || status.routeCheckMs !== undefined || status.engineVersion || status.error) {
      throw new ContractViolation();
    }
    if (status.proofs.length !== allProofKinds.length || status.proofs.some((proof) => proof.state !== "not_run")) {
      throw new ContractViolation();
    }
  }

  if (status.phase === "local_proxy_ready") {
    if (!status.sessionId || !status.nodeId || !status.ports || status.error || status.routeCheckMs === undefined) {
      throw new ContractViolation();
    }
    if (status.scope !== "local_only" || status.mode !== "local_only" || status.proofs.length !== allProofKinds.length) {
      throw new ContractViolation();
    }
    for (const kind of readyProofKinds) {
      const proof = status.proofs.find((candidate) => candidate.kind === kind);
      if (!proof || proof.state !== "passed") throw new ContractViolation();
    }
    const outbound = status.proofs.find((proof) => proof.kind === "selected_outbound_https");
    if (outbound?.latencyMs === undefined || outbound.latencyMs !== status.routeCheckMs) throw new ContractViolation();
    if (status.proofs.find((proof) => proof.kind === "system_proxy_ownership")?.state !== "not_run") {
      throw new ContractViolation();
    }
  }

  if (status.phase === "system_proxy_ready") {
    if (status.scope !== "system_proxy" || status.mode !== "system_proxy" || !status.sessionId || !status.nodeId
      || !status.ports || status.error || status.routeCheckMs === undefined || status.proofs.length !== allProofKinds.length) {
      throw new ContractViolation();
    }
    for (const kind of allProofKinds) {
      const proof = status.proofs.find((candidate) => candidate.kind === kind);
      if (!proof || proof.state !== "passed") throw new ContractViolation();
    }
    const outbound = status.proofs.find((proof) => proof.kind === "selected_outbound_https");
    if (outbound?.latencyMs === undefined || outbound.latencyMs !== status.routeCheckMs) throw new ContractViolation();
  }

  if (status.phase === "tun_ready") {
    if (status.scope !== "tun" || status.mode !== "tun" || !status.sessionId || !status.nodeId
      || !status.ports || status.error || status.routeCheckMs === undefined || status.proofs.length !== allProofKinds.length) {
      throw new ContractViolation();
    }
    for (const kind of readyProofKinds) {
      const proof = status.proofs.find((candidate) => candidate.kind === kind);
      if (!proof || proof.state !== "passed") throw new ContractViolation();
    }
    const outbound = status.proofs.find((proof) => proof.kind === "selected_outbound_https");
    if (outbound?.latencyMs === undefined || outbound.latencyMs !== status.routeCheckMs) throw new ContractViolation();
    if (status.proofs.find((proof) => proof.kind === "system_proxy_ownership")?.state !== "not_run") {
      throw new ContractViolation();
    }
  }

  if (status.phase === "applying_system_proxy") {
    if (!status.sessionId || !status.nodeId || !status.ports || status.error
      || status.proofs.find((proof) => proof.kind === "system_proxy_ownership")?.state !== "pending") {
      throw new ContractViolation();
    }
  }

  if (status.phase === "restoring_system_proxy" && (!status.sessionId || !status.nodeId || !status.ports || status.error)) {
    throw new ContractViolation();
  }

  if (status.phase === "blocked_by_conflict") {
    if (!status.sessionId || !status.nodeId || !status.ports || status.error?.stage !== "system_proxy_ownership"
      || status.proofs.find((proof) => proof.kind === "system_proxy_ownership")?.state !== "failed") {
      throw new ContractViolation();
    }
  }

  if (status.phase === "degraded" && (!status.sessionId || !status.nodeId || !status.ports || !status.error)) {
    throw new ContractViolation();
  }

  if ((status.phase === "recovery_required" || status.phase === "disconnected_with_error") && !status.error) {
    throw new ContractViolation();
  }
}

export function isVerifiedLocalReady(status: RuntimeStatusDto): boolean {
  if (status.phase !== "local_proxy_ready") return false;
  try {
    validateRuntimeRelationships(status);
    return true;
  } catch {
    return false;
  }
}

export function isVerifiedSystemProxyReady(status: RuntimeStatusDto): boolean {
  if (status.phase !== "system_proxy_ready") return false;
  try {
    validateRuntimeRelationships(status);
    return true;
  } catch {
    return false;
  }
}

export function isVerifiedTunReady(status: RuntimeStatusDto): boolean {
  if (status.phase !== "tun_ready") return false;
  try {
    validateRuntimeRelationships(status);
    return true;
  } catch {
    return false;
  }
}

export function parseRunningApplications(value: unknown): RunningApplicationDto[] {
  if (!Array.isArray(value) || value.length > 256) throw new ContractViolation();
  const applications = value.map((entry): RunningApplicationDto => {
    const input = record(entry);
    exactKeys(input, ["processName", "executablePath", "displayName"]);
    return {
      processName: boundedString(input.processName, 260),
      executablePath: boundedString(input.executablePath, 4096),
      displayName: boundedString(input.displayName, 260),
    };
  });
  const paths = applications.map((application) => application.executablePath.replaceAll("/", "\\").toLocaleLowerCase("en-US"));
  if (new Set(paths).size !== paths.length) throw new ContractViolation();
  return applications;
}

function parseConfirmedNodeArray(value: unknown, allowSource = false): ConfirmedNodeDto[] {
  if (!Array.isArray(value) || value.length > 2000) throw new ContractViolation();
  const nodes = value.map((entry): ConfirmedNodeDto => {
    const node = record(entry);
    const baseKeys = ["id", "displayName", "protocol", "insecureTls"];
    exactKeys(node, [...baseKeys, ...(allowSource ? ["sourceId", "sourceName", "sourceKind", "sourceRefreshable", "sourceUpdatedAtMs"] : [])], baseKeys);
    if (typeof node.insecureTls !== "boolean") throw new ContractViolation();
    const hasSource = ["sourceId", "sourceName", "sourceKind"].some((key) => node[key] !== undefined);
    const source = hasSource ? {
      sourceId: boundedString(node.sourceId, 80),
      sourceName: boundedString(node.sourceName, 160),
      sourceKind: member(node.sourceKind, ["manual", "subscription"] as const),
    } : {};
    if (source.sourceId !== undefined && !/^[a-f0-9]{32}$/.test(source.sourceId)) throw new ContractViolation();
    if (node.sourceRefreshable !== undefined && (typeof node.sourceRefreshable !== "boolean" || !source.sourceId)) throw new ContractViolation();
    if (node.sourceUpdatedAtMs !== undefined && (!Number.isSafeInteger(node.sourceUpdatedAtMs) || (node.sourceUpdatedAtMs as number) < 0 || !source.sourceId)) throw new ContractViolation();
    if (source.sourceKind === "manual" && node.sourceRefreshable === true) throw new ContractViolation();
    return {
      id: boundedString(node.id, 256),
      displayName: boundedString(node.displayName, 512),
      protocol: member(node.protocol, protocols),
      insecureTls: node.insecureTls,
      ...source,
      ...(node.sourceRefreshable === undefined ? {} : { sourceRefreshable: node.sourceRefreshable as boolean }),
      ...(node.sourceUpdatedAtMs === undefined ? {} : { sourceUpdatedAtMs: node.sourceUpdatedAtMs as number }),
    };
  });
  if (new Set(nodes.map((node) => node.id)).size !== nodes.length) throw new ContractViolation();
  return nodes;
}

export function parseConfirmedNodes(value: unknown): ConfirmedNodeDto[] {
  const nodes = parseConfirmedNodeArray(value, true);
  const groups = new Map<string, string>();
  for (const node of nodes) {
    if (!node.sourceId) continue;
    const metadata = JSON.stringify([node.sourceName, node.sourceKind, node.sourceRefreshable, node.sourceUpdatedAtMs]);
    if (groups.has(node.sourceId) && groups.get(node.sourceId) !== metadata) throw new ContractViolation();
    groups.set(node.sourceId, metadata);
  }
  return nodes;
}

export function parseImportPreview(value: unknown): ImportPreviewDto {
  const input = record(value);
  exactKeys(input, ["previewId", "nodes", "rejected", "warnings"]);
  if (!Array.isArray(input.nodes) || input.nodes.length > 2000) throw new ContractViolation();
  if (!Array.isArray(input.rejected) || input.rejected.length > 2000) throw new ContractViolation();
  if (!Array.isArray(input.warnings) || input.warnings.length > 64) throw new ContractViolation();
  const preview: ImportPreviewDto = {
    previewId: boundedString(input.previewId, 256),
    nodes: parseConfirmedNodeArray(input.nodes),
    rejected: input.rejected.map((entry) => {
      const rejection = record(entry);
      exactKeys(rejection, ["index", "reason"]);
      return {
        index: finiteInteger(rejection.index, 0, 2000),
        reason: boundedString(rejection.reason, 1024),
      };
    }),
    warnings: input.warnings.map((warning) => boundedString(warning, 1024)),
  };
  return preview;
}

export function parseConfirmedImport(value: unknown): ConfirmedImportDto {
  const input = record(value);
  exactKeys(input, ["imported", "nodeIds"]);
  if (!Array.isArray(input.nodeIds) || input.nodeIds.length > 2000) throw new ContractViolation();
  const confirmed: ConfirmedImportDto = {
    imported: finiteInteger(input.imported, 0, 2000),
    nodeIds: input.nodeIds.map((id) => boundedString(id, 256)),
  };
  if (confirmed.imported !== confirmed.nodeIds.length) throw new ContractViolation();
  if (new Set(confirmed.nodeIds).size !== confirmed.nodeIds.length) throw new ContractViolation();
  return confirmed;
}

export function parseDiagnostics(value: unknown): DiagnosticsDto {
  const input = record(value);
  exactKeys(input, ["status", "lines", "systemProxy"]);
  if (!Array.isArray(input.lines) || input.lines.length > 256) throw new ContractViolation();
  return {
    status: parseRuntimeStatus(input.status),
    lines: input.lines.map((line) => boundedString(line, 8192, true)),
    systemProxy: parseSystemProxyDiagnostic(input.systemProxy),
  };
}

export function parseSystemProxyDiagnostic(value: unknown): SystemProxyDiagnosticDto {
  const input = record(value);
  exactKeys(input, ["state", "endpoint", "detail", "cleanupToken"]);
  if (!["disabled", "owned", "foreignActive", "stale", "conflict", "unavailable"].includes(input.state as string)) throw new ContractViolation();
  const endpoint = input.endpoint === null ? null : boundedString(input.endpoint, 64);
  if (endpoint !== null) {
    const match = /^(?:127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})|\[::1\]):([1-9]\d{0,4})$/.exec(endpoint);
    if (!match || match.slice(1, 4).some((part) => part !== undefined && Number(part) > 255) || Number(match[4]) > 65535) throw new ContractViolation();
  }
  const detail = boundedString(input.detail, 512, true);
  if (/[\u0000-\u001f\u007f-\u009f]/.test(detail) || /(?:https?|ftp):\/\//i.test(detail) || /\b(?:vless|hysteria2|naive):/i.test(detail) || /\S+@\S+/.test(detail)) throw new ContractViolation();
  const cleanupToken = input.cleanupToken === null ? null : boundedString(input.cleanupToken, 64);
  if ((cleanupToken !== null && (!/^[a-f0-9]{64}$/.test(cleanupToken) || input.state !== "stale" || endpoint === null))) throw new ContractViolation();
  return { state: input.state as SystemProxyDiagnosticDto["state"], endpoint, detail, cleanupToken };
}

/** Rust unit responses serialize as JSON null. */
export function parseUnitResponse(value: unknown): void {
  if (value !== null) throw new ContractViolation();
}

/** Accepts only strictly newer snapshots, preventing the initial invoke result from overwriting an event. */
export class RuntimeRevisionGate {
  private revision = -1;

  accept(status: RuntimeStatusDto): boolean {
    if (status.revision <= this.revision) return false;
    this.revision = status.revision;
    return true;
  }

  current(): number {
    return this.revision;
  }
}
