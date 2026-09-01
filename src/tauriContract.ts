const runtimePhases = [
  "disconnected",
  "preparing",
  "validating_config",
  "starting_core",
  "verifying_listener",
  "proving_traffic",
  "outbound_verified",
  "local_proxy_ready",
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
  scope: "local_only";
  mode: "local_only";
  phase: RuntimePhaseDto;
  nodeId?: string;
  ports?: { http: number; socks: number; health: number };
  routeCheckMs?: number;
  engineVersion?: string;
  proofs: RuntimeProofDto[];
  error?: PublicErrorDto;
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

export interface ConfirmedImportDto {
  imported: number;
  nodeIds: string[];
}

export interface DiagnosticsDto {
  status: RuntimeStatusDto;
  lines: string[];
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
    ["revision", "sessionId", "scope", "mode", "phase", "nodeId", "ports", "routeCheckMs", "engineVersion", "proofs", "error"],
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
    scope: member(input.scope, ["local_only"] as const),
    mode: member(input.mode, ["local_only"] as const),
    phase: member(input.phase, runtimePhases),
    nodeId: optionalIdentifier(input.nodeId, 256),
    ports,
    routeCheckMs: optionalDuration(input.routeCheckMs),
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

function validateRuntimeRelationships(status: RuntimeStatusDto): void {
  for (const proof of status.proofs) {
    if (proof.latencyMs !== undefined && proof.state !== "passed") throw new ContractViolation();
    if (proof.kind !== "selected_outbound_https" && proof.latencyMs !== undefined) throw new ContractViolation();
  }

  if (status.phase === "disconnected") {
    if (status.sessionId || status.nodeId || status.ports || status.routeCheckMs !== undefined || status.engineVersion || status.error) {
      throw new ContractViolation();
    }
    if (status.proofs.length !== readyProofKinds.length || status.proofs.some((proof) => proof.state !== "not_run")) {
      throw new ContractViolation();
    }
  }

  if (status.phase === "local_proxy_ready") {
    if (!status.sessionId || !status.nodeId || !status.ports || status.error || status.routeCheckMs === undefined) {
      throw new ContractViolation();
    }
    if (status.proofs.length !== readyProofKinds.length) throw new ContractViolation();
    for (const kind of readyProofKinds) {
      const proof = status.proofs.find((candidate) => candidate.kind === kind);
      if (!proof || proof.state !== "passed") throw new ContractViolation();
    }
    const outbound = status.proofs.find((proof) => proof.kind === "selected_outbound_https");
    if (outbound?.latencyMs === undefined || outbound.latencyMs !== status.routeCheckMs) throw new ContractViolation();
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

export function parseImportPreview(value: unknown): ImportPreviewDto {
  const input = record(value);
  exactKeys(input, ["previewId", "nodes", "rejected", "warnings"]);
  if (!Array.isArray(input.nodes) || input.nodes.length > 2000) throw new ContractViolation();
  if (!Array.isArray(input.rejected) || input.rejected.length > 2000) throw new ContractViolation();
  if (!Array.isArray(input.warnings) || input.warnings.length > 64) throw new ContractViolation();
  const preview: ImportPreviewDto = {
    previewId: boundedString(input.previewId, 256),
    nodes: input.nodes.map((entry) => {
      const node = record(entry);
      exactKeys(node, ["id", "displayName", "protocol", "insecureTls"]);
      if (typeof node.insecureTls !== "boolean") throw new ContractViolation();
      return {
        id: boundedString(node.id, 256),
        displayName: boundedString(node.displayName, 512),
        protocol: member(node.protocol, protocols),
        insecureTls: node.insecureTls,
      };
    }),
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
  if (new Set(preview.nodes.map((node) => node.id)).size !== preview.nodes.length) throw new ContractViolation();
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
  exactKeys(input, ["status", "lines"]);
  if (!Array.isArray(input.lines) || input.lines.length > 256) throw new ContractViolation();
  return {
    status: parseRuntimeStatus(input.status),
    lines: input.lines.map((line) => boundedString(line, 8192, true)),
  };
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
