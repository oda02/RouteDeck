import assert from "node:assert/strict";
import test from "node:test";

import { selectControllerRuntime } from "../src/runtimeSelection.ts";
import {
  ContractViolation,
  RuntimeRevisionGate,
  parseRuntimeStatus,
  parseUnitResponse,
  type RuntimeStatusDto,
} from "../src/tauriContract.ts";
import {
  TauriController,
  runtimePhaseToConnectionPhase,
  type TauriTransport,
} from "../src/tauriController.ts";

function runtimeStatus(revision: number, phase: RuntimeStatusDto["phase"]): RuntimeStatusDto {
  return {
    revision,
    sessionId: phase === "disconnected" ? undefined : "fixture-session",
    scope: "local_only",
    mode: "local_only",
    phase,
    nodeId: phase === "disconnected" ? undefined : "fixture-node",
    ports: phase === "disconnected" ? undefined : { http: 24080, socks: 24081, health: 24082 },
    routeCheckMs: phase === "local_proxy_ready" ? 84 : undefined,
    engineVersion: phase === "disconnected" ? undefined : "1.13.19",
    proofs: [
      { kind: "engine_config", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "engine_process", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "http_listener", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "socks_listener", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "health_listener", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "selected_outbound_https", state: phase === "local_proxy_ready" ? "passed" : "not_run", latencyMs: phase === "local_proxy_ready" ? 84 : undefined },
      { kind: "local_scope_ownership", state: phase === "disconnected" ? "not_run" : "passed" },
    ],
  };
}

test("release selection can never choose the demo controller", () => {
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: false, tauriIpcAvailable: true }), "tauri");
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: false, tauriIpcAvailable: false }), "unavailable");
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: true, tauriIpcAvailable: true }), "demo");
});

test("local-only readiness never maps to global Connected", () => {
  assert.equal(runtimePhaseToConnectionPhase("outbound_verified"), "verifying-outbound");
  assert.equal(runtimePhaseToConnectionPhase("local_proxy_ready"), "degraded");
  assert.notEqual(runtimePhaseToConnectionPhase("local_proxy_ready"), "connected");
});

test("revision gate rejects a stale initial snapshot after a newer event", () => {
  const gate = new RuntimeRevisionGate();
  assert.equal(gate.accept(runtimeStatus(2, "local_proxy_ready")), true);
  assert.equal(gate.accept(runtimeStatus(1, "disconnected")), false);
  assert.equal(gate.current(), 2);
});

test("listen-first initialization preserves the event that wins the snapshot race", async () => {
  let unlistenCalls = 0;
  const transport: TauriTransport = {
    listen: async (_event, handler) => {
      handler(runtimeStatus(2, "local_proxy_ready"));
      return () => { unlistenCalls += 1; };
    },
    invoke: async (command) => {
      assert.equal(command, "runtime_status");
      return runtimeStatus(1, "disconnected");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();

  const snapshot = controller.getSnapshot();
  assert.equal(snapshot.phase, "degraded");
  assert.equal(snapshot.environment.systemProxyOwner, "none");
  assert.equal(snapshot.notice?.id, "local-proxy-only");
  assert.match(snapshot.notice?.body ?? "", /Системный прокси и TUN пока не включены/);

  controller.dispose();
  assert.equal(unlistenCalls, 1);
});

test("malformed runtime DTO fails closed without surfacing raw payload", async () => {
  const secret = "fixture-super-secret";
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async () => ({ ...runtimeStatus(1, "local_proxy_ready"), revision: "bad", leaked: secret }),
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();

  const snapshot = controller.getSnapshot();
  assert.equal(snapshot.backendAvailable, false);
  assert.equal(snapshot.phase, "failed");
  assert.equal(snapshot.notice?.id, "backend-response-invalid");
  assert.doesNotMatch(JSON.stringify(snapshot), new RegExp(secret));
  await assert.rejects(controller.connect(), { code: "backend-unavailable" });
  controller.dispose();
});

test("schema validator rejects duplicate proofs and invalid enum values", () => {
  const duplicate = runtimeStatus(1, "disconnected");
  duplicate.proofs[1] = { ...duplicate.proofs[0] };
  assert.throws(() => parseRuntimeStatus(duplicate), ContractViolation);
  assert.throws(
    () => parseRuntimeStatus({ ...runtimeStatus(1, "disconnected"), scope: "system_proxy" }),
    ContractViolation,
  );
});

test("unit command responses accept only Rust null", () => {
  assert.doesNotThrow(() => parseUnitResponse(null));
  assert.throws(() => parseUnitResponse(undefined), ContractViolation);
  assert.throws(() => parseUnitResponse({}), ContractViolation);
});

test("ready status requires complete proof, identity, latency, and distinct ports", () => {
  const ready = runtimeStatus(4, "local_proxy_ready");
  assert.doesNotThrow(() => parseRuntimeStatus(ready));
  assert.throws(() => parseRuntimeStatus({ ...ready, sessionId: undefined }), ContractViolation);
  assert.throws(
    () => parseRuntimeStatus({ ...ready, ports: { http: 24080, socks: 24080, health: 24082 } }),
    ContractViolation,
  );
  assert.throws(
    () => parseRuntimeStatus({ ...ready, routeCheckMs: 85 }),
    ContractViolation,
  );
  assert.throws(
    () => parseRuntimeStatus({ ...ready, proofs: ready.proofs.map((proof) => proof.kind === "local_scope_ownership" ? { ...proof, state: "failed" as const } : proof) }),
    ContractViolation,
  );
});

test("cancelled import cannot retain or publish a late preview", async () => {
  let resolvePreview!: (value: unknown) => void;
  const discarded: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const previewResult = new Promise<unknown>((resolve) => { resolvePreview = resolve; });
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return previewResult;
      if (command === "discard_import_preview") {
        discarded.push({ command, arguments_ });
        return null;
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  const pending = controller.previewSubscription({ type: "clipboard", value: "vless://hidden-fixture" });
  controller.cancelImportPreview();
  resolvePreview({
    previewId: "preview-fixture",
    nodes: [{ id: "node-fixture", displayName: "Fixture", protocol: "vless", insecureTls: false }],
    rejected: [],
    warnings: [],
  });
  await assert.rejects(pending, { code: "stale-subscription-preview" });
  assert.deepEqual(discarded, [{ command: "discard_import_preview", arguments_: { previewId: "preview-fixture" } }]);
  assert.equal(controller.getSnapshot().servers.length, 0);
  controller.dispose();
});

test("closing a known preview discards its opaque token with exact arguments", async () => {
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return {
        previewId: "preview-known",
        nodes: [{ id: "node-known", displayName: "Known", protocol: "vless", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "discard_import_preview") return null;
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  await controller.previewSubscription({ type: "clipboard", value: "vless://hidden-fixture" });
  controller.cancelImportPreview();
  await Promise.resolve();
  assert.deepEqual(calls.at(-1), {
    command: "discard_import_preview",
    arguments_: { previewId: "preview-known" },
  });
  controller.dispose();
});

test("cancel during confirm cannot hide the reconciled import result", async () => {
  let resolveConfirm!: (value: unknown) => void;
  const confirmResult = new Promise<unknown>((resolve) => { resolveConfirm = resolve; });
  const calls: string[] = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      calls.push(command);
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return {
        previewId: "preview-confirm",
        nodes: [{ id: "node-confirm", displayName: "Confirmed", protocol: "hysteria2", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "confirm_import") return confirmResult;
      if (command === "discard_import_preview") return null;
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "hysteria2://hidden-fixture" });
  const confirming = controller.commitSubscription(preview);
  controller.cancelImportPreview();
  resolveConfirm({ imported: 1, nodeIds: ["node-confirm"] });
  await confirming;
  assert.equal(controller.getSnapshot().servers[0]?.id, "node-confirm");
  assert.equal(calls.filter((command) => command === "discard_import_preview").length, 0);
  controller.dispose();
});

test("local-only routing and settings actions fail instead of claiming success", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async () => runtimeStatus(1, "disconnected"),
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  assert.equal(controller.getSnapshot().runtimeScope, "local-only");
  await assert.rejects(controller.applyRouting({ defaultRoute: "vpn", apps: [] }), { code: "capability-unavailable" });
  await assert.rejects(controller.saveSettings(controller.getSnapshot().settings), { code: "capability-unavailable" });
  controller.dispose();
});

test("malformed diagnostics always clears the running flag and fails closed", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => command === "runtime_status"
      ? runtimeStatus(1, "disconnected")
      : { status: { ...runtimeStatus(2, "disconnected"), unexpected: true }, lines: [] },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  await assert.rejects(controller.runDiagnostics(), { code: "backend-response-invalid" });
  assert.equal(controller.getSnapshot().diagnostics.running, false);
  assert.equal(controller.getSnapshot().backendAvailable, false);
  controller.dispose();
});

test("runtime diagnostics is labelled as a received snapshot, not a fresh proof run", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => command === "runtime_status"
      ? runtimeStatus(1, "disconnected")
      : { status: runtimeStatus(2, "disconnected"), lines: ["sanitized"] },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  await controller.runDiagnostics();
  const diagnostics = controller.getSnapshot().diagnostics;
  assert.equal(typeof diagnostics.snapshotReceivedAt, "string");
  assert.equal(diagnostics.running, false);
  assert.ok(diagnostics.steps.every((proof) => proof.checkedAt === undefined));
  assert.deepEqual(diagnostics.sanitizedLog, ["sanitized"]);
  controller.dispose();
});
