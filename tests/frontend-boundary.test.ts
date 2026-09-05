import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

async function withPreferenceStorage(body: (storage: Map<string, string>, faults: { write: boolean }) => Promise<void>, initial: Record<string, string> = {}) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "window");
  const storage = new Map(Object.entries(initial));
  const faults = { write: false };
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    addEventListener() {}, removeEventListener() {},
    localStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { if (faults.write) throw new Error("Storage unavailable"); storage.set(key, value); },
      removeItem: (key: string) => { if (faults.write) throw new Error("Storage unavailable"); storage.delete(key); },
    },
  } });
  try { await body(storage, faults); }
  finally { if (previous) Object.defineProperty(globalThis, "window", previous); else Reflect.deleteProperty(globalThis, "window"); }
}

async function lifecycleFixture(connected = true, protocol = "vless") {
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  let revision = 0;
  const sourceId = "a".repeat(32);
  let nodes = ["a", "b", "c"].map((id) => ({ id, displayName: `Server ${id}`, protocol, insecureTls: false,
    sourceId: id === "c" ? "b".repeat(32) : sourceId, sourceName: id === "c" ? "Other" : "Subscription", sourceKind: "subscription", sourceRefreshable: true, sourceUpdatedAtMs: 100 }));
  const hooks: { stop?: () => Promise<unknown>; start?: () => Promise<unknown>; refresh?: () => Promise<unknown> } = {};
  const status = (phase: RuntimeStatusDto["phase"], nodeId = "a") => ({ ...runtimeStatus(++revision, phase), ...(phase === "disconnected" ? {} : { nodeId }) });
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return status(connected ? "system_proxy_ready" : "disconnected");
      if (command === "confirmed_nodes") return nodes;
      if (command.startsWith("stop_")) return hooks.stop ? hooks.stop() : status("disconnected");
      if (command.startsWith("start_")) return hooks.start ? hooks.start() : status(command === "start_tun" ? "tun_ready" : "system_proxy_ready", arguments_?.nodeId as string);
      if (command === "refresh_source") {
        if (hooks.refresh) return hooks.refresh();
        nodes = nodes.map((node) => node.sourceId === sourceId ? { ...node, sourceUpdatedAtMs: 200 } : node);
        return { imported: 2, nodeIds: ["a", "b"] };
      }
      if (command === "remove_source") { nodes = nodes.filter((node) => node.sourceId !== arguments_?.sourceId); return null; }
      if (command === "retry_session_recovery") return status("disconnected");
      if (command === "reset_local_state") { nodes = []; return null; }
      throw new Error("Unexpected fixture command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  calls.length = 0;
  return { controller, calls, hooks, status, sourceId };
}

import { toPublicActionError } from "../src/actionErrors.ts";
import { defaultTrafficRules, RouteDeckError } from "../src/model.ts";
import { selectControllerRuntime } from "../src/runtimeSelection.ts";
import {
  ContractViolation,
  RuntimeRevisionGate,
  parsePublicError,
  parseConfirmedNodes,
  parseImportPreview,
  parseDiagnostics,
  parseRunningApplications,
  parseRuntimeStatus,
  parseUnitResponse,
  type RuntimeStatusDto,
} from "../src/tauriContract.ts";
import {
  TauriController,
  validatedRouting,
  runtimePhaseToConnectionPhase,
  type TauriTransport,
} from "../src/tauriController.ts";

function runtimeStatus(revision: number, phase: RuntimeStatusDto["phase"]): RuntimeStatusDto {
  const ready = phase === "local_proxy_ready" || phase === "system_proxy_ready" || phase === "tun_ready";
  const systemProxy = phase === "system_proxy_ready";
  const tun = phase === "tun_ready";
  return {
    revision,
    sessionId: phase === "disconnected" ? undefined : "fixture-session",
    scope: tun ? "tun" : systemProxy ? "system_proxy" : "local_only",
    mode: tun ? "tun" : systemProxy ? "system_proxy" : "local_only",
    phase,
    nodeId: phase === "disconnected" ? undefined : "fixture-node",
    ports: phase === "disconnected" ? undefined : { http: 24080, socks: 24081, health: 24082 },
    routeCheckMs: ready ? 84 : undefined,
    steadyLatencyMs: systemProxy || tun ? 42 : undefined,
    engineVersion: phase === "disconnected" ? undefined : "1.13.19",
    proofs: [
      { kind: "engine_config", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "engine_process", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "http_listener", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "socks_listener", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "health_listener", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "selected_outbound_https", state: ready ? "passed" : "not_run", latencyMs: ready ? 84 : undefined },
      { kind: "local_scope_ownership", state: phase === "disconnected" ? "not_run" : "passed" },
      { kind: "system_proxy_ownership", state: systemProxy ? "passed" : "not_run" },
    ],
  };
}

function withEmptyConfirmedNodes(transport: TauriTransport): TauriTransport {
  let confirmedNodes: unknown[] = [];
  let previewNodes: Array<{ id: string }> = [];
  return {
    ...transport,
    invoke: async (command, arguments_) => {
      if (command === "confirmed_nodes") return confirmedNodes;
      const result = await transport.invoke(command, arguments_);
      if (command === "preview_import_content" || command === "preview_import_url") previewNodes = (result as { nodes: Array<{ id: string }> }).nodes;
      if (command === "confirm_import") {
        const ids = new Set((result as { nodeIds: string[] }).nodeIds);
        confirmedNodes = [...confirmedNodes, ...previewNodes.filter((node) => ids.has(node.id))];
      }
      return result;
    },
  };
}

test("release selection can never choose the demo controller", () => {
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: false, tauriIpcAvailable: true }), "tauri");
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: false, tauriIpcAvailable: false }), "unavailable");
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: true, tauriIpcAvailable: true }), "demo");
});

test("source metadata is complete, consistent and forbidden in import previews", () => {
  const node = { id: "group-node", displayName: "Naive fixture", protocol: "naive", insecureTls: false,
    sourceId: "a".repeat(32), sourceName: "Personal", sourceKind: "manual" };
  assert.equal(parseConfirmedNodes([node])[0].sourceName, "Personal");
  for (const sourceId of ["__proto__", "constructor", "x".repeat(32), "a".repeat(33)]) {
    assert.throws(() => parseConfirmedNodes([{ ...node, sourceId }]), ContractViolation);
  }
  assert.throws(() => parseConfirmedNodes([{ ...node, sourceKind: "other" }]), ContractViolation);
  assert.throws(() => parseConfirmedNodes([{ ...node, sourceName: undefined }]), ContractViolation);
  assert.throws(() => parseConfirmedNodes([node, { ...node, id: "other", sourceName: "Different" }]), ContractViolation);
  assert.throws(() => parseConfirmedNodes([{ ...node, content: "secret" }]), ContractViolation);
  assert.throws(() => parseImportPreview({ previewId: "p", nodes: [node], rejected: [], warnings: [] }), ContractViolation);
});

test("manual import reloads the additive library and preserves the selected server", async () => {
  const old = { id: "old-node", displayName: "Existing", protocol: "hysteria2", insecureTls: false,
    sourceId: "0".repeat(32), sourceName: "Provider", sourceKind: "subscription" };
  const added = { id: "new-scoped-node", displayName: "Naive", protocol: "naive", insecureTls: false,
    sourceId: "1".repeat(32), sourceName: "Personal", sourceKind: "manual" };
  let saved = false;
  const controller = new TauriController(async () => ({
    listen: async () => () => undefined,
    invoke: async (command, args) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "confirmed_nodes") return saved ? [old, added] : [old];
      if (command === "preview_import_content") return { previewId: "p", nodes: [{ id: "raw-id", displayName: "Naive", protocol: "naive", insecureTls: false }], rejected: [], warnings: [] };
      if (command === "confirm_import") {
        assert.deepEqual(args, { previewId: "p", sourceName: "Personal" });
        saved = true;
        return { imported: 1, nodeIds: [added.id] };
      }
      throw new Error("unexpected fixture command");
    },
  }));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "naive+https://fixture:secret@example.invalid" });
  await controller.commitSubscription(preview, "Personal");
  const state = controller.getSnapshot();
  assert.equal(state.selectedServerId, old.id);
  assert.deepEqual(state.servers.map((server) => server.source), ["Provider", "Personal"]);
  assert.equal(state.servers[1].detail, "Импортировано");
  assert.doesNotMatch(JSON.stringify(state), /fixture:secret/);
  controller.dispose();
});

test("confirmation fails closed if the backend library loses previously imported nodes", async () => {
  let confirmed = false;
  const controller = new TauriController(async () => ({
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "confirmed_nodes") return [{ id: confirmed ? "new" : "old", displayName: "Fixture", protocol: "naive", insecureTls: false }];
      if (command === "preview_import_content") return { previewId: "p", nodes: [{ id: "raw", displayName: "Fixture", protocol: "naive", insecureTls: false }], rejected: [], warnings: [] };
      if (command === "confirm_import") { confirmed = true; return { imported: 1, nodeIds: ["new"] }; }
      throw new Error("unexpected fixture command");
    },
  }));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "fixture" });
  await assert.rejects(controller.commitSubscription(preview), { code: "backend-response-invalid" });
  assert.equal(controller.getSnapshot().backendAvailable, false);
  controller.dispose();
});

test("busy import keeps focus inside the mounted dialog", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(source, /previouslyFocusedRef\.current = document\.activeElement[\s\S]*return \(\) => \{[\s\S]*previouslyFocusedRef\.current\.focus\(\{ preventScroll: true \}\)/);
  assert.match(source, /data-dialog-busy-focus/);
  assert.match(source, /role="status" aria-live="polite" tabIndex=\{-1\} data-dialog-busy-focus/);
  assert.match(source, /document\.addEventListener\("focusin", onFocusIn\)/);
  assert.match(source, /dialog\.contains\(event\.target as Node \| null\)/);
  assert.doesNotMatch(source, /previouslyFocused\?\.focus/);
});

test("every import failure focuses its enabled source or recovery control", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const errorTarget = source.indexOf('querySelector<HTMLElement>("[data-error-autofocus]:not(:disabled)")');
  const genericTarget = source.indexOf('querySelector<HTMLElement>("[data-autofocus]:not(:disabled)")', errorTarget);
  assert.ok(errorTarget >= 0 && genericTarget > errorTarget);
  assert.match(source, /id="subscription-url"[^\n]*data-error-autofocus=\{importError \? "true" : undefined\}/);
  assert.match(source, /focusKey=\{importPreview \? "import-preview" : importKind\}/);
  assert.match(source, /id="subscription-import-form"[^\n]*onSubmit=/);
  assert.doesNotMatch(source, /focusKey=\{[^\n]*importError/);
  assert.match(source, /requestAnimationFrame[\s\S]*subscriptionInputRef\.current : serverInputRef\.current\)\?\.focus/);
});

test("manual and URL sources use uncontrolled secret fields and a separate confirmation", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(source, /id="subscription-url" type="url" inputMode="url" autoComplete="off"/);
  assert.match(source, /textarea ref=\{serverInputRef\} id="server-content"/);
  assert.doesNotMatch(source, /subscriptionSource|setSubscriptionSource|setServerContent/);
  assert.match(source, /type: importKind === "subscription" \? "url" : "clipboard"/);
  assert.match(source, /controller.commitSubscription\(preview, sourceName\)/);
  assert.match(source, /clearSubscriptionUrl\(\);\s*setImportPreview\(preview\)/);
  assert.match(source, /closeDisabled=\{committingImport\}/);
  assert.match(source, /controller.cancelImportPreview\(\)/);
});

test("URL import keeps automatic transport and source-labelled groups", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(source, /SubscriptionFetchTransport|subscriptionTransport|current_loopback_system_proxy/);
  assert.match(source, /Добавить подписку/);
  assert.match(source, /Добавить сервер/);
  assert.match(source, /server.sourceId \?\? server.source/);
  assert.match(source, /aria-expanded=\{expanded\}/);
});

test("local-only readiness never maps to global Connected", () => {
  assert.equal(runtimePhaseToConnectionPhase("outbound_verified"), "verifying-outbound");
  assert.equal(runtimePhaseToConnectionPhase("local_proxy_ready"), "degraded");
  assert.notEqual(runtimePhaseToConnectionPhase("local_proxy_ready"), "connected");
});

test("verified System Proxy readiness maps to Connected", () => {
  assert.equal(runtimePhaseToConnectionPhase("applying_system_proxy"), "applying-windows-mode");
  assert.equal(runtimePhaseToConnectionPhase("system_proxy_ready"), "connected");
  assert.equal(runtimePhaseToConnectionPhase("blocked_by_conflict"), "blocked-by-conflict");
  assert.doesNotThrow(() => parseRuntimeStatus(runtimeStatus(3, "system_proxy_ready")));
  assert.throws(
    () => parseRuntimeStatus({ ...runtimeStatus(4, "system_proxy_ready"), scope: "local_only", mode: "local_only" }),
    ContractViolation,
  );
  assert.throws(
    () => parseRuntimeStatus({ ...runtimeStatus(5, "local_proxy_ready"), phase: "blocked_by_conflict" }),
    ContractViolation,
  );
});

test("verified TUN readiness maps to Connected without pretending to own System Proxy", () => {
  const ready = runtimeStatus(6, "tun_ready");
  assert.equal(runtimePhaseToConnectionPhase("tun_ready"), "connected");
  assert.doesNotThrow(() => parseRuntimeStatus(ready));
  assert.throws(() => parseRuntimeStatus({ ...ready, scope: "system_proxy", mode: "system_proxy" }), ContractViolation);
  assert.throws(() => parseRuntimeStatus({
    ...ready,
    proofs: ready.proofs.map((proof) => proof.kind === "system_proxy_ownership"
      ? { ...proof, state: "passed" as const }
      : proof),
  }), ContractViolation);
});

test("live System Proxy transition keeps final proof summary coherent", () => {
  const ready = runtimeStatus(9, "system_proxy_ready");
  const applying = {
    ...ready,
    revision: 8,
    phase: "applying_system_proxy",
    steadyLatencyMs: undefined,
    routeCheckMs: null,
    proofs: ready.proofs.map((proof) => proof.kind === "system_proxy_ownership"
      ? { ...proof, state: "pending" }
      : proof),
  };
  assert.doesNotThrow(() => parseRuntimeStatus(applying));
  assert.doesNotThrow(() => parseRuntimeStatus(ready));
  // This is the exact broken final shape observed live before the backend fix.
  assert.throws(() => parseRuntimeStatus({ ...ready, routeCheckMs: null }), ContractViolation);
});

test("invalid backend copy stays simple and actionable", () => {
  const appSource = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const controllerSource = readFileSync(new URL("../src/tauriController.ts", import.meta.url), "utf8");
  const actionSource = readFileSync(new URL("../src/actionErrors.ts", import.meta.url), "utf8");
  assert.doesNotMatch(`${appSource}\n${controllerSource}\n${actionSource}`, /безопасн(?:ый|ая|о|ую)|Backend RouteDeck|Windows-backend|Локальный backend|listeners принадлежат|outbound подтверждён|Снимок доказательств/i);
  assert.match(toPublicActionError(new RouteDeckError("backend-response-invalid")).message, /Перезапустите RouteDeck/);
});

test("home stays focused on connection controls while detailed checks remain in diagnostics", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const home = source.slice(source.indexOf("function HomePage"), source.indexOf("function ServersPage"));
  const diagnostics = source.slice(source.indexOf("function DiagnosticsPage"), source.indexOf("function Dialog"));
  assert.doesNotMatch(home, /<ProofCard/);
  assert.match(diagnostics, /<ProofCard proofs=\{snapshot\.diagnostics\.steps\} title="Проверки"/);
  assert.match(source, /<small>VPN-клиент<\/small>/);
  assert.doesNotMatch(source, /Добавить · скоро|Этот вариант появится позже|advanced-settings/);
});

test("TUN and System Proxy application routing state their capture boundaries", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const styles = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
  assert.match(source, /value: "tun", label: "TUN"/);
  assert.doesNotMatch(source, /value: "tun"[^\n]*disabled: true|TUN · скоро/);
  assert.match(source, /Windows запросит права при подключении/);
  assert.match(source, /Добавить приложение/);
  assert.match(source, /controller\.listRunningApplications\(\)/);
  assert.match(source, /route: draft\.defaultRoute === "direct" \? "vpn" : "direct"/);
  assert.match(source, /[Тт]олько TCP приложений, использующих прокси Windows/);
  assert.match(source, /UDP и системный DNS не перехватываются/);
  assert.match(source, /Для остальных приложений и UDP нужен TUN/);
  assert.match(source, /Изменения сохраняются автоматически; активное соединение переподключится/);
  assert.doesNotMatch(source, /Настройки Direct и исключений применяются только в TUN|Правила приложений используются в режиме TUN|Прокси Windows: через выбранный VPN/);
  assert.doesNotMatch(source, /tun-preflight|nested|Физический адаптер|security mode|режим безопасности/i);
  assert.doesNotMatch(source, /запустите .*администратор/i);
  assert.doesNotMatch(source, /Проверить задержки|controller\.refreshServers/);
  assert.match(styles, /\.segmented-control \{[\s\S]*width: 100%;[\s\S]*grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/);
  assert.match(styles, /\.segmented-control label \{[\s\S]*min-width: 0;[\s\S]*min-height: 44px/);
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
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();

  const snapshot = controller.getSnapshot();
  assert.equal(snapshot.phase, "degraded");
  assert.equal(snapshot.environment.systemProxyOwner, "none");
  assert.equal(snapshot.notice?.id, "local-proxy-only");
  assert.match(snapshot.notice?.body ?? "", /Системный прокси и TUN пока не включены/);

  controller.dispose();
  assert.equal(unlistenCalls, 1);
});

test("cold initialization restores public nodes and follows an active TUN runtime", async () => {
  const calls: string[] = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      calls.push(command);
      if (command === "runtime_status") return runtimeStatus(7, "tun_ready");
      if (command === "confirmed_nodes") return [{
        id: "fixture-node",
        displayName: "Restored HY2",
        protocol: "hysteria2",
        insecureTls: false,
      }];
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();

  const snapshot = controller.getSnapshot();
  assert.equal(snapshot.mode, "tun");
  assert.equal(snapshot.runtimeScope, "tun");
  assert.equal(snapshot.selectedServerId, "fixture-node");
  assert.equal(snapshot.subscriptionName, "Подписка");
  assert.deepEqual(snapshot.servers, [{
    id: "fixture-node",
    name: "Restored HY2",
    country: "—",
    protocol: "Hysteria2",
    detail: "Импортировано",
    source: "Подписка",
    sourceId: undefined,
    sourceKind: undefined,
    sourceRefreshable: undefined,
    sourceUpdatedAtMs: undefined,
    latencyState: "ready",
    latencyMs: 42,
    checkedAt: undefined,
  }]);
  assert.deepEqual(calls, ["runtime_status", "confirmed_nodes"]);
  assert.doesNotMatch(JSON.stringify(snapshot), /https?:\/\//);
  controller.dispose();
});

test("runtime event received while nodes restore wins the server latency race", async () => {
  let emitRuntime!: (payload: unknown) => void;
  const transport: TauriTransport = {
    listen: async (_event, handler) => {
      emitRuntime = handler;
      return () => undefined;
    },
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "system_proxy_ready");
      if (command === "confirmed_nodes") {
        emitRuntime(runtimeStatus(2, "disconnected"));
        return [{
          id: "fixture-node",
          displayName: "Restored VLESS",
          protocol: "vless",
          insecureTls: false,
        }];
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();

  const snapshot = controller.getSnapshot();
  assert.equal(snapshot.phase, "disconnected");
  assert.equal(snapshot.servers[0]?.latencyState, "unavailable");
  assert.equal(snapshot.servers[0]?.latencyMs, undefined);
  assert.equal(snapshot.servers[0]?.checkedAt, undefined);
  controller.dispose();
});

test("malformed runtime DTO fails closed without surfacing raw payload", async () => {
  const secret = "fixture-super-secret";
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async () => ({ ...runtimeStatus(1, "local_proxy_ready"), revision: "bad", leaked: secret }),
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
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

test("running application contract is finite, exact, and deduplicated by executable", () => {
  const applications = [{
    processName: "browser.exe",
    executablePath: "C:\\Apps\\Browser.exe",
    displayName: "Browser.exe",
  }];
  assert.deepEqual(parseRunningApplications(applications), applications);
  assert.throws(() => parseRunningApplications([{ ...applications[0], pid: 7 }]), ContractViolation);
  assert.throws(() => parseRunningApplications([
    applications[0],
    { ...applications[0], executablePath: "c:/apps/browser.exe" },
  ]), ContractViolation);
});

test("subscription fetch errors require the exact finite contract", () => {
  assert.deepEqual(parsePublicError({
    code: "subscription_fetch_timeout",
    stage: "subscription_fetch",
    message: "subscription.timeout",
    detail: null,
  }), {
    code: "subscription_fetch_timeout",
    stage: "subscription_fetch",
    message: "subscription.timeout",
    detail: undefined,
  });
  assert.throws(() => parsePublicError({
    code: "subscription_fetch_timeout",
    stage: "subscription_response",
    message: "subscription.timeout",
    detail: null,
  }), ContractViolation);
  assert.doesNotThrow(() => parsePublicError({
    code: "subscription_fetch_timeout",
    stage: "subscription_dns",
    message: "subscription.timeout",
    detail: null,
  }));
  assert.throws(() => parsePublicError({
    code: "unknown_subscription_error",
    stage: "subscription_fetch",
    message: "subscription.unknown",
    detail: null,
  }), ContractViolation);
  assert.doesNotThrow(() => parsePublicError({
    code: "subscription_fetch_failed",
    stage: "subscription_dns",
    message: "subscription.fetch_failed",
    detail: null,
  }));
  assert.throws(() => parsePublicError({
    code: "subscription_policy_blocked",
    stage: "subscription_fetch",
    message: "subscription.policy_blocked",
    detail: null,
  }), ContractViolation);
  assert.throws(() => parsePublicError({
    code: "subscription_fetch_timeout",
    stage: "subscription_fetch",
    message: "raw backend detail",
    detail: "https://secret.example/token",
  }), ContractViolation);
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
  let markPreviewInvoked!: () => void;
  const discarded: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const previewResult = new Promise<unknown>((resolve) => { resolvePreview = resolve; });
  const previewInvoked = new Promise<void>((resolve) => { markPreviewInvoked = resolve; });
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") {
        markPreviewInvoked();
        return previewResult;
      }
      if (command === "discard_import_preview") {
        discarded.push({ command, arguments_ });
        return null;
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const pending = controller.previewSubscription({ type: "clipboard", value: "vless://hidden-fixture" });
  await previewInvoked;
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

test("cancelled import waiting for transport never sends secret-bearing IPC", async () => {
  const secret = "https://provider.example/subscription?token=cancel-before-ready";
  let resolveLoader!: (transport: TauriTransport) => void;
  const loader = new Promise<TauriTransport>((resolve) => { resolveLoader = resolve; });
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(await loader));
  const pending = controller.previewSubscription({ type: "url", value: secret });
  controller.cancelImportPreview();
  resolveLoader(transport);

  await assert.rejects(pending, { code: "stale-subscription-preview" });
  assert.deepEqual(calls, [{ command: "runtime_status", arguments_: undefined }]);
  assert.doesNotMatch(JSON.stringify(calls), /cancel-before-ready/);
  controller.dispose();
});

test("HTTPS URL preview uses the exact typed command and retains no secret", async () => {
  const secret = "https://user:password@provider.example/subscription?token=secret";
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_url") return {
        previewId: "preview-url",
        nodes: [{ id: "node-url", displayName: "Fetched", protocol: "vless", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "discard_import_preview") return null;
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "url", value: secret });
  assert.deepEqual(calls[1], { command: "preview_import_url", arguments_: { url: secret } });
  assert.equal(preview.sourceLabel, "HTTPS-подписка");
  assert.ok(!JSON.stringify(preview).includes(secret));
  assert.ok(!JSON.stringify(controller.getSnapshot()).includes(secret));
  assert.ok(!JSON.stringify(controller).includes(secret));
  controller.cancelImportPreview();
  controller.dispose();
});

test("automatic URL fetch failure performs one backend request", async () => {
  const secret = "https://provider.example/subscription?token=single-request";
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_url") {
        throw { code: "subscription_fetch_failed", stage: "subscription_fetch", message: "subscription.fetch_failed", detail: null };
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  await assert.rejects(
    controller.previewSubscription({ type: "url", value: secret }),
    (error: unknown) => {
      assert.ok(error instanceof RouteDeckError);
      assert.equal(error.code, "subscription-fetch-failed");
      assert.equal(toPublicActionError(error).message, "Не удалось загрузить подписку. Проверьте ссылку и подключение к интернету.");
      return true;
    },
  );
  const previewCalls = calls.filter((call) => call.command === "preview_import_url");
  assert.deepEqual(previewCalls, [{ command: "preview_import_url", arguments_: { url: secret } }]);
  controller.dispose();
});

test("stale HTTPS URL preview is discarded without publishing its secret", async () => {
  const secret = "https://provider.example/subscription?token=late-secret";
  let resolvePreview!: (value: unknown) => void;
  let markPreviewInvoked!: () => void;
  const previewResult = new Promise<unknown>((resolve) => { resolvePreview = resolve; });
  const previewInvoked = new Promise<void>((resolve) => { markPreviewInvoked = resolve; });
  const discarded: unknown[] = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_url") {
        markPreviewInvoked();
        return previewResult;
      }
      if (command === "discard_import_preview") {
        discarded.push(arguments_);
        return null;
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const pending = controller.previewSubscription({ type: "url", value: secret });
  await previewInvoked;
  controller.cancelImportPreview();
  resolvePreview({
    previewId: "preview-url-late",
    nodes: [{ id: "node-url-late", displayName: "Late", protocol: "hysteria2", insecureTls: false }],
    rejected: [],
    warnings: [],
  });
  await assert.rejects(pending, { code: "stale-subscription-preview" });
  assert.deepEqual(discarded, [{ previewId: "preview-url-late" }]);
  assert.ok(!JSON.stringify(controller).includes(secret));
  controller.dispose();
});

test("HTTPS fetch failures map to finite localized errors without backend detail", async () => {
  const cases = [
    ["subscription_url_invalid", "subscription_url", "subscription.url.invalid", "invalid-subscription-url"],
    ["subscription_policy_blocked", "subscription_dns", "subscription.policy_blocked", "subscription-policy-blocked"],
    ["subscription_fetch_failed", "subscription_fetch", "subscription.fetch_failed", "subscription-fetch-failed"],
    ["subscription_response_too_large", "subscription_response", "subscription.response_too_large", "subscription-response-too-large"],
    ["subscription_fetch_timeout", "subscription_fetch", "subscription.timeout", "subscription-fetch-timeout"],
    ["subscription_invalid_encoding", "subscription_response", "subscription.invalid_encoding", "subscription-invalid-encoding"],
  ] as const;
  let backendError: unknown;
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_url") throw backendError;
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  for (const [code, stage, message, expectedCode] of cases) {
    const secret = `https://provider.example/${code}?token=never-display`;
    backendError = { code, stage, message, detail: null };
    await assert.rejects(
      controller.previewSubscription({ type: "url", value: secret }),
      (error: unknown) => {
        assert.ok(error instanceof RouteDeckError);
        assert.equal(error.code, expectedCode);
        const localized = toPublicActionError(error);
        assert.ok(localized.message.length > 0 && localized.message.length < 240);
        assert.doesNotMatch(JSON.stringify(localized), /never-display|subscription\./);
        assert.doesNotMatch(JSON.stringify(error), /never-display/);
        return true;
      },
    );
  }
  controller.dispose();
});

test("known import rejection is localized instead of masked as a runtime failure", async () => {
  const secret = "https://provider.example/subscription?token=never-display";
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_url") {
        throw {
          code: "import_rejected",
          stage: "import",
          message: "subscription.content.rejected",
          detail: null,
        };
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();

  await assert.rejects(
    controller.previewSubscription({ type: "url", value: secret }),
    (error: unknown) => {
      assert.ok(error instanceof RouteDeckError);
      assert.equal(error.code, "subscription-import-rejected");
      const publicError = toPublicActionError(error);
      assert.match(publicError.message, /Проверьте формат ссылки или конфигурации/);
      assert.doesNotMatch(JSON.stringify(publicError), /never-display|provider\.example/);
      return true;
    },
  );
  controller.dispose();
});

test("malformed backend error closes the renderer boundary", async () => {
  const secret = "https://provider.example/subscription?token=malformed-error";
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_url") {
        throw {
          code: "subscription_fetch_timeout",
          stage: "subscription_response",
          message: "subscription.timeout",
          detail: secret,
        };
      }
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();

  await assert.rejects(
    controller.previewSubscription({ type: "url", value: secret }),
    { code: "backend-response-invalid" },
  );
  const snapshot = controller.getSnapshot();
  assert.equal(snapshot.backendAvailable, false);
  assert.equal(snapshot.notice?.id, "backend-response-invalid");
  assert.doesNotMatch(JSON.stringify(snapshot), /malformed-error|subscription\.timeout/);
  await assert.rejects(controller.connect(), { code: "backend-unavailable" });
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
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
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
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
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

test("routing policy remains saved while System Proxy mode is selected", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async () => runtimeStatus(1, "disconnected"),
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  assert.equal(controller.getSnapshot().runtimeScope, "system-proxy");
  await controller.applyRouting({ defaultRoute: "vpn", apps: [] });
  assert.equal(controller.getSnapshot().routing.defaultRoute, "vpn");
  await controller.saveSettings({ ...controller.getSnapshot().settings, theme: "light" });
  assert.equal(controller.getSnapshot().settings.theme, "light");
  await assert.rejects(controller.saveSettings({ ...controller.getSnapshot().settings, httpPort: 3333 }), { code: "capability-unavailable" });
  controller.dispose();
});

test("System Proxy sends the saved Direct default and application VPN exception", async () => {
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return {
        previewId: "preview-system-proxy",
        nodes: [{ id: "fixture-node", displayName: "Fixture", protocol: "vless", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "confirm_import") return { imported: 1, nodeIds: ["fixture-node"] };
      if (command === "start_system_proxy") return runtimeStatus(2, "system_proxy_ready");
      if (command === "stop_system_proxy") return runtimeStatus(3, "disconnected");
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "fixture" });
  await controller.commitSubscription(preview);
  await controller.applyRouting({
    defaultRoute: "direct",
    apps: [{ id: "browser", name: "Browser", path: "C:\\Apps\\browser.exe", route: "vpn" }],
  });
  await controller.connect();
  await controller.disconnect();
  assert.deepEqual(calls.slice(-2), [
    {
      command: "start_system_proxy",
      arguments_: {
        nodeId: "fixture-node",
        routing: {
          defaultRoute: "direct",
          apps: [{ processPath: "C:\\Apps\\browser.exe", processName: "browser.exe", route: "vpn" }],
        },
      },
    },
    { command: "stop_system_proxy", arguments_: undefined },
  ]);
  controller.dispose();
});

test("TUN controller path uses typed start and stop commands with current routing", async () => {
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command, arguments_) => {
      calls.push({ command, arguments_ });
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return {
        previewId: "preview-tun",
        nodes: [{ id: "fixture-node", displayName: "Fixture", protocol: "hysteria2", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "confirm_import") return { imported: 1, nodeIds: ["fixture-node"] };
      if (command === "start_tun") return runtimeStatus(2, "tun_ready");
      if (command === "stop_tun") return runtimeStatus(3, "disconnected");
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "fixture" });
  await controller.commitSubscription(preview);
  controller.setMode("tun");
  await controller.applyRouting({
    defaultRoute: "vpn",
    apps: [{ id: "browser", name: "Browser", path: "C:\\Apps\\browser.exe", route: "direct" }],
  });
  await controller.connect();
  assert.equal(controller.getSnapshot().runtimeScope, "tun");
  await controller.disconnect();
  assert.deepEqual(calls.slice(-2), [
    {
      command: "start_tun",
      arguments_: {
        nodeId: "fixture-node",
        routing: {
          defaultRoute: "vpn",
          stack: "gvisor",
          trafficRules: [{ network: "udp", port: 443, action: "block" }],
          apps: [{ processPath: "C:\\Apps\\browser.exe", processName: "browser.exe", route: "direct" }],
        },
      },
    },
    { command: "stop_tun", arguments_: undefined },
  ]);
  controller.dispose();
});

test("TUN stack migrates to gvisor, is omitted from System Proxy, and reconnects only active TUN", async () => {
  await withPreferenceStorage(async () => {
    const f = await lifecycleFixture();
    assert.equal(f.controller.getSnapshot().routing.tunStack, "gvisor");
    await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, tunStack: "gvisor" });
    assert.deepEqual(f.calls, []);
    await f.controller.setMode("tun");
    assert.equal((f.calls.at(-1)?.arguments_?.routing as { stack?: string }).stack, "gvisor");
    f.calls.length = 0;
    await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, tunStack: "system" });
    assert.deepEqual(f.calls.map((call) => call.command), ["stop_tun", "start_tun"]);
    assert.equal((f.calls[1].arguments_?.routing as { stack?: string }).stack, "system");
    f.controller.dispose();
  }, { "routedeck.routing.v1": '{"defaultRoute":"direct","apps":[]}' });
});

test("unknown persisted or submitted TUN stack fails safely", async () => {
  await withPreferenceStorage(async () => {
    const f = await lifecycleFixture(false);
    assert.deepEqual(f.controller.getSnapshot().routing, { defaultRoute: "direct", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [] });
    await assert.rejects(f.controller.applyRouting({ defaultRoute: "vpn", tunStack: "native", apps: [] } as unknown as RoutingConfig), { code: "invalid-routing" });
    assert.deepEqual(f.calls, []);
    f.controller.dispose();
  }, { "routedeck.routing.v1": '{"defaultRoute":"vpn","tunStack":"native","apps":[]}' });
});

test("gvisor is the fresh default while an explicit saved system stack is retained", () => {
  assert.equal(validatedRouting({ defaultRoute: "direct", apps: [] }).tunStack, "gvisor");
  assert.equal(validatedRouting({ defaultRoute: "direct", apps: [], tunStack: "system" }).tunStack, "system");
});

test("Naive UoT is opt-in, persisted, typed and restarts only a relevant protocol", async () => {
  await withPreferenceStorage(async () => {
    const ordinary = await lifecycleFixture();
    await ordinary.controller.applyRouting({ ...ordinary.controller.getSnapshot().routing, naiveUdpOverTcp: true });
    assert.deepEqual(ordinary.calls, [], "unrelated VLESS session remains running");
    ordinary.controller.dispose();
    const naive = await lifecycleFixture(true, "naive");
    assert.equal(naive.controller.getSnapshot().routing.naiveUdpOverTcp, true);
    await naive.controller.applyRouting({ ...naive.controller.getSnapshot().routing, naiveUdpOverTcp: false });
    assert.deepEqual(naive.calls.map((call) => call.command), ["stop_system_proxy", "start_system_proxy"]);
    await naive.controller.setMode("tun"); naive.calls.length = 0;
    await naive.controller.applyRouting({ ...naive.controller.getSnapshot().routing, naiveUdpOverTcp: true });
    assert.deepEqual(naive.calls.map((call) => call.command), ["stop_tun", "start_tun"]);
    assert.equal((naive.calls.at(-1)?.arguments_?.routing as any).naiveUdpOverTcp, true);
    naive.controller.dispose();
  });
  assert.equal(validatedRouting({ defaultRoute: "direct", apps: [] }).naiveUdpOverTcp, false);
  for (const naiveUdpOverTcp of ["true", 1, null, {}, []]) assert.throws(() => validatedRouting({ defaultRoute: "direct", apps: [], naiveUdpOverTcp }), { code: "invalid-routing" });
});

test("selected server and mode survive restart without automatically connecting", async () => {
  await withPreferenceStorage(async (storage) => {
    const f = await lifecycleFixture(false);
    await f.controller.selectServer("b"); await f.controller.setMode("tun");
    assert.deepEqual(f.calls, []);
    assert.deepEqual(JSON.parse(storage.get("routedeck.selection.v1")!), { version: 1, selectedServerId: "b", mode: "tun" });
    const restored = await lifecycleFixture(false);
    assert.equal(restored.controller.getSnapshot().selectedServerId, "b");
    assert.equal(restored.controller.getSnapshot().mode, "tun");
    assert.equal(restored.controller.getSnapshot().phase, "disconnected");
    assert.deepEqual(restored.calls, []);
    const active = await lifecycleFixture(true);
    assert.equal(active.controller.getSnapshot().selectedServerId, "a", "actual runtime takes precedence over saved intent");
    assert.equal(active.controller.getSnapshot().mode, "proxy");
    await restored.controller.resetLocalState();
    assert.equal(storage.has("routedeck.selection.v1"), false);
    f.controller.dispose(); restored.controller.dispose(); active.controller.dispose();
  });
});

test("invalid and missing saved selection falls back to an existing server", async () => {
  for (const stored of ['null', '{"version":1,"selectedServerId":"missing","mode":"tun"}', '{"version":1,"selectedServerId":"b","mode":"other"}', '{"version":1,"selectedServerId":"b","mode":"tun","extra":true}', '{"version":1,"selectedServerId":4,"mode":"tun"}']) {
    await withPreferenceStorage(async () => {
      const f = await lifecycleFixture(false);
      assert.equal(f.controller.getSnapshot().selectedServerId, "a");
      assert.deepEqual(f.calls, []);
      f.controller.dispose();
    }, { "routedeck.selection.v1": stored });
  }
});

test("selection persistence failure cannot disrupt a working connection", async () => {
  await withPreferenceStorage(async (_storage, faults) => {
    const f = await lifecycleFixture(); faults.write = true;
    await assert.rejects(f.controller.selectServer("b"), { code: "preferences-save-failed" });
    await assert.rejects(f.controller.setMode("tun"), { code: "preferences-save-failed" });
    assert.equal(f.controller.getSnapshot().selectedServerId, "a");
    assert.equal(f.controller.getSnapshot().mode, "proxy");
    assert.deepEqual(f.calls, []); f.controller.dispose();
  });
});

test("traffic rules migrate once and explicit removal survives loading", async () => {
  await withPreferenceStorage(async () => {
    const f = await lifecycleFixture(false);
    assert.deepEqual(f.controller.getSnapshot().routing.trafficRules, defaultTrafficRules());
    await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [] });
    const restored = await lifecycleFixture(false);
    assert.deepEqual(restored.controller.getSnapshot().routing.trafficRules, []);
    assert.deepEqual(f.calls, []);
    f.controller.dispose(); restored.controller.dispose();
  }, { "routedeck.routing.v1": '{"defaultRoute":"direct","apps":[]}' });
});

test("traffic rule boundary rejects malformed, excessive and ambiguous input", () => {
  const base = { defaultRoute: "direct", apps: [] };
  const rule = defaultTrafficRules()[0];
  const invalid = [null, {}, "rules", Array.from({ length: 33 }, (_, i) => ({ ...rule, id: String(i) })),
    [rule, rule], [null], [{ ...rule, id: "" }], [{ ...rule, id: "x".repeat(129) }],
    [{ ...rule, enabled: 1 }], [{ ...rule, network: "quic" }], [{ ...rule, network: ["udp"] }],
    [{ ...rule, port: "443" }], [{ ...rule, port: 0 }], [{ ...rule, port: 53 }],
    [{ ...rule, port: 65536 }], [{ ...rule, port: 443.5 }], [{ ...rule, port: NaN }],
    [{ ...rule, action: "drop" }], [{ ...rule, outbound: "selected" }], [{ ...rule, inbound: ["health-in"] }]];
  for (const trafficRules of invalid) assert.throws(() => validatedRouting({ ...base, trafficRules }), { code: "invalid-routing" });
  for (const port of [1, 443, 65535]) {
    assert.equal(validatedRouting({ ...base, trafficRules: [{ ...rule, port }] }).trafficRules[0].port, port);
  }
});

test("traffic edits reconnect only TUN, preserve order, and omit disabled rows and UI fields from IPC", async () => {
  const f = await lifecycleFixture();
  const block = defaultTrafficRules()[0];
  const direct = { ...block, id: "direct-443", action: "direct" as const };
  await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [direct, block] });
  assert.deepEqual(f.calls, [], "System Proxy ignores TUN rules");
  await f.controller.setMode("tun");
  assert.deepEqual((f.calls.at(-1)?.arguments_?.routing as any).trafficRules, [
    { network: "udp", port: 443, action: "direct" }, { network: "udp", port: 443, action: "block" },
  ]);
  f.calls.length = 0;
  await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [block, direct] });
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_tun", "start_tun"], "first-match order is significant");
  f.calls.length = 0;
  await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [{ ...block, enabled: false }, direct] });
  assert.deepEqual((f.calls.at(-1)?.arguments_?.routing as any).trafficRules, [{ network: "udp", port: 443, action: "direct" }]);
  f.calls.length = 0;
  await f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [{ ...block, enabled: false, port: 80 }, { ...direct, id: "renamed" }] });
  assert.deepEqual(f.calls, [], "disabled edits and UI identity do not restart TUN");
  await f.controller.setMode("proxy");
  assert.equal(Object.hasOwn(f.calls.at(-1)?.arguments_?.routing as object, "trafficRules"), false);
  f.controller.dispose();
});

test("traffic rules persist before restart and preserve working TUN on storage failure", async () => {
  await withPreferenceStorage(async (_storage, faults) => {
    const f = await lifecycleFixture();
    await f.controller.setMode("tun");
    f.calls.length = 0;
    faults.write = true;
    await assert.rejects(f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [] }), { code: "preferences-save-failed" });
    assert.deepEqual(f.calls, []);
    assert.deepEqual(f.controller.getSnapshot().routing.trafficRules, defaultTrafficRules());
    f.controller.dispose();
  });
});

test("failed TUN stop prevents traffic-rule restart and retains saved pending changes", async () => {
  const f = await lifecycleFixture();
  await f.controller.setMode("tun");
  f.calls.length = 0;
  f.hooks.stop = async () => { throw { code: "runtime_failure", stage: "cleanup", message: "fixture failure" }; };
  await assert.rejects(f.controller.applyRouting({ ...f.controller.getSnapshot().routing, trafficRules: [] }));
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_tun"]);
  assert.deepEqual(f.controller.getSnapshot().routing.trafficRules, []);
  assert.equal(f.controller.getSnapshot().routingPending, true);
  f.controller.dispose();
});

test("ordinary TUN privilege failure maps to plain finite copy", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return {
        previewId: "preview-tun-admin",
        nodes: [{ id: "fixture-node", displayName: "Fixture", protocol: "hysteria2", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "confirm_import") return { imported: 1, nodeIds: ["fixture-node"] };
      if (command === "start_tun") throw {
        code: "runtime_failure",
        stage: "start",
        message: "TUN requires RouteDeck to be run as administrator",
      };
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "fixture" });
  await controller.commitSubscription(preview);
  controller.setMode("tun");
  await assert.rejects(controller.connect(), { code: "tun-admin-required" });
  const message = toPublicActionError(new RouteDeckError("tun-admin-required")).message;
  assert.match(message, /Не удалось запросить права Windows/);
  assert.doesNotMatch(message, /administrator|администратор|elevat/i);
  controller.dispose();
});

test("cancelled standard Windows UAC has a clear retryable TUN error", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "confirmed_nodes") return [{
        id: "saved-node",
        displayName: "Saved",
        protocol: "hysteria2",
        insecureTls: false,
      }];
      if (command === "start_tun") throw {
        code: "runtime_failure",
        stage: "start",
        message: "The RouteDeck connection operation failed",
        detail: "TUN permission request was cancelled",
      };
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  controller.setMode("tun");

  await assert.rejects(controller.connect(), { code: "tun-uac-cancelled" });
  const message = toPublicActionError(new RouteDeckError("tun-uac-cancelled")).message;
  assert.match(message, /Запрос прав Windows отменён/);
  assert.match(message, /Нажмите «Подключить» ещё раз/);
  assert.doesNotMatch(message, /administrator|администратор|elevat/i);
  controller.dispose();
});

test("running application picker uses one typed finite backend call", async () => {
  const calls: string[] = [];
  const applications = [{
    processName: "browser.exe",
    executablePath: "C:\\Apps\\browser.exe",
    displayName: "Browser.exe",
  }];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      calls.push(command);
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "list_running_applications") return applications;
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  assert.deepEqual(await controller.listRunningApplications(), applications);
  assert.equal(calls.filter((command) => command === "list_running_applications").length, 1);
  controller.dispose();
});

test("reset clears backend persistence before publishing an empty local snapshot", async () => {
  const calls: string[] = [];
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      calls.push(command);
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "confirmed_nodes") return [{
        id: "saved-node",
        displayName: "Saved",
        protocol: "hysteria2",
        insecureTls: false,
      }];
      if (command === "reset_local_state") return null;
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  assert.equal(controller.getSnapshot().servers.length, 1);

  await controller.resetLocalState();

  assert.equal(controller.getSnapshot().servers.length, 0);
  assert.equal(controller.getSnapshot().subscriptionName, "Подписка не импортирована");
  assert.equal(calls.filter((command) => command === "reset_local_state").length, 1);
  controller.dispose();
});

test("failed backend reset preserves the visible confirmed subscription", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "confirmed_nodes") return [{
        id: "saved-node",
        displayName: "Saved",
        protocol: "vless",
        insecureTls: false,
      }];
      if (command === "reset_local_state") throw {
        code: "runtime_failure",
        stage: "session_storage",
        message: "Could not reset local state",
      };
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => transport);
  await controller.ready();

  await assert.rejects(controller.resetLocalState(), { code: "runtime-failure" });
  assert.equal(controller.getSnapshot().servers.length, 1);
  assert.equal(controller.getSnapshot().selectedServerId, "saved-node");
  controller.dispose();
});

test("runtime detail is available only as expandable detail while the main error stays plain", async () => {
  const backendDetail = "prove_traffic: selected outbound handshake failed";
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => {
      if (command === "runtime_status") return runtimeStatus(1, "disconnected");
      if (command === "preview_import_content") return {
        previewId: "preview-runtime-detail",
        nodes: [{ id: "fixture-node", displayName: "Fixture", protocol: "vless", insecureTls: false }],
        rejected: [],
        warnings: [],
      };
      if (command === "confirm_import") return { imported: 1, nodeIds: ["fixture-node"] };
      if (command === "start_system_proxy") throw {
        code: "runtime_failure",
        stage: "prove_traffic",
        message: "The RouteDeck connection operation failed",
        detail: backendDetail,
      };
      throw new Error("unexpected command");
    },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "clipboard", value: "fixture" });
  await controller.commitSubscription(preview);

  await assert.rejects(controller.connect(), (error: unknown) => {
    assert.ok(error instanceof RouteDeckError);
    const publicError = toPublicActionError(error);
    assert.doesNotMatch(publicError.message, /handshake|prove_traffic/);
    assert.equal(publicError.redactedDetail, backendDetail);
    return true;
  });
  controller.dispose();
});

test("malformed diagnostics always clears the running flag and fails closed", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async (command) => command === "runtime_status"
      ? runtimeStatus(1, "disconnected")
      : { status: { ...runtimeStatus(2, "disconnected"), unexpected: true }, lines: [], systemProxy: { state: "disabled", endpoint: null, detail: "", cleanupToken: null } },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
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
      : { status: runtimeStatus(2, "disconnected"), lines: ["sanitized"], systemProxy: { state: "disabled", endpoint: null, detail: "Прокси отключён.", cleanupToken: null } },
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  await controller.runDiagnostics();
  const diagnostics = controller.getSnapshot().diagnostics;
  assert.equal(typeof diagnostics.snapshotReceivedAt, "string");
  assert.equal(diagnostics.running, false);
  assert.ok(diagnostics.steps.every((proof) => proof.checkedAt === undefined));
  assert.deepEqual(diagnostics.sanitizedLog, ["sanitized"]);
  controller.dispose();
});

test("system proxy diagnostics accepts only sanitized loopback endpoints and stale cleanup tokens", () => {
  const status = runtimeStatus(2, "disconnected");
  const token = "a".repeat(64);
  assert.equal(parseDiagnostics({ status, lines: [], systemProxy: { state: "stale", endpoint: "127.0.0.1:10808", detail: "Локальный порт не отвечает.", cleanupToken: token } }).systemProxy.cleanupToken, token);
  assert.equal(parseDiagnostics({ status, lines: [], systemProxy: { state: "owned", endpoint: "[::1]:2080", detail: "Порт отвечает.", cleanupToken: null } }).systemProxy.endpoint, "[::1]:2080");
  assert.equal(parseDiagnostics({ status, lines: [], systemProxy: { state: "stale", endpoint: "127.0.0.1:10808", detail: "Очистка временно недоступна.", cleanupToken: null } }).systemProxy.cleanupToken, null);
  for (const systemProxy of [
    { state: "stale", endpoint: "example.com:1080", detail: "", cleanupToken: token },
    { state: "stale", endpoint: "127.0.0.1:1080", detail: "https://user:secret@example.invalid", cleanupToken: token },
    { state: "stale", endpoint: "127.0.0.1:1080", detail: "", cleanupToken: "short" },
    { state: "owned", endpoint: "127.0.0.1:1080", detail: "", cleanupToken: token },
    { state: "stale", endpoint: null, detail: "", cleanupToken: token },
  ]) assert.throws(() => parseDiagnostics({ status, lines: [], systemProxy }), ContractViolation);
});

test("stale proxy cleanup is typed, single-use, and publishes the returned diagnostic snapshot", async () => {
  const token = "b".repeat(64);
  const calls: Array<{ command: string; arguments_?: Record<string, unknown> }> = [];
  const stale = { state: "stale", endpoint: "127.0.0.1:10808", detail: "Локальный порт не отвечает.", cleanupToken: token };
  const disabled = { state: "disabled", endpoint: null, detail: "Прокси отключён.", cleanupToken: null };
  const transport: TauriTransport = { listen: async () => () => undefined, invoke: async (command, arguments_) => {
    calls.push({ command, arguments_ });
    if (command === "runtime_status") return runtimeStatus(1, "disconnected");
    if (command === "confirmed_nodes") return [];
    if (command === "runtime_diagnostics") return { status: runtimeStatus(2, "disconnected"), lines: [], systemProxy: stale };
    if (command === "clear_stale_system_proxy") return { status: runtimeStatus(3, "disconnected"), lines: ["cleaned"], systemProxy: disabled };
    throw new Error("unexpected command");
  } };
  const controller = new TauriController(async () => transport);
  await controller.ready();
  await controller.runDiagnostics();
  await controller.clearStaleSystemProxy(token);
  assert.deepEqual(calls.at(-1), { command: "clear_stale_system_proxy", arguments_: { token } });
  assert.deepEqual(controller.getSnapshot().diagnostics.systemProxy, disabled);
  await assert.rejects(controller.clearStaleSystemProxy(token), { code: "backend-response-invalid" });
  controller.dispose();
});

test("diagnostic refresh invalidates its prior token and ignores an older response", async () => {
  const first = deferred<unknown>();
  let diagnosticsCalls = 0;
  const stale = (token: string, detail: string) => ({ status: runtimeStatus(1, "disconnected"), lines: [detail], systemProxy: { state: "stale", endpoint: "127.0.0.1:10808", detail, cleanupToken: token } });
  const transport: TauriTransport = { listen: async () => () => undefined, invoke: async (command) => {
    if (command === "runtime_status") return runtimeStatus(1, "disconnected");
    if (command === "confirmed_nodes") return [];
    if (command === "runtime_diagnostics") return ++diagnosticsCalls === 1 ? first.promise : stale("c".repeat(64), "new");
    throw new Error("unexpected command");
  } };
  const controller = new TauriController(async () => transport); await controller.ready();
  const old = controller.runDiagnostics();
  assert.equal(controller.getSnapshot().diagnostics.systemProxy.cleanupToken, null);
  await controller.runDiagnostics();
  first.resolve(stale("d".repeat(64), "old"));
  await old;
  assert.equal(controller.getSnapshot().diagnostics.systemProxy.cleanupToken, "c".repeat(64));
  assert.deepEqual(controller.getSnapshot().diagnostics.sanitizedLog, ["new"]);
  controller.dispose();
});

test("cleanup rejects duplicate direct calls and consumes the token after failure", async () => {
  const token = "f".repeat(64);
  const cleanup = deferred<unknown>();
  const transport: TauriTransport = { listen: async () => () => undefined, invoke: async (command) => {
    if (command === "runtime_status") return runtimeStatus(1, "disconnected");
    if (command === "confirmed_nodes") return [];
    if (command === "runtime_diagnostics") return { status: runtimeStatus(1, "disconnected"), lines: [], systemProxy: { state: "stale", endpoint: "127.0.0.1:10808", detail: "stale", cleanupToken: token } };
    if (command === "clear_stale_system_proxy") return cleanup.promise;
    throw new Error("unexpected command");
  } };
  const controller = new TauriController(async () => transport); await controller.ready(); await controller.runDiagnostics();
  const pending = controller.clearStaleSystemProxy(token);
  await assert.rejects(controller.clearStaleSystemProxy(token), { code: "capability-unavailable" });
  cleanup.reject({ code: "runtime_failure", stage: "system_proxy_restore", message: "failed" });
  await assert.rejects(pending, { code: "runtime-failure" });
  assert.equal(controller.getSnapshot().diagnostics.systemProxy.cleanupToken, null);
  controller.dispose();
});

test("offline selections never start a runtime", async () => {
  const f = await lifecycleFixture(false);
  await f.controller.selectServer("b");
  await f.controller.setMode("tun");
  assert.equal(f.controller.getSnapshot().selectedServerId, "b");
  assert.equal(f.controller.getSnapshot().mode, "tun");
  assert.equal(f.calls.length, 0);
  f.controller.dispose();
});

test("connected server and mode changes stop the actual mode before starting the target", async () => {
  const f = await lifecycleFixture();
  await f.controller.selectServer("b");
  await f.controller.setMode("tun");
  await f.controller.setMode("proxy");
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "start_system_proxy", "stop_system_proxy", "start_tun", "stop_tun", "start_system_proxy"]);
  assert.equal(f.controller.getSnapshot().activeServerId, "b");
  assert.equal(f.controller.getSnapshot().activeMode, "proxy");
  assert.equal(f.controller.getSnapshot().switching, false);
  f.controller.dispose();
});

test("rapid changes coalesce while stop is pending and preserve actual versus desired selection", async () => {
  const f = await lifecycleFixture();
  const stopped = deferred<unknown>();
  const entered = deferred();
  f.hooks.stop = async () => { entered.resolve(); return stopped.promise; };
  const first = f.controller.selectServer("b");
  await entered.promise;
  const second = f.controller.selectServer("c");
  const mode = f.controller.setMode("tun");
  assert.equal(f.controller.getSnapshot().activeServerId, "a");
  assert.equal(f.controller.getSnapshot().activeMode, "proxy");
  assert.equal(f.controller.getSnapshot().selectedServerId, "c");
  assert.equal(f.controller.getSnapshot().mode, "tun");
  stopped.resolve(f.status("disconnected"));
  await Promise.all([first, second, mode]);
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "start_tun"]);
  assert.equal(f.calls[1].arguments_?.nodeId, "c");
  f.controller.dispose();
});

test("disconnect cancels a reconnect waiting for verified stop", async () => {
  const f = await lifecycleFixture();
  const stopped = deferred<unknown>();
  const entered = deferred();
  f.hooks.stop = async () => { entered.resolve(); return stopped.promise; };
  const switching = f.controller.selectServer("b");
  await entered.promise;
  const disconnecting = f.controller.disconnect();
  stopped.resolve(f.status("disconnected"));
  await Promise.all([switching, disconnecting]);
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy"]);
  assert.equal(f.controller.getSnapshot().phase, "disconnected");
  f.controller.dispose();
});

test("disconnect during startup waits for completion and tears down that exact runtime", async () => {
  const f = await lifecycleFixture(false);
  const started = deferred<unknown>();
  const entered = deferred();
  f.hooks.start = async () => { entered.resolve(); return started.promise; };
  await f.controller.setMode("tun");
  const connecting = f.controller.connect();
  await entered.promise;
  const disconnecting = f.controller.disconnect();
  started.resolve(f.status("tun_ready"));
  await Promise.all([connecting, disconnecting]);
  assert.deepEqual(f.calls.map((call) => call.command), ["start_tun", "stop_tun"]);
  assert.equal(f.controller.getSnapshot().phase, "disconnected");
  f.controller.dispose();
});

test("retained runtime after stop failure prevents every queued restart", async () => {
  const f = await lifecycleFixture();
  f.hooks.stop = async () => ({ ...f.status("system_proxy_ready"), phase: "recovery_required", steadyLatencyMs: undefined, error: { code: "recovery_required", stage: "system_proxy_restore", message: "Recovery required" } });
  await assert.rejects(f.controller.selectServer("b"), { code: "runtime-failure" });
  await assert.rejects(f.controller.connect(), { code: "runtime-failure" });
  assert.equal(f.calls.some((call) => call.command.startsWith("start_")), false);
  assert.equal(f.controller.getSnapshot().phase, "failed");
  f.controller.dispose();
});

test("cancelled UAC never starts a fallback or retries by itself", async () => {
  const f = await lifecycleFixture();
  f.hooks.start = async () => { throw { code: "runtime_failure", stage: "start", message: "Operation failed", detail: "TUN permission request was cancelled" }; };
  await assert.rejects(f.controller.setMode("tun"), { code: "tun-uac-cancelled" });
  await f.controller.selectServer("c");
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "start_tun"]);
  assert.equal(f.controller.getSnapshot().switching, false);
  f.controller.dispose();
});

test("duplicate connect actions share one active runtime", async () => {
  const f = await lifecycleFixture(false);
  await Promise.all([f.controller.connect(), f.controller.connect(), f.controller.connect()]);
  assert.deepEqual(f.calls.map((call) => call.command), ["start_system_proxy"]);
  f.controller.dispose();
});

test("explicit retry re-establishes an existing connection instead of becoming a no-op", async () => {
  const f = await lifecycleFixture();
  await f.controller.retry();
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "start_system_proxy"]);
  assert.equal(f.controller.getSnapshot().phase, "connected");
  f.controller.dispose();
});

test("retry cannot start a new runtime if stopping the previous one fails", async () => {
  const f = await lifecycleFixture();
  f.hooks.stop = async () => { throw { code: "runtime_failure", stage: "system_proxy_restore", message: "Fixture restoration failure" }; };
  await assert.rejects(f.controller.retry(), { code: "runtime-failure" });
  assert.equal(f.calls.some((call) => call.command.startsWith("start_")), false);
  f.controller.dispose();
});

test("refresh active subscription stops, reloads authoritative nodes and reconnects", async () => {
  const f = await lifecycleFixture();
  await f.controller.refreshSource(f.sourceId);
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "refresh_source", "confirmed_nodes", "start_system_proxy"]);
  assert.equal(f.controller.getSnapshot().servers[0].sourceUpdatedAtMs, 200);
  assert.equal(f.controller.getSnapshot().activeServerId, "a");
  f.controller.dispose();
});

test("refresh failure retains the source and restores the previous connection", async () => {
  const f = await lifecycleFixture();
  f.hooks.refresh = async () => { throw { code: "subscription_fetch_failed", stage: "subscription_fetch", message: "subscription.fetch_failed" }; };
  await assert.rejects(f.controller.refreshSource(f.sourceId), { code: "subscription-fetch-failed" });
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "refresh_source", "start_system_proxy"]);
  assert.equal(f.controller.getSnapshot().servers.length, 3);
  assert.equal(f.controller.getSnapshot().servers[0].sourceUpdatedAtMs, 100);
  f.controller.dispose();
});

test("disconnect during refresh failure prevents restoration", async () => {
  const f = await lifecycleFixture();
  const refresh = deferred<unknown>();
  const entered = deferred();
  f.hooks.refresh = async () => { entered.resolve(); return refresh.promise; };
  const refreshing = f.controller.refreshSource(f.sourceId);
  await entered.promise;
  const disconnecting = f.controller.disconnect();
  const rejected = assert.rejects(refreshing, { code: "subscription-fetch-failed" });
  refresh.reject({ code: "subscription_fetch_failed", stage: "subscription_fetch", message: "subscription.fetch_failed" });
  await Promise.all([rejected, disconnecting]);
  assert.equal(f.calls.some((call) => call.command.startsWith("start_")), false);
  f.controller.dispose();
});

test("deleting active source stops and selects remaining server without connecting", async () => {
  const f = await lifecycleFixture();
  await f.controller.removeSource(f.sourceId);
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "remove_source", "confirmed_nodes"]);
  assert.equal(f.controller.getSnapshot().selectedServerId, "c");
  assert.equal(f.controller.getSnapshot().activeServerId, undefined);
  assert.equal(f.controller.getSnapshot().servers.length, 1);
  f.controller.dispose();
});

test("source changes outside active group leave the runtime untouched", async () => {
  const f = await lifecycleFixture();
  await f.controller.removeSource("b".repeat(32));
  assert.deepEqual(f.calls.map((call) => call.command), ["remove_source", "confirmed_nodes"]);
  assert.equal(f.controller.getSnapshot().activeServerId, "a");
  f.controller.dispose();
});

test("source refresh metadata rejects malformed values and mismatched group revisions", () => {
  const node = { id: "a", displayName: "A", protocol: "naive", insecureTls: false, sourceId: "a".repeat(32), sourceName: "Group", sourceKind: "subscription", sourceRefreshable: true, sourceUpdatedAtMs: 100 };
  assert.equal(parseConfirmedNodes([node])[0].sourceUpdatedAtMs, 100);
  for (const patch of [{ sourceRefreshable: "true" }, { sourceUpdatedAtMs: -1 }, { sourceUpdatedAtMs: 0.1 }, { sourceUpdatedAtMs: Number.MAX_SAFE_INTEGER + 1 }, { sourceKind: "manual" }]) {
    assert.throws(() => parseConfirmedNodes([{ ...node, ...patch }]), ContractViolation);
  }
  assert.throws(() => parseConfirmedNodes([node, { ...node, id: "b", sourceUpdatedAtMs: 101 }]), ContractViolation);
});

test("selection changing during startup finishes teardown before starting the latest target", async () => {
  const f = await lifecycleFixture(false);
  const started = deferred<unknown>();
  const entered = deferred();
  f.hooks.start = async () => { entered.resolve(); return started.promise; };
  const connecting = f.controller.connect();
  await entered.promise;
  const selection = f.controller.selectServer("c");
  const mode = f.controller.setMode("tun");
  f.hooks.start = undefined;
  started.resolve(f.status("system_proxy_ready"));
  await Promise.all([connecting, selection, mode]);
  assert.deepEqual(f.calls.map((call) => call.command), ["start_system_proxy", "stop_system_proxy", "start_tun"]);
  assert.equal(f.controller.getSnapshot().activeServerId, "c");
  f.controller.dispose();
});

test("rejected teardown prevents source mutation and preserves its visible nodes", async () => {
  const f = await lifecycleFixture();
  f.hooks.stop = async () => { throw { code: "runtime_failure", stage: "stop_engine", message: "Stop failed" }; };
  await assert.rejects(f.controller.refreshSource(f.sourceId), { code: "runtime-failure" });
  await assert.rejects(f.controller.removeSource(f.sourceId), { code: "runtime-failure" });
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "stop_system_proxy"]);
  assert.equal(f.controller.getSnapshot().servers.length, 3);
  f.controller.dispose();
});

test("stale stop response cannot authorize a new start", async () => {
  const f = await lifecycleFixture();
  f.hooks.stop = async () => runtimeStatus(0, "disconnected");
  await assert.rejects(f.controller.selectServer("b"), { code: "runtime-failure" });
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy"]);
  assert.equal(f.controller.getSnapshot().activeServerId, "a");
  f.controller.dispose();
});

test("replacement subscription URL is passed only to typed IPC and never retained in public state", async () => {
  const f = await lifecycleFixture(false);
  const url = "https://fixture.invalid/subscription?token=private-fixture";
  await f.controller.refreshSource(f.sourceId, url);
  assert.deepEqual(f.calls[0], { command: "refresh_source", arguments_: { sourceId: f.sourceId, url } });
  assert.doesNotMatch(JSON.stringify(f.controller.getSnapshot()), /private-fixture|fixture\.invalid/);
  assert.doesNotMatch(f.controller.getSanitizedReport(), /private-fixture|fixture\.invalid/);
  f.controller.dispose();
});

test("incomplete source refresh uses localized copy and keeps the prior library", async () => {
  const f = await lifecycleFixture(false);
  f.hooks.refresh = async () => { throw { code: "import_rejected", stage: "import", message: "subscription.refresh_incomplete" }; };
  await assert.rejects(f.controller.refreshSource(f.sourceId), { code: "subscription-refresh-incomplete" });
  assert.match(toPublicActionError(new RouteDeckError("subscription-refresh-incomplete")).message, /Прежние серверы сохранены/);
  assert.equal(f.controller.getSnapshot().servers[0].sourceUpdatedAtMs, 100);
  f.controller.dispose();
});

test("a start reply for a different mode or node never enters an automatic restart loop", async () => {
  for (const mismatch of ["mode", "node"] as const) {
    const f = await lifecycleFixture(false);
    f.hooks.start = async () => f.status(mismatch === "mode" ? "local_proxy_ready" : "system_proxy_ready", mismatch === "node" ? "b" : "a");
    await assert.rejects(f.controller.connect(), { code: "runtime-failure" });
    assert.deepEqual(f.calls.map((call) => call.command), ["start_system_proxy"]);
    f.controller.dispose();
  }
});

test("routing autosave persists offline edits and restores inherit rows without touching runtime", async () => {
  await withPreferenceStorage(async (storage) => {
    const f = await lifecycleFixture(false);
    await f.controller.applyRouting({ defaultRoute: "vpn", apps: [{ id: "app", name: " App ", path: "C:/Apps/App.exe", route: "inherit" }] });
    assert.deepEqual(f.calls, []);
    assert.deepEqual(JSON.parse(storage.get("routedeck.routing.v1")!), { defaultRoute: "vpn", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [{ id: "app", name: "App", path: "C:\\Apps\\App.exe", route: "inherit" }] });
    const restored = await lifecycleFixture(false);
    assert.deepEqual(restored.controller.getSnapshot().routing, f.controller.getSnapshot().routing);
    f.controller.dispose(); restored.controller.dispose();
  });
});

test("routing autosave while connected restarts once with the latest saved edits", async () => {
  const f = await lifecycleFixture();
  const stopped = deferred<unknown>(); const entered = deferred();
  f.hooks.stop = async () => { entered.resolve(); return stopped.promise; };
  const first = f.controller.applyRouting({ defaultRoute: "vpn", apps: [] });
  await entered.promise;
  const finalRouting = { defaultRoute: "direct" as const, apps: [{ id: "browser", name: "Browser", path: "C:\\Apps\\browser.exe", route: "vpn" as const }] };
  const second = f.controller.applyRouting(finalRouting);
  assert.equal(f.controller.getSnapshot().routingPending, true);
  assert.deepEqual(f.controller.getSnapshot().routing, { ...finalRouting, tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules() });
  stopped.resolve(f.status("disconnected"));
  await Promise.all([first, second]);
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy", "start_system_proxy"]);
  assert.deepEqual(f.calls[1].arguments_?.routing, { defaultRoute: "direct", apps: [{ processPath: "C:\\Apps\\browser.exe", processName: "browser.exe", route: "vpn" }] });
  assert.equal(f.controller.getSnapshot().routingPending, false);
  f.controller.dispose();
});

test("routing edits arriving during startup are applied after exact teardown", async () => {
  const f = await lifecycleFixture(false);
  const started = deferred<unknown>(); const entered = deferred();
  f.hooks.start = async () => { entered.resolve(); return started.promise; };
  const connecting = f.controller.connect(); await entered.promise;
  const editing = f.controller.applyRouting({ defaultRoute: "vpn", apps: [] });
  f.hooks.start = undefined; started.resolve(f.status("system_proxy_ready"));
  await Promise.all([connecting, editing]);
  assert.deepEqual(f.calls.map((call) => call.command), ["start_system_proxy", "stop_system_proxy", "start_system_proxy"]);
  assert.equal((f.calls[2].arguments_?.routing as { defaultRoute: string }).defaultRoute, "vpn");
  f.controller.dispose();
});

test("disconnect during routing autosave preserves the saved edit without reconnecting", async () => {
  const f = await lifecycleFixture();
  const stopped = deferred<unknown>(); const entered = deferred();
  f.hooks.stop = async () => { entered.resolve(); return stopped.promise; };
  const editing = f.controller.applyRouting({ defaultRoute: "vpn", apps: [] }); await entered.promise;
  const disconnecting = f.controller.disconnect(); stopped.resolve(f.status("disconnected"));
  await Promise.all([editing, disconnecting]);
  assert.deepEqual(f.calls.map((call) => call.command), ["stop_system_proxy"]);
  assert.equal(f.controller.getSnapshot().routing.defaultRoute, "vpn");
  f.controller.dispose();
});

test("failed routing restart keeps saved edits and marks old active rules pending", async () => {
  await withPreferenceStorage(async (storage) => {
    const f = await lifecycleFixture();
    f.hooks.stop = async () => ({ ...f.status("system_proxy_ready"), phase: "recovery_required", steadyLatencyMs: undefined, error: { code: "recovery_required", stage: "system_proxy_restore", message: "Recovery required" } });
    await assert.rejects(f.controller.applyRouting({ defaultRoute: "vpn", apps: [] }), { code: "runtime-failure" });
    assert.equal(f.controller.getSnapshot().routing.defaultRoute, "vpn");
    assert.equal(f.controller.getSnapshot().routingPending, true);
    assert.equal(JSON.parse(storage.get("routedeck.routing.v1")!).defaultRoute, "vpn");
    assert.equal(f.calls.some((call) => call.command.startsWith("start_")), false);
    f.controller.dispose();
  });
});

test("routing write failure preserves the active runtime and previous saved selection", async () => {
  await withPreferenceStorage(async (_storage, faults) => {
    const f = await lifecycleFixture(); faults.write = true;
    await assert.rejects(f.controller.applyRouting({ defaultRoute: "vpn", apps: [] }), { code: "preferences-save-failed" });
    assert.deepEqual(f.calls, []);
    assert.equal(f.controller.getSnapshot().routing.defaultRoute, "direct");
    assert.equal(f.controller.getSnapshot().activeServerId, "a");
    f.controller.dispose();
  });
});

test("display-only routing edits do not restart an active runtime", async () => {
  const f = await lifecycleFixture();
  await f.controller.applyRouting({ defaultRoute: "direct", apps: [{ id: "app", name: "Inherited", path: "C:\\Apps\\app.exe", route: "inherit" }] });
  assert.deepEqual(f.calls, []);
  assert.equal(f.controller.getSnapshot().routingPending, false);
  f.controller.dispose();
});

test("invalid routing paths, duplicate identities and unsupported fields are rejected before saving", async () => {
  const f = await lifecycleFixture();
  const app = { id: "app", name: "App", path: "C:\\Apps\\app.exe", route: "vpn" as const };
  for (const apps of [[{ ...app, path: "  " }], [{ ...app, path: "app.exe" }], [{ ...app, path: "C:\\App\n.exe" }], [app, { ...app, id: "other", path: "c:/apps/APP.exe" }], [app, { ...app, path: "C:\\Apps\\other.exe" }], [{ ...app, unexpected: true }]]) {
    await assert.rejects(f.controller.applyRouting({ defaultRoute: "direct", apps }), { code: "invalid-routing" });
  }
  assert.deepEqual(f.calls, []);
  f.controller.dispose();
});

test("theme and scheduled refresh preference persist without restarting the connection", async () => {
  await withPreferenceStorage(async (storage) => {
    const f = await lifecycleFixture();
    assert.equal(f.controller.getSnapshot().settings.subscriptionRefreshHours, 0);
    await f.controller.saveSettings({ ...f.controller.getSnapshot().settings, theme: "system", subscriptionRefreshHours: 6 });
    assert.deepEqual(JSON.parse(storage.get("routedeck.preferences.v1")!), { version: 1, theme: "system", subscriptionRefreshHours: 6 });
    assert.deepEqual(f.calls, []);
    const restored = await lifecycleFixture(false);
    assert.equal(restored.controller.getSnapshot().settings.theme, "system");
    assert.equal(restored.controller.getSnapshot().settings.subscriptionRefreshHours, 6);
    f.controller.dispose(); restored.controller.dispose();
  });
});

test("malformed stored rules and preferences use defaults without interpreting extra fields", async () => {
  for (const preferences of ["{", '{"version":2,"theme":"light","subscriptionRefreshHours":6}', '{"version":1,"theme":"light","subscriptionRefreshHours":2}', '{"version":1,"theme":"light","subscriptionRefreshHours":6,"httpPort":1234}']) {
    await withPreferenceStorage(async () => {
      const f = await lifecycleFixture(false);
      assert.equal(f.controller.getSnapshot().settings.theme, "dark");
      assert.equal(f.controller.getSnapshot().settings.subscriptionRefreshHours, 0);
      assert.deepEqual(f.controller.getSnapshot().routing, { defaultRoute: "direct", tunStack: "gvisor", naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps: [] });
      f.controller.dispose();
    }, { "routedeck.preferences.v1": preferences, "routedeck.routing.v1": '{"defaultRoute":"vpn","apps":[],"unknown":true}' });
  }
});

test("failed preference write does not publish optimistic settings", async () => {
  await withPreferenceStorage(async (_storage, faults) => {
    const f = await lifecycleFixture(false); faults.write = true;
    await assert.rejects(f.controller.saveSettings({ ...f.controller.getSnapshot().settings, theme: "light", subscriptionRefreshHours: 24 }), { code: "preferences-save-failed" });
    assert.equal(f.controller.getSnapshot().settings.theme, "dark");
    assert.equal(f.controller.getSnapshot().settings.subscriptionRefreshHours, 0);
    f.controller.dispose();
  });
});

test("background refresh skips active and newly requested connections inside the queue", async () => {
  const active = await lifecycleFixture();
  await active.controller.refreshSource(active.sourceId, undefined, true);
  assert.deepEqual(active.calls, []); active.controller.dispose();
  const f = await lifecycleFixture(false);
  const refreshing = f.controller.refreshSource(f.sourceId, undefined, true);
  const connecting = f.controller.connect();
  await Promise.all([refreshing, connecting]);
  assert.deepEqual(f.calls.map((call) => call.command), ["start_system_proxy"]);
  f.controller.dispose();
});

test("background refresh updates only an idle subscription without starting a runtime", async () => {
  const f = await lifecycleFixture(false);
  await f.controller.refreshSource(f.sourceId, undefined, true);
  assert.deepEqual(f.calls.map((call) => call.command), ["refresh_source", "confirmed_nodes"]);
  assert.equal(f.controller.getSnapshot().phase, "disconnected");
  f.controller.dispose();
});

test("reset removes persisted rules and refresh preferences before restoring defaults", async () => {
  await withPreferenceStorage(async (storage) => {
    const f = await lifecycleFixture(false);
    await f.controller.applyRouting({ defaultRoute: "vpn", apps: [] });
    await f.controller.saveSettings({ ...f.controller.getSnapshot().settings, theme: "light", subscriptionRefreshHours: 24 });
    await f.controller.resetLocalState();
    assert.equal(storage.has("routedeck.preferences.v1"), false);
    assert.equal(storage.has("routedeck.routing.v1"), false);
    assert.equal(f.controller.getSnapshot().settings.theme, "dark");
    assert.equal(f.controller.getSnapshot().settings.subscriptionRefreshHours, 0);
    assert.equal(f.controller.getSnapshot().routing.defaultRoute, "direct");
    f.controller.dispose();
  });
});


test("steady response is optional, bounded and cannot replace connection proof", () => {
  const ready = runtimeStatus(1, "system_proxy_ready");
  assert.equal(parseRuntimeStatus({ ...ready, steadyLatencyMs: 42 }).steadyLatencyMs, 42);
  assert.equal(parseRuntimeStatus({ ...ready, steadyLatencyMs: undefined }).steadyLatencyMs, undefined);
  for (const value of [-1, 0.5, Infinity, NaN, "42", Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => parseRuntimeStatus({ ...ready, steadyLatencyMs: value }), ContractViolation);
  }
  assert.throws(() => parseRuntimeStatus({ ...runtimeStatus(2, "disconnected"), steadyLatencyMs: 42 }), ContractViolation);
  assert.throws(() => parseRuntimeStatus({ ...ready, phase: "degraded", steadyLatencyMs: 42 }), ContractViolation);
  assert.throws(() => parseRuntimeStatus({ ...ready, routeCheckMs: undefined, steadyLatencyMs: 42 }), ContractViolation);
});

test("a missing steady sample never falls back to cold HTTPS time or clears a proven connection", async () => {
  let emit!: (payload: unknown) => void;
  const ready = { ...runtimeStatus(1, "system_proxy_ready"), steadyLatencyMs: undefined };
  const transport: TauriTransport = {
    listen: async (_event, handler) => { emit = handler; return () => undefined; },
    invoke: async (command) => command === "runtime_status" ? ready : [{ id: "fixture-node", displayName: "Fixture", protocol: "vless", insecureTls: false }],
  };
  const controller = new TauriController(async () => transport); await controller.ready();
  assert.equal(controller.getSnapshot().phase, "connected");
  assert.equal(controller.getSnapshot().servers[0].latencyMs, undefined);
  emit({ ...ready, revision: 2, steadyLatencyMs: 21 });
  assert.equal(controller.getSnapshot().servers[0].latencyMs, 21);
  emit({ ...ready, revision: 3 });
  assert.equal(controller.getSnapshot().servers[0].latencyMs, undefined);
  assert.equal(controller.getSnapshot().phase, "connected");
  controller.dispose();
});
