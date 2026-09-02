import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { toPublicActionError } from "../src/actionErrors.ts";
import { RouteDeckError } from "../src/model.ts";
import { selectControllerRuntime } from "../src/runtimeSelection.ts";
import {
  ContractViolation,
  RuntimeRevisionGate,
  parsePublicError,
  parseRunningApplications,
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
  return {
    ...transport,
    invoke: (command, arguments_) => command === "confirmed_nodes"
      ? Promise.resolve([])
      : transport.invoke(command, arguments_),
  };
}

test("release selection can never choose the demo controller", () => {
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: false, tauriIpcAvailable: true }), "tauri");
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: false, tauriIpcAvailable: false }), "unavailable");
  assert.equal(selectControllerRuntime({ explicitDemo: true, isDevelopment: true, tauriIpcAvailable: true }), "demo");
});

test("busy import keeps focus inside the mounted dialog", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(source, /previouslyFocusedRef\.current = document\.activeElement[\s\S]*return \(\) => previouslyFocusedRef\.current\?\.focus\([\s\S]*\}, \[\]\);/);
  assert.match(source, /data-dialog-busy-focus/);
  assert.match(source, /role="status" aria-live="polite" tabIndex=\{-1\} data-dialog-busy-focus/);
  assert.match(source, /document\.addEventListener\("focusin", onFocusIn\)/);
  assert.match(source, /dialog\.contains\(event\.target as Node \| null\)/);
  assert.doesNotMatch(source, /previouslyFocused\?\.focus/);
});

test("every import failure focuses its enabled source or recovery control", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const errorTarget = source.indexOf('querySelector<HTMLElement>("[data-error-autofocus]:not(:disabled)")');
  const genericTarget = source.indexOf('querySelector<HTMLElement>("[data-autofocus]")', errorTarget);
  assert.ok(errorTarget >= 0 && genericTarget > errorTarget);
  assert.match(source, /id="subscription-url"[^\n]*data-error-autofocus=\{importError \? "true" : undefined\}/);
  assert.match(source, /focusKey="subscription-url"/);
  assert.match(source, /id="subscription-import-form"[^\n]*onSubmit=/);
  assert.doesNotMatch(source, /focusKey=\{[^\n]*importError/);
  assert.match(source, /setImportError\("Вставьте ссылку на подписку\."\)[\s\S]*requestAnimationFrame\(\(\) => subscriptionInputRef\.current\?\.focus\(\)\)/);
});

test("URL import is a normal editable field and one validation-plus-commit action", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(source, /id="subscription-url" type="url" inputMode="url" autoComplete="url"/);
  assert.match(source, /id="subscription-url"[\s\S]*defaultValue=""/);
  assert.doesNotMatch(source, /subscriptionSource|setSubscriptionSource|value=\{subscriptionSource\}/);
  assert.doesNotMatch(source, /type=\{subscriptionVisible|EyeIcon|Прочитать буфер обмена|Файл · скоро|Подтвердить импорт/);
  const urlRead = source.indexOf("const subscriptionUrl = subscriptionInputRef.current?.value.trim()");
  const previewCall = source.indexOf('controller.previewSubscription({ type: "url", value: subscriptionUrl })', urlRead);
  const commitCall = source.indexOf("controller.commitSubscription(preview)", previewCall);
  const clearAfterSuccess = source.indexOf("clearSubscriptionUrl();", commitCall);
  assert.ok(urlRead >= 0 && urlRead < previewCall && previewCall < commitCall && commitCall < clearAfterSuccess);
});

test("URL import uses automatic backend transport without a renderer selector", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const model = readFileSync(new URL("../src/model.ts", import.meta.url), "utf8");
  const styles = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
  assert.doesNotMatch(source, /SubscriptionFetchTransport|subscriptionTransport|Транспорт HTTPS-загрузки|subscription-transport-help|current_loopback_system_proxy/);
  assert.doesNotMatch(model, /SubscriptionFetchTransport|current_loopback_system_proxy/);
  assert.doesNotMatch(styles, /subscription-transport/);
  assert.match(source, /description="Вставьте ссылку от провайдера\."/);
  assert.match(source, /importing \? "Импортируем…" : "Импортировать"/);
  assert.doesNotMatch(source, /Источник подписки|importMethod|clipboardSource|file-adapter-note|import-preview/);
  assert.doesNotMatch(source, /Безопасно загрузить|опасные перенаправления|заблокирует .*локальные адреса|import-help/);
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

test("TUN and application routing use ordinary-client copy without extra ceremonies", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(source, /value: "tun", label: "TUN · скоро", disabled: true/);
  assert.match(source, /Добавить приложение/);
  assert.match(source, /controller\.listRunningApplications\(\)/);
  assert.match(source, /route: draft\.defaultRoute === "direct" \? "vpn" : "direct"/);
  assert.match(source, /Правила отдельных приложений применяются в режиме TUN/);
  assert.doesNotMatch(source, /tun-preflight|nested|Физический адаптер|security mode|режим безопасности/i);
  assert.doesNotMatch(source, /запустите .*администратор/i);
  assert.doesNotMatch(source, /Проверить задержки|controller\.refreshServers/);
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
    detail: "Импортировано из подписки",
    source: "Подписка",
    latencyState: "ready",
    latencyMs: 84,
    checkedAt: "сейчас",
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
      assert.match(publicError.message, /не распознаны как поддерживаемая подписка/);
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

test("System Proxy routing is saved for the next connection while unsupported settings still fail", async () => {
  const transport: TauriTransport = {
    listen: async () => () => undefined,
    invoke: async () => runtimeStatus(1, "disconnected"),
  };
  const controller = new TauriController(async () => withEmptyConfirmedNodes(transport));
  await controller.ready();
  assert.equal(controller.getSnapshot().runtimeScope, "system-proxy");
  await controller.applyRouting({ defaultRoute: "vpn", apps: [] });
  assert.equal(controller.getSnapshot().routing.defaultRoute, "vpn");
  await assert.rejects(controller.saveSettings(controller.getSnapshot().settings), { code: "capability-unavailable" });
  controller.dispose();
});

test("connect and disconnect use the typed System Proxy commands and routing draft", async () => {
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
          apps: [],
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
          apps: [{ processPath: "C:\\Apps\\browser.exe", processName: "browser.exe", route: "direct" }],
        },
      },
    },
    { command: "stop_tun", arguments_: undefined },
  ]);
  controller.dispose();
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
  assert.match(message, /TUN пока недоступен/);
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
      : { status: { ...runtimeStatus(2, "disconnected"), unexpected: true }, lines: [] },
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
      : { status: runtimeStatus(2, "disconnected"), lines: ["sanitized"] },
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
