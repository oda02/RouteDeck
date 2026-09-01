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

test("non-dismissible import keeps focus inside the mounted dialog", () => {
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
  assert.match(source, /ref=\{clipboardButtonRef\}[^\n]*data-error-autofocus=\{importError \? "true" : undefined\}[^\n]*onClick=\{readClipboardSource\}/);
  assert.match(source, /data-error-autofocus=\{importError \? "true" : undefined\}[^\n]*onClick=\{commitImport\}/);
  assert.match(source, /focusKey=\{subscriptionPreview \? "preview" : `source-\$\{importMethod\}`\}/);
  assert.doesNotMatch(source, /focusKey=\{[^\n]*importError/);
  assert.equal(source.match(/\bfocusImportInput\(\);/g)?.length, 1, "only synchronous empty-source validation may schedule direct focus");
});

test("URL input is masked and cleared before the async preview action", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(source, /id="subscription-url" type=\{subscriptionVisible \? "text" : "password"\}/);
  assert.match(source, /id="subscription-url"[\s\S]*defaultValue=""/);
  assert.doesNotMatch(source, /subscriptionSource|setSubscriptionSource|value=\{subscriptionSource\}/);
  const secretRead = source.indexOf("let subscriptionUrl = subscriptionInputRef.current?.value");
  const secretClear = source.indexOf("clearSubscriptionUrl();", secretRead);
  const ipcCall = source.indexOf("controller.previewSubscription({ type: \"url\", value: subscriptionUrl })", secretClear);
  const localClear = source.indexOf('subscriptionUrl = "";', ipcCall);
  const asyncAction = source.indexOf("void runAsyncAction({", localClear);
  assert.ok(secretRead >= 0 && secretRead < secretClear && secretClear < ipcCall && ipcCall < localClear && localClear < asyncAction);
  assert.match(source, /retry: sourceType === "url" \? undefined : previewImport/);
});

test("URL import delegates transport selection to the backend without a renderer selector", () => {
  const source = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const model = readFileSync(new URL("../src/model.ts", import.meta.url), "utf8");
  const styles = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
  assert.doesNotMatch(source, /SubscriptionFetchTransport|subscriptionTransport|Транспорт HTTPS-загрузки|subscription-transport-help|current_loopback_system_proxy/);
  assert.doesNotMatch(model, /SubscriptionFetchTransport|current_loopback_system_proxy/);
  assert.doesNotMatch(styles, /subscription-transport/);
  assert.match(source, /загрузит подписку по HTTPS через текущий сетевой путь Windows/);
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
  assert.doesNotThrow(() => parsePublicError({
    code: "subscription_fetch_timeout",
    stage: "subscription_proxy_connect",
    message: "subscription.timeout",
    detail: null,
  }));
  assert.doesNotThrow(() => parsePublicError({
    code: "subscription_proxy_unavailable",
    stage: "subscription_proxy",
    message: "subscription.proxy.unavailable",
    detail: null,
  }));
  assert.throws(() => parsePublicError({
    code: "subscription_proxy_policy_blocked",
    stage: "subscription_proxy_connect",
    message: "subscription.proxy.policy_blocked",
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
  const controller = new TauriController(async () => transport);
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
  const controller = new TauriController(async () => loader);
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
  const controller = new TauriController(async () => transport);
  await controller.ready();
  const preview = await controller.previewSubscription({ type: "url", value: secret });
  assert.deepEqual(calls[1], { command: "preview_import_url", arguments_: { url: secret } });
  assert.equal(preview.sourceLabel, "HTTPS-подписка · адрес скрыт");
  assert.ok(!JSON.stringify(preview).includes(secret));
  assert.ok(!JSON.stringify(controller.getSnapshot()).includes(secret));
  assert.ok(!JSON.stringify(controller).includes(secret));
  controller.cancelImportPreview();
  controller.dispose();
});

test("automatic URL fetch failure sends the secret once without renderer fallback", async () => {
  const secret = "https://provider.example/subscription?token=automatic-no-fallback";
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
  const controller = new TauriController(async () => transport);
  await controller.ready();
  await assert.rejects(
    controller.previewSubscription({ type: "url", value: secret }),
    (error: unknown) => {
      assert.ok(error instanceof RouteDeckError);
      assert.equal(error.code, "subscription-fetch-failed");
      assert.match(toPublicActionError(error).message, /текущий сетевой путь Windows/);
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
  const controller = new TauriController(async () => transport);
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
    ["subscription_proxy_unavailable", "subscription_proxy", "subscription.proxy.unavailable", "subscription-proxy-unavailable"],
    ["subscription_proxy_policy_blocked", "subscription_proxy", "subscription.proxy.policy_blocked", "subscription-proxy-policy-blocked"],
    ["subscription_proxy_connect_failed", "subscription_proxy_connect", "subscription.proxy.connect_failed", "subscription-proxy-connect-failed"],
    ["subscription_response_too_large", "subscription_response", "subscription.response_too_large", "subscription-response-too-large"],
    ["subscription_fetch_timeout", "subscription_fetch", "subscription.timeout", "subscription-fetch-timeout"],
    ["subscription_fetch_timeout", "subscription_proxy_connect", "subscription.timeout", "subscription-fetch-timeout"],
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
  const controller = new TauriController(async () => transport);
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
  const controller = new TauriController(async () => transport);
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
  const controller = new TauriController(async () => transport);
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
