// Browser-only synthetic IPC. Loaded by the browser test's request interception.
// This file is never imported by application source or a production bundle.
import { TauriController } from "/src/tauriController.ts";

const group = "a".repeat(32);
const manual = "b".repeat(32);
const legacy = "c".repeat(32);
const previousUpdate = Date.now() - 25 * 60 * 60 * 1000;
const fixture = {
  calls: [], failRefresh: false, failStop: false, failProxyCleanup: false, failUpdateCheck: false, failOpenReleases: false, proxyCleanupDelay: 0, startDelay: 40, refreshDelay: 0,
  updateResponse: { currentVersion: "0.1.0", latestVersion: "0.1.0", status: "upToDate", releaseUrl: null },
  systemProxy: { state: "stale", endpoint: "127.0.0.1:24080", detail: "Локальный порт не отвечает.", cleanupToken: "e".repeat(64) },
  nodes: Array.from({ length: 130 }, (_, index) => ({
    id: `${group}-${index}`, displayName: `Европа ${String(index + 1).padStart(3, "0")}`,
    protocol: "vless", insecureTls: false, sourceId: group,
    sourceName: "Основная подписка", sourceKind: "subscription", sourceRefreshable: true,
    sourceUpdatedAtMs: previousUpdate,
  })).concat([
    { id: `${manual}-naive`, displayName: "Мой Naive", protocol: "naive", insecureTls: false, sourceId: manual, sourceName: "Личные серверы", sourceKind: "manual", sourceRefreshable: false },
    { id: `${legacy}-hy2`, displayName: "Сохранённый сервер", protocol: "hysteria2", insecureTls: false, sourceId: legacy, sourceName: "Старая подписка", sourceKind: "subscription", sourceRefreshable: false },
  ]),
};
let revision = 0;
let current;
let listener;
let previewKind = "manual";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function status(phase = "disconnected", mode = "local_only", nodeId) {
  const active = phase !== "disconnected";
  const ready = phase === "system_proxy_ready" || phase === "tun_ready";
  return {
    revision: ++revision, phase, mode, scope: mode,
    ...(active ? { sessionId: "fixture-session", nodeId, ports: { http: 24080, socks: 24081, health: 24082 }, engineVersion: "1.13.21" } : {}),
    ...(ready ? { routeCheckMs: 384, ...(fixture.steadyUnavailable ? {} : { steadyLatencyMs: 42 }) } : {}),
    proofs: ["engine_config", "engine_process", "http_listener", "socks_listener", "health_listener", "selected_outbound_https", "local_scope_ownership", "system_proxy_ownership"].map((kind) => ({
      kind, state: !active ? "not_run" : kind === "system_proxy_ownership" ? mode === "system_proxy" && ready ? "passed" : "not_run" : ready ? "passed" : "pending",
      ...(kind === "selected_outbound_https" && ready ? { latencyMs: 384 } : {}),
    })),
  };
}
const emit = (next) => { current = next; listener?.(next); return next; };
const transport = {
  listen: async (_name, callback) => { listener = callback; return () => { listener = undefined; }; },
  invoke: async (command, args) => {
    // Never include supplied URLs/share contents in even this synthetic log.
    fixture.calls.push({ command, nodeId: args?.nodeId, sourceId: args?.sourceId, ...(command.startsWith("start_") ? { routing: structuredClone(args?.routing) } : {}) });
    if (command === "runtime_status") return current ?? (current = status());
    if (command === "get_app_version") return "0.1.0";
    if (command === "check_app_update") {
      if (fixture.failUpdateCheck) throw "fixture update check failed";
      return structuredClone(fixture.updateResponse);
    }
    if (command === "open_app_releases") {
      if (fixture.failOpenReleases) throw "fixture release opener failed";
      return null;
    }
    if (command === "confirmed_nodes") return structuredClone(fixture.nodes);
    if (command === "runtime_diagnostics") return { status: current, lines: ["Fixture diagnostics"], systemProxy: structuredClone(fixture.systemProxy) };
    if (command === "clear_stale_system_proxy") {
      if (fixture.proxyCleanupDelay) await sleep(fixture.proxyCleanupDelay);
      if (args?.token !== fixture.systemProxy.cleanupToken) throw { code: "runtime_failure", stage: "system_proxy_restore", message: "stale observation" };
      if (fixture.failProxyCleanup) throw { code: "runtime_failure", stage: "system_proxy_restore", message: "fixture cleanup failed" };
      fixture.systemProxy = { state: "disabled", endpoint: null, detail: "Прокси Windows отключён.", cleanupToken: null };
      return { status: current, lines: ["Fixture diagnostics"], systemProxy: structuredClone(fixture.systemProxy) };
    }
    if (command.startsWith("start_")) {
      const mode = command === "start_tun" ? "tun" : "system_proxy";
      emit(status("starting_core", mode, args.nodeId));
      await sleep(fixture.startDelay);
      return emit(status(mode === "tun" ? "tun_ready" : "system_proxy_ready", mode, args.nodeId));
    }
    if (command.startsWith("stop_")) {
      await sleep(35);
      if (fixture.failStop) throw { code: "runtime_failure", stage: "system_proxy_restore", message: "fixture stop failed" };
      return emit(status());
    }
    if (command === "refresh_source") {
      if (fixture.refreshDelay) await new Promise((resolve) => setTimeout(resolve, fixture.refreshDelay));
      await sleep(60);
      if (fixture.failRefresh) throw { code: "subscription_fetch_failed", stage: "subscription_fetch", message: "subscription.fetch_failed" };
      const updatedAtMs = Date.now();
      fixture.nodes = fixture.nodes.map((node) => node.sourceId === args.sourceId ? { ...node, sourceRefreshable: true, sourceUpdatedAtMs: updatedAtMs } : node);
      const ids = fixture.nodes.filter((node) => node.sourceId === args.sourceId).map((node) => node.id);
      return { imported: ids.length, nodeIds: ids };
    }
    if (command === "remove_source") { fixture.nodes = fixture.nodes.filter((node) => node.sourceId !== args.sourceId); return null; }
    if (command === "preview_import_content" || command === "preview_import_url") {
      previewKind = command === "preview_import_url" ? "subscription" : "manual";
      await sleep(40);
      return { previewId: "fixture-preview", nodes: [{ id: "new", displayName: "Новый Naive", protocol: "naive", insecureTls: false }], rejected: [], warnings: [] };
    }
    if (command === "confirm_import") {
      const sourceId = "d".repeat(32);
      const node = { id: `${sourceId}-new`, displayName: "Новый Naive", protocol: "naive", insecureTls: false, sourceId, sourceName: args.sourceName || "Добавленная группа", sourceKind: previewKind, sourceRefreshable: previewKind === "subscription" };
      fixture.nodes.push(node);
      return { imported: 1, nodeIds: [node.id] };
    }
    if (command === "discard_import_preview") return null;
    if (command === "list_running_applications") return Array.from({ length: 20 }, (_, index) => ({
      processName: `app${index + 1}.exe`, displayName: `Приложение ${String(index + 1).padStart(2, "0")}`,
      executablePath: `C:\\Fixture Apps\\Application ${index + 1}\\app${index + 1}.exe`,
    }));
    throw new Error(`Unsupported fixture command: ${command}`);
  },
};
// Exercise standalone frontend IPC clients through the same synthetic transport.
window.__TAURI_INTERNALS__ = { invoke: (command, args) => transport.invoke(command, args) };
window.isTauri = true;
export const controller = new TauriController(async () => transport);
window.__routeDeckFixture = fixture;
fixture.snapshot = () => controller.getSnapshot();
fixture.runDiagnostics = () => controller.runDiagnostics();
fixture.setMetricAvailable = (available) => { fixture.steadyUnavailable = !available; emit(status(current.phase, current.mode, current.nodeId)); };
