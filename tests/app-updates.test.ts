import assert from "node:assert/strict";
import test from "node:test";
import { AppUpdateMonitor, parseAppUpdateInfo, parsePortableUpdateState, type AppUpdateClient, type UpdateScheduler } from "../src/appUpdates.ts";

test("portable progress parser accepts only bounded typed progress and redacted errors", () => {
  assert.equal(parsePortableUpdateState({ phase: "ready", downloaded: 100, total: 100, version: "1.2.0", error: null }).phase, "ready");
  assert.equal(parsePortableUpdateState({ phase: "error", downloaded: 0, total: 0, version: "1.2.0", error: "portable_update_unsafe_location" }).error, "portable_update_unsafe_location");
  for (const input of [
    { phase: "ready", downloaded: 1, total: 2, version: "1.2.0", error: null },
    { phase: "downloading", downloaded: 3, total: 2, version: "1.2.0", error: null },
    { phase: "downloading", downloaded: 0, total: 1024 ** 3, version: "1.2.0", error: null },
    { phase: "error", downloaded: 0, total: 0, version: null, error: "secret or local path" },
    { phase: "ready", downloaded: 2, total: 2, version: "1.2.0", error: null, path: "caller-controlled" },
    { phase: "error", downloaded: 0, total: 0, version: "1.2.0", error: "portable_update_unsafe_location", path: "caller-controlled" },
  ]) assert.throws(() => parsePortableUpdateState(input));
});

test("background ACL refusal keeps the finite location error and stops polling", async () => {
  let timers = 0;
  const scheduler: UpdateScheduler = { setInterval: () => ++timers, clearInterval: () => { timers--; } };
  const client: AppUpdateClient = { available: () => true, getVersion: async () => "1.0.0", check: async () => ({ currentVersion: "1.0.0", latestVersion: "1.2.0", status: "available", releaseUrl }), openReleases: async () => null, stage: async () => null,
    portableStatus: async () => ({ phase: "error", downloaded: 0, total: 0, version: "1.2.0", error: "portable_update_unsafe_location" }) };
  const monitor = new AppUpdateMonitor(client, scheduler, false);
  await monitor.check(); await monitor.download();
  assert.equal(monitor.getSnapshot().portable.error, "portable_update_unsafe_location");
  assert.equal(monitor.getSnapshot().portable.phase, "error");
  assert.equal(timers, 0);
  monitor.dispose();
});

test("signed update stages in background, progress reaches ready, install failure can retry", async () => {
  const timers = new Map<number, () => void>(); let nextTimer = 0; let phase = "downloading"; let stages = 0; let installs = 0; let failInstall = true;
  const scheduler: UpdateScheduler = { setInterval: (callback) => { timers.set(++nextTimer, callback); return nextTimer; }, clearInterval: (id) => { timers.delete(id as number); } };
  const client: AppUpdateClient = { available: () => true, getVersion: async () => "1.0.0", check: async () => ({ currentVersion: "1.0.0", latestVersion: "1.2.0", status: "available", releaseUrl }), openReleases: async () => null,
    stage: async () => { stages++; return null; }, portableStatus: async () => ({ phase, downloaded: phase === "ready" ? 100 : 50, total: 100, version: "1.2.0", error: null }), install: async () => { installs++; if (failInstall) throw "portable_update_failed"; return null; } };
  const monitor = new AppUpdateMonitor(client, scheduler, true);
  await monitor.start(); await monitor.download();
  assert.equal(stages, 1); assert.equal(monitor.getSnapshot().portable.downloaded, 50);
  phase = "ready"; for (const callback of timers.values()) callback(); await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(monitor.getSnapshot().portable.phase, "ready");
  await monitor.install(); assert.equal(monitor.getSnapshot().portable.phase, "error");
  await monitor.download(); assert.equal(monitor.getSnapshot().portable.phase, "ready");
  failInstall = false; await monitor.install(); assert.equal(installs, 2); assert.equal(monitor.getSnapshot().portable.phase, "installing");
  monitor.dispose(); assert.equal(timers.size, 0);
});

test("late background status after disposal cannot publish or retain polling", async () => {
  let finish!: (value: unknown) => void; let timers = 0;
  const scheduler: UpdateScheduler = { setInterval: () => { timers++; return timers; }, clearInterval: () => undefined };
  const client: AppUpdateClient = { available: () => true, getVersion: async () => "1.0.0", check: async () => ({ currentVersion: "1.0.0", latestVersion: "1.2.0", status: "available", releaseUrl }), openReleases: async () => null, stage: async () => null, portableStatus: () => new Promise((resolve) => { finish = resolve; }) };
  const monitor = new AppUpdateMonitor(client, scheduler, false); await monitor.check();
  await new Promise<void>((resolve) => setImmediate(resolve)); monitor.dispose();
  finish({ phase: "ready", downloaded: 100, total: 100, version: "1.2.0", error: null }); await monitor.download();
  assert.equal(monitor.getSnapshot().portable.phase, "downloading"); assert.equal(timers, 0);
});

const releaseUrl = "https://github.com/oda02/RouteDeck/releases/latest";

test("update response parser accepts finite release states and rejects redirects or inconsistent fields", () => {
  assert.deepEqual(parseAppUpdateInfo({ currentVersion: "1.2.3", latestVersion: "1.3.0", status: "available", releaseUrl }), {
    currentVersion: "1.2.3", latestVersion: "1.3.0", status: "available", releaseUrl,
  });
  assert.equal(parseAppUpdateInfo({ currentVersion: "1.2.3", latestVersion: "1.2.3", status: "upToDate", releaseUrl: null }).status, "upToDate");
  assert.equal(parseAppUpdateInfo({ currentVersion: "1.2.3", latestVersion: null, status: "noRelease", releaseUrl: null }).status, "noRelease");
  for (const value of [
    { currentVersion: "dev", latestVersion: null, status: "noRelease", releaseUrl: null },
    { currentVersion: "1.0.0", latestVersion: "2.0.0", status: "available", releaseUrl: "https://example.invalid/file" },
    { currentVersion: "1.0.0", latestVersion: null, status: "available", releaseUrl },
    { currentVersion: "1.0.0", latestVersion: null, status: "noRelease", releaseUrl: null, extra: true },
  ]) assert.throws(() => parseAppUpdateInfo(value));
});

test("monitor checks at startup and six-hour intervals, debounces, retries, and disposes", async () => {
  const callbacks: Array<() => void> = [];
  const cleared: unknown[] = [];
  const scheduler: UpdateScheduler = {
    setInterval: (callback, milliseconds) => { assert.equal(milliseconds, 21_600_000); callbacks.push(callback); return callbacks.length; },
    clearInterval: (handle) => cleared.push(handle),
  };
  let checks = 0;
  let fail = false;
  let release!: () => void;
  const client: AppUpdateClient = {
    available: () => true,
    getVersion: async () => "1.2.3",
    check: async () => { checks += 1; if (fail) throw new Error("offline"); await new Promise<void>((resolve) => { release = resolve; }); return { currentVersion: "1.2.3", latestVersion: "1.3.0", status: "available", releaseUrl }; },
    openReleases: async () => null,
  };
  const monitor = new AppUpdateMonitor(client, scheduler, true);
  const starting = monitor.start();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(monitor.getSnapshot().status, "checking");
  assert.strictEqual(monitor.check(), monitor.check(), "concurrent checks share one promise");
  release(); await starting;
  assert.equal(monitor.getSnapshot().status, "available");
  assert.equal(callbacks.length, 1);
  fail = true; callbacks[0](); await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(monitor.getSnapshot().status, "idle", "automatic failures stay quiet");
  await monitor.check(false); assert.equal(monitor.getSnapshot().status, "error");
  fail = false; const retry = monitor.check(false); await new Promise<void>((resolve) => setImmediate(resolve)); release(); await retry;
  assert.equal(monitor.getSnapshot().status, "available");
  monitor.dispose(); assert.deepEqual(cleared, [1]);
  assert.equal(checks, 4);
});

test("browser mode performs no update calls or scheduling", async () => {
  let calls = 0;
  const client: AppUpdateClient = { available: () => false, getVersion: async () => { calls++; }, check: async () => { calls++; }, openReleases: async () => { calls++; } };
  const scheduler: UpdateScheduler = { setInterval: () => { calls++; return 1; }, clearInterval: () => { calls++; } };
  const monitor = new AppUpdateMonitor(client, scheduler);
  await monitor.start(); await monitor.check(); await monitor.openReleases(); monitor.dispose();
  assert.equal(calls, 0);
  assert.equal(monitor.getSnapshot().status, "unavailable");
});

test("disabling or disposing during the startup check cannot install a late timer", async () => {
  for (const finish of ["disable", "dispose"] as const) {
    let release!: () => void;
    let timers = 0;
    const scheduler: UpdateScheduler = { setInterval: () => { timers += 1; return timers; }, clearInterval: () => undefined };
    const client: AppUpdateClient = {
      available: () => true,
      getVersion: async () => "1.0.0",
      check: async () => { await new Promise<void>((resolve) => { release = resolve; }); return { currentVersion: "1.0.0", latestVersion: "1.0.0", status: "upToDate", releaseUrl: null }; },
      openReleases: async () => null,
    };
    const monitor = new AppUpdateMonitor(client, scheduler, true);
    const starting = monitor.start(); await new Promise<void>((resolve) => setImmediate(resolve));
    if (finish === "disable") monitor.setAutomatic(false); else monitor.dispose();
    release(); await starting;
    assert.equal(timers, 0, `${finish} allowed a late interval`);
  }
});

test("enabling automatic checks during startup keeps only one interval", async () => {
  let release!: () => void;
  const active = new Set<unknown>(); let sequence = 0;
  const scheduler: UpdateScheduler = { setInterval: () => { const handle = ++sequence; active.add(handle); return handle; }, clearInterval: (handle) => { active.delete(handle); } };
  const client: AppUpdateClient = { available: () => true, getVersion: async () => "1.0.0", check: async () => { await new Promise<void>((resolve) => { release = resolve; }); return { currentVersion: "1.0.0", latestVersion: null, status: "noRelease", releaseUrl: null }; }, openReleases: async () => null };
  const monitor = new AppUpdateMonitor(client, scheduler, true);
  const starting = monitor.start(); await new Promise<void>((resolve) => setImmediate(resolve));
  monitor.setAutomatic(true); assert.equal(active.size, 1);
  release(); await starting; assert.equal(active.size, 1);
  monitor.dispose(); assert.equal(active.size, 0);
});
