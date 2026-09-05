import { invoke, isTauri } from "@tauri-apps/api/core";

const RELEASES_URL = "https://github.com/oda02/RouteDeck/releases/latest";
const STORAGE_KEY = "routedeck.updates.v1";
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

export type AppUpdateStatus = "idle" | "checking" | "upToDate" | "available" | "noRelease" | "error" | "unavailable";
export interface AppUpdateSnapshot { automatic: boolean; currentVersion: string | null; latestVersion: string | null; status: AppUpdateStatus; }
export interface AppUpdateInfo { currentVersion: string; latestVersion: string | null; status: "upToDate" | "available" | "noRelease"; releaseUrl: string | null; }
export interface AppUpdateClient { available(): boolean; getVersion(): Promise<unknown>; check(): Promise<unknown>; openReleases(): Promise<unknown>; }
export interface UpdateScheduler { setInterval(callback: () => void, milliseconds: number): unknown; clearInterval(handle: unknown): void; }

function version(value: unknown): string {
  if (typeof value !== "string" || value.length > 64 || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value)) throw new Error("invalid update response");
  return value;
}

export function parseAppUpdateInfo(value: unknown): AppUpdateInfo {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid update response");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["currentVersion", "latestVersion", "status", "releaseUrl"].includes(key))
    || !["upToDate", "available", "noRelease"].includes(input.status as string)) throw new Error("invalid update response");
  const currentVersion = version(input.currentVersion);
  const latestVersion = input.latestVersion === null ? null : version(input.latestVersion);
  const releaseUrl = input.releaseUrl === null ? null : input.releaseUrl;
  if ((releaseUrl !== null && releaseUrl !== RELEASES_URL)
    || (input.status === "available") !== (latestVersion !== null && releaseUrl === RELEASES_URL)
    || (input.status === "upToDate" && (latestVersion === null || releaseUrl !== null))
    || (input.status === "noRelease" && (latestVersion !== null || releaseUrl !== null))) throw new Error("invalid update response");
  return { currentVersion, latestVersion, status: input.status as AppUpdateInfo["status"], releaseUrl: releaseUrl as string | null };
}

const nativeClient: AppUpdateClient = {
  available: () => isTauri(),
  getVersion: () => invoke("get_app_version"),
  check: () => invoke("check_app_update"),
  openReleases: () => invoke("open_app_releases"),
};

const browserScheduler: UpdateScheduler = {
  setInterval: (callback, milliseconds) => window.setInterval(callback, milliseconds),
  clearInterval: (handle) => window.clearInterval(handle as number),
};

export class AppUpdateMonitor {
  private readonly client: AppUpdateClient;
  private readonly scheduler: UpdateScheduler;
  private snapshot: AppUpdateSnapshot;
  private readonly listeners = new Set<() => void>();
  private timer?: unknown;
  private pending?: Promise<void>;
  private started = false;
  private disposed = false;
  private generation = 0;
  constructor(client: AppUpdateClient = nativeClient, scheduler: UpdateScheduler = browserScheduler, automatic = true) {
    this.client = client;
    this.scheduler = scheduler;
    this.snapshot = { automatic, currentVersion: null, latestVersion: null, status: client.available() ? "idle" : "unavailable" };
  }
  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private publish(update: Partial<AppUpdateSnapshot>) { this.snapshot = { ...this.snapshot, ...update }; this.listeners.forEach((listener) => listener()); }
  start = async () => {
    if (this.started || this.disposed) return;
    this.started = true;
    const generation = this.generation;
    if (!this.client.available()) return;
    try { const currentVersion = version(await this.client.getVersion()); if (!this.disposed && generation === this.generation) this.publish({ currentVersion }); }
    catch { if (!this.disposed && generation === this.generation) this.publish({ status: "error" }); }
    if (this.snapshot.automatic) await this.check(true);
    if (!this.disposed && generation === this.generation) this.reschedule();
  };
  private reschedule() {
    if (this.timer !== undefined) this.scheduler.clearInterval(this.timer);
    this.timer = undefined;
    if (this.started && !this.disposed && this.snapshot.automatic && this.client.available()) {
      this.timer = this.scheduler.setInterval(() => { void this.check(true); }, SIX_HOURS_MS);
    }
  }
  setAutomatic = (automatic: boolean) => {
    if (this.disposed) return;
    this.publish({ automatic });
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ version: 1, automatic })); } catch { /* Preference remains active for this run. */ }
    this.reschedule();
  };
  check = (quiet = false): Promise<void> => {
    if (this.pending) return this.pending;
    if (this.disposed || !this.client.available()) return Promise.resolve();
    const generation = this.generation;
    this.publish({ status: "checking" });
    this.pending = this.client.check().then((raw) => {
      const info = parseAppUpdateInfo(raw);
      if (!this.disposed && generation === this.generation) this.publish({ currentVersion: info.currentVersion, latestVersion: info.latestVersion, status: info.status });
    }).catch(() => { if (!this.disposed && generation === this.generation) this.publish({ status: quiet ? "idle" : "error", latestVersion: null }); }).finally(() => { this.pending = undefined; });
    return this.pending;
  };
  openReleases = async () => {
    if (!this.client.available()) return;
    try { if (await this.client.openReleases() !== null) throw new Error("invalid update response"); }
    catch (error) { this.publish({ status: "error" }); throw error; }
  };
  dispose = () => { this.disposed = true; this.generation += 1; if (this.timer !== undefined) this.scheduler.clearInterval(this.timer); this.timer = undefined; this.listeners.clear(); };
}

function loadAutomatic(): boolean {
  if (typeof window === "undefined") return true;
  try { const value = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "null"); return value?.version === 1 && typeof value.automatic === "boolean" ? value.automatic : true; } catch { return true; }
}

export const appUpdateMonitor = new AppUpdateMonitor(nativeClient, browserScheduler, loadAutomatic());
