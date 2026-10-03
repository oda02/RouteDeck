import { invoke, isTauri } from "@tauri-apps/api/core";

const RELEASES_URL = "https://github.com/oda02/RouteDeck/releases/latest";
const STORAGE_KEY = "routedeck.updates.v1";
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

export type AppUpdateStatus = "idle" | "checking" | "upToDate" | "available" | "noRelease" | "error" | "unavailable";
export interface PortableUpdateState { phase: "idle" | "downloading" | "ready" | "installing" | "error"; downloaded: number; total: number; version: string | null; error: string | null; }
export interface AppUpdateSnapshot { portable: PortableUpdateState; automatic: boolean; currentVersion: string | null; latestVersion: string | null; status: AppUpdateStatus; }
export interface AppUpdateInfo { currentVersion: string; latestVersion: string | null; status: "upToDate" | "available" | "noRelease"; releaseUrl: string | null; }
export interface AppUpdateClient { available(): boolean; getVersion(): Promise<unknown>; check(): Promise<unknown>; openReleases(): Promise<unknown>; stage?(): Promise<unknown>; portableStatus?(): Promise<unknown>; install?(): Promise<unknown>; }
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

const UPDATE_ERRORS = ["portable_update_failed", "portable_update_manual", "portable_update_repair", "portable_update_foreign_files", "portable_update_unsafe_location", "portable_update_disconnect_first", "portable_update_teardown_failed", "portable_update_unavailable"] as const;
function updateError(value: unknown): string { return typeof value === "string" && UPDATE_ERRORS.includes(value as typeof UPDATE_ERRORS[number]) ? value : "portable_update_failed"; }
export function parsePortableUpdateState(value: unknown): PortableUpdateState {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid update response");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((k) => !["phase", "downloaded", "total", "version", "error"].includes(k)) || !["idle", "downloading", "ready", "installing", "error"].includes(input.phase as string)
    || !Number.isSafeInteger(input.downloaded) || !Number.isSafeInteger(input.total) || (input.downloaded as number) < 0 || (input.total as number) < 0 || (input.total as number) > 512 * 1024 * 1024
    || (input.downloaded as number) > (input.total as number) || (input.error !== null && !UPDATE_ERRORS.includes(input.error as typeof UPDATE_ERRORS[number]))) throw new Error("invalid update response");
  const updateVersion = input.version === null ? null : version(input.version);
  if (["ready", "installing"].includes(input.phase as string) && (updateVersion === null || input.total === 0 || input.downloaded !== input.total || input.error !== null)) throw new Error("invalid update response");
  return { phase: input.phase as PortableUpdateState["phase"], downloaded: input.downloaded as number, total: input.total as number, version: updateVersion, error: input.error as string | null };
}

const nativeClient: AppUpdateClient = {
  available: () => isTauri(),
  getVersion: () => invoke("get_app_version"),
  check: () => invoke("check_app_update"),
  openReleases: () => invoke("open_app_releases"),
  stage: () => invoke("stage_app_update"),
  portableStatus: () => invoke("portable_update_status"),
  install: () => invoke("install_app_update"),
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
  private downloadTimer?: unknown;
  private downloadPending?: Promise<void>;
  private polling = false;
  private pending?: Promise<void>;
  private started = false;
  private disposed = false;
  private generation = 0;
  constructor(client: AppUpdateClient = nativeClient, scheduler: UpdateScheduler = browserScheduler, automatic = true) {
    this.client = client;
    this.scheduler = scheduler;
    this.snapshot = { portable: { phase: "idle", downloaded: 0, total: 0, version: null, error: null }, automatic, currentVersion: null, latestVersion: null, status: client.available() ? "idle" : "unavailable" };
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
      if (!this.disposed && generation === this.generation) {
        this.publish({ currentVersion: info.currentVersion, latestVersion: info.latestVersion, status: info.status });
        if (info.status === "available" && this.client.stage && (!quiet || this.snapshot.portable.phase !== "error" || this.snapshot.portable.version !== info.latestVersion)) void this.download();
      }
    }).catch(() => { if (!this.disposed && generation === this.generation) this.publish({ status: quiet ? "idle" : "error", latestVersion: null }); }).finally(() => { this.pending = undefined; });
    return this.pending;
  };
  private stopDownloadPolling() {
    if (this.downloadTimer !== undefined) this.scheduler.clearInterval(this.downloadTimer);
    this.downloadTimer = undefined;
  }
  private pollDownload = async () => {
    if (this.disposed || this.polling || !this.client.portableStatus) return;
    this.polling = true;
    const generation = this.generation;
    try {
      const portable = parsePortableUpdateState(await this.client.portableStatus());
      if (!this.disposed && generation === this.generation) {
        this.publish({ portable });
        if (portable.phase !== "downloading") this.stopDownloadPolling();
      }
    } catch {
      if (!this.disposed && generation === this.generation) this.publish({ portable: { ...this.snapshot.portable, phase: "error", error: "portable_update_failed" } });
      this.stopDownloadPolling();
    } finally { this.polling = false; }
  };
  download = (): Promise<void> => {
    if (this.downloadPending) return this.downloadPending;
    if (this.disposed || !this.client.stage || !this.client.portableStatus || this.snapshot.portable.phase === "ready" || this.snapshot.portable.phase === "installing" || this.snapshot.portable.phase === "downloading") return Promise.resolve();
    const generation = this.generation;
    this.publish({ portable: { phase: "downloading", downloaded: 0, total: 0, version: this.snapshot.latestVersion, error: null } });
    this.downloadPending = this.client.stage().then(async (result) => {
      if (result !== null) throw new Error("invalid update response");
      if (this.disposed || generation !== this.generation) return;
      await this.pollDownload();
      if (!this.disposed && generation === this.generation && this.snapshot.portable.phase === "downloading" && this.downloadTimer === undefined) this.downloadTimer = this.scheduler.setInterval(() => { void this.pollDownload(); }, 1000);
    }).catch((error: unknown) => {
      if (!this.disposed && generation === this.generation) this.publish({ portable: { ...this.snapshot.portable, phase: "error", error: updateError(error) } });
    }).finally(() => { this.downloadPending = undefined; });
    return this.downloadPending;
  };
  install = async () => {
    if (this.disposed || !this.client.install || this.snapshot.portable.phase !== "ready") return;
    const generation = this.generation;
    this.publish({ portable: { ...this.snapshot.portable, phase: "installing", error: null } });
    try { if (await this.client.install() !== null) throw new Error("invalid update response"); }
    catch (error: unknown) { if (!this.disposed && generation === this.generation) this.publish({ portable: { ...this.snapshot.portable, phase: "error", error: updateError(error) } }); }
  };
  openReleases = async () => {
    if (!this.client.available()) return;
    try { if (await this.client.openReleases() !== null) throw new Error("invalid update response"); }
    catch (error) { this.publish({ status: "error" }); throw error; }
  };
  dispose = () => { this.stopDownloadPolling(); this.disposed = true; this.generation += 1; if (this.timer !== undefined) this.scheduler.clearInterval(this.timer); this.timer = undefined; this.listeners.clear(); };
}

function loadAutomatic(): boolean {
  if (typeof window === "undefined") return true;
  try { const value = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "null"); return value?.version === 1 && typeof value.automatic === "boolean" ? value.automatic : true; } catch { return true; }
}

export const appUpdateMonitor = new AppUpdateMonitor(nativeClient, browserScheduler, loadAutomatic());
