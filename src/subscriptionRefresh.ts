import type { ControllerSnapshot } from "./model";

// Attempt times also throttle failures. There is no catch-up burst after sleep.
export function nextSubscriptionRefresh(snapshot: ControllerSnapshot, attempts: ReadonlyMap<string, number>, now: number): string | undefined {
  const hours = snapshot.settings.subscriptionRefreshHours;
  if (!hours || !snapshot.backendAvailable || snapshot.switching || snapshot.activeServerId
    || (snapshot.phase !== "disconnected" && snapshot.phase !== "failed")) return;
  const interval = hours * 60 * 60 * 1000;
  return snapshot.servers.find((server) => server.sourceId && server.sourceRefreshable
    && now - Math.max(server.sourceUpdatedAtMs ?? 0, attempts.get(server.sourceId) ?? 0) >= interval)?.sourceId;
}
