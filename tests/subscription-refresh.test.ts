import assert from "node:assert/strict";
import test from "node:test";
import { nextSubscriptionRefresh } from "../src/subscriptionRefresh.ts";
import type { ControllerSnapshot } from "../src/model.ts";

const now = 100_000_000;
const snapshot = () => ({ backendAvailable: true, phase: "disconnected", switching: false,
  settings: { subscriptionRefreshHours: 6 },
  servers: [{ sourceId: "legacy", sourceRefreshable: false },
    { sourceId: "old", sourceRefreshable: true, sourceUpdatedAtMs: now - 25_000_000 },
    { sourceId: "fresh", sourceRefreshable: true, sourceUpdatedAtMs: now }],
}) as ControllerSnapshot;

test("background refresh chooses one due saved source; skips legacy and fresh sources", () => {
  assert.equal(nextSubscriptionRefresh(snapshot(), new Map(), now), "old");
  assert.equal(nextSubscriptionRefresh(snapshot(), new Map([["old", now]]), now + 60_000), undefined);
});
test("disabled, connected, transitioning and unavailable states never schedule refresh", () => {
  for (const patch of [{ backendAvailable: false }, { switching: true }, { activeServerId: "x" }, { phase: "connected" }, { phase: "validating-config" }, { settings: { subscriptionRefreshHours: 0 } }]) {
    assert.equal(nextSubscriptionRefresh({ ...snapshot(), ...patch } as ControllerSnapshot, new Map(), now), undefined);
  }
});
test("failed attempt cooldown and successful timestamp each postpone the next fetch", () => {
  const attempts = new Map([["old", now]]);
  assert.equal(nextSubscriptionRefresh(snapshot(), attempts, now + 6 * 3_600_000 - 1), undefined);
  assert.equal(nextSubscriptionRefresh(snapshot(), attempts, now + 6 * 3_600_000), "old");
  const state = snapshot(); state.servers[1].sourceUpdatedAtMs = now + 1_000;
  assert.equal(nextSubscriptionRefresh(state, attempts, now + 6 * 3_600_000), "fresh");
});
