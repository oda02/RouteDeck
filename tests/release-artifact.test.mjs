import assert from "node:assert/strict";
import { test } from "node:test";
import { selectReleaseArtifact } from "../scripts/select-release-artifact.mjs";

const commit = "a".repeat(40);
const repositoryId = 123;
const mainRun = {
  id: 21,
  path: ".github/workflows/ci.yml",
  event: "push",
  head_branch: "main",
  head_sha: commit,
  repository: { id: repositoryId },
  head_repository: { id: repositoryId },
  status: "completed",
  conclusion: "success",
};
const portable = {
  id: 34,
  name: "RouteDeck-windows-x64",
  digest: `sha256:${"b".repeat(64)}`,
  expired: false,
  expires_at: "2026-11-16T00:00:00.000Z",
  workflow_run: {
    id: mainRun.id,
    repository_id: repositoryId,
    head_repository_id: repositoryId,
    head_branch: "main",
    head_sha: commit,
  },
};

function fixture({ runs = () => [mainRun], artifacts = [portable] } = {}) {
  let checks = 0;
  let waited = 0;
  const requests = [];
  return {
    requests,
    get waited() { return waited; },
    select: () => selectReleaseArtifact({
      commit,
      repositoryId,
      now: () => Date.parse("2026-11-15T00:00:00.000Z") + waited,
      wait: (ms) => { waited += ms; },
      get: (path) => {
        requests.push(path);
        if (path.includes("/workflows/")) return { workflow_runs: runs(++checks) };
        assert.equal(path, "repos/oda02/RouteDeck/actions/runs/21/artifacts?name=RouteDeck-windows-x64");
        return { artifacts };
      },
    }),
  };
}

test("selects the exact portable artifact by trusted run and artifact IDs", async () => {
  const probe = fixture();
  assert.deepEqual(await probe.select(), { runId: 21, artifactId: 34 });
  assert.equal(probe.waited, 0);
  assert.equal(probe.requests[0], `repos/oda02/RouteDeck/actions/workflows/ci.yml/runs?branch=main&event=push&head_sha=${commit}&per_page=100`);
});

test("rejects runs outside the successful same-repository push to main", async (t) => {
  for (const [label, change] of Object.entries({
    pull_request: { event: "pull_request" },
    manual: { event: "workflow_dispatch" },
    branch: { head_branch: "feature" },
    commit: { head_sha: "b".repeat(40) },
    workflow: { path: ".github/workflows/other.yml" },
    repository: { repository: { id: 456 } },
    fork: { head_repository: { id: 456 } },
    failed: { conclusion: "failure" },
    cancelled: { conclusion: "cancelled" },
    invalidId: { id: "21" },
  })) {
    await t.test(label, async () => {
      const probe = fixture({ runs: () => [{ ...mainRun, ...change }] });
      assert.equal(await probe.select(), null);
      assert.ok(probe.requests.every((path) => path.includes("/workflows/")));
    });
  }
});

test("rebuilds when the expected artifact is unavailable or its metadata does not match", async (t) => {
  for (const [label, artifacts] of Object.entries({
    missing: [],
    duplicate: [portable, { ...portable, id: 35 }],
    wrongName: [{ ...portable, name: "RouteDeck-ui-failure" }],
    expired: [{ ...portable, expired: true }],
    pastExpiry: [{ ...portable, expires_at: "2026-11-14T00:00:00.000Z" }],
    expiresWhilePublishing: [{ ...portable, expires_at: "2026-11-15T00:01:00.000Z" }],
    missingDigest: [{ ...portable, digest: null }],
    arrayDigest: [{ ...portable, digest: [portable.digest] }],
    wrongRun: [{ ...portable, workflow_run: { ...portable.workflow_run, id: 22 } }],
    wrongCommit: [{ ...portable, workflow_run: { ...portable.workflow_run, head_sha: "b".repeat(40) } }],
  })) {
    await t.test(label, async () => assert.equal(await fixture({ artifacts }).select(), null));
  }
});

test("falls back when the GitHub artifact lookup is unavailable", async () => {
  for (const get of [() => null, (path) => path.includes("/workflows/") ? { workflow_runs: [mainRun] } : null]) {
    assert.equal(await selectReleaseArtifact({ get, commit, repositoryId }), null);
  }
});

test("waits for a near-simultaneous main push and reuses the completed build", async () => {
  const probe = fixture({
    runs: (check) => {
      if (check === 1) return [];
      if (check === 2) return [{ ...mainRun, status: "queued", conclusion: null }];
      return [mainRun];
    },
  });
  assert.deepEqual(await probe.select(), { runId: 21, artifactId: 34 });
  assert.equal(probe.waited, 30_000);
});

test("bounds the wait for main and falls back promptly when no run appears", async () => {
  const missing = fixture({ runs: () => [] });
  assert.equal(await missing.select(), null);
  assert.equal(missing.waited, 15_000);

  const active = fixture({ runs: () => [{ ...mainRun, status: "in_progress", conclusion: null }] });
  assert.equal(await active.select(), null);
  assert.equal(active.waited, 30 * 60_000);
});
