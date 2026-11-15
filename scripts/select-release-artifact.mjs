import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const repository = "oda02/RouteDeck";
const artifactName = "RouteDeck-windows-x64";
const actionsPath = `repos/${repository}/actions`;
const activeStates = new Set(["requested", "waiting", "pending", "queued", "in_progress"]);
const validId = (id) => Number.isSafeInteger(id) && id > 0;

export async function selectReleaseArtifact({
  get, commit, repositoryId, now = Date.now, wait = sleep,
}) {
  if (!/^[a-f0-9]{40}$/.test(commit) || !validId(repositoryId)) {
    throw new Error("Invalid release commit or repository ID");
  }

  const firstCheck = now();
  const runsPath = `${actionsPath}/workflows/ci.yml/runs?branch=main&event=push&head_sha=${commit}&per_page=100`;

  for (;;) {
    const runs = get(runsPath)?.workflow_runs;
    if (!Array.isArray(runs)) return null;
    const matches = runs.filter((run) =>
      run.path === ".github/workflows/ci.yml" && run.event === "push" &&
      run.head_branch === "main" && run.head_sha === commit && validId(run.id) &&
      run.repository?.id === repositoryId && run.head_repository?.id === repositoryId
    );

    for (const run of matches) {
      if (run.status !== "completed" || run.conclusion !== "success") continue;
      const artifacts = get(`${actionsPath}/runs/${run.id}/artifacts?name=${artifactName}`)?.artifacts;
      if (!Array.isArray(artifacts)) return null;
      const namedArtifacts = artifacts.filter((artifact) => artifact.name === artifactName);
      if (namedArtifacts.length !== 1) continue;
      const [artifact] = namedArtifacts;
      const origin = artifact.workflow_run;
      if (validId(artifact.id) && artifact.expired === false &&
          typeof artifact.expires_at === "string" && Date.parse(artifact.expires_at) > now() + 120_000 &&
          typeof artifact.digest === "string" && /^sha256:[a-f0-9]{64}$/.test(artifact.digest) &&
          origin?.id === run.id && origin.head_branch === "main" && origin.head_sha === commit &&
          origin.repository_id === repositoryId && origin.head_repository_id === repositoryId) {
        return { runId: run.id, artifactId: artifact.id };
      }
    }

    const elapsed = now() - firstCheck;
    // Give near-simultaneous pushes time to appear in the run list.
    const waitingForPush = matches.length === 0 && elapsed < 15_000;
    const waitingForBuild = matches.some((run) => activeStates.has(run.status)) && elapsed < 30 * 60_000;
    if (!waitingForPush && !waitingForBuild) return null;
    await wait(15_000);
  }
}

if (import.meta.main) {
  if (process.env.GITHUB_REPOSITORY !== repository) throw new Error("Unexpected release repository");
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const result = await selectReleaseArtifact({
    get: (path) => {
      try {
        return JSON.parse(execFileSync("gh", ["api", path], { encoding: "utf8", timeout: 15_000 }));
      } catch {
        console.warn("GitHub artifact lookup failed.");
        return null;
      }
    },
    commit,
    repositoryId: Number(process.env.GITHUB_REPOSITORY_ID),
  });
  if (result) {
    appendFileSync(process.env.GITHUB_OUTPUT, `run-id=${result.runId}\nartifact-id=${result.artifactId}\n`);
    console.log(`Selected artifact ${result.artifactId} from main CI run ${result.runId}.`);
  } else {
    console.log("No eligible main artifact. Run the full tagged build.");
  }
}
