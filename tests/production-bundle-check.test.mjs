import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { assertProductionBundle } from "./assert-production-bundle.mjs";

async function withFixture(run) {
  const root = await mkdtemp(join(tmpdir(), "routedeck-production-boundary-"));
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("production boundary rejects an empty artifact directory", async () => {
  await withFixture(async (root) => {
    await assert.rejects(assertProductionBundle(root), /contains no artifacts/);
  });
});

test("production boundary rejects an incomplete artifact directory", async () => {
  await withFixture(async (root) => {
    await writeFile(join(root, "index.html"), "<!doctype html>", "utf8");
    await assert.rejects(assertProductionBundle(root), /missing assets\/\*\.js/);
  });
});

test("production boundary requires index.html at the artifact root", async () => {
  await withFixture(async (root) => {
    await mkdir(join(root, "assets"));
    await writeFile(join(root, "assets", "main.js"), "", "utf8");
    await assert.rejects(assertProductionBundle(root), /missing root index\.html/);
  });
});

test("production boundary accepts the minimum complete artifact shape", async () => {
  await withFixture(async (root) => {
    await mkdir(join(root, "assets"));
    await writeFile(join(root, "index.html"), "<!doctype html>", "utf8");
    await writeFile(join(root, "assets", "main.js"), "console.info('production fixture')", "utf8");
    assert.equal(await assertProductionBundle(root), 2);
  });
});
