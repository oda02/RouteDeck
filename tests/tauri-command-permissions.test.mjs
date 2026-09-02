import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (relativePath) => readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8");

test("every registered renderer command is generated and allowed for the main window", () => {
  const library = read("src-tauri/src/lib.rs");
  const buildScript = read("src-tauri/build.rs");
  const capability = JSON.parse(read("src-tauri/capabilities/default.json"));

  const registered = new Set([...library.matchAll(/commands::([a-z_]+)/g)].map((match) => match[1]));
  const commandBlock = buildScript.match(/const COMMANDS:[\s\S]*?=\s*&\[([\s\S]*?)\];/)?.[1];
  assert.ok(commandBlock, "build.rs must declare the Tauri command manifest");
  const generated = new Set([...commandBlock.matchAll(/"([a-z_]+)"/g)].map((match) => match[1]));
  const allowed = new Set(capability.permissions
    .filter((permission) => permission.startsWith("allow-"))
    .map((permission) => permission.slice("allow-".length).replaceAll("-", "_")));

  assert.deepEqual([...generated].sort(), [...registered].sort(), "build.rs omitted a registered Tauri command");
  assert.deepEqual([...allowed].sort(), [...registered].sort(), "the main-window capability omitted a registered Tauri command");
  assert.ok(allowed.has("runtime_status"));
  assert.ok(allowed.has("confirmed_nodes"));
});
