import assert from "node:assert/strict";
import test from "node:test";
import { executableName, validExecutableName, appRuleMatchKey } from "../src/appRuleMatching.ts";
import { effectiveRoutingKey, validatedRouting } from "../src/tauriController.ts";
import { defaultTrafficRules, type AppRule } from "../src/model.ts";

const app: AppRule = { id: "app", name: "Client", path: "C:\\Apps\\v1\\Client.exe", route: "vpn" };
const routing = (apps: AppRule[]) => ({ defaultRoute: "direct" as const, tunStack: "gvisor" as const, naiveUdpOverTcp: false, trafficRules: defaultTrafficRules(), apps });

test("stable filenames are bounded Windows executable basenames", () => {
  for (const name of ["", ".exe", "client", "client.dll", "client.exe:stream", "a/b.exe", "C:\\a.exe", "a?.exe", "a*.exe", "CON.exe", "a\u0080.exe", " a.exe", `${"a".repeat(257)}.exe`, `${"Ж".repeat(129)}.exe`]) assert.equal(validExecutableName(name), false, name);
  for (const name of ["a.exe", "ChatGPT.EXE", "Client (beta)+[1]$^.exe", "Программа.exe"]) assert.equal(validExecutableName(name), true, name);
  assert.equal(executableName("C:/Apps/v2/Client.exe"), "Client.exe");
});

test("legacy and explicit path modes preserve old exact-path storage", () => {
  assert.deepEqual(validatedRouting(routing([app])).apps, [app]);
  assert.deepEqual(validatedRouting(routing([{ ...app, matchBy: "path" }])).apps, [app]);
  assert.equal(validatedRouting(routing([{ ...app, matchBy: "name" }])).apps[0].matchBy, "name");
  assert.throws(() => validatedRouting(routing([{ ...app, matchBy: "regex" } as unknown as AppRule])), { code: "invalid-routing" });
  assert.throws(() => validatedRouting(routing([{ ...app, matchBy: "name", path: "C:\\Apps\\a.exe:stream" }])), { code: "invalid-routing" });
});

test("stable duplicate identity ignores folders, separators and filename case", () => {
  const stable = { ...app, matchBy: "name" as const };
  assert.throws(() => validatedRouting(routing([stable, { ...stable, id: "other", path: "D:/v2/CLIENT.EXE" }])), { code: "invalid-routing" });
  assert.doesNotThrow(() => validatedRouting(routing([app, { ...stable, id: "stable" }])));
  assert.equal(appRuleMatchKey({ ...stable, path: "C:\\Apps\\ſ.exe" }), appRuleMatchKey({ ...stable, path: "D:\\Apps\\S.exe" }));
});

test("stable rules survive a version-folder change without runtime change; mode changes matter", () => {
  const stable = { ...app, matchBy: "name" as const };
  assert.equal(effectiveRoutingKey(routing([stable])), effectiveRoutingKey(routing([{ ...stable, path: "D:\\NewVersion\\CLIENT.EXE" }])));
  assert.notEqual(effectiveRoutingKey(routing([app])), effectiveRoutingKey(routing([stable])));
  assert.notEqual(effectiveRoutingKey(routing([app])), effectiveRoutingKey(routing([{ ...app, path: "D:\\NewVersion\\Client.exe" }])));
  assert.equal(effectiveRoutingKey(routing([{ ...app, route: "inherit" }])), effectiveRoutingKey(routing([{ ...stable, route: "inherit" }])));
});

test("effective stable rules never collapse different Go Unicode regex literals", () => {
  const key = (name: string) => effectiveRoutingKey(routing([{ ...app, matchBy: "name", path: `C:\\Apps\\${name}.exe` }]));
  assert.notEqual(key("ß"), key("SS"));
  assert.notEqual(key("ı"), key("I"));
  assert.notEqual(key("Программа"), key("Other"));
  assert.equal(key("CODEX"), key("codex"));
});
