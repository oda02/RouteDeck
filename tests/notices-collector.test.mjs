import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { containedFile, noticeFiles, renderInventory, requiredNoticeFiles } from "../scripts/collect-controller-notices.mjs";

test("notice paths cannot escape a dependency root", () => {
  const fixture = mkdtempSync(join(tmpdir(), "routedeck-notices-"));
  const dependency = join(fixture, "dependency");
  mkdirSync(dependency);
  const outside = join(fixture, "LICENSE");
  writeFileSync(outside, "outside");
  assert.throws(() => containedFile(dependency, outside), /escapes dependency root/);
});

test("a dependency without recognized notice text fails closed", () => {
  const fixture = mkdtempSync(join(tmpdir(), "routedeck-notices-"));
  writeFileSync(join(fixture, "package.json"), "{}");
  assert.throws(() => requiredNoticeFiles(fixture, null, "fixture@1.0.0"), /fixture@1.0.0/);
});

test("malformed UTF-8 notice text fails closed", () => {
  const fixture = mkdtempSync(join(tmpdir(), "routedeck-notices-"));
  writeFileSync(join(fixture, "LICENSE"), Buffer.from([0xc3, 0x28]));
  assert.throws(() => noticeFiles(fixture), /not UTF-8/);
});

test("rendered inventory contains no source paths", () => {
  const rendered = renderInventory([{ ecosystem: "npm", name: "fixture", version: "1.0.0", license: "MIT", files: [{ name: "LICENSE", text: "terms" }] }]);
  assert.match(rendered.text, /fixture 1\.0\.0/);
  assert.doesNotMatch(rendered.text + rendered.json, /[A-Z]:\\|file:\/\//i);
});
