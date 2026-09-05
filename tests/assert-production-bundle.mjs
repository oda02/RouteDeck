import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const forbiddenMarkers = [
  "Amsterdam Edge",
  "DEMO profile",
  "203.0.113.42",
  "createDevelopmentDemoController",
  "demoController",
  "__routeDeckFixture",
  "Fixture diagnostics",
];

async function productionFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? productionFiles(path) : [path];
  }));
  return nested.flat();
}

export async function assertProductionBundle(directory) {
  const root = resolve(directory);
  const files = await productionFiles(root);
  const artifacts = files.map((file) => relative(root, file).replaceAll("\\", "/"));

  if (artifacts.length === 0) {
    throw new Error("production bundle contains no artifacts");
  }
  if (!artifacts.includes("index.html")) {
    throw new Error("production bundle is missing root index.html");
  }
  if (!artifacts.some((artifact) => /^assets\/.+\.js$/.test(artifact))) {
    throw new Error("production bundle is missing assets/*.js");
  }

  for (const file of files) {
    const content = await readFile(file);
    const text = content.toString("utf8");
    for (const marker of forbiddenMarkers) {
      if (text.includes(marker)) {
        throw new Error(`production bundle contains forbidden development marker: ${marker}`);
      }
    }
  }
  return files.length;
}

const invokedAsScript = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  const count = await assertProductionBundle(fileURLToPath(new URL("../dist", import.meta.url)));
  console.log(`production bundle boundary verified (${count} files)`);
}
