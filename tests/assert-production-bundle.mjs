import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const forbiddenMarkers = [
  "Amsterdam Edge",
  "DEMO profile",
  "203.0.113.42",
  "createDevelopmentDemoController",
  "demoController",
];

async function productionFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? productionFiles(path) : [path];
  }));
  return nested.flat();
}

const files = await productionFiles(fileURLToPath(new URL("../dist", import.meta.url)));
for (const file of files) {
  const content = await readFile(file);
  const text = content.toString("utf8");
  for (const marker of forbiddenMarkers) {
    if (text.includes(marker)) {
      throw new Error(`production bundle contains forbidden development marker: ${marker}`);
    }
  }
}

console.log(`production bundle boundary verified (${files.length} files)`);
