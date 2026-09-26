// Synthetic browser preview only: no native app, host settings or real processes.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const root = fileURLToPath(new URL("../", import.meta.url));
const controllerPath = fileURLToPath(new URL("../src/controller.ts", import.meta.url)).replaceAll("\\", "/");
const fixture = await readFile(new URL("../tests/fixtures/ui-runtime.mjs", import.meta.url), "utf8");
const server = await createServer({
  root,
  server: { host: "127.0.0.1", port: 1423, strictPort: true },
  plugins: [{
    name: "synthetic-app-picker-preview", enforce: "pre",
    load(id) {
      if (id.replaceAll("\\", "/") !== controllerPath) return;
      return fixture + '\nfixture.applicationCount = 80; fixture.applicationsDelay = 1200;';
    },
  }],
});
await server.listen();
server.printUrls();
const close = async () => { await server.close(); process.exit(0); };
process.on("SIGINT", close);
process.on("SIGTERM", close);
