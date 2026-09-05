import { spawn } from "node:child_process";
import net from "node:net";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const vite = fileURLToPath(new URL("../node_modules/vite/bin/vite.js", import.meta.url));
const browserTest = fileURLToPath(new URL("../tests/browser-ux.mjs", import.meta.url));
const host = "127.0.0.1";
const port = 1421;
const base = `http://${host}:${port}`;

async function requireFreePort() {
  await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.once("error", reject);
    probe.listen({ host, port, exclusive: true }, () => probe.close(resolve));
  });
}

async function waitForVite(child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Vite exited before readiness (${child.exitCode})`);
    try {
      const response = await fetch(base, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch { /* Retry only the owned loopback server until the deadline. */ }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error("Timed out waiting for the owned Vite server");
}

async function waitForExit(child, milliseconds) {
  if (child.exitCode !== null) return true;
  return new Promise((resolve) => {
    const timer = setTimeout(() => { child.off("exit", done); resolve(false); }, milliseconds);
    const done = () => { clearTimeout(timer); resolve(true); };
    child.once("exit", done);
  });
}

await requireFreePort();
const viteChild = spawn(process.execPath, [vite, "--host", host, "--port", String(port), "--strictPort"], {
  cwd: root,
  env: { ...process.env, VITE_ROUTEDECK_DEMO: "true" },
  stdio: ["ignore", "inherit", "inherit"],
  windowsHide: true,
});

try {
  await waitForVite(viteChild);
  const testChild = spawn(process.execPath, [browserTest], {
    cwd: root,
    env: { ...process.env, ROUTEDECK_UI_URL: base },
    stdio: "inherit",
    windowsHide: true,
  });
  const exitCode = await new Promise((resolve, reject) => {
    testChild.once("error", reject);
    testChild.once("exit", (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
  if (exitCode !== 0) process.exitCode = exitCode;
} finally {
  // This handle identifies the exact Node process spawned above; no port scan,
  // wildcard process name, or unrelated Vite instance is terminated.
  if (viteChild.exitCode === null) viteChild.kill();
  if (!(await waitForExit(viteChild, 5_000)) && viteChild.exitCode === null) viteChild.kill("SIGKILL");
  await waitForExit(viteChild, 2_000);
}
