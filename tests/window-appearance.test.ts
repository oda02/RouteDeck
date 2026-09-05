import assert from "node:assert/strict";
import test from "node:test";
import { syncWindowTheme } from "../src/windowAppearance.ts";

test("native appearance skips browser mode, serializes changes and recovers after failure", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalTauri = Object.getOwnPropertyDescriptor(globalThis, "isTauri");
  const calls: unknown[] = [];
  let release!: () => void;
  let attempts = 0;
  const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    __TAURI_INTERNALS__: { invoke: async (command: string, args: unknown) => {
      calls.push({ command, args });
      if (++attempts === 1) await new Promise<void>((resolve) => { release = resolve; });
      if (attempts === 2) throw new Error("fixture appearance failure");
    } },
  } });
  const native = (value: boolean) => Object.defineProperty(globalThis, "isTauri", { configurable: true, value });
  try {
    native(false); syncWindowTheme("light"); await tick(); assert.equal(calls.length, 0);
    native(true); syncWindowTheme("dark"); await tick();
    syncWindowTheme("light"); syncWindowTheme("dark"); syncWindowTheme("light");
    await tick(); assert.equal(calls.length, 1, "native calls overlapped");
    release(); await tick();
    assert.deepEqual(calls, [
      { command: "set_interface_theme", args: { theme: "dark" } },
      { command: "set_interface_theme", args: { theme: "light" } },
    ]);
    syncWindowTheme("dark"); await tick(); assert.equal(calls.length, 3);
  } finally {
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
    if (originalTauri) Object.defineProperty(globalThis, "isTauri", originalTauri);
    else Reflect.deleteProperty(globalThis, "isTauri");
  }
});
