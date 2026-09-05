import { invoke, isTauri } from "@tauri-apps/api/core";

type InterfaceTheme = "dark" | "light";
let pending = Promise.resolve();
let revision = 0;

// Serialize native updates so a slow response cannot restore an older theme.
export function syncWindowTheme(theme: InterfaceTheme): void {
  if (!isTauri()) return;
  const current = ++revision;
  pending = pending.then(async () => {
    if (current !== revision) return;
    await invoke("set_interface_theme", { theme });
  }).catch(() => {
    // Cosmetic failure must not affect connection state or prevent later updates.
  });
}
