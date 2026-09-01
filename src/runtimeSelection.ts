export type ControllerRuntimeKind = "demo" | "tauri" | "unavailable";

export interface RuntimeSelectionInput {
  explicitDemo: boolean;
  isDevelopment: boolean;
  tauriIpcAvailable: boolean;
}

/**
 * Demo data is an explicit development-only choice. A release build can never
 * select the synthetic controller, even if an environment value is injected.
 */
export function selectControllerRuntime(input: RuntimeSelectionInput): ControllerRuntimeKind {
  if (input.isDevelopment && input.explicitDemo) return "demo";
  return input.tauriIpcAvailable ? "tauri" : "unavailable";
}

export function hasTauriIpc(globalValue: unknown): boolean {
  if (typeof globalValue !== "object" || globalValue === null) return false;
  return "__TAURI_INTERNALS__" in globalValue;
}
