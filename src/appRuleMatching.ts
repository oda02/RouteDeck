import type { AppRule } from "./model";

export function executableName(path: string): string {
  return path.replaceAll("/", "\\").split("\\").at(-1) ?? "";
}

// Windows basename only, not a path, glob, alternate data stream or regex.
export function validExecutableName(name: string): boolean {
  return new TextEncoder().encode(name).length <= 260
    && name.length > 4 && /\.exe$/i.test(name) && name === name.trim()
    && !/[\\/:<>"|?*\u0000-\u001f\u007f-\u009f]/.test(name)
    && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])\./i.test(name);
}

export function appRuleMatchKey(app: Pick<AppRule, "path" | "matchBy">): string {
  return app.matchBy === "name"
    ? `name:${executableName(app.path).toUpperCase().toLowerCase()}`
    : `path:${app.path.replaceAll("/", "\\").toLocaleLowerCase("en-US")}`;
}

// Case-insensitive stable names don't depend on the selected version's folder.
// Exact-path compilation preserves native path case, so the effective key does too.
export function effectiveAppRuleKey(app: AppRule): string {
  return app.matchBy === "name" ? appRuleMatchKey(app) : `path:${app.path}`;
}
