import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, readFileSync, readdirSync, realpathSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_NOTICE_BYTES = 1024 * 1024;
const NOTICE_NAME = /^(?:licen[cs]e|copying|notice|authors)(?:[-_.].*)?$/i;

export function containedFile(root, candidate) {
  let base;
  let target;
  try {
    base = realpathSync(root);
    target = realpathSync(candidate);
  } catch {
    throw new Error(`license file is missing: ${basename(candidate)}`);
  }
  const rel = relative(base, target);
  if (!rel || rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) {
    throw new Error(`license file escapes dependency root: ${basename(candidate)}`);
  }
  return target;
}

function readNotice(root, path) {
  const safe = containedFile(root, path);
  const bytes = readFileSync(safe);
  if (bytes.length === 0 || bytes.length > MAX_NOTICE_BYTES || bytes.includes(0)) {
    throw new Error(`invalid license text: ${basename(path)}`);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`license text is not UTF-8: ${basename(path)}`);
  }
  return { name: basename(path), text: text.replace(/\r\n/g, "\n").trimEnd() };
}

export function noticeFiles(root, declaredFile = null) {
  const names = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile() && NOTICE_NAME.test(entry.name))
    .map((entry) => entry.name);
  if (declaredFile !== null) {
    if (typeof declaredFile !== "string" || !declaredFile || isAbsolute(declaredFile)) {
      throw new Error("invalid declared license_file");
    }
    names.push(declaredFile);
  }
  return [...new Set(names)]
    .sort((a, b) => a.localeCompare(b, "en"))
    .map((name) => readNotice(root, join(root, name)));
}

export function requiredNoticeFiles(root, declaredFile, label) {
  const files = noticeFiles(root, declaredFile);
  if (files.length === 0) throw new Error(`missing license text: ${label}`);
  return files;
}

function platformMatches(entry) {
  const permits = (values, wanted) => {
    if (!Array.isArray(values) || values.length === 0) return true;
    if (values.includes(`!${wanted}`)) return false;
    const positives = values.filter((value) => typeof value === "string" && !value.startsWith("!"));
    return positives.length === 0 || positives.includes(wanted);
  };
  return permits(entry.os, "win32") && permits(entry.cpu, "x64");
}

function npmInventory() {
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8"));
  const missing = [];
  const entries = Object.entries(lock.packages ?? {})
    .filter(([key, entry]) =>
      key.startsWith("node_modules/") && entry.dev !== true && entry.devOptional !== true && platformMatches(entry))
    .flatMap(([key, entry]) => {
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      const root = join(ROOT, key);
      if (!existsSync(root)) {
        missing.push(`npm dependency is not installed: ${name}@${entry.version}`);
        return [];
      }
      const files = noticeFiles(root);
      if (files.length === 0) {
        missing.push(`missing npm license text: ${name}@${entry.version}`);
        return [];
      }
      return [{ ecosystem: "npm", name, version: entry.version, license: entry.license ?? null, files }];
    });
  if (missing.length) throw new Error(missing.join("\n"));
  return entries;
}

function cargoInventory() {
  const raw = execFileSync("cargo", [
    "metadata", "--locked", "--offline", "--filter-platform", "x86_64-pc-windows-msvc", "--format-version", "1",
  ], { cwd: join(ROOT, "src-tauri"), encoding: "utf8", windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  const metadata = JSON.parse(raw);
  const overrideRoot = join(ROOT, "licenses", "controller");
  const overrideData = JSON.parse(readFileSync(join(overrideRoot, "overrides.json"), "utf8"));
  const overrides = new Map(overrideData.packages.map((entry) => [`${entry.name}@${entry.version}`, entry]));
  const workspace = new Set(metadata.workspace_members);
  const missing = [];
  const entries = metadata.packages
    .filter((pkg) => !workspace.has(pkg.id) && typeof pkg.source === "string" && pkg.source.startsWith("registry+"))
    .flatMap((pkg) => {
      const root = dirname(pkg.manifest_path);
      const declared = pkg.license_file && relative(root, pkg.license_file);
      let files = noticeFiles(root, declared);
      let provenance = "crate-package";
      if (files.length === 0) {
        const override = overrides.get(`${pkg.name}@${pkg.version}`);
        if (override) {
          const manifest = readFileSync(join(root, "Cargo.toml"), "utf8");
          const repository = manifest.match(/^repository\s*=\s*"([^"]+)"/m)?.[1]?.replace(/\/$/, "");
          const vcs = JSON.parse(readFileSync(join(root, ".cargo_vcs_info.json"), "utf8"));
          if (repository !== override.repository.replace(/\/$/, "") || vcs.git?.sha1 !== override.commit) {
            throw new Error(`override identity mismatch: ${pkg.name}@${pkg.version}`);
          }
          const github = repository.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)$/i);
          if (!github || !Array.isArray(override.files) || override.files.length === 0) {
            throw new Error(`invalid override source: ${pkg.name}@${pkg.version}`);
          }
          const sourcePrefix = `https://raw.githubusercontent.com/${github[1]}/${github[2]}/${override.commit}/`;
          files = override.files.map((file) => {
            const trustedSource = override.kind === "canonicalLicense"
              ? override.license === pkg.license && file.sourceUrl === "https://www.mozilla.org/media/MPL/2.0/index.txt"
              : file.sourceUrl.startsWith(sourcePrefix);
            if (!trustedSource || !/^[a-f0-9]{64}$/.test(file.sha256)) {
              throw new Error(`invalid override source: ${pkg.name}@${pkg.version}`);
            }
            const loaded = readNotice(overrideRoot, join(overrideRoot, file.path));
            const digest = createHash("sha256").update(readFileSync(containedFile(overrideRoot, join(overrideRoot, file.path)))).digest("hex");
            if (digest !== file.sha256) throw new Error(`override hash mismatch: ${pkg.name}@${pkg.version}`);
            return { ...loaded, sourceUrl: file.sourceUrl, sha256: file.sha256 };
          });
          provenance = override.kind === "canonicalLicense" ? "reviewed-canonical-license" : "reviewed-upstream-commit";
          if (override.kind === "canonicalLicense") {
            const proof = readFileSync(containedFile(root, join(root, override.sourceHeaderFile)), "utf8");
            if (!proof.includes(override.sourceHeaderProof)) throw new Error(`missing source license proof: ${pkg.name}@${pkg.version}`);
          }
          overrides.delete(`${pkg.name}@${pkg.version}`);
        }
      }
      if (files.length === 0) {
        missing.push(`missing Cargo license text: ${pkg.name}@${pkg.version}`);
        return [];
      }
      const sourceArchives = [];
      const override = overrideData.packages.find((item) => item.name === pkg.name && item.version === pkg.version);
      if (override?.sourceArchive) {
        const cacheRoot = resolve(dirname(root), "..", "..", "cache");
        const archiveName = `${pkg.name}-${pkg.version}.crate`;
        const candidates = readdirSync(cacheRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory())
          .map((entry) => join(cacheRoot, entry.name, archiveName)).filter(existsSync);
        if (candidates.length !== 1) throw new Error(`source archive unavailable: ${pkg.name}@${pkg.version}`);
        const digest = createHash("sha256").update(readFileSync(candidates[0])).digest("hex");
        const lock = readFileSync(join(ROOT, "src-tauri", "Cargo.lock"), "utf8");
        const escaped = pkg.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const locked = lock.match(new RegExp(`\\[\\[package\\]\\]\\s*name = "${escaped}"\\s*version = "${pkg.version.replaceAll(".", "\\.")}".*?checksum = "([a-f0-9]{64})"`, "s"))?.[1];
        if (digest !== override.sourceArchive.sha256 || digest !== locked) throw new Error(`source archive checksum mismatch: ${pkg.name}@${pkg.version}`);
        sourceArchives.push({ name: archiveName, sha256: digest, path: candidates[0] });
      }
      return [{ ecosystem: "cargo", name: pkg.name, version: pkg.version, license: pkg.license ?? null, provenance, files, sourceArchives }];
    });
  if (missing.length) throw new Error(missing.join("\n"));
  if (overrides.size) throw new Error(`unused license overrides: ${[...overrides.keys()].join(", ")}`);
  return entries;
}

export function renderInventory(entries) {
  const sorted = [...entries].sort((a, b) =>
    a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  const inventory = sorted.map(({ ecosystem, name, version, license, provenance = "package", files, sourceArchives = [] }) => ({
    ecosystem, name, version, license, provenance,
    noticeFiles: files.map(({ text: _text, ...file }) => file),
    sourceArchives: sourceArchives.map(({ path: _path, ...archive }) => archive),
  }));
  const sections = sorted.map((entry) => {
    const heading = `${entry.name} ${entry.version} (${entry.ecosystem}; declared license: ${entry.license ?? "unspecified"})`;
    const texts = entry.files.map((file) => `--- ${file.name} ---\n${file.text}`).join("\n\n");
    return `${"=".repeat(heading.length)}\n${heading}\n${"=".repeat(heading.length)}\n\n${texts}`;
  });
  return {
    json: `${JSON.stringify({ scope: "RouteDeck controller dependencies; conservative build-time superset; excludes RouteDeck and external engines", dependencies: inventory }, null, 2)}\n`,
    text: `THIRD-PARTY NOTICES\n\nScope: RouteDeck controller dependencies. This is a conservative build-time superset and excludes RouteDeck itself and separately distributed engines.\n\n${sections.join("\n\n")}\n`,
  };
}

function main() {
  const output = resolve(ROOT, process.argv[2] ?? "artifacts/notices");
  const entries = [...cargoInventory(), ...npmInventory()];
  const rendered = renderInventory(entries);
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, "THIRD-PARTY-NOTICES.txt"), rendered.text, "utf8");
  writeFileSync(join(output, "third-party-inventory.json"), rendered.json, "utf8");
  for (const entry of entries) for (const archive of entry.sourceArchives ?? []) {
    mkdirSync(join(output, "sources"), { recursive: true });
    copyFileSync(archive.path, join(output, "sources", archive.name));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
