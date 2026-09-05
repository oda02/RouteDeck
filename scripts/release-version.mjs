import { readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export function parseVersion(value) {
  if (typeof value !== 'string' || value !== value.trim() || value.length > 64 || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.([1-9]\d*))?$/.test(value)) {
    throw new Error('Use X.Y.Z or X.Y.Z-alpha.N / beta.N / rc.N without leading zeroes');
  }
  return { version: value, tag: `v${value}`, prerelease: value.includes('-') };
}

export async function saveVersions(original, updated, write) {
  const attempted = [];
  try {
    for (const name of Object.keys(updated)) {
      attempted.push(name);
      await write(name, updated[name]);
    }
  } catch (error) {
    const failed = [];
    for (const name of attempted.reverse()) {
      try { await write(name, original[name]); } catch { failed.push(name); }
    }
    if (failed.length) throw new Error(`Version write failed; restore these files from Git before continuing: ${failed.join(', ')}`);
    throw new Error(`Version write failed; original files restored: ${error.message}`);
  }
}

export function versionFiles(files, next) {
  const pkg = JSON.parse(files['package.json']);
  const npmLock = JSON.parse(files['package-lock.json']);
  const tauri = JSON.parse(files['src-tauri/tauri.conf.json']);
  const cargoVersion = files['src-tauri/Cargo.toml'].match(/\[package\][\s\S]*?^version = "([^"]+)"/m)?.[1];
  const rustLock = files['src-tauri/Cargo.lock'].match(/\[\[package\]\]\r?\nname = "routedeck"\r?\nversion = "([^"]+)"/);
  const versions = [pkg.version, npmLock.version, npmLock.packages?.['']?.version, tauri.version, cargoVersion, rustLock?.[1]];
  for (const version of versions) parseVersion(version);
  if (next === undefined) {
    if (versions.some(v => v !== versions[0])) throw new Error('Application versions disagree across npm, Cargo and Tauri');
    return parseVersion(versions[0]);
  }
  parseVersion(next);
  pkg.version = npmLock.version = npmLock.packages[''].version = tauri.version = next;
  return {
    'package.json': JSON.stringify(pkg, null, 2) + '\n',
    'package-lock.json': JSON.stringify(npmLock, null, 2) + '\n',
    'src-tauri/tauri.conf.json': JSON.stringify(tauri, null, 2) + '\n',
    'src-tauri/Cargo.toml': files['src-tauri/Cargo.toml'].replace(/(\[package\][\s\S]*?^version = ")[^"]+(")/m, `$1${next}$2`),
    'src-tauri/Cargo.lock': files['src-tauri/Cargo.lock'].replace(rustLock[0], rustLock[0].replace(`version = "${rustLock[1]}"`, `version = "${next}"`)),
  };
}

async function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const names = ['package.json', 'package-lock.json', 'src-tauri/tauri.conf.json', 'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock'];
  const files = Object.fromEntries(await Promise.all(names.map(async name => [name, await readFile(resolve(root, name), 'utf8')])));
  const [command = 'check', argument] = process.argv.slice(2);
  if (command === 'set') {
    const updated = versionFiles(files, parseVersion(argument).version);
    // Validate every input before the first write; dependencies are never resolved.
    await saveVersions(files, updated, (name, contents) => writeFile(resolve(root, name), contents));
    console.log(`Version set to ${argument}. Commit all five version files before tagging.`);
  } else if (command === 'check') {
    const version = versionFiles(files);
    if (argument !== undefined && argument !== version.tag) throw new Error(`Tag must exactly match ${version.tag}`);
    console.log(JSON.stringify(version));
  } else throw new Error('Usage: node scripts/release-version.mjs check [vX.Y.Z] | set X.Y.Z');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
