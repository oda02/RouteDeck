import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { createReadStream, readFileSync, writeFileSync, lstatSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const UPDATE_PUBLIC_KEY = '6c22a738e8c9770949944f1a434818ff31a8fe8b1d9d5a1047f6c12383da5491';
const LIMIT = 512 * 1024 * 1024;
const REQUIRED = ['routedeck.exe', 'routedeck-tun-helper.exe', 'routedeck-updater.exe', 'routedeck-build.json', 'engine/sing-box.exe', 'engine/libcronet.dll', 'xray/xray.exe', 'runtime-pins/sing-box.lock.json', 'runtime-pins/xray-core.lock.json'];
const TOP = [...REQUIRED.slice(0, 4), 'README.txt', 'THIRD-PARTY-NOTICES.txt', 'dependency-inventory.json', 'ENGINE-THIRD-PARTY-NOTICES.txt', 'SOURCE-CODE.txt', 'engine-distribution-inventory.json'];
const fail = () => { throw new Error('Update release validation failed'); };
const fields = (object, expected) => object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).sort().join(',') === [...expected].sort().join(',');
const stable = (version) => typeof version === 'string' && version.length <= 32 && /^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/.test(version);
const hash = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const size = (value) => Number.isSafeInteger(value) && value > 0 && value <= LIMIT;

function safePath(path) {
  return typeof path === 'string' && path.length <= 200 && path.split('/').every((part) => /^[A-Za-z0-9._-]+$/.test(part) && part !== '.' && part !== '..' && !part.endsWith('.') && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}

export function parseUpdateManifest(body, version) {
  if (body.length > 256 * 1024 || !stable(version)) fail();
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  // The publisher emits exactly these bytes. This also rejects duplicate keys,
  // a BOM and ambiguous alternate JSON encodings before any signing operation.
  if (!Buffer.from(JSON.stringify(manifest) + '\n').equals(body)) fail();
  if (!fields(manifest, ['schemaVersion', 'version', 'platform', 'archive', 'size', 'sha256', 'files']) || manifest.schemaVersion !== 1 || manifest.version !== version || manifest.platform !== 'windows-x64' || manifest.archive !== `RouteDeck-${version}-windows-x64.zip` || !size(manifest.size) || !hash(manifest.sha256) || !Array.isArray(manifest.files) || manifest.files.length < REQUIRED.length || manifest.files.length > 512) fail();
  const names = new Set(); let total = 0;
  for (const file of manifest.files) {
    if (!fields(file, ['path', 'size', 'sha256']) || !safePath(file.path) || (!TOP.includes(file.path) && !['engine/', 'xray/', 'runtime-pins/', 'licenses/', 'controller-sources/'].some((prefix) => file.path.startsWith(prefix))) || !size(file.size) || !hash(file.sha256) || names.has(file.path.toLowerCase())) fail();
    names.add(file.path.toLowerCase()); total += file.size;
  }
  if (total > 1024 * 1024 * 1024 || REQUIRED.some((path) => !names.has(path))) fail();
  for (const path of names) {
    const parts = path.split('/'); parts.pop();
    while (parts.length) { if (names.has(parts.join('/'))) fail(); parts.pop(); }
  }
  return manifest;
}

export function signUpdateManifest(body, privatePem, expectedHex = UPDATE_PUBLIC_KEY) {
  if (typeof privatePem !== 'string' || privatePem.length > 4096 || !/^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PRIVATE KEY-----\r?\n?$/.test(privatePem)) fail();
  const key = createPrivateKey({ key: privatePem, format: 'pem', type: 'pkcs8' });
  if (key.asymmetricKeyType !== 'ed25519') fail();
  const publicKey = createPublicKey(key);
  if (publicKey.export({ format: 'jwk' }).x !== Buffer.from(expectedHex, 'hex').toString('base64url')) fail();
  const signature = sign(null, body, key);
  if (signature.length !== 64 || !verify(null, body, publicKey, signature)) fail();
  return signature;
}

export function verifyUpdateManifest(body, signature, expectedHex = UPDATE_PUBLIC_KEY) {
  const key = createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(expectedHex, 'hex').toString('base64url') } });
  if (signature.length !== 64 || !verify(null, body, key, signature)) fail();
}

async function validateArtifact(manifestPath, archivePath, version) {
  const meta = lstatSync(manifestPath); if (!meta.isFile() || meta.isSymbolicLink() || meta.size > 256 * 1024) fail();
  const body = readFileSync(manifestPath); const manifest = parseUpdateManifest(body, version);
  const archive = lstatSync(archivePath);
  if (!archive.isFile() || archive.isSymbolicLink() || archive.size !== manifest.size || basename(archivePath) !== manifest.archive) fail();
  const digest = createHash('sha256'); for await (const chunk of createReadStream(archivePath)) digest.update(chunk);
  if (digest.digest('hex') !== manifest.sha256) fail();
  return body;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [mode, manifestPath, archivePath, version, ...extra] = process.argv.slice(2);
    if (!['validate', 'sign', 'verify'].includes(mode) || !manifestPath || !archivePath || extra.length) fail();
    const body = await validateArtifact(manifestPath, archivePath, version);
    const signaturePath = join(dirname(manifestPath), 'RouteDeck-update.sig');
    if (mode === 'sign') {
      // Key is supplied only to this trusted release step; never through argv,
      // a temporary file, build jobs or a logged value.
      const signature = signUpdateManifest(body, process.env.ROUTEDECK_UPDATE_SIGNING_KEY);
      writeFileSync(signaturePath, signature, { flag: 'wx' });
      verifyUpdateManifest(body, readFileSync(signaturePath));
    } else if (mode === 'verify') {
      const signatureMeta = lstatSync(signaturePath);
      if (!signatureMeta.isFile() || signatureMeta.isSymbolicLink() || signatureMeta.size !== 64) fail();
      verifyUpdateManifest(body, readFileSync(signaturePath));
    }
  } catch {
    // OpenSSL/parser errors can contain supplied material. Emit a fixed error.
    process.stderr.write('Update release validation or signing failed.\n'); process.exitCode = 1;
  }
}
