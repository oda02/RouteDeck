import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parseUpdateManifest, signUpdateManifest, verifyUpdateManifest, UPDATE_PUBLIC_KEY } from '../scripts/sign-update.mjs';

const fixture = generateKeyPairSync('ed25519');
const pem = fixture.privateKey.export({ format: 'pem', type: 'pkcs8' });
const publicHex = Buffer.from(fixture.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
const paths = ['routedeck.exe','routedeck-tun-helper.exe','routedeck-updater.exe','routedeck-build.json','engine/sing-box.exe','engine/libcronet.dll','xray/xray.exe','runtime-pins/sing-box.lock.json','runtime-pins/xray-core.lock.json'];
const descriptor = () => ({ schemaVersion: 1, version: '1.2.3', platform: 'windows-x64', archive: 'RouteDeck-1.2.3-windows-x64.zip', size: 123, sha256: 'a'.repeat(64), files: paths.map((path) => ({ path, size: 12, sha256: 'b'.repeat(64) })) });
const bytes = (value) => Buffer.from(JSON.stringify(value) + '\n');

test('Ed25519 signs exact descriptor bytes using an explicit fixture key and verifies pin', () => {
  const body = bytes(descriptor()); parseUpdateManifest(body, '1.2.3');
  const signature = signUpdateManifest(body, pem, publicHex);
  assert.equal(signature.length, 64); assert.equal(verify(null, body, fixture.publicKey, signature), true);
  verifyUpdateManifest(body, signature, publicHex);
  assert.throws(() => verifyUpdateManifest(Buffer.concat([body, Buffer.from(' ')]), signature, publicHex));
  assert.throws(() => verifyUpdateManifest(body, signature.subarray(1), publicHex));
  assert.throws(() => signUpdateManifest(body, pem));
  assert.throws(() => verifyUpdateManifest(body, signature));
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => signUpdateManifest(body, rsa.privateKey.export({ format: 'pem', type: 'pkcs8' }), publicHex));
});

test('descriptor schema, versions, complete bundle and hostile paths are closed', () => {
  for (const mutation of [
    (m) => m.extra = true, (m) => m.version = '1.2.3-beta.1', (m) => m.platform = 'linux-x64', (m) => m.archive = 'foreign.zip',
    (m) => m.files.pop(), (m) => m.files[0].extra = true, (m) => m.files[0].size = 0, (m) => m.size = 536870913,
    (m) => m.files[0].sha256 = 'B'.repeat(64), (m) => m.files.push({ ...m.files[0], path: 'ROUTEDECK.EXE' }),
    ...['../outside', 'engine/a:ads', 'engine/a\\b', 'engine/CON.txt', 'engine//a', 'engine/a.', 'engine'].map((path) => (m) => m.files.push({ path, size: 1, sha256: 'c'.repeat(64) })),
  ]) { const m = descriptor(); mutation(m); assert.throws(() => parseUpdateManifest(bytes(m), '1.2.3')); }
  const body = bytes(descriptor());
  assert.throws(() => parseUpdateManifest(body, '1.2.4'));
  assert.throws(() => parseUpdateManifest(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]), body]), '1.2.3'));
  assert.throws(() => parseUpdateManifest(Buffer.from(body.toString().replace('"schemaVersion":1', '"schemaVersion":0,"schemaVersion":1')), '1.2.3'));
  assert.throws(() => parseUpdateManifest(Buffer.alloc(262145), '1.2.3'));
});

test('production signing key matches runtime pin and never appears in PR build workflow', () => {
  const runtime = readFileSync(new URL('../src-tauri/src/portable_update.rs', import.meta.url), 'utf8');
  assert.match(runtime, new RegExp(`PUBLIC_KEY: &str = "${UPDATE_PUBLIC_KEY}"`));
  assert.equal(createPublicKey({ format:'jwk', key:{ kty:'OKP', crv:'Ed25519', x:Buffer.from(UPDATE_PUBLIC_KEY,'hex').toString('base64url') } }).asymmetricKeyType, 'ed25519');
  const build = readFileSync(new URL('../.github/workflows/build.yml', import.meta.url), 'utf8');
  const ci = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.doesNotMatch(build + ci, /ROUTEDECK_UPDATE_SIGNING_KEY|secrets:\s*inherit/);
  const release = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  assert.equal((release.match(/secrets\.ROUTEDECK_UPDATE_SIGNING_KEY/g) ?? []).length, 1);
  assert.match(release, /if: startsWith\(github.ref, 'refs\/tags\/v'\).*github.repository == 'oda02\/RouteDeck'/);
});
