import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVersion, versionFiles, saveVersions } from '../scripts/release-version.mjs';

function fixture() {
  return {
    'package.json': '{"version":"0.1.0"}',
    'package-lock.json': '{"version":"0.1.0","packages":{"":{"version":"0.1.0"},"dependency":{"version":"9.9.9"}}}',
    'src-tauri/tauri.conf.json': '{"version":"0.1.0"}',
    'src-tauri/Cargo.toml': '[package]\nname = "routedeck"\nversion = "0.1.0"\n[dependencies]\nfixture = "=9.9.9"\n',
    'src-tauri/Cargo.lock': '[[package]]\nname = "fixture"\nversion = "9.9.9"\n[[package]]\nname = "routedeck"\nversion = "0.1.0"\n',
  };
}
test('release versions are bounded canonical tags and prereleases are explicit', () => {
  assert.deepEqual(parseVersion('1.2.3'), { version: '1.2.3', tag: 'v1.2.3', prerelease: false });
  assert.equal(parseVersion('1.2.3-rc.2').prerelease, true);
  for (const invalid of ['v1.2.3', '01.2.3', '1.2', '1.2.3-beta.0', '1.2.3\n', '1.2.3+metadata', '1.2.3;cmd', undefined]) assert.throws(() => parseVersion(invalid));
});
test('all five files move together without resolving or changing dependencies', () => {
  const files = versionFiles(fixture(), '0.2.0-beta.1');
  assert.equal(versionFiles(files).version, '0.2.0-beta.1');
  assert.equal(JSON.parse(files['package-lock.json']).packages.dependency.version, '9.9.9');
  assert.match(files['src-tauri/Cargo.toml'], /fixture = "=9\.9\.9"/);
  assert.match(files['src-tauri/Cargo.lock'], /name = "fixture"\nversion = "9\.9\.9"/);
});
test('mismatches and missing root packages fail validation', () => {
  const files = fixture();
  files['package.json'] = '{"version":"0.2.0"}';
  assert.throws(() => versionFiles(files), /disagree/);
  files['src-tauri/Cargo.lock'] = '';
  assert.throws(() => versionFiles(files, '0.3.0'));
});
test('failed version writes restore originals, including a partially written destination', async () => {
  const original = fixture();
  const disk = { ...original };
  let count = 0;
  await assert.rejects(saveVersions(original, versionFiles(original, '0.2.0'), async (name, value) => {
    disk[name] = value;
    if (++count === 3) throw new Error('disk failure');
  }), /original files restored/);
  assert.deepEqual(disk, original);
});
