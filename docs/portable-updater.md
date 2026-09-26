# Portable updater implementation

Implementation on 26 September 2026. The chosen release path remains portable.
A complete signed bootstrap release must be installed manually once after this
change is merged; the existing unsigned 0.1.2 cannot update itself using new code.
No release has been published or installed during implementation.

## User flow

A stable release check starts downloading in the background. Downloading does not
stop, restart, or reconfigure the VPN. Settings shows bounded progress and the
actual prepared version. After explicit VPN disconnection, **Обновить и
перезапустить** starts installation once. User data stays in Windows app data.
Installation never reconnects a VPN automatically. Automatic checks/downloads can
be disabled; manual check remains available. Errors offer retry and the fixed
GitHub Releases page.

## Trust and replacement

- The baked-in Ed25519 public key verifies exact bounded JSON bytes before parsing.
  It authorizes a stable version, windows-x64, fixed archive name/size/SHA256 and
  every file size/SHA256. The detached manifest/signature live outside the ZIP.
  The entire compatible GUI/helper/updater/sing-box/Cronet/Xray bundle is required.
- Sources are fixed RouteDeck GitHub release URLs. HTTPS redirects accept only
  this release prefix or GitHub's release-assets CDN, at most three redirects.
  Metadata <=256KiB, archive <=512MiB, <=512 files, expanded files <=1GiB.
  Absolute paths, traversal, ADS, reserved Windows names, duplicate case variants,
  symlinks, junctions, hardlinks, encrypted entries and unexpected files are refused.
- Signed manifests for both current and next releases are cached and verified
  during background staging. There is no network dependency during replacement.
  Current installed files must match their immutable current signed release.
  Additional/modified user files cause refusal; the updater never deletes them.
- Staging uses OS KnownFolder LocalAppData plus the fixed app identifier. New
  directories have a protected current-user/SYSTEM/admin ACL. Installed root,
  child directories and files reject untrusted write/delete/ACL permissions.
  This is not a defense against compromised same-user or administrator accounts.
- The GUI embeds the exact trusted current updater digest. Its copy outside the
  application directory remains locked before launching. IPC accepts no URLs,
  paths, executables or commands. The updater accepts only parent PID/creation and
  bounded random stage/launch tokens, verifies actual parent PID and signed image,
  then acknowledges its own exact PID/creation with the fresh token.
- An atomic controller gate serializes against Connect/Stop, requires no active
  process, connection intent or unresolved recovery, and prevents new work.
  Failure before authenticated updater readiness cancels only that child and
  restores the gate and event stream; an explicit later Connect remains possible.
- The updater waits the exact authenticated GUI process (60s maximum), never kills
  VPN processes by name and never requests elevation or installs a service.
- A private sibling incoming folder receives copies from already verified locked
  source handles into create-new files. Synced incomplete markers are written to
  old/new folders before replacement. Root directory handles remain fixed during
  rename; Windows descendant handles close only for the move, followed by full
  revalidation before continuing. Old files remain in a unique previous folder.
  No automatic rollback is performed. If power loss or a copy/rename fails, no
  mixed bundle is launched. Any folder with an incomplete marker refuses startup
  before constructing the controller; manual repair uses a new complete ZIP folder.

## Signing key

Public raw Ed25519 key:
`6c22a738e8c9770949944f1a434818ff31a8fe8b1d9d5a1047f6c12383da5491`.
SPKI SHA256 fingerprint:
`271d42e8567cc4dc3d13b00498a987e3dfd4191b344f91d3cce2ddf82b132cd7`.
The dedicated PKCS8 PEM private key was generated in process memory and sent only
through stdin to repository Actions secret `ROUTEDECK_UPDATE_SIGNING_KEY`. It was
never placed in argv, stdout, source, a local disk artifact or plaintext backup.
The tag-only publishing step receives it; PR/reusable build jobs do not.
Loss requires key rotation through a manually trusted bootstrap release. Windows
Authenticode and SmartScreen publisher reputation remain separate future work.

## Dependency review

No JavaScript package changed; package-lock.json remains byte-identical. Rust
new direct dependencies are pinned ed25519-dalek=2.2.0, zip=8.2.0 (default features
false, only deflate-flate2), and existing flate2=1.1.9 explicitly pinned to its
pure Rust backend. Cargo.lock records exact transitive versions/checksums.
[Dalek official source](https://github.com/dalek-cryptography/curve25519-dalek),
[ZIP official source](https://github.com/zip-rs/zip2), and the exact published
Cargo manifests/source were reviewed before build. Strict verification is used;
no key generation, network, executable download or runtime execution is performed
by the new libraries. ZIP encryption/native codecs/default features are disabled.
The only new active build script selects curve target/rustc support and invokes
rustc-version introspection; the derive macro emits Rust target-feature wrappers.
Other dependencies reuse previously locked hashing/compression/serde components.
Registry source archive SHA256 was checked locally against Cargo.lock for every
new lock entry, including optional/target-only entries:

| New locked crate | Registry SHA256 | Official repository | Lifecycle |
| --- | --- | --- | --- |
| base64ct 1.8.3 | `2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06` | https://github.com/RustCrypto/formats | No build.rs |
| const-oid 0.9.6 | `c2459377285ad874054d797f3ccebf984978aa39129f6eafde5cdc8315b612f8` | https://github.com/RustCrypto/formats/tree/master/const-oid | No build.rs |
| curve25519-dalek 4.1.3 | `97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be` | https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek | build.rs reviewed (rustc version/target selection only) |
| curve25519-dalek-derive 0.1.1 | `f46882e17999c6cc590af592290432be3bce0428cb0d5f8b6715e4dc7b383eb3` | https://github.com/dalek-cryptography/curve25519-dalek | No build.rs |
| der 0.7.10 | `e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb` | https://github.com/RustCrypto/formats/tree/master/der | No build.rs |
| ed25519 2.2.3 | `115531babc129696a58c64a4fef0a8bf9e9698629fb97e9e40767d235cfbcd53` | https://github.com/RustCrypto/signatures/tree/master/ed25519 | No build.rs |
| ed25519-dalek 2.2.0 | `70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9` | https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek | No build.rs |
| fiat-crypto 0.2.9 | `28dea519a9695b9977216879a3ebfddf92f1c08c05d984f8996aecd6ecdc811d` | https://github.com/mit-plv/fiat-crypto | No build.rs |
| pkcs8 0.10.2 | `f950b2377845cebe5cf8b5165cb3cc1a5e0fa5cfa3e1f7f55707d8fd82e0a7b7` | https://github.com/RustCrypto/formats/tree/master/pkcs8 | No build.rs |
| rand_core 0.6.4 | `ec0be4795e2f6a28069bec0b5ff3e2ac9bafc99e6a9a7dc3547996c5c816922c` | https://github.com/rust-random/rand | No build.rs |
| signature 2.2.0 | `77549399552de45a898a580c1b41d445bf730df867cc44e6c0233bbc4b8329de` | https://github.com/RustCrypto/traits/tree/master/signature | No build.rs |
| spki 0.7.3 | `d91ed6c858b01f942cd56b37a94b3e0a1798290327d1236e4d9cf4eaca44d29d` | https://github.com/RustCrypto/formats/tree/master/spki | No build.rs |
| typed-path 0.12.3 | `8e28f89b80c87b8fb0cf04ab448d5dd0dd0ade2f8891bae878de66a75a28600e` | https://github.com/chipsenkbeil/typed-path | No build.rs |
| zip 8.2.0 | `b680f2a0cd479b4cff6e1233c483fdead418106eae419dc60200ae9850f6d004` | https://github.com/zip-rs/zip2.git | No build.rs |

## Validation and limits

Combined validation with the reviewed UI and stable-app rules: 386 Rust tests
passed (two existing integration tests ignored), 144 Node tests, 89 synthetic
browser scenarios, production frontend build and offline Rust all-target checks.
Controller packaging, publisher and portable-input hostile fixtures passed.
Actual runtime assembly awaits the CI-reviewed build/runtime artifacts; no live
installed-bundle replacement is included in these local results.

- Native fake/temp fixtures cover signatures, limits, unsafe ZIP names, full bundle
  integrity, hardlinks/reparse rejection, ownership, populated Windows handle
  rename, interrupted transaction steps, exact-child abort, retry after failure,
  lifecycle gate preservation and Connect/recovery refusal.
- Frontend tests cover strict progress/error IPC, background stage/progress,
  disposal and explicit failed-install retry. Browser synthetic IPC scenarios
  cover progress, VPN-active disabled installation, disconnection and retry.
- Production frontend build and offline Rust all-target compilation are required.
  Release/signing fixtures use synthetic bytes and separate disposable keys.
- No live tunnel, running GUI replacement, native restart, Windows proxy/routes/
  DNS/adapters/services or real privileged host test was performed. Real portable
  N->N+1 launch qualification remains an isolated Windows VM release smoke test.
- Read-only/public-writable folders and altered portable bundles fall back
  to manual repair in a new folder. UNC/device paths are rejected before filesystem
  access; drive-letter paths can also be mapped remote drives, whose update/rename
  behavior has not been qualified. Previous and staging folders are retained as
  evidence; automatic garbage collection and automatic rollback are outside MVP.
  This disk usage is not bounded: each successful update retains one full previous
  bundle, and failed staging can retain partial downloads. After verifying that
  the new version launches and works, close RouteDeck and manually remove only
  its old `.RouteDeck-previous-<token>`/`.RouteDeck-incoming-<token>` sibling folders
  and obsolete token folders under its app-data `updates` directory. Preserve any
  folder needed for an interrupted-update repair; do not delete the current app
  folder. Automatic cleanup requires a separately reviewed ownership policy.
