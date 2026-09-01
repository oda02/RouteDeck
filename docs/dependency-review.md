# Rust dependency review

- Review date: 2026-09-01
- Scope: unprivileged local-only sing-box runtime
- Policy: exact direct pins, committed Cargo lock, no native OpenSSL, no build/start download hook

## Typed core dependency baseline

The typed import/config core previously reviewed the following exact direct set. This material remains authoritative and is extended, not replaced, by the runtime review below.

| Crate | Exact version | crates.io checksum | Official upstream / ownership | Purpose and lifecycle review |
| --- | --- | --- | --- | --- |
| `base64` | 0.22.1 | `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6` | `rust-base64/base64`, rust-base64 organization | Strict one-pass standard/base64url subscription-list decoding. Pure Rust; no network, native binary, or install lifecycle hook. |
| `percent-encoding` | 2.3.2 | `9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220` | `servo/rust-url`, Servo project | Exactly-once URI component decoding. Pure Rust; no network/native binary/install hook. |
| `serde` | 1.0.229 | `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` | `serde-rs/serde`, Serde project | Closed-model serialization. The derive proc-macro is compile-time Rust code only; no network/native payload. |
| `serde_json` | 1.0.151 | `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` | `serde-rs/json`, Serde project | Bounded JSON input, embedded lock parsing, and deterministic configuration. Its build script performs local compiler/cfg detection only. |
| `sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | `RustCrypto/hashes`, RustCrypto organization | Stable identifiers and pinned artifact SHA-256 verification. Pure Rust; no network/native payload/install hook. |
| `url` | 2.5.8 | `ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed` | `servo/rust-url`, Servo project | Standards-based authority/host/port parsing and URL sanitization. |
| `serde-saphyr` | 1.2.0 | `3afb591f9cdb6223c88ba39269aff895620c7f0716dc42b705b5733d5c7c0823` | `bourumir-wyngs/serde-saphyr`, crates.io owner | Strict Clash `proxies`-only deserialization with `default-features = false, features = ["deserialize"]`; no includes/filesystem/robotics features. |

The reviewed YAML graph is `serde-saphyr 1.2.0` → `granit-parser 1.2.0`, `annotate-snippets 0.12.16`, `encoding_rs_io 0.1.8`, `num-traits 0.2.19`, `smallvec 1.15.1`, with leaf additions `anstyle 1.0.14`, `unicode-width 0.2.2`, `encoding_rs 0.8.35`, and `arraydeque 0.5.1`. The parser backend forbids unsafe code; `arraydeque` and `anstyle` retain their previously documented localized unsafe review points. `tauri 2.11.5` and `tauri-build 2.6.3` remain exact pre-existing direct dependencies.

## Added direct dependencies

### `getrandom = 0.3.4`

- Provenance: established RustCrypto-adjacent ecosystem crate maintained in the `rust-random/getrandom` repository and published on crates.io.
- Purpose: operating-system CSPRNG bytes for per-session IDs and health-listener credentials. It replaces unsafe timestamps/counters and is already present transitively in the reviewed lock graph.
- Surface: tiny platform abstraction; no network, parser, shell, or filesystem API. On Windows it uses the OS random source.
- Build/lifecycle: Rust build script selects supported targets; Cargo has no npm-style install lifecycle. No artifact download.
- Advisory review: no RustSec advisory was present in the locally available advisory/security checks for this pinned release. Re-run the repository security job when the lock changes.
- crates.io checksum: `899def5c37c4fd7b2664648c28120ecec138e4d395b459e5ca34f9cce2dd77fd`.

### `reqwest = 0.13.4` with `default-features = false`, `blocking`, `rustls`

- Provenance: widely used HTTP client from the `seanmonstar/reqwest` project. Its sources were already available in the local cache; this change adds the exact resolved graph to the committed lockfile.
- Purpose: one bounded HTTPS 204 proof through the authenticated, loopback-only `health-in` HTTP proxy. The runtime never offers a direct fallback client.
- Surface reduction: default features are disabled; native TLS/OpenSSL and system-proxy discovery are not enabled. Only the blocking API and Rustls TLS backend are selected.
- Build/lifecycle: no download hook or executable is fetched at build/start. The selected Rustls provider includes `aws-lc-rs 1.16.3` / `aws-lc-sys 0.40.0`; its reviewed build script uses locked `cc 1.2.61`, `cmake 0.1.58`, `dunce 1.0.5`, and `fs_extra 1.3.0` to compile the vendored AWS-LC C/assembly sources locally. It does not invoke a package manager or network downloader.
- Transitives: Hyper, rustls, AWS-LC, webpki/platform verifier, Tokio support, URL/HTTP primitives, and compression-free response plumbing. Bodies, redirects, status, and total time are bounded by RouteDeck. `cargo tree --locked --offline -i openssl-sys` confirms that native OpenSSL is absent.
- Advisory review: no RustSec advisory was present in the locally available advisory/security checks for this exact pin. Re-run the repository security job when the lock changes.
- crates.io checksum: `219c5811de6525e5416c7d5d53bb656d3afdbc6c5af816e0802bcfa42dbdc1c3`.

### `windows-sys = 0.61.2` (Windows target only)

- Provenance: official Microsoft `windows-rs` projection crate, already present transitively.
- Purpose: narrow Win32 calls for protected session directories, reparse/file flags, a kill-on-close Job Object, and exact-PID ownership checks for the three loopback listeners.
- Enabled namespaces: Foundation, Security/Authorization, Storage FileSystem, NetworkManagement/IpHelper, Networking/WinSock, JobObjects, Memory, and Threading only.
- Build/lifecycle: generated FFI bindings; no runtime, installer, network access, or build download.
- crates.io checksum: `ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc`.

## Existing dependencies used by the runtime

- `sha2 = 0.10.9`: hashes already pinned engine files from open handles.
- `serde` / `serde_json`: parse the embedded, reviewed engine lock and serialize typed command/event DTOs.
- `tauri`: typed command/state/event wiring only; the renderer cannot supply an executable, configuration path, arguments, environment, or health URL.

## Deliberately not added

- No shell/process helper crate: `std::process::Command` is constrained to fixed arguments and a verified app-owned binary.
- No async runtime direct dependency: serialized operations run behind the controller boundary; Tauri owns command dispatch.
- No temporary-file/ACL convenience crate: session files use a fixed application-data root, random private directory, restrictive Windows DACL, atomic rename, and best-effort deletion.
- No native OpenSSL backend, updater, archive extractor, engine downloader, telemetry, DNS client, or arbitrary URL configuration.

## Residual risks

Holding engine and DLL handles without write/delete sharing materially narrows verify-to-launch replacement, and the runtime re-verifies immediately before each process creation. Windows process creation still names the fixed executable path; a malicious process running as the same user is not a strong isolation boundary and remains a documented TOCTOU residual until packaging supplies a package-private ACL plus file-identity revalidation/handle-based launch acceptable to independent Windows security review.

The standard-library process launcher starts the child before RouteDeck can assign it to the configured Job Object. RouteDeck fails closed if assignment fails and holds verified artifact/config handles, but the pre-assignment execution window remains a release-blocking hardening item for hostile same-user scenarios. A native suspended `CreateProcess` → assign Job → resume path requires independent Windows security review before the local runtime is called fully hardened.

Session construction failure deletes only the fresh random directory created by that same operation. Startup recovery deliberately does not infer ownership from a directory name or expected filenames: if any previous session entry exists, RouteDeck preserves it, starts the UI in typed `RecoveryRequired` state, and blocks Connect. The explicit `retry_session_recovery` command only rechecks that the user-reviewed directory is empty; it never deletes files. Any future automated deletion requires a durable product marker plus owner/DACL and opened-file identity revalidation.

## Update rule

Any version change requires a fresh review of the official repository and crates.io checksum, lockfile diff, newly introduced transitive packages, build scripts, advisories, and full locked offline test suite. Floating constraints and unreviewed convenience crates remain prohibited by `AGENTS.md`.
