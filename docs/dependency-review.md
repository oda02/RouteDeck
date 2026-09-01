# Rust dependency review

- Review date: 2026-09-02
- Scope: unprivileged local-only runtime and explicit HTTPS subscription transports
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

- Provenance: widely used HTTP client from the `seanmonstar/reqwest` project. Its exact resolved graph was already reviewed and committed for traffic proof, and its sources are available in the local cache.
- Purpose: two bounded HTTPS 204 traffic proofs plus direct HTTPS subscription retrieval. The fetch boundary manually validates redirects and passes a separately resolved, policy-checked address set to reqwest while retaining the hostname for TLS verification.
- Surface reduction: default features are disabled; native TLS/OpenSSL, cookie storage, automatic redirects, compression decoders, and system/environment proxy discovery are not enabled. Only the blocking API and Rustls TLS backend are selected. Subscription requests additionally set no proxy, no Referer, no retry, HTTPS-only, fixed DNS overrides, and bounded timeouts.
- Build/lifecycle: no download hook or executable is fetched at build/start. The selected Rustls provider includes `aws-lc-rs 1.16.3` / `aws-lc-sys 0.40.0`; its reviewed build script uses locked `cc 1.2.61`, `cmake 0.1.58`, `dunce 1.0.5`, and `fs_extra 1.3.0` to compile the vendored AWS-LC C/assembly sources locally. It does not invoke a package manager or network downloader.
- Transitives: Hyper, rustls, AWS-LC, webpki/platform verifier, Tokio support, URL/HTTP primitives, and compression-free response plumbing. No dependency or lockfile change was needed for subscription fetching. Identity bodies, redirects, status, address count, and DNS/connect/read/overall time are bounded by RouteDeck; non-identity encodings fail closed. `cargo tree --locked --offline -i openssl-sys` confirms that native OpenSSL is absent.
- Advisory review: no RustSec advisory was present in the locally available advisory/security checks for this exact pin. Re-run the repository security job when the lock changes.
- crates.io checksum: `219c5811de6525e5416c7d5d53bb656d3afdbc6c5af816e0802bcfa42dbdc1c3`.

### `rustls = 0.23.39` and `rustls-platform-verifier = 0.7.0`

- Provenance: the Rustls project and its official platform-verifier integration. Both exact versions and checksums were already present in the committed reqwest traffic-proof graph; making them direct dependencies adds no new crate or build script.
- Purpose: after the loopback HTTP proxy acknowledges a numeric pinned-IP CONNECT, RouteDeck performs TLS itself with the original URL hostname as SNI and certificate identity. The platform verifier applies current Windows trust policy; verification is never disabled and blocks certificates that do not chain to a Windows-trusted root. A proxy-controlled root already trusted by Windows remains trusted by definition and can enable TLS interception; this transport makes no certificate-pinning claim.
- Surface reduction: Rustls default features are disabled and only `aws_lc_rs`, `std`, and TLS 1.2/1.3 support are selected. ALPN offers only HTTP/1.1. There is no client certificate, custom root, caller-supplied trust-bypass verifier, TLS-to-proxy mode, proxy authentication, or certificate-ignore switch.
- The custom HTTP/1.1 code is product-owned and bounded: numeric CONNECT authority only, fixed headers, no Referer/cookies/compression, 16 KiB/64-header response limit, 8 KiB line/trailer limits, unique framing, at most 4,096 chunks and 64 KiB of chunk framing, a 10 MiB decoded body, and one absolute deadline re-applied before every socket/TLS read and write.
- crates.io checksums: Rustls `7c2c118cb077cca2822033836dfb1b975355dfb784b5e8da48f7b6c5db74e60e`; platform verifier `26d1e2536ce4f35f4846aa13bff16bd0ff40157cdb14cc056c7b14ba41233ba0`.

### `windows-sys = 0.61.2` (Windows target only)

- Provenance: official Microsoft `windows-rs` projection crate, already present transitively.
- Purpose: narrow Win32 calls for protected session files/directories, local-volume and opened-file identity/owner/DACL/reparse checks, bounded `GetAddrInfoExW` DNS resolution, read-only WinINet per-connection proxy inspection, active-RAS rejection, restricted child pipes/handle inheritance, suspended process creation, a kill-on-close Job Object, and exact-PID ownership checks for the three loopback listeners.
- Enabled namespaces: Foundation, Security/Authorization, Storage FileSystem, NetworkManagement/IpHelper/Rras, Networking/WinSock/WinInet, JobObjects, Memory, Pipes, SystemInformation, and Threading only. The subscription path calls `InternetQueryOptionW` and `RasEnumConnectionsW`; it never calls a setter or registry API.
- Build/lifecycle: generated FFI bindings; no runtime, installer, network access, or build download.
- crates.io checksum: `ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc`.

## Existing dependencies used by the runtime

- `sha2 = 0.10.9`: hashes already pinned engine files from open handles.
- `serde` / `serde_json`: parse the embedded, reviewed engine lock and serialize typed command/event DTOs.
- `tauri`: typed command/state/event wiring only; an `AppManifest` generates permissions for the nine named commands, and the main capability grants only those commands plus event listen/unlisten. `preview_import_url` accepts one bounded secret URL and the closed enum `direct | current_loopback_system_proxy`; the renderer cannot supply a proxy endpoint, request headers, executable/configuration paths, arguments, environment, or health URL.

## Deliberately not added

- No shell/process helper crate: the Windows boundary calls `CreateProcessW` directly with a closed internal action enum, fixed arguments, explicit application/current-directory paths, an allow-listed environment with no `PATH`, and an explicit inherited-handle list.
- No async runtime direct dependency: serialized operations run behind the controller boundary; Tauri owns command dispatch.
- No temporary-file/ACL convenience crate: session files use a fixed application-data root, random private directory, restrictive Windows DACL, atomic rename, and best-effort deletion.
- No native OpenSSL backend, updater, archive extractor, engine downloader, telemetry, third-party DNS client, compression decoder, cookie jar, HTTP parser crate, or arbitrary request configuration. Windows DNS and read-only WinINet/RAS inspection use the reviewed `windows-sys` binding; tests use fake resolver/proxy/TLS boundaries and never contact the internet.

## Residual risks

Each check/run first verifies the package engine directory and hashes the exact executable and companion DLL through non-write/non-delete-shared handles. It then copies only those two held files into a fresh random per-session execution directory below the application LocalAppData root. The destination must be on a local fixed NTFS/ReFS volume with persistent ACL support. Files and directory receive an explicit owner and a protected DACL: the current user has only read/execute/delete, SYSTEM has full control, and inherited/package permissions are absent. RouteDeck hashes the copied files, records opened-handle volume/file IDs and exact security descriptors, rejects reparse points and every additional name, and performs an effective late-create denial probe.

The native launch boundary completes pipes, environment, handle allow-list and Job setup first. Its immediately adjacent preflight then repeats exact enumeration, hashes, handle type/reparse/link/file-ID/owner/DACL checks, and the late-create denial probe before `CreateProcessW(CREATE_SUSPENDED)`. The verified destination handles survive process creation and the child lifetime; the process is assigned to a kill-on-close Job before resume. All pre-resume failure paths terminate the suspended process. The secret configuration separately retains its protected opened handle and exact content/file-ID/security baseline.

This closes the release-blocking cross-user and accidental late-DLL planting gap without relying on portable-directory permissions. It deliberately does **not** claim that a portable desktop process can resist malicious native code already running as the same Windows user: the owner can change its own DACL, inject/debug the process, or race namespace operations after taking equivalent rights. Administrators, SYSTEM, kernel compromise, and pre-existing privileged handles are likewise outside this boundary. Those conditions require OS isolation or an elevated broker and are not solved by more path hashing. Windows still launches by a fixed verified path because `CreateProcessW` has no supported launch-by-file-handle API.

Cleanup is fail-closed and non-recursive: only the two exact sealed filenames are removed. A foreign/reparse/unknown entry is preserved and the non-empty session root causes `RecoveryRequired` on the next startup. Hostile second-user creation, ACL tamper, late-DLL attempts, unsupported filesystem, crash preservation, and handle-inheritance behavior remain isolated Windows-VM release tests; live-engine execution remains forbidden until those gates and the independent security review pass.

Session construction reopens the atomically renamed config with non-reparse/non-write-sharing flags, hashes the bytes from that protected handle, and compares them to the exact generated bytes before recording file identity. Session construction failure deletes only the fresh random directory created by that same operation. Startup recovery deliberately does not infer ownership from a directory name or expected filenames: if any previous session entry exists, RouteDeck preserves it, starts the UI in typed `RecoveryRequired` state, and blocks Connect and confirmed-import replacement. The explicit `retry_session_recovery` command only rechecks that the user-reviewed directory is empty; it never deletes files. Any future automated deletion requires a durable product marker plus owner/DACL and opened-file identity revalidation.

The explicit System Proxy fetch takes one read-only snapshot and then uses the copied loopback endpoint for that request. A concurrent settings change cannot alter the already selected numeric endpoint, but another same-user process can replace a loopback service and the user's or machine's trust store can contain a proxy-controlled root. The CONNECT authority contains only a pinned public IP, while a tunnel proxy can still observe that destination IP and the plaintext TLS SNI hostname. TLS hides the URL path/query, HTTP `Host` and other headers, and body from an ordinary tunnel proxy, but a proxy with a Windows-trusted MITM root can decrypt them; hostname secrecy would require ECH and is not claimed. Resisting same-user socket takeover or trusted-root compromise is outside a portable unprivileged process boundary.

## Update rule

Any version change requires a fresh review of the official repository and crates.io checksum, lockfile diff, newly introduced transitive packages, build scripts, advisories, and full locked offline test suite. Floating constraints and unreviewed convenience crates remain prohibited by `AGENTS.md`.
