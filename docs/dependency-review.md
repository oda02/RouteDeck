# Rust dependency review for the typed core

- Review date: 2026-09-01
- Scope: direct dependencies added for canonical node modelling, bounded subscription parsing, deterministic JSON generation, stable non-secret identifiers, and redaction
- Decision: accepted at the exact versions below

All six crates were already present at these exact versions in the committed Tauri dependency graph and local Cargo cache. Promoting them to direct dependencies added no new package version and required no network access. `Cargo.lock` remains authoritative; verification uses `--locked --offline`.

| Crate | Exact version | crates.io checksum | Official upstream / ownership | Purpose and lifecycle review |
| --- | --- | --- | --- | --- |
| `base64` | 0.22.1 | `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6` | [rust-base64/base64](https://github.com/marshallpierce/rust-base64), maintained by the rust-base64 organization | Strict one-pass standard/base64url subscription-list decoding. Pure Rust; no network, native binary, or install lifecycle hook. |
| `percent-encoding` | 2.3.2 | `9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220` | [servo/rust-url](https://github.com/servo/rust-url), Servo project | Explicit, exactly-once URI component decoding. Pure Rust; no network/native binary/install hook. |
| `serde` | 1.0.229 | `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` | [serde-rs/serde](https://github.com/serde-rs/serde), Serde project led by David Tolnay | Serialization of closed RoutePolicy enums. The reviewed derive proc-macro is compile-time Rust code only; no network/native payload. |
| `serde_json` | 1.0.151 | `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` | [serde-rs/json](https://github.com/serde-rs/json), Serde project | Bounded JSON input and deterministic generated configuration. Its build script performs local compiler/cfg capability detection only; it performs no network download or binary installation. |
| `sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | [RustCrypto/hashes](https://github.com/RustCrypto/hashes), RustCrypto organization | Stable identifier hashing over normalized, non-secret node identity. Pure Rust implementation with CPU feature selection; no network/native payload/install hook. It is not used for password storage or artifact verification. |
| `url` | 2.5.8 | `ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed` | [servo/rust-url](https://github.com/servo/rust-url), Servo project | Standards-based authority/host/port parsing and URL sanitization. Pure Rust dependency family; no network/native binary/install hook. |

`tauri = 2.11.5` and `tauri-build = 2.6.3` were already direct, exactly pinned project dependencies and were not changed by this review.

No crate in this change downloads or executes sing-box, WinTUN, an installer, or any other binary. No package lifecycle action mutates Windows networking, services, registry, processes, or user proxy state.

## Update rule

Any version change requires a new review of the official repository and crates.io checksum, lockfile diff, newly introduced transitive packages, build scripts, advisories, and the full locked offline test suite. Floating constraints and unreviewed convenience crates are prohibited by `AGENTS.md`.
