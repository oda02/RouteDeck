# Portable engine distribution plan

This is the packaging contract for RouteDeck 0.1.1's public portable release. It records conservative source and notice handling; it does not make a blanket legal clearance or compliance claim.

## Pinned runtime scope

The release contains the exact bytes pinned by `engine/sing-box.lock.json` and `engine/xray-core.lock.json`: sing-box 1.13.21 at `628cb31ffa79cffffd34c2f9cde6cae044e4fc12`; cronet-go `ec9a39c5ba3b4a8d625ede04deaf3c9020afb916`; NaiveProxy `510717a833c95a17218efc550fe6cac02414cad5` with Chromium 150.0.7871.63; and Xray-core 26.3.27 at `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`.

The packaging collector never starts or loads these binaries. Runtime acquisition and hash verification are separate explicit release operations.

## Published source and notices

Run `node scripts/collect-engine-distribution.mjs <outputDir>`. The explicit packaging command acquires missing sources into `.cache/artifacts/engine-sources` and creates:

- `ENGINE-THIRD-PARTY-NOTICES.txt` and `SOURCE-CODE.txt`;
- exact sing-box and Xray source archives;
- a cronet-go source-only archive excluding prebuilt `.a`, `.lib`, `.dll`, `.so`, `.dylib`, `.exe`, and `.node` files;
- the complete exact NaiveProxy tree, including its vendored Chromium source, plus a conservative aggregation of every LICENSE, NOTICE, COPYING, and README.chromium file in that tree;
- an omissions manifest with path, Git blob SHA-1, size, and reason for every excluded cronet-go prebuilt binary;
- checksum-verified source ZIPs, notice texts, and build-info provenance for every linked Go dependency embedded in the two reviewed executables;
- `engine-distribution-inventory.json`, binding every file to its size and SHA-256 and binding the set to both runtime-lock byte hashes.

Publish all source assets beside the portable ZIP on the same GitHub release. `SOURCE-CODE.txt` repeats that location for recipients of a detached ZIP.

sing-box and cronet-go identify as GPL-3.0-or-later. NaiveProxy and Chromium use BSD-style licensing and require preserved notices. Xray-core uses MPL-2.0 and its exact source tree is included. Ordinary unmodified general-purpose compiler or build-tool source is not added merely because it built an upstream binary.

## Verification

`scripts/test-collect-engine-distribution.mjs` is deterministic and has no network access. It checks schema, sizes, hashes, the source set, and refusal to overwrite a completed distribution. `scripts/portable-inputs.ps1` verifies the inventory again during portable packaging.
