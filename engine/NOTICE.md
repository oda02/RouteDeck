# Engine provenance and portable-assembly notice review

- Review date: 2026-09-03
- Artifact: official sing-box 1.13.21 Windows amd64 no-suffix release
- Local portable assembly status: **available**
- Public redistribution review: **incomplete**
- Legal conclusion: **none** — this is engineering evidence, not legal advice or a compliance claim

## Pinned binary chain

The engine lock pins the official release ZIP, `sing-box.exe`, `libcronet.dll`, and the license shipped in that ZIP. The exact release workflow checks out `lib/windows_amd64/libcronet.dll` from the pinned cronet-go revision, copies the sing-box `LICENSE`, and creates the Windows archive. It does not copy a Cronet/Chromium notice bundle or generate an SBOM in that archive.

The pinned chain is:

1. sing-box `628cb31ffa79cffffd34c2f9cde6cae044e4fc12`;
2. `.github/CRONET_GO_VERSION` selects cronet-go `ec9a39c5ba3b4a8d625ede04deaf3c9020afb916`;
3. that cronet-go tree selects SagerNet/naiveproxy `510717a833c95a17218efc550fe6cac02414cad5`;
4. `lib/windows_amd64/libcronet.dll` in the cronet-go tree is the same 9,528,832-byte DLL pinned by RouteDeck (`SHA-256 257f9661...d02823`).

## Material upstream provides

- The release ZIP contains exactly `sing-box.exe`, `libcronet.dll`, and the sing-box GPL-3.0-or-later license.
- The pinned cronet-go tree provides its GPL-3.0-or-later license, source, build/package tools, and the exact prebuilt DLL. Its package command copies the DLL to `lib/windows_amd64`; it does not copy notices.
- The pinned SagerNet/naiveproxy tree provides the NaiveProxy BSD-3-Clause license, Chromium's top-level BSD-3-Clause license, source files, 36 `README.chromium` files, and 38 files whose basename matches `LICENSE`, `COPYING`, or `NOTICE` (with optional extensions).
- Chromium's included `create_android_metadata_license.py` can derive dependency-reachable material for Android Cronet targets and generate `LICENSE.gn2bp`. In the pinned tree, no generated `LICENSE.gn2bp` or `MODULE_LICENSE_*` output is committed. The script's configured aggregate target is `//components/cronet/android:cronet_non_test_package`, not the Windows `//components/cronet:cronet` DLL built by cronet-go.
- The sing-box release metadata has 154 assets and no asset named as an SBOM, SPDX document, source bundle, license bundle, or notice bundle. The pinned sing-box tree has `go.mod` and `go.sum`, but no reviewed dependency notice inventory.

Counts above are reproducible observations from the non-truncated GitHub trees at the pinned commits; they do not establish which third-party units are linked into either binary and are not legal conclusions.

## Public redistribution work still open

The three texts under `engine/licenses/` are authentic and hash-pinned, but they are not demonstrated to be a complete notice set for the Windows Cronet DLL or the Go dependencies in `sing-box.exe`. The exact source repositories are identified below, but this review does not determine whether pointing to them satisfies any corresponding-source or written-offer requirement.

`scripts/assemble-portable.ps1` supports local self-contained test builds: it verifies the exact pinned engine/Xray files and copies the available licenses and this notice without making a legal-compliance claim. Before publishing a public redistribution, a later review still needs a dependency-filtered Windows Cronet notice bundle, a complete sing-box dependency notice inventory, and a source-compliance decision. The detailed evidence manifest remains marked `blocked` for that public-release purpose.

## Point-in-time malware scan

On 2026-09-01, the then-locked 1.13.19 ZIP was verified, extracted into a unique `%TEMP%` directory, verified again as a directory, and scanned with the installed Microsoft Defender command-line scanner. The hash-bound, path-sanitized historical report is committed at `engine/security/defender-scan-20260901T103906Z.json`; it records scanner `4.18.26070.9-0`, UTC timestamps, command shape, exit code `0`, and the captured `found no threats` output. No exclusions were added and neither binary was executed. `Get-MpComputerStatus` denied access, so the report explicitly marks engine/signature metadata unavailable rather than inferring it. That historical scan does not cover the newly pinned 1.13.21 archive.

This scan is point-in-time supporting evidence only. It is not proof that the binary is harmless, does not replace provenance/hash/runtime controls, and says nothing about license completeness.

## Official primary evidence

- [sing-box 1.13.21 release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.21)
- [sing-box exact Windows build workflow](https://github.com/SagerNet/sing-box/blob/628cb31ffa79cffffd34c2f9cde6cae044e4fc12/.github/workflows/build.yml#L627-L646)
- [sing-box exact source tree](https://github.com/SagerNet/sing-box/tree/628cb31ffa79cffffd34c2f9cde6cae044e4fc12)
- [cronet-go exact package code](https://github.com/SagerNet/cronet-go/blob/ec9a39c5ba3b4a8d625ede04deaf3c9020afb916/cmd/build-naive/cmd_package.go#L67-L79)
- [cronet-go exact prebuilt DLL](https://github.com/SagerNet/cronet-go/blob/ec9a39c5ba3b4a8d625ede04deaf3c9020afb916/lib/windows_amd64/libcronet.dll)
- [cronet-go exact source tree](https://github.com/SagerNet/cronet-go/tree/ec9a39c5ba3b4a8d625ede04deaf3c9020afb916)
- [SagerNet/naiveproxy exact source tree](https://github.com/SagerNet/naiveproxy/tree/510717a833c95a17218efc550fe6cac02414cad5)
- [Chromium Cronet Android license generator in that tree](https://github.com/SagerNet/naiveproxy/blob/510717a833c95a17218efc550fe6cac02414cad5/src/components/cronet/license/create_android_metadata_license.py#L20-L29)

The exact upstream and repository-copy digests are recorded in `engine/licenses/manifest.json`. The cronet-go raw file has no final newline; the repository text copy adds one LF and pins both forms explicitly.
