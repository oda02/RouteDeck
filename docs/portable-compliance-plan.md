# Portable engine compliance evidence plan

Status: **public redistribution review remains blocked**. This does not block
the hash-verified local portable folder used for development and testing.

This document is an engineering evidence plan, not legal advice and not a
claim that redistributing the pinned engine is compliant. It records what is
known from primary upstream sources, what is still unproved, and the exact
fail-closed process required before `engine/licenses/manifest.json` may be
marked `ready`.

## Scope and immutable inputs

The review is limited to the artifact pinned by `engine/sing-box.lock.json`:

- sing-box `1.13.21`, source commit
  `628cb31ffa79cffffd34c2f9cde6cae044e4fc12`;
- official Windows amd64 archive SHA-256
  `a03291793d3a3c6e266447a58140657ac099ff278abf3b8ff678932356a62ced`;
- `sing-box.exe` SHA-256
  `ccb2fad603c89efcbc14358ab40b2c7000a5bb4e3bffa170d5c355cda90757ba`;
- `libcronet.dll` SHA-256
  `257f966119ffca91d7a2ce110a4b668b865d88bf2ed5339fd06a5644b0d02823`;
- cronet-go source commit
  `ec9a39c5ba3b4a8d625ede04deaf3c9020afb916`;
- SagerNet/naiveproxy source commit
  `510717a833c95a17218efc550fe6cac02414cad5`.

The naiveproxy tree's pinned `CHROMIUM_VERSION` is `150.0.7871.63`. That value
identifies the upstream Chromium baseline, but it does not replace the exact
SagerNet source commit as evidence for the DLL actually shipped.

Changing any artifact hash, source commit, build target, build tag, toolchain,
or source replacement invalidates the resulting inventory. The process must
restart from immutable inputs; it must never silently reuse a notice bundle
from another sing-box or Chromium version.

## Evidence already established

The following are point-in-time source facts, not a completeness conclusion:

1. The sing-box release workflow builds `./cmd/sing-box` for Windows with
   `CGO_ENABLED=0`, reads build tags from
   `release/DEFAULT_BUILD_TAGS_WINDOWS`, and obtains `libcronet.dll` from the
   exact cronet-go revision selected by `.github/CRONET_GO_VERSION`.
2. The workflow archives `sing-box.exe`, `libcronet.dll`, and the sing-box
   `LICENSE`; it does not archive a Go module inventory, an SBOM, a Windows
   Cronet third-party notice bundle, or corresponding source.
3. cronet-go's pinned Windows build path uses a GN output directory for
   Windows x64 and builds the `cronet` Ninja target from the pinned
   naiveproxy submodule. Its GN arguments are source-controlled in
   `cmd/build-naive/cmd_build.go`.
4. Upstream Chromium provides a generic licensing tool that can derive
   third-party metadata from a configured GN output directory and GN target.
   The exact reduced SagerNet tree does **not** contain `src/tools/licenses`;
   it contains only the Cronet Android-specific generator discussed below.
   A moving or separately fetched copy of Chromium's generic tool therefore
   cannot be treated as evidence for the pinned DLL without an exact upstream
   baseline and source-delta review.
5. `go.mod` is a module graph input. It is not evidence of the exact set of
   packages compiled for one GOOS/GOARCH/build-tag combination. Conversely, a
   directory-wide scan of every module named by `go.mod` would be overbroad
   and still would not prove the linked closure.
6. Go embeds build information in Go binaries in a format readable without
   executing the inspected binary. That information can identify the Go
   version, module dependencies, replacements, and build settings present in
   `sing-box.exe`.

Primary evidence links are listed at the end of this document.

## Exact unresolved blockers

These are release blockers, not optional cleanup.

### P0-1: Go toolchain and linked-module notice closure

The exact Go patch toolchain used for the release is not pinned by the
workflow: the Windows job requests `^1.25.4`, which is a version range. The
release archive does not include the Go license or a reviewed inventory of the
modules and packages linked into `sing-box.exe`.

Required evidence:

- the exact toolchain version and build settings read from the pinned binary;
- the exact Windows build tags and linker flags as bytes from the pinned
  sing-box source commit;
- a target-specific compiled package/module closure derived with that exact
  toolchain and compared to binary build information;
- the exact Go toolchain/standard-library license from that toolchain tag;
- license, notice, copying, attribution, and required-text files for every
  linked module, including replacement modules;
- a human-reviewed disposition for modules that expose no license text or
  whose applicable terms cannot be determined mechanically.

Neither `go.mod` alone nor the module list embedded in the binary alone is a
sufficient replacement for this comparison.

### P0-2: Windows Cronet/Chromium target notice closure

The three texts currently pinned under `engine/licenses/` do not demonstrate
the third-party notice set of the exact Windows `//components/cronet:cronet`
DLL. The Android Cronet license generator targets a different GN graph and
must not be reused as Windows evidence.

Required evidence:

- a recursive source checkout matching both pinned cronet-go and naiveproxy
  commits, with the submodule relationship verified;
- a GN output directory created from the exact arguments in the pinned
  cronet-go build code for Windows amd64;
- the exact dependency graph of `//components/cronet:cronet`, including data
  and generated inputs relevant to distribution;
- an official Chromium commit corresponding to `150.0.7871.63`, plus a
  machine-reviewed mapping between that full tree and the reduced SagerNet
  commit used to build the DLL;
- a reviewed, hash-pinned Windows-target license extractor whose logic and
  support files are tied to that exact Chromium baseline and whose inputs are
  the exact SagerNet GN closure; the generic extractor is not present in the
  reduced source tree and must not be borrowed from `main`;
- a clean metadata scan with every warning, missing `README.chromium`, absent
  license file, `Required Text`, `COPYING`, and `NOTICE` disposition reviewed;
- a conservative cross-check between the GN closure, licensing-tool output,
  and files actually compiled into the hash-pinned DLL.

The source tree is a deliberately reduced SagerNet tree. Its small number of
license-like files is not evidence that all of them are required, or that no
additional text/source is required.

### P0-3: Applicable GPL text and additional upstream notice

The release's 808-byte sing-box `LICENSE` identifies GPL-3.0-or-later and adds
an upstream naming/association condition. It is not the full GPL version 3
license text. The same is true of the short cronet-go repository license
notice currently pinned by RouteDeck.

Required evidence:

- the authoritative, exact applicable GPL license text included in the
  portable notice bundle;
- preservation of each upstream notice and its additional wording;
- legal review of the additional condition and of the combined distribution;
- a decision about which component notices apply to `sing-box.exe`, the
  separately shipped DLL, and the bundle as a whole.

RouteDeck must not infer that one repository-level SPDX identifier is a
complete distribution notice.

### P0-4: Corresponding source and build-material review

Exact repository URLs are useful provenance, but no reviewed conclusion has
been made about corresponding-source delivery, a source offer, or the build
materials needed for the exact binaries.

Required evidence:

- immutable source archives and hashes for sing-box, every linked Go module,
  the exact Go toolchain source, cronet-go, and its recursive naiveproxy tree;
- all replacements, patches, generated-source inputs, build scripts, build
  tags, linker flags, GN arguments, submodule mappings, and relevant tool
  versions;
- a rebuild or equivalence record that explains any difference from the
  official binaries without substituting newly built binaries into the
  pinned release;
- a reviewed distribution method for source/source offer and durable source
  availability.

Only a qualified legal reviewer can decide whether the evidence and chosen
distribution method satisfy the applicable obligations. Until that decision
is recorded, assembly stays blocked.

### P1 evidence-quality risks

- License discovery based only on filename patterns can miss required text
  referenced from metadata or embedded in source headers.
- Case folding, line-ending normalization, symlinks, submodules, nested Go
  modules, and `replace` directives can cause a notice file to be attributed
  to the wrong source unit.
- Chromium licensing-tool warnings must be fatal to the RouteDeck gate until
  individually reviewed; a generated file with warnings is not automatically
  complete.
- URLs to moving branches such as `main` are not evidence. Every source URL in
  the final manifest must resolve to a commit, tag tied to a verified commit,
  or a content-addressed module artifact.
- A release rebuild may select a different Go patch version from the workflow
  range. Binary build information is authoritative for the already-pinned
  executable; a local rebuild is a comparison, not a substitute.
- The notice generator itself, its configuration, and its output need hashes
  and review. Hand-copied notice text is not reproducible provenance.

## Proposed isolated acquisition and verification pipeline

This pipeline belongs in a dedicated, networked compliance job. It must not
run during a frontend build, dependency install, normal application startup,
or unit test. It reads the release binaries but never executes them.

### 1. Acquire and verify sources

1. Read pins only from `engine/sing-box.lock.json`; reject caller-supplied
   alternate repositories, refs, destinations, or executables.
2. Fetch the exact sing-box and cronet-go commits and the recursive
   naiveproxy submodule into a newly created isolated workspace.
3. Verify commit object IDs, submodule object IDs, and clean working trees.
4. Record the raw SHA-256 and size of every build-control input, including
   `go.mod`, `go.sum`, `release/DEFAULT_BUILD_TAGS_WINDOWS`, `release/LDFLAGS`,
   `.github/CRONET_GO_VERSION`, cronet-go's build/package code, `.gitmodules`,
   and naiveproxy's `CHROMIUM_VERSION`.
5. Reject submodule URLs or replacement sources not covered by the reviewed
   allow-list. Do not run repository hooks or downloaded executables.

The acquisition job should preserve content-addressed source archives after
the inventory is approved. A later offline analysis stage should consume only
those verified archives.

### 2. Establish Go binary identity without execution

1. Re-verify the archive and `sing-box.exe` against the lock.
2. Use a small, reviewed analyzer built from Go's standard
   `debug/buildinfo` package, or another reviewed parser of the same format,
   to read `sing-box.exe`. Do not start the engine and do not load the PE as a
   DLL.
3. Emit canonical JSON containing the exact Go version, main module,
   dependency path/version/sum, replacement chain, and all build settings.
4. Compare GOOS, GOARCH, CGO status, VCS revision, VCS modified status, tags,
   and other recorded settings with the pinned source and official workflow.
   Any missing, unexpected, or contradictory value blocks release.

The analyzer source, compiler version, executable hash, and JSON schema must
be pinned. Parser failure must not fall back to `go.mod`.

### 3. Reproduce the Windows Go package closure

1. Use exactly the Go version reported by the binary with
   `GOTOOLCHAIN=local`, `GOWORK=off`, `GOOS=windows`, `GOARCH=amd64`,
   `CGO_ENABLED=0`, `-mod=readonly`, and the exact source-controlled Windows
   tags. Do not use `latest`, an updater, or an unrecorded workspace file.
2. Run `go list -deps -json` for `./cmd/sing-box` and retain package-to-module
   attribution, standard-library packages, ignored files, embed inputs,
   module sums, and replacement information.
3. Compare the selected modules with the binary build-information inventory.
   Extra or missing modules, sums, replacements, or a dirty main module are
   fatal until explained and reviewed.
4. Acquire every selected module at the exact version, verify `Sum` and
   `GoModSum` against the authenticated module data, and create a stable source
   archive hash. Local replacements must resolve inside the pinned source set.
5. For every selected package, scan its directory and parent directories up
   to its module root for license/notice metadata. Also scan the module root
   for conventional license, copying, notice, authorship, patent, and required
   attribution files. Record all candidates; do not choose one solely by
   filename precedence.
6. Have a reviewer classify the applicable license expression and required
   material for each module. Missing/ambiguous licenses remain blockers.
7. Add the exact Go toolchain license and the selected standard-library source
   archive to the same reviewed inventory.

This stage must emit both a package-level closure and a de-duplicated
module-level notice inventory so that reviewers can trace every bundled text
back to compiled code.

### 4. Derive the Windows Cronet notice set

1. Verify naiveproxy `CHROMIUM_VERSION` is exactly `150.0.7871.63`, then use
   the SagerNet commit as the build source of record.
2. Resolve `150.0.7871.63` to an immutable commit in Chromium's official
   repository, acquire that exact full source tree, and record a deterministic
   file-level mapping/delta to the reduced SagerNet source. Missing source or
   unexplained SagerNet changes block release.
3. Recreate `out/cronet-win-x64` with the exact GN arguments assembled by the
   pinned cronet-go `cmd/build-naive/cmd_build.go`. Record the final `args.gn`,
   GN version, Ninja version, Python version, environment allow-list, and all
   generated-input hashes.
4. Ask GN for the recursive dependency and source closure of
   `//components/cronet:cronet`; retain machine-readable output as evidence.
5. Verify that the generic Chromium licensing tool is absent from the pinned
   reduced tree. Inspect the generic tool and support modules only from the
   exact official Chromium commit identified in step 2. Create or adapt a
   minimal Windows-target extractor in the isolated compliance workspace,
   review its source and tests, and pin its hash. It must consume the exact
   SagerNet GN output and `//components/cronet:cronet`; it must not substitute
   an upstream-only GN graph or the Android target.
6. Run the reviewed extractor's metadata scan. Treat non-zero exit, warnings,
   missing files, unparsable metadata, and empty dependency results as fatal.
7. Compare every third-party directory in the GN closure with the licensing
   tool's selected metadata. Review `License File`, `Required Text`,
   `COPYING`, `NOTICE`, shipped/not-shipped markers, generated code, and
   special cases. An unmatched shipped dependency blocks release.
8. Rebuild in the isolated environment only as a provenance comparison. Hash
   the result and explain reproducibly why it does or does not match the
   official `libcronet.dll`; never overwrite the release artifact pinned by
   RouteDeck.

The generated Chromium output is evidence, not self-certifying legal advice.
It still requires review and must be tied to the exact GN graph and source
commit in the final manifest.

### 5. Generate a reviewable, deterministic bundle

The acquisition pipeline should generate, but not automatically approve:

- `compiled-packages.json`: Go package/module closure and binary comparison;
- `cronet-gn-closure.json`: exact target dependencies and source ownership;
- `source-manifest.json`: source archives, commits, sums, sizes, and hashes;
- `notice-candidates.json`: one record per candidate text;
- `THIRD-PARTY-NOTICES.txt`: deterministic reviewed concatenation;
- `licenses.spdx.json`: SPDX output where supported, with manual review
  annotations kept outside generated upstream fields;
- `review.json`: reviewer identity, timestamp, tool hashes, resolved findings,
  and an explicit accept/reject decision for each candidate.

Each notice record needs at least component/module name, version or commit,
source repository, source-relative path, byte size, SHA-256, unmodified or
normalized status, linked-by evidence, proposed SPDX expression, required-text
status, and review disposition. Normalization must preserve the original hash
and record the transformation.

Generated files must be reproducible byte-for-byte from the verified inputs.
The review step must reject duplicate component identities with differing
texts, missing source archives, unpinned links, unknown licenses, and orphaned
GN or Go dependencies.

## Gate to change portable assembly to `ready`

All conditions below are mandatory:

1. The release archive and both runtime binaries still match the engine lock.
2. The exact Go toolchain, Windows settings, tags, package closure, module
   sources, Go license, and reviewed module notice set are hash-pinned.
3. The exact Windows Cronet GN closure has a clean target-filtered notice set
   and no unresolved metadata/source findings.
4. The complete applicable GPL text and every upstream notice/additional term
   selected by review are included and hash-pinned.
5. A reviewed corresponding-source/source-offer plan is documented and its
   source artifacts are durable and hash-pinned.
6. A qualified reviewer records an explicit redistribution decision. The
   machine manifest must not synthesize this decision from scanner success.
7. The public release workflow is updated in the same reviewed change to
   validate the complete approved manifest and exact redistributed file set.
8. Negative tests prove that a status-only flip, missing/extra/tampered text,
   changed source pin, unreviewed component, toolchain mismatch, incomplete
   source set, or stale generated bundle fails before writing a target.
9. The gate passes under Windows PowerShell 5.1 and PowerShell 7 with identical
   semantic results.

Until every condition is met, `portableAssemblyStatus` must remain `blocked`
and `legalComplianceClaim` must remain `false`; a locally assembled test folder
must not be presented as an approved public redistribution.

## Primary upstream evidence

- [sing-box exact Windows build workflow](https://github.com/SagerNet/sing-box/blob/628cb31ffa79cffffd34c2f9cde6cae044e4fc12/.github/workflows/build.yml#L556-L648)
- [sing-box exact go.mod](https://github.com/SagerNet/sing-box/blob/628cb31ffa79cffffd34c2f9cde6cae044e4fc12/go.mod)
- [sing-box exact license notice](https://github.com/SagerNet/sing-box/blob/628cb31ffa79cffffd34c2f9cde6cae044e4fc12/LICENSE)
- [cronet-go exact Windows build code](https://github.com/SagerNet/cronet-go/blob/ec9a39c5ba3b4a8d625ede04deaf3c9020afb916/cmd/build-naive/cmd_build.go)
- [cronet-go exact source tree and naiveproxy submodule](https://github.com/SagerNet/cronet-go/tree/ec9a39c5ba3b4a8d625ede04deaf3c9020afb916)
- [naiveproxy exact source tree](https://github.com/SagerNet/naiveproxy/tree/510717a833c95a17218efc550fe6cac02414cad5)
- [naiveproxy pinned Chromium version](https://github.com/SagerNet/naiveproxy/blob/510717a833c95a17218efc550fe6cac02414cad5/CHROMIUM_VERSION)
- [exact reduced naiveproxy `src/tools` tree (generic licensing tool absent)](https://github.com/SagerNet/naiveproxy/tree/510717a833c95a17218efc550fe6cac02414cad5/src/tools)
- [exact Android-only Cronet license generator](https://github.com/SagerNet/naiveproxy/blob/510717a833c95a17218efc550fe6cac02414cad5/src/components/cronet/license/create_android_metadata_license.py)
- [Chromium upstream generic licensing tool](https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/tools/licenses/licenses.py)
- [Chromium primary documentation for third-party metadata](https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/docs/adding_to_third_party.md)
- [Go module reference](https://go.dev/ref/mod)
- [Go debug/buildinfo package](https://pkg.go.dev/debug/buildinfo)
- [Go source license](https://cs.opensource.google/go/go/+/master:LICENSE)

The moving Chromium `main` and Go `master` links above document upstream tool
semantics and license location only. They are not acceptable final artifact
evidence; the acquisition pipeline must replace them with the exact resolved
Chromium and Go toolchain commits before review can approve a bundle.
