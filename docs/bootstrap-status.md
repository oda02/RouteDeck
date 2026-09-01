# Bootstrap verification status

Checked through 2026-09-02 in the local Windows workspace.

## Completed

- Direct JavaScript and Rust dependencies are exactly pinned; `package-lock.json` and `Cargo.lock` are present.
- JavaScript dependencies were installed with lifecycle scripts disabled.
- `npm run build` passes with Node.js on `PATH` (TypeScript and Vite production build).
- Visual Studio 2022 Build Tools 17.14.39 with the x64 MSVC toolchain is installed.
- `cargo check --locked --offline` passes from an x64 Visual Studio Developer Command Prompt.
- `cargo fmt --check` passes.
- `git diff --check` passes.
- The official stable `sing-box` 1.13.19 Windows amd64 no-suffix release is pinned in `engine/sing-box.lock.json`. The 21,046,252-byte archive digest matches GitHub release metadata, and the archive, `sing-box.exe`, `libcronet.dll`, and bundled license have exact SHA-256 pins.
- The developer/packaging-only `scripts/verify-engine.ps1` verifies either the untouched release ZIP or a directly extracted engine directory. It authenticates the complete archive before ZIP parsing, rejects unsafe/duplicate/unexpected entries and Windows device-name aliases, and rejects unpinned executable or DLL files. `scripts/test-verify-engine.ps1` covers the reviewed artifact, pre-parse hash ordering, hostile names, and same-size file tampering.
- The official stable XTLS/Xray-core 26.3.27 Windows x64 release is independently pinned in `engine/xray-core.lock.json` for the VLESS REALITY compatibility sidecar. The release is neither draft nor prerelease; its lightweight tag resolves to GitHub-verified commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`. The ZIP SHA-256 agrees with both GitHub API metadata and the separately hash-pinned official `.dgst` asset. The exact `xray.exe` and MPL-2.0 `LICENSE` bytes, official source tree, release workflow, and license URL are recorded in the lock.
- `scripts/verify-xray.ps1` verifies the ZIP, `.dgst`, exact archive paths, and minimal staged directory without executing the binary. `scripts/stage-xray.ps1` stages only `xray.exe` and `LICENSE`; it deliberately excludes `geoip.dat`, `geosite.dat`, WinTun, launcher scripts, and other unused release files. `scripts/test-xray-artifact.ps1` covers digest/archive tampering, hostile lock paths, API-digest disagreement, minimal staging, idempotence, and same-size executable tampering.
- The Tauri application icon is generated locally from `scripts/generate-icon.ps1`; the generator uses only Windows/.NET `System.Drawing` and performs no network access.
- No Windows proxy, route, registry, service, adapter, or VPN process was touched by scaffold verification.

## Current limitations

- The release artifact was inspected and hashed without executing it. The shell does not yet package or execute `sing-box`, WinTUN, a proxy controller, or privileged code.
- Microsoft Defender scanned a uniquely staged, twice-verified copy of the exact engine directory on 2026-09-01 and returned exit code `0` with no threats found. The sanitized report at `engine/security/defender-scan-20260901T103906Z.json` binds the result to the engine lock and runtime hashes; unavailable signature metadata is explicit. No exclusions were added. This point-in-time result is evidence only, not a safety guarantee.
- `cargo check` must run through `VsDevCmd.bat` (or another shell where MSVC tools including `link.exe` are already on `PATH`).
- Deterministic Rust tests cover the local-only controller and the native sealed-engine preflight, but isolated Windows integration and privileged tests remain intentionally out of scope.
- The PowerShell verifier is not the runtime integrity-and-launch gate. The native controller now copies only verified held engine files into a protected per-session LocalAppData directory and revalidates exact contents, file IDs, owner/DACL, reparse state, and late-create denial immediately before suspended launch. Independent review and hostile multi-user/concurrency tests in a disposable Windows VM remain release gates.
- The upstream ZIP includes the sing-box GPL-3.0-or-later license but not a complete Cronet/Chromium or sing-box dependency notice inventory. Authentic top-level Cronet/NaiveProxy/Chromium license texts and the unresolved evidence are pinned under `engine/licenses/` and `engine/NOTICE.md`. `scripts/assemble-portable.ps1` enforces the exact reviewed notice schema, provenance, hashes, set cardinality, and current `blocked` status before any target action. `scripts/test-assemble-portable.ps1` exercises tamper and no-write cases. This is not a legal-compliance claim; release packaging remains blocked pending the documented Windows Cronet notices, sing-box transitive notices, and source-compliance review.
- Xray is staged only as a reviewed local sidecar input by this change; application selection/launch and public packaging are separate work. The lock establishes artifact and MPL-2.0 source/license provenance, not a broader legal-compliance claim.

## Reproduce the checks

Use the committed lockfiles and keep npm lifecycle scripts disabled:

```powershell
npm ci --ignore-scripts
npm run build
cmd /d /s /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 && cargo check --locked --offline --manifest-path src-tauri\Cargo.toml'
pwsh -NoProfile -File scripts\verify-engine.ps1 -Path <release-zip-or-extracted-engine-directory>
pwsh -NoProfile -File scripts\test-verify-engine.ps1 -ArchivePath <reviewed-release-zip>
pwsh -NoProfile -File scripts\test-assemble-portable.ps1 -ArchivePath <reviewed-release-zip>
pwsh -NoProfile -File scripts\verify-xray.ps1 -Path <Xray-windows-64.zip> -DigestPath <Xray-windows-64.zip.dgst>
pwsh -NoProfile -File scripts\test-xray-artifact.ps1 -ArchivePath <Xray-windows-64.zip> -DigestPath <Xray-windows-64.zip.dgst>
pwsh -NoProfile -File scripts\stage-xray.ps1 -ArchivePath <Xray-windows-64.zip> -DigestPath <Xray-windows-64.zip.dgst> -Destination <empty-sidecar-directory>
```
