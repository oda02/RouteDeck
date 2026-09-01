# Bootstrap verification status

Checked on 2026-09-01 in the local Windows workspace.

## Completed

- Direct JavaScript and Rust dependencies are exactly pinned; `package-lock.json` and `Cargo.lock` are present.
- JavaScript dependencies were installed with lifecycle scripts disabled.
- `npm run build` passes with Node.js on `PATH` (TypeScript and Vite production build).
- Visual Studio 2022 Build Tools 17.14.39 with the x64 MSVC toolchain is installed.
- `cargo check --locked --offline` passes from an x64 Visual Studio Developer Command Prompt.
- `cargo fmt --check` passes.
- `git diff --check` passes.
- The official stable `sing-box` 1.13.19 Windows amd64 no-suffix release is pinned in `engine/sing-box.lock.json`. The 21,046,252-byte archive digest matches GitHub release metadata, and the archive, `sing-box.exe`, `libcronet.dll`, and bundled license have exact SHA-256 pins.
- `scripts/verify-engine.ps1` verifies either the untouched release ZIP or a directly extracted engine directory, rejects unsafe/duplicate/unexpected archive entries, and rejects unpinned executable or DLL files.
- The Tauri application icon is generated locally from `scripts/generate-icon.ps1`; the generator uses only Windows/.NET `System.Drawing` and performs no network access.
- No Windows proxy, route, registry, service, adapter, or VPN process was touched by scaffold verification.

## Current limitations

- The release artifact was inspected and hashed without executing it. The shell does not yet package or execute `sing-box`, WinTUN, a proxy controller, or privileged code.
- `cargo check` must run through `VsDevCmd.bat` (or another shell where MSVC tools including `link.exe` are already on `PATH`).
- The current verification covers compilation only; Windows integration and privileged tests remain intentionally out of scope.
- The upstream ZIP includes the sing-box GPL-3.0-or-later license but not the separate Cronet/NaiveProxy/Chromium notices identified in the lock provenance. Packaging must include those notices (and complete third-party notices/source-compliance material after legal review) before release.

## Reproduce the checks

Use the committed lockfiles and keep npm lifecycle scripts disabled:

```powershell
npm ci --ignore-scripts
npm run build
cmd /d /s /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 && cargo check --locked --offline --manifest-path src-tauri\Cargo.toml'
pwsh -NoProfile -File scripts\verify-engine.ps1 -Path <release-zip-or-extracted-engine-directory>
```
