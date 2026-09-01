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
- The Tauri application icon is generated locally from `scripts/generate-icon.ps1`; the generator uses only Windows/.NET `System.Drawing` and performs no network access.
- No Windows proxy, route, registry, service, adapter, or VPN process was touched by scaffold verification.

## Current limitations

- The shell does not yet include or execute `sing-box`, WinTUN, a proxy controller, or privileged code.
- `cargo check` must run through `VsDevCmd.bat` (or another shell where MSVC tools including `link.exe` are already on `PATH`).
- The current verification covers compilation only; Windows integration and privileged tests remain intentionally out of scope.

## Reproduce the checks

Use the committed lockfiles and keep npm lifecycle scripts disabled:

```powershell
npm ci --ignore-scripts
npm run build
cmd /d /s /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 && cargo check --locked --offline --manifest-path src-tauri\Cargo.toml'
```
