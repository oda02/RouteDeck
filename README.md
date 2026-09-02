# RouteDeck

RouteDeck is a portable-first Windows desktop client built around pinned `sing-box` and Xray runtimes. The application supports current-user System Proxy and keeps TUN elevation in a separate on-demand helper; it does not install a service.

## Product goals

- Import reviewed subscription formats into a normalized local model.
- Support VLESS/REALITY, Hysteria2, and Naive through a pinned `sing-box` distribution.
- Offer two explicit operating modes: System Proxy and TUN.
- Route System Proxy traffic through the selected VPN; expose `Direct`/`VPN` defaults and per-application overrides as TUN policy.
- Report “Connected” only after a real request succeeds through the selected outbound.
- Coexist safely with other VPN clients without overwriting state RouteDeck does not own.

## Architecture

```text
React UI
  │ typed commands/events
Tauri controller (unprivileged)
  ├─ application state machine
  ├─ subscription parser + normalized profile model
  ├─ sing-box config renderer and validator
  ├─ child-process supervisor + health probes
  └─ Windows state ownership/recovery
       ├─ current-user System Proxy
       └─ narrow UAC-on-demand TUN launcher
             └─ sing-box + WinTUN (reviewed external artifacts)
```

The planned modules are intentionally separated:

- `domain`: profiles, routes, connection state, and typed errors; no platform access.
- `subscription`: parsers and validation; secrets are never logged.
- `engine`: deterministic sing-box configuration and lifecycle supervision.
- `platform/windows`: narrowly scoped proxy, elevation, route, and recovery code.
- `application`: orchestration, idempotency, ownership markers, and UI commands.
- `ui`: rendering only; it does not infer success from process state.

System Proxy can coexist with another locally listening proxy because listeners use different ports, but Windows has only one effective per-user proxy configuration. RouteDeck therefore must detect and explain ownership conflicts. Two TUN/VPN route managers can also conflict; simultaneous use is not assumed safe.

## Development

Requirements: Windows 10/11, WebView2, Node.js 22.12+, npm 10+, Rust 1.89+ with the MSVC target and Visual Studio C++ Build Tools.

Dependency execution is intentionally conservative:

```powershell
npm ci --ignore-scripts
npm run build
cargo check --locked --manifest-path src-tauri/Cargo.toml
```

Use `npm run tauri dev` only after dependencies have been reviewed and installed.

## Portable packaging

`scripts/build-local-portable.ps1` builds the GUI and on-demand TUN helper into an isolated target directory and records their exact hashes in `routedeck-build.json`. It does not download engines. With the pinned engine directories already staged, assemble the self-contained local folder without an installer or service:

```powershell
pwsh -NoProfile -File scripts\build-local-portable.ps1
pwsh -NoProfile -File scripts\assemble-portable.ps1 -TargetRoot src-tauri\target\portable\RouteDeck
```

The output contains `routedeck.exe`, its fixed sibling helper, exact `engine` and `xray` runtime directories, and a separate `licenses` directory. The assembler verifies the GUI/helper build manifest and both engine lockfiles before and after copying, and never runs any packaged executable.

See [ADR-0001](docs/adr/0001-portable-system-proxy-and-uac-tun.md) for the privilege model. This local portable workflow is separate from a public redistribution decision; the [portable compliance evidence plan](docs/portable-compliance-plan.md) records the remaining public-release notice/source work.
