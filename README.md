# RouteDeck

RouteDeck is a portable-first Windows desktop client planned around `sing-box`. The initial repository is deliberately only a safe Tauri shell: it does not download a core, change Windows proxy settings, request elevation, or create routes.

## Product goals

- Import reviewed subscription formats into a normalized local model.
- Support VLESS/REALITY, Hysteria2, and Naive through a pinned `sing-box` distribution.
- Offer two explicit operating modes: System Proxy and TUN.
- Make the default route (`Direct` or `VPN`) visible and allow per-application overrides.
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

Use `npm run tauri dev` only after dependencies have been reviewed and installed. The current shell has no privileged command and does not require `sing-box`.

## Portable packaging

The first deliverable is a directory containing the RouteDeck executable, the reviewed `sing-box.exe`, its required companion files (including `libcronet.dll` when Naive is enabled), licenses, and configuration templates. `tauri build --no-bundle` produces the application executable without an installer. Distribution assembly and binary verification will be separate, explicit steps; the frontend build never downloads binaries.

See [ADR-0001](docs/adr/0001-portable-system-proxy-and-uac-tun.md) for the privilege model.
