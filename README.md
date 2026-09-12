# RouteDeck

## Download and run

Download `RouteDeck-<version>-windows-x64.zip` from
[GitHub Releases](https://github.com/oda02/RouteDeck/releases/latest), extract the
whole archive, and launch `routedeck.exe`. The full portable includes the pinned
sing-box/Cronet and Xray runtimes; no separate engine setup is required. The other
source-code assets on the release page are optional downloads for source inspection.
Keep `engine` and `xray` beside the application. See
[portable instructions](docs/portable-full-release.txt) for updating an existing copy.

[![CI](https://github.com/oda02/RouteDeck/actions/workflows/ci.yml/badge.svg)](https://github.com/oda02/RouteDeck/actions/workflows/ci.yml)

See [CI, release tags and portable updates](docs/releases.md) for versioning,
stable/prerelease publishing and the application's GitHub update check.

RouteDeck is a portable-first Windows desktop client built around pinned `sing-box` and Xray runtimes. The application supports current-user System Proxy and keeps TUN elevation in a separate on-demand helper; it does not install a service.

## Product goals

- Import reviewed subscription formats into a normalized local model.
- Support VLESS/REALITY, Hysteria2, and Naive through a pinned `sing-box` distribution.
- Offer two explicit operating modes: System Proxy and TUN.
- Apply `Direct`/`VPN` defaults and per-application overrides to TUN traffic and to proxy-aware TCP traffic in System Proxy mode.
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

System Proxy routing is intentionally described as best-effort application proxy routing, not full-device tunnelling. Applications that ignore the Windows proxy, UDP/QUIC traffic, and operating-system DNS requests are outside its capture scope; use TUN when those flows must be covered.

## Development

### Server library

The Servers page has separate **Add server** (share links or sing-box JSON) and
**Add subscription** (HTTPS URL) actions. Imports preview supported records and
append a named source group, preserving previous servers and the current selection.
Disconnect RouteDeck before saving a new group. Sources persist locally, with
limits of 64 groups, 2000 servers, and 10 MiB of original content in total.

The existing v1 subscription is restored as “Сохранённые серверы”. Versions 1 and 2
migrate to the v3 library on the next successful mutation. Subscription URLs remain
private in local storage; they are never sent back to the renderer. Existing groups
without a saved URL ask for it once on refresh. Each subscription header offers refresh
and deletion; standalone groups can be deleted. Refresh replaces only that source and
preserves node IDs across reordering. Failed downloads preserve the old source.

In TUN, selecting a prepared server keeps the same engine and adapter: a separate
HTTPS check runs first, new connections then use that server, and existing connections
remain on their old exits while available. Failed candidates do not restart TUN.
See [TUN server switching and verification limits](docs/tun-server-switching.md).
System Proxy server changes and capture-mode changes still stop and reconnect in sequence.
Disconnect cancels pending work; a restoration error prevents another core starting.
Refreshing the active source reconnects afterward; deleting it leaves RouteDeck
disconnected. Home displays actual active server/mode separately from the selection.
Its latency is a warm HTTP response measurement, separate from the HTTPS readiness proof.

The UI work plan and regression evidence are in [UX workflow](docs/ux-work-plan.md).
Browser checks use the real frontend controller with synthetic IPC, so they do not
change Windows networking. Run `node tests/browser-ux.mjs` against a Vite dev server,
with an existing Playwright runtime supplied using `ROUTEDECK_PLAYWRIGHT_PATH` if
it is not on the Node module path. Do not install a browser as part of the build.

See [Naive support and verification](docs/naive-support.md) for supported link formats,
the pinned Windows engine checks, and the current TCP-only limitation.

Current reliability review and remaining TUN acceptance gates:
[audit dated 2026-09-05](docs/audit-2026-09-05.md).

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

Open `routedeck.exe` directly from the portable folder. Release builds use the Windows
GUI subsystem and do not allocate a terminal. Only the explicit diagnostic CLI flag
attaches to an existing parent console. The frontend assets are embedded; Vite is a
development server, not a runtime requirement. Tauri uses Windows WebView2 for the UI
and local IPC to the Rust backend. VPN engine listeners are separate local proxy ports.

See [ADR-0001](docs/adr/0001-portable-system-proxy-and-uac-tun.md) for the privilege model. This local portable workflow is separate from a public redistribution decision; the [portable compliance evidence plan](docs/portable-compliance-plan.md) records the remaining public-release notice/source work.

### Rules and preferences

Rules save automatically and reconnect an active session when the effective policy
changes. Application rules stay in one column at all widths, with search and optional
paths. The selected server and mode persist across restart without automatically
connecting. Missing server IDs fall back to an existing library entry; an actual
active backend session takes precedence over saved selection. TUN defaults to gVisor
when no explicit stack preference exists; a saved System choice remains available.
Under **Rules → Additional Naive settings**, opt into UDP over TCP v2 for all Naive
profiles. The server must support SagerNet UoT v2. This defaults off and reconnects
only active Naive sessions when changed; HTTPS readiness alone does not verify UDP.
Under **Rules → Traffic rules**, add or edit ordered TCP/UDP destination-port rules
with block, direct or VPN actions. These rules apply only in TUN, before application
exceptions and after mandatory DNS/IPv6 safeguards. UDP 443 blocking is enabled by
default to help clients fall back from QUIC to TCP when needed (for example, YouTube
compatibility). Disable it for client applications that require QUIC. It does not
block the VPN engine's own Hysteria2 transport. Removed/disabled rules stay that way
after restart; the editor supports up to 32 rules. Port 53 remains managed by TUN DNS.
TUN uses TCP to the first eligible IPv4 DNS resolver configured on its selected
physical adapter. The helper independently verifies that resolver before launch;
Windows DNS settings and caches are not changed. If no eligible IPv4 resolver exists,
the existing local resolver remains the fallback. System Proxy keeps local DNS.
This does not provide automatic resolver failover; reconnect after a network DNS
change. See [DNS investigation and test limits](docs/discord-zapret-diagnostics.md).
Settings include persisted themes and optional subscription refresh every 6 or 24 hours.
Periodic refresh runs while RouteDeck is open and disconnected; active sessions defer it.

The main latency indicator measures steady HTTP response time to Google through the
selected VPN, after warming one connection. It is separate from the full HTTPS proof
used for connection readiness. See [measurement details](docs/latency-measurement.md).
