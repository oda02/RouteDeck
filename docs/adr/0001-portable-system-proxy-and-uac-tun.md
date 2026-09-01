# ADR-0001: Portable System Proxy and UAC-on-demand TUN

- Status: Accepted for the first implementation
- Date: 2026-09-01

## Context

RouteDeck should be usable from an unpacked directory without an installer or permanent privileged service. Windows System Proxy is current-user state and can be managed without elevation. Creating a TUN adapter and changing routes requires administrator authority. A permanently installed SYSTEM service would reduce prompts but substantially enlarges the privileged attack surface and complicates install, upgrade, and recovery.

Windows also exposes only one effective System Proxy configuration per user. A second proxy listener can run on another port, but it cannot independently become the system-wide choice. Route changes made by multiple VPN clients can overlap and must be treated as a conflict-prone condition rather than presumed safe coexistence.

## Decision

1. The normal Tauri application remains unprivileged.
2. System Proxy mode records the exact previous Windows state plus an ownership marker before publishing a loopback endpoint. It restores only state it still owns.
3. TUN mode launches a fixed, application-owned executable through a narrow UAC-on-demand path. The UI cannot provide an arbitrary executable, arguments, environment, registry path, or destination path.
4. The first release does not install a persistent Windows service.
5. RouteDeck validates generated sing-box configuration before elevation and performs an end-to-end health probe after startup.
6. If another VPN changes proxy or route state, RouteDeck reports the conflict and avoids force-restoring foreign state without explicit, narrowly validated recovery.
7. Portable packaging is an explicit offline assembly step from pinned, hashed, license-reviewed artifacts. Application startup and npm/Cargo builds do not download binaries.

## Consequences

- System Proxy mode is genuinely portable and should not trigger UAC.
- TUN activation may prompt for UAC each time until a separately reviewed service design is adopted.
- A crash between elevation and cleanup needs a durable recovery journal and a startup reconciliation flow.
- Per-app routing is reliable in TUN mode. In System Proxy mode it applies only to applications that use the configured proxy or that RouteDeck launches with an explicit proxy; the UI must state this limitation.
- Testing must cover concurrent proxy changes, stale ownership markers, partial startup, denied UAC, crashed children, and shutdown with another VPN active.

## Rejected alternatives

- **Permanent SYSTEM service from the first release:** rejected because it creates a broad, persistent trust boundary before core behavior is proven.
- **Elevating the complete UI:** rejected because webview/UI compromise would inherit administrator authority.
- **Blindly restoring the captured proxy on exit:** rejected because it can overwrite legitimate changes made by another VPN or the user.
- **Assuming two VPNs always coexist:** rejected because route, DNS, proxy, and adapter ownership vary by client and Windows configuration.
