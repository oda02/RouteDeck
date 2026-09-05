# RouteDeck: UX and connection workflow overhaul

## Acceptance plan

1. Reproduce blank/shifted screens at 360×560, 440×760 and wide desktop sizes.
   Check server selection, notices, modal open/close, keyboard focus and navigation.
2. Rebuild Home around actual connection state, a prominent action, active server,
   mode and measured HTTPS latency. Keep navigation stable and overlays outside
   the layout grid. Server picking from Home returns Home; library use stays put.
3. Serialize server/mode changes: stop owned connection, verify stop, then reconnect.
   Latest selection wins; disconnect cancels restart. Failed restoration blocks start.
4. Implement private subscription URL persistence, atomic refresh of one source,
   source removal, migration and safe recovery when fetching or saving fails.
5. Verify controller races and hostile inputs with fixtures; click through the UI
   with simulated IPC including connected, busy, failure and recovery states.
6. Review integrated changes, run Rust/frontend/build checks, then produce a portable
   build with verified engines and matching helper hash for the user's live testing.

No live VPN, routes, adapters, DNS or Windows proxy settings are modified during
these checks. Browser fixtures must never enter the production bundle.

## Design references

- [Mullvad app](https://mullvad.net/en/help/using-mullvad-vpn-app): prominent connection
  controls and a separate location picker.
- [Proton VPN Windows app](https://protonvpn.com/support/protonvpn-windows-vpn-application):
  Home communicates connection state and the current server.

RouteDeck adapts these interaction patterns without adding maps, decorative metrics
or implying that System Proxy captures all device traffic. Latency is an actual HTTPS
probe duration, not an ICMP ping or a speed test.

## Progress

- Reproduced the blank-screen failure: choosing row 86 moved the main viewport to
  y = -6418 px. Hidden native radio inputs were not anchored to their labels;
  focusing them scrolled outer containers. Anchored inputs and non-scrollable
  outer frames fix this; only the main content scrolls.
- Home redesigned, overlays portaled to the document body, modal background inert,
  focus restoration uses preventScroll. Library state survives navigation. Picking
  from Home returns Home, including clicking an already selected server.
- Subscription v3 refresh/removal and serialized connection intent implemented.
- 284 Rust tests, 73 frontend/permission/bundle tests and 21 browser scenarios passed.
  Browser checks cover 360×560, 440×760, wide windows, light theme/200% zoom,
  reduced motion, long lists, dialogs, cancellation, active-source removal,
  failed refresh rollback, and teardown failure preventing a new start.
- Portable packaging uses the reviewed source snapshot, pinned engines and an exact
  helper hash. Live TUN/network acceptance remains the user's manual check.

## Compact rules and settings follow-up

- Audited every page with separate controller, URL-persistence and read-only UX reviews.
  Removed repeated per-app explanations and unsupported settings controls. Corrected
  reset copy: it also deletes the server library and stops the connection.
- Application rows are 52 px; a wide two-column layout displays the 20-app fixture
  without scrolling at 1000x900. Narrow windows use one column, search and optional
  paths. The picker supports batch addition and refreshing running applications.
- Rules and preferences autosave; failures remain visible and retryable. Navigation
  retains pending edits, older completions cannot replace newer drafts. Routing
  changes persist before serialized reconnect; failed teardown prevents a new start.
- Theme now persists. Optional 6/24-hour source refresh runs only while disconnected,
  with a second activity check inside the queue and per-source retry cooldown.
- Selection uses the existing radio indicator and a restrained tint. Focus rings are
  inset and keyboard-only, eliminating clipped blue lines and corner stripes.
- Two additional Rust fixtures confirm URL import/legacy migration, restart and refresh
  without re-entering the URL. Older sources require one successful URL-based update.
- Validation: 286 Rust tests; 90 frontend, scheduler, permissions and bundle tests;
  33 browser scenarios include 20 apps, save failures/retry, persistence across reload,
  active-rule edits, background refresh, 200% zoom and keyboard focus.

## Steady response measurement follow-up

- Split full HTTPS availability evidence from the user-facing steady response metric.
  A warmup and three consumed 204 responses must share one forwarded connection;
  the median excludes setup. Failed reconnect, timeout or response validation yields
  no sample, with no substitution of full-proof timing.
- Preserved readiness, ownership and TUN counter proofs. Optional sampling is outside
  the controller lock, bounded, and checked against the current session before publish.
  Healthy periodic updates retain the previous sample until replacement. Failures,
  transitions and stop clear it; late process death follows the existing stop path.
- Recovery unit fixtures now inject file-only recovery, avoiding dependence on a
  real RouteDeck TUN adapter during production-style fixture setup.
- Verified 299 Rust tests, 92 frontend/scheduler/permission/bundle tests, and 35 browser
  scenarios. Local relay fixtures cover pooling, reconnect rejection, reserved-port
  lifetime, deadlines and teardown. Google and live VPN networking were not tested.
- Details and primary reference: [latency measurement](latency-measurement.md).

## Window and desktop polish follow-up

1. Center every width-limited page in the available content area at wide sizes.
2. Match the native window, WebView and document background in both themes;
   investigate resize flashes without changing VPN or system networking state.
3. Theme scrollbars, retaining native high-contrast rendering and keyboard access.
4. Suppress browser context menus without swallowing application events or editing
   shortcuts. Keep the ordinary packaged application free of console windows.
5. Verify wide/narrow layouts, rapid viewport changes, themes and context-menu
   behavior with synthetic IPC. Verify the release PE GUI subsystem and package a
   reproducible portable build. Native compositor behavior during fast edge dragging
   remains a manual check in the delivered application.

Implemented all five items. Validation passed: 301 Rust tests, 93 frontend/permission/
bundle tests, and 39 browser scenarios. Added checks cover all five pages centered at
1600/1920 px, repeated 360–1920 px viewport changes in both themes, high contrast,
context-menu propagation, and serialized native appearance updates after failure.
The release build rejects a GUI executable linked with the console PE subsystem.

## Deferred: one UAC prompt per continuous TUN session

Code review confirmed that profile switching currently tears down `TunHelperChild`,
waits for helper exit, and launches a fresh helper with `runas`. The protocol explicitly
rejects another StartTun after StopTun. Reusing elevation therefore requires a lifecycle
and privilege-boundary change, not a UI setting. Current behavior remains unchanged;
the user considers repeated prompts tolerable if avoiding them is not a small safe fix.

Proposed scope for a separate implementation:

- Keep the ordinary UI unprivileged. Retain only the authenticated on-demand helper
  across an explicitly requested TUN-to-TUN profile/routing transition. Do not install
  a service or retain elevation across an explicit disconnect or switch to System Proxy.
- Separate helper lifetime from engine/session lifetime. Each new engine generation
  gets fresh validated configuration and ownership records. Verified cleanup of the
  preceding generation must succeed before accepting another start.
- Retain kernel-reported peer PID and creation-time checks, local-only IPC, fixed
  executable/configuration validation, bounded messages and monotonic request IDs.
  An arbitrary process must not acquire the existing helper by opening its pipe.
- Close the helper on parent exit, IPC loss or aborted handover; bound the idle handover
  period. Failed restoration must preserve evidence and prevent a new TUN start.
- Test foreign peers, replay, stale handles/generations, rapid selection changes,
  disconnect during restart, failed cleanup, parent/engine crashes and expiry with
  isolated fixtures. Complete privileged acceptance in an isolated Windows environment
  before exercising the user's real adapters or VPN connection.

Review only: no runtime changes, native launches or host-network testing for this item.

## Proxy diagnostics and opt-in TUN compatibility

- Added a compact Windows System Proxy card with sanitized loopback endpoint,
  ownership and listener evidence, ambiguous/unavailable states, and an explicit
  confirmation for disabling a stale foreign manual proxy. It does not terminate
  processes. No cleanup runs automatically.
- Cleanup uses a one-use native preview bound to the exact WinInet/registry state,
  checks both IPv4/IPv6 listener tables, preserves durable prior-state evidence,
  rechecks immediately before mutation, and changes only manual-proxy enablement.
  PAC, WPAD, policy, RAS, live listeners and RouteDeck ownership conflicts block it.
  Stable TUN sessions can remain connected. Detected concurrent changes are preserved;
  Windows provides no atomic transaction spanning another application's proxy writes.
- Refreshes and runtime changes invalidate UI previews. Errors survive dialog closure;
  the diagnostics report includes proxy state and stack preference without action tokens.
- Added an opt-in `system`/`gvisor` TUN stack selector under Rules → Additional TUN
  settings. Existing preferences remain `system`. Unknown values are rejected by
  frontend parsing, typed native IPC and the elevated helper. A stack change restarts
  active TUN through the existing stop/start sequence; System Proxy is unaffected.
- The setting is an experiment prompted by reproducible zapret coexistence failures,
  not a verified live fix. No zapret configuration, service or active TUN was changed
  for this implementation. See [observations and manual comparison](discord-zapret-diagnostics.md).
- Validation: 313 Rust tests, 99 frontend/boundary/scheduler tests, 47 browser scenarios,
  production build and all-target native compile. Browser cases cover narrow layout,
  cancel, obsolete confirmation, visible cleanup failure, successful cleanup, stack
  propagation, automatic TUN restart and no System Proxy restart. Host mutation is
  replaced by synthetic IPC/platform fixtures in these tests.

## Editable TUN traffic rules

- Added a compact, collapsible Traffic Rules editor below application exceptions.
  A rule has a TCP/UDP network, one destination port, enabled state and a fixed action:
  block, direct or selected VPN. Users can add, edit, reorder, disable and delete rules.
  The first enabled match wins; the compatibility badge follows that same ordering.
- Old preferences without this field receive an enabled UDP 443 block. Explicit empty
  lists and disabled rules persist. System Proxy does not receive or apply these rules.
- The modal keeps incomplete edits local, validates ports (1–65535 except reserved DNS
  port 53) and allows cancel. Applying uses existing autosave; only effective active
  TUN changes trigger serialized stop/start. Failed persistence preserves the session;
  failed teardown prevents starting a replacement.
- Native input and elevated configuration validation are closed and bounded to 32
  rules. Generated rules match only `tun-in`, following mandatory health, DNS,
  own-prefix and IPv6 guards, before app exceptions and LAN/default routing. Blocking
  uses `reject` with `method: default` and `no_drop: true`, allowing TCP fallback.
  Outer Hysteria2/Naive QUIC sockets are outside this inbound. QUIC-only client apps
  may require disabling the default rule; this is a compatibility measure, not proof
  that the underlying zapret interaction is fixed.
- Independent security review found and closed a forged whole-TUN direct route that
  could otherwise escape prefix validation. The helper now also verifies exact app
  and optional LAN suffix rules, final outbound and DNS resolver.
- Validation: 317 Rust tests, 104 frontend/boundary/scheduler tests, 54 browser scenarios
  using synthetic IPC, plus all-target native compilation and production build.
  Browser coverage includes cancel, reserved DNS feedback, editing and ordering,
  disabled-rule precedence, persistence across reload, TUN reconnect and no System
  Proxy reconnect, and 360/1200 px layouts. Live acceptance with zapret remains for
  the user; no running network process, service or adapter was changed for this work.

## One-column application rules, saved selection and Naive UoT

- Application rules now remain one column at every width, as requested. The compact
  row height and search remain; large lists use normal page scrolling.
- Added a collapsed Naive setting for SagerNet UoT v2, off by default and shared by
  Naive profiles. Copy explains compatible server requirements, TUN for app UDP,
  and continuing UDP 443 blocking. The server row displays the selected UoT preference
  without claiming UDP connectivity has been proven.
- The native flag is normalized to the confirmed Naive protocol. It is part of active
  session identity for Naive only; unrelated protocols do not reconnect. The helper
  permits only the exact enabled/version-2 object on Naive outbounds and rejects
  malformed values, other protocols and REALITY bridges.
- Last selected server ID and mode persist in a bounded versioned preference. Loading
  validates the ID against the confirmed library, prefers actual active runtime state,
  and never auto-connects from preferences. A write failure leaves the prior selection
  and connection untouched. Local reset clears this preference alongside existing
  routing/theme/subscription-refresh settings.
- Fresh or legacy preferences without a stack now use gVisor. Explicit System choices
  are preserved; either stack remains selectable.
- Validation: 319 offline Rust tests, 109 frontend/boundary/scheduler tests, 57 browser
  scenarios, all-target native compilation and production build. Browser coverage
  checks one-column layout, UoT switch persistence/reconnect, server/mode restoration,
  no automatic connection and narrow/wide settings. An independent security review
  found no further issues. User acceptance of real server UDP remains pending.

## Intermittent TUN DNS investigation

- Captured name-resolution failures while the selected HTTPS proxy still worked.
  Apparent browser recovery is not considered acceptance; the running session and
  Windows/browser caches were left unchanged during investigation.
- Repeated queries isolated a configured IPv6 DNS returning NXDOMAIN for YouTube,
  plus intermittent NXDOMAIN over UDP to the configured IPv4 DNS. TCP to that same
  IPv4 resolver returned addresses. See the evidence and limits in
  `docs/discord-zapret-diagnostics.md`.
- TUN now derives its bootstrap DNS from the selected physical adapter and uses
  TCP/53. The typed helper request binds the DNS address to its preflight digest;
  the helper independently verifies the Windows snapshot and exact generated DNS
  transport. No renderer-supplied resolver, public-DNS substitution or cache flush.
- No eligible IPv4 resolver retains the local fallback. System Proxy is unchanged.
  DNS is selected anew on reconnect; a DHCP DNS refresh alone does not terminate a
  healthy active session. Automatic multi-resolver failover is still unimplemented.
- Validation: 323 offline Rust tests, 109 frontend/boundary/scheduler tests and the
  production frontend build passed. Independent security review found and closed a
  signed Windows socket-address-length validation issue; hostile parser fixtures
  cover null/short/negative lengths, IPv6, byte order and duplicate resolver ordering.
  The reviewed sing-box accepted synthetic TCP DNS configs for Naive, Hysteria2 and
  a REALITY SOCKS bridge, plus the local fallback. A temporary TCP DNS transport
  passed 36 queries across three sites/rounds through the existing engine; this does
  not replace privileged TUN acceptance.
- Privileged acceptance remains a user-started new TUN session: load YouTube/ChatGPT immediately,
  repeat after several minutes, switch Hysteria2/Naive, and repeat a disconnect and
  reconnect. Retain the server, mode and contemporaneous error on any recurrence.
