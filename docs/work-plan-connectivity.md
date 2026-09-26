# Connection availability and kill-switch work plan

## Scope and agreed boundary

This PR implements automatic availability recovery. The user agreed to defer a true kill switch to a separate task with security review and qualification in an isolated Windows environment. Automatic recovery is **not protection from direct egress**: engine death and capture restart can expose direct traffic. System Proxy applies only to applications honoring Windows proxy settings and is neither full-device nor reliable per-app protection.

## Completed implementation

- Backend owns connection intent until explicit Disconnect or application shutdown. Renderer events do not cancel recovery or override a newer user Disconnect.
- System Proxy retries recoverable startup/process errors indefinitely with bounded 2–60 second exponential backoff. Ownership conflicts, integrity/configuration problems, and incomplete cleanup pause recovery.
- Live outbound outages keep the existing capture/process and continue end-to-end probes. Six consecutive failed samples (roughly one minute, excluding probe duration) trigger bounded recovery of a potentially wedged core.
- TUN restarts a dead/wedged core inside its existing authenticated elevated helper without another UAC prompt. The narrow protocol-v4 `RestartOwnedCore` operation accepts only the existing session, monotonic request ID and a bounded index into already sealed targets. It accepts no caller executable, command, path or configuration.
- Helper replacement first stops and verifies exact owned route/adapter cleanup, retains the original GUI configuration transfer handle, revalidates configuration/binary/upstream, journals replacement ownership, and restores the current sealed selector default before starting listeners.
- Reality sessions retain the reviewed Xray launcher and owned sidecar configuration. A dead sidecar is restarted before its TUN front, without new elevation.
- Old proof/counter generations are invalidated. Green Connected requires fresh selected-outbound HTTPS plus ordinary capture/listener proof; replacement process existence never turns the UI green.
- Ownership journal schema 3 records distinct original GUI and launched-engine digests; schema 2 remains accepted only in its exact old form. Altered nested configuration blocks automatic crash-data cleanup.
- UI exposes active recovery, paused recovery and cancellation, and states that direct-egress blocking is unavailable.

## Limits requiring user action

- A dead elevated helper, denied UAC, authenticated channel loss, foreign proxy ownership, incomplete cleanup, changed sealed physical network topology, or rejected integrity/configuration evidence pauses automatic recovery. Disconnect and Connect can request fresh permission after the cause is reviewed. Automatic retries never create repeated unattended UAC dialogs.
- Intent is maintained for the current app lifetime. App crash/relaunch still follows owned-state recovery and does not silently connect.
- No existing service is installed and no persistent background elevation is introduced.
- Router/DHCP/interface changes that invalidate the sealed helper preflight are deliberately not bypassed automatically.

## Validation

Deterministic Rust fakes and loopback fixtures cover bounded retries, indefinite failure, explicit cancellation, helper reuse, proof invalidation, warm-measurement process death, sustained outage thresholds, topology pause, sidecar recovery, narrow/replay-resistant protocol input, and original/launched journal digest recovery. Frontend tests cover bounded recovery metadata, late backend intent after Disconnect, and stopping a pending retry without a live child. Validation completed: 360 Rust tests passed (2 explicit fixture-export tests ignored); all 131 frontend/release tests passed; 68 browser scenarios passed after integrating the staged routing PR; production frontend build and offline Windows compilation of every target passed. Mobile home preview was visually inspected. Browser preview exercises UI only; no production engine or TUN is launched. Independent review found no remaining merge blockers.

## Deferred task: true kill switch

Build an independent, narrowly owned Windows Filtering Platform guard before claiming prevention of direct egress. Requirements: durable unique filter/provider ownership before writes; IPv4/IPv6 TCP/UDP and existing-flow coverage; sealed routing/app/direct exceptions; reviewed engine/DNS bootstrap exceptions; typed elevated install/verify/release operations; explicit Disconnect release; crash/helper-loss and BFE/reset recovery; preserve foreign concurrent changes. Prefer non-reboot-persistent owned objects that survive helper death, with exact cleanup evidence. Dynamic WFP sessions alone disappear when the owning process dies and cannot meet helper-crash protection. Qualify hostile input, sleep/resume, core/helper crash, partial installation, cancellation and concurrent VPN behavior in an isolated Windows environment before enabling any default-on protected setting.

Sources: [Microsoft WFP object management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management), [Microsoft WFP best practices](https://learn.microsoft.com/en-us/windows/win32/fwp/best-practices), [sing-box TUN configuration](https://sing-box.sagernet.org/configuration/inbound/tun/). Windows `strict_route` DNS filtering is not a general independent kill switch.
