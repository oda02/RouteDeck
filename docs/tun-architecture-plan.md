# TUN architecture and staged implementation plan

Status: proposed architecture; evidence recorded on 2026-09-04. This document does not claim that live TUN works.

## What is established

- The user reports that System Proxy, including split routing, works. Preserve that path while fixing TUN.
- The old TUN DNS rule matched `protocol: dns` without a preceding sniff action. Pinned sing-box leaves the initial TUN protocol metadata empty. Replacing that selector with TUN-only TCP/UDP port 53 was a real correction, independently reproducible with a localhost DNS fixture. It is not proof that the entire TUN session works.
- A separate, user-authorized VLESS diagnostic without TUN produced HTTPS timeout for hostname/unbound, HTTP 204 for hostname/physical-bound, and HTTP 204 for literal-IPv4/physical-bound. Its child/session cleanup checks succeeded. These results establish a working selected-node data path in those conditions, not successful Windows capture.
- The latest reported failure after build `7822168` includes Windows error **232** on the controller/helper IPC path. Microsoft identifies 232 as `ERROR_NO_DATA`, a closing pipe. It is not a DNS error and does not, by itself, explain why the peer closed. Establish the first failing operation and helper exit reason before making another routing change. [Microsoft error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).
- The user's active v2rayN must not be stopped or reconfigured by an automatic test. Actual single-VPN TUN tests require the user's manual coordination.

## Existing-client comparison

Reference: official v2rayN release **7.24.9**, commit `521230c40d5c180bc0727cf4003907edfae5a3e0`. Its sing-box wrapper is an explicit `EnableLegacyProtect` path for another main core; not every current v2rayN setup uses this architecture. See [wrapper selection](https://github.com/2dust/v2rayN/blob/7.24.9/v2rayN/ServiceLib/Handler/ConfigHandler.cs).

| Concern | Referenced implementation | RouteDeck implication |
| --- | --- | --- |
| Core versus application traffic | Protected core process paths get port-53 DNS interception, then a direct route before user routing. | Core transport needs an explicit policy distinct from user split routing. RouteDeck currently relies on physical socket binding instead. |
| Wrapper and binding | The main core does not own TUN when the wrapper is used. Under strict routing, the context builder clears the main core's interface/source binding. The wrapper detects the outbound interface. | This is one coherent capture-and-direct design, different from RouteDeck's physically bound Xray design. Do not mix their assumptions. |
| DNS bootstrap | Separate bootstrap/direct/remote DNS roles. Proxy-server domains are collected and sent to direct DNS before ordinary DNS rules. | Define server-bootstrap DNS independently of the user's ordinary DNS policy. OS-local discovery alone is not the same contract. |
| DNS interception | Port 53 is intercepted without sniffing; protocol matching is paired with sniffing. | Keep the corrected port-based rule. Do not reintroduce protocol-only matching. |
| Own-address guard | Exact assigned TUN addresses are dropped, not their complete prefixes. | RouteDeck's broader prefix guard must continue to have DNS interception before it. Any later change in scope needs its own regression proof. |
| Application rules | Process names/paths are routed before the final rule. | RouteDeck's default route plus per-app overrides is a compatible model; core-control exceptions must not be editable user rules. |

Sources: [routing and protected core paths](https://github.com/2dust/v2rayN/blob/7.24.9/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxRoutingService.cs), [context construction and binding removal](https://github.com/2dust/v2rayN/blob/7.24.9/v2rayN/ServiceLib/Handler/Builder/CoreConfigContextBuilder.cs), [DNS roles and protected domains](https://github.com/2dust/v2rayN/blob/7.24.9/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxDnsService.cs), [loopback-aware outbound binding](https://github.com/2dust/v2rayN/blob/7.24.9/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxConfigTemplateService.cs).

Do not copy v2rayN's region-specific resolver defaults or all of its features. Adopt the separation of responsibilities, then verify behavior with our pinned engines and Windows ownership model.

## Pinned-engine constraints

- sing-box **1.13.21** depends on sing-tun **0.8.15**. On Windows, auto-route configures the virtual DNS address and flushes the resolver cache. Strict-route WFP rules permit the sing-box executable and TUN interface, then block other port-53 traffic. A separate Xray executable is not the sing-box executable exemption. [Dependency pin](https://github.com/SagerNet/sing-box/blob/v1.13.21/go.mod), [Windows TUN implementation](https://github.com/SagerNet/sing-tun/blob/v0.8.15/tun_windows.go).
- Xray **26.3.27** resolves a hostname before applying its outbound socket-control hook. Its physical-interface option does not bind the DNS query. IPv4 interface-index byte order is correct in the pinned implementation; socket-option errors are logged rather than propagated by the control callback. [Socket options](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/sockopt_windows.go), [system dialer](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/system_dialer.go).
- sing-box's Windows local resolver filters out its own registered TUN interface. A blanket claim that local DNS necessarily recurses into its own TUN is therefore unsupported. Selection of other adapters' DNS remains a distinct compatibility question. [Local resolver](https://github.com/SagerNet/sing-box/blob/v1.13.21/dns/transport/local/resolv_windows.go).
- TUN metadata is not automatically sniffed. The protocol matcher reads metadata; it does not inspect DNS payloads. [TUN inbound](https://github.com/SagerNet/sing-box/blob/v1.13.21/protocol/tun/inbound.go), [protocol matcher](https://github.com/SagerNet/sing-box/blob/v1.13.21/route/rule/rule_item_protocol.go), [route actions](https://github.com/SagerNet/sing-box/blob/v1.13.21/route/route.go).

## Responsibility boundaries

The following are target internal boundaries, not a demand for a wholesale rewrite or new dependencies.

```text
UI / application state
        |
        v
TunSession coordinator -----> TrafficProofs
        |
        v
typed helper transport
        |
        v
elevated helper session -> owned engine jobs + owned TUN state
```

### 1. Helper transport: local control channel only

Own authentication, framing, connection state, request/reply correlation, cancellation, deadlines, and peer-exit reporting. Preserve the existing narrow typed privilege boundary and executable/config verification.

- It must not interpret an IPC failure as a VPN-server or DNS failure.
- Partial reads/writes, EOF, peer closure, cancellation, and malformed frames have distinct finite outcomes.
- A stop request, active verification, and channel shutdown must not race independent readers or writers on the same pipe.
- Record stage, operation, numeric Windows code, session correlation, and known child exit status. Do not record raw configs, endpoint credentials, subscription URLs, or arbitrary child errors.
- A ready engine cannot compensate for an unusable control channel.

### 2. TunSession: one lifecycle owner

Own the sequence and its resources: preflight, helper connection, authenticated start, engine pair, adapter identity, route ownership, proofs, stop, cleanup, and recovery evidence. Other components request transitions; they do not independently stop a child or dispose the shared channel.

Conceptual sequence:

```text
Idle -> Preflight -> AwaitingElevation -> HelperConnected
     -> Starting -> Verifying -> Ready -> Stopping -> Idle
failure at any stage -> Cleanup -> Idle or RecoveryRequired
```

- Attach all outcomes to one session generation so an old reply cannot update a newer session.
- Make cancellation and repeated stop idempotent.
- Hold the exact process/job/config/adapter identities until cleanup is accounted for.
- On partial startup, clean up only owned resources. Never repair a foreign VPN by globally resetting routes, DNS, adapters, or proxies.
- IPC loss triggers owned-session recovery, not a fake successful disconnect or a new session over uncertain old state.

### 3. TrafficProofs: evidence, not lifecycle ownership

Keep three results separate:

1. **Engine/local listener:** exact owned child and listener are available.
2. **Selected outbound:** a request forced through the chosen node completes the bounded HTTPS proof.
3. **Windows capture:** a no-proxy system request, owned route/interface evidence, and corresponding TUN activity establish capture.

Only the session coordinator combines these into Ready. A localhost proof is not a TUN proof. A displayed server IP is not proof that the browser uses it. Proof code cannot silently switch to another VPN or direct route to produce green status.

### 4. State and UI: show the first failure and cleanup separately

Preserve a structured first failure and a separate cleanup outcome, for example:

```text
primary: phase=helper_transport, operation=read_reply, windows_code=232
cleanup: outcome=complete | incomplete | unknown, owned_resource_facts=...
```

The first failure must survive later pipe-close, stop-timeout, or cleanup errors. UI wording should distinguish inability to talk to the helper, inability to start the core, failed selected-server traffic, failed Windows capture, and incomplete cleanup. Do not rewrite every failure as "VPN connection failed" with one generic network explanation.

## Staged plan and release gates

### Stage A: stabilize the current control path

- [x] Record the independent System Proxy success, corrected DNS selector, and no-TUN VLESS controls.
- [x] Record latest error 232 as IPC evidence, separate from previous DNS defects.
- [ ] Locate the earliest failing helper operation and the reason the peer exits/closes; retain cleanup errors separately.
- [ ] Reproduce the failure with local helper-transport fixtures that do not create a TUN adapter or alter network state.
- [ ] Correct the demonstrated transport/lifecycle defect and add its regression test.

Required hostile fixtures: fragmented frames, short writes, oversized/zero-length frames, invalid/replayed or wrong-session messages, peer closure before and during a reply, cancellation during startup, stop during active verification, repeated stop, helper crash, timeout, and first-error preservation when cleanup also fails. Tests must prove exact child/job cleanup without killing unrelated processes.

### Stage B: make session boundaries explicit without changing routing policy

- [ ] Incrementally isolate helper transport from TunSession coordination and TrafficProofs.
- [ ] Assert one owner for pipe operations and resource disposal.
- [ ] Add transition tests for each partial-start failure and cancellation point.
- [ ] Expose stage-specific UI errors and independent cleanup status.
- [ ] Keep the already-working System Proxy implementation/configuration unchanged and run its regression suite.

### Stage C: validate the existing data path, then choose any architecture change

- [x] Keep a separate localhost DNS fixture showing old selector failure, new TCP/UDP-53 success, and non-DNS own-address rejection.
- [x] Keep the separate VLESS no-TUN controls distinct from capture validation.
- [ ] Repeat needed local fixtures against the exact release engine/config hashes after changes.
- [ ] Obtain one fully traced actual-TUN attempt after the IPC fix: startup, selected proof, capture proof, failure if any, and cleanup.
- [ ] Only if that evidence demonstrates a data-plane problem, select a coherent model: the current physically bound sidecar, or a sing-box-owned capture-and-direct sidecar model with exact protected process paths and endpoint-domain DNS protection.
- [ ] If changing the model, implement and test its whole contract together. Do not remove Xray binding without adding and proving the corresponding loop prevention. Do not add broad process-name exceptions or weaken strict routing merely to hide a timeout.

Endpoint address freezing is an optional, independently justified bootstrap technique, not a substitute for working ordinary DNS or IPC. If adopted, resolve before route mutation, preserve TLS/Reality SNI and transport host fields, bound address lifetime/family selection, and test reconnect behavior.

### Stage D: release only what was actually verified

- [ ] Full deterministic Rust/frontend suites, formatting, static checks, and independent diff review pass.
- [ ] Local helper IPC hostile fixtures pass without host network mutation.
- [ ] Pinned-engine DNS and VLESS local fixtures pass; cleanup is verified.
- [ ] Portable main/helper/engine artifacts are matched and hashed; a single explicit launch location is handed off.
- [ ] User manually tests actual TUN while other TUN capture is disabled, then restores v2rayN to report results. Automation does not disconnect v2rayN.
- [ ] Confirm ordinary browser traffic, default-VPN/default-direct modes, per-app exceptions, DNS, reconnect, cancellation, and disconnect restoration.
- [ ] Confirm System Proxy remains working.

Until these gates pass, describe the build as a test build with TUN unverified. Successful unit tests, a DNS fixture, a VLESS sidecar proof, or a clean installation must never be presented as successful end-to-end TUN.

## Implemented slice and current verification (2026-09-04)

The current implementation extracts helper transport into a separate module with bounded overlapped I/O, cancellation-safe operation ownership, fail-closed incomplete frames, and an idle wait distinct from the frame deadline. Bootstrap diagnostics distinguish finite early helper-exit causes and verify that the pipe peer is the exact launched process. The handshake-only `--diagnose-tun-helper` command does not send `StartTun` or configure networking; it checks bootstrap and the exact child's exit after closing its channel.

Application diagnostics now expose reviewed helper bootstrap stages, preserve successful selected-outbound HTTPS evidence when capture fails, and retain the first failure plus any later cleanup failure as separate diagnostic lines. Structured primary/cleanup UI fields and the complete TunSession separation remain planned, not finished.

Reported checks for this slice: 233 Rust tests passed, including 10 local IPC tests; Rust formatting and Clippy passed. The frontend suite passed 48 tests in this work cycle. The three pinned-engine localhost DNS cases were repeated and passed. These are separate checks, not proof that every hostile fixture listed above or the release gates are complete.

The reason for the user's latest error 232 and successful actual Windows TUN capture remain unverified. Keep those checklist items open until a traced live attempt establishes the result; System Proxy routing and the active v2rayN configuration are not changed by this slice.
