# RouteDeck verification and test matrix

- Status: acceptance baseline
- Scope: deterministic tests, isolated Windows integration, and explicitly authorized host validation
- Engine baseline: pinned sing-box 1.13.19 Windows x64 artifact

## 1. Test tiers and safety boundary

| Tier | Environment | Permitted actions |
| --- | --- | --- |
| U — unit/property | normal CI, no network | Pure parsing, normalization, config generation, state machine, redaction, journal logic using fixtures/mocks. No process, registry, routes, adapters, DNS, services, or network. |
| C — core integration | CI sandbox with pinned engine fixture | Run the hash-verified engine only against generated local fixtures; `sing-box check`; loopback mock endpoints. No Windows global state changes. |
| W — isolated Windows VM | disposable snapshot | System Proxy mutation, UAC helper, TUN/route/DNS, crash/power-loss simulations, Defender/package checks. Security review required first. |
| H — user-authorized host | the target PC | Minimal final smoke tests after U/C/W pass. Capture only redacted state; never stop or reconfigure another VPN without explicit authorization. |

Every state-changing W/H test records a before snapshot and has a verified cleanup assertion. A test fails if cleanup is unknown, even when connectivity succeeded.

The normative mode boundary and safe sequencing are defined in
[Safe Windows mode ownership](windows-mode-ownership.md). Tests must not bypass its
consent, journal, guardian, helper, or ownership requirements.

## 2. Release-blocking acceptance summary

- All U and C cases pass on every change.
- All High-risk W cases pass from a clean VM snapshot and from a snapshot with a second VPN/proxy installed.
- No test ever obtains `Connected` without `HC-04` end-to-end proof.
- No proxy restore overwrites a foreign state (`PX-08` through `PX-13`).
- TUN helper accepts no arbitrary command/path/config (`PR-05` through `PR-12`).
- VLESS/REALITY, Hysteria2, and Naive each pass config validation and real authorized proof.
- Default Direct + selected-app VPN and default VPN + selected-app Direct pass in TUN for IPv4 and IPv6.

### 2.1 Hard Windows VM gate

**Do not publish RouteDeck Windows System Proxy or start RouteDeck TUN on the user's main
PC until all U/C tests, the independent ownership/helper security review, and all
applicable W tests pass in both a clean disposable Windows VM snapshot and a snapshot
with a second VPN/proxy installed.** Local-only proof through explicit loopback ports is
not a Windows mode mutation and may proceed separately.

Before this gate passes, the main PC must not be used for a WinINet write, existing
proxy/PAC takeover, UAC helper activation, route/DNS/adapter mutation, stale-state
cleanup, forced crash/power/sleep/network-change case, physical-interface bypass, or
another-VPN race. Direct registry edits, service/task/startup installation, blind force
restore, and termination or reconfiguration of another VPN are forbidden in every tier.

## 3. Artifact and supply-chain tests

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| SC-01 | U | Lock has exact stable version, release tag/commit, official HTTPS asset URL, archive hash, `sing-box.exe` hash, and `libcronet.dll` hash | Missing/floating/placeholder value blocks packaging. |
| SC-02 | C | Downloaded archive matches pinned SHA-256 | Exact match before extraction. |
| SC-03 | C | Archive hash differs by one bit | Abort; extract/execute nothing. |
| SC-04 | C | Archive contains absolute path, `..`, link/reparse escape, duplicate normalized name, or unexpected executable/DLL | Reject archive. |
| SC-05 | C | Extracted `sing-box.exe` and `libcronet.dll` match pins | Packaging continues. |
| SC-06 | C | DLL missing, renamed, or replaced | Naive-capable package fails closed before engine launch. |
| SC-07 | U | URL uses `latest`, non-GitHub host, query redirector, prerelease tag, or non-amd64 asset | Policy validation rejects it. |
| SC-08 | C | Run `sing-box version`; compare to lock | Exact `1.13.19`; mismatch blocks release. |
| SC-09 | W | Defender scans unpacked engine and assembled portable directory | No detection; scan result recorded without allow-listing. |
| SC-10 | U | npm/Cargo/frontend build examined for engine download hooks | No build/start hook downloads or executes engine artifacts. |
| SC-11 | U/W | Seal destination is removable, remote, FAT/exFAT, or lacks persistent ACLs | Fail closed before copying or executing the engine. |
| SC-12 | W | Sealed execution directory owner/DACL is changed, a reparse point appears, or a third name is planted | Immediately adjacent preflight rejects it; engine is not executed. |
| SC-13 | W | Another unelevated Windows user attempts to read/write/replace the sealed engine files or create a late DLL | Protected DACL denies access; exact preflight remains valid. |
| SC-14 | W | Same-user hostile test changes the DACL and races a late DLL between validation and launch | Test records the documented same-user boundary; no claim of resistance without OS isolation/elevated broker. |
| SC-15 | W | Crash leaves a sealed session; unknown file/reparse point is present during cleanup | Exact non-recursive cleanup preserves ambiguity; next startup enters `RecoveryRequired`. |

## 4. Subscription fetch and parser tests

### 4.1 Fetch boundary

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| SF-01 | U | `https` URL with encoded bearer/query secret | Accepted for request lifetime; raw URL is absent from errors, diagnostics, preview DTOs, logs, and retained pending state. |
| SF-02 | U | `file:`, `ftp:`, `gopher:`, UNC, bare path, `data:`, custom scheme | Rejected before request. |
| SF-03 | U | Three legal redirects through fake resolver/transport | Success; HTTPS URL and fresh pinned address policy rechecked each hop. |
| SF-04 | U | Fourth redirect, loop, missing Location, or HTTPS→HTTP downgrade | Stable policy-blocked failure. |
| SF-05 | U | Initial or redirected destination resolves to loopback, private, CGNAT, link-local, unspecified, multicast, documentation, benchmark, transition, or reserved IPv4/IPv6 | Entire answer rejected; no LAN-source exception exists in v1. |
| SF-06 | U | First DNS answer is public, next answer for the same redirect host is private or mixed | Second request is never issued; each connection uses only its validated pinned set. |
| SF-07 | U | DNS/connect/read/overall timeout injected by fake boundary | Stable timeout code/key; preview slot released and prior subscription preserved. |
| SF-08 | U | Identity body is >10 MiB; any gzip/br/zstd/deflate response | Oversize or unsupported encoding fails without partial import; no decoder dependency runs. |
| SF-09 | U | Invalid UTF-8/HTML login page | Invalid encoding has a finite error; HTML is rejected by the importer and never link-sniffed. |
| SF-10 | U | Failed refresh after valid prior snapshot | Prior snapshot remains active atomically. |
| SF-11 | U/C | v2rayN/System Proxy/environment proxy is configured while fetch policy is v1 Direct | Client has proxy discovery disabled and uses only policy-validated pinned destinations. |
| SF-12 | U | User requests fetch through active RouteDeck in v1 | Not representable; only the explicit direct/current-network fetch boundary exists. |
| SF-13 | U | URL is oversized, has userinfo/fragment, lexical localhost/.local name, an IP literal in a blocked class, or >16 DNS answers | Rejected before transport (or immediately after the bounded DNS result). |
| SF-14 | U | Four concurrent URL previews occupy fetch slots | Fifth request is rejected before URL parsing/DNS/network work; RAII releases every failed slot. |
| SF-15 | U | TLS/connect/HTTP failure includes a secret query in the original or redirect URL | Public error contains only finite code/stage/localization key and `detail=null`. |

### 4.2 Share links and lists

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| SP-01 | U | VLESS TCP+TLS, IPv4/hostname, percent-encoded name | Correct canonical node. |
| SP-02 | U | VLESS REALITY + Vision (`pbk`, `sid`, `sni`, `fp`, `flow`) | No field loss; correct sing-box TLS/REALITY mapping. |
| SP-03 | U | VLESS WS and gRPC supported variants | Correct bounded transport mapping; generated config validates. |
| SP-04 | U | VLESS missing UUID/host/port, invalid UUID, unsupported flow/security/transport | Node rejected with field-specific reason; no downgrade. |
| SP-05 | U | VLESS `%25`/double-encoding, duplicate critical query key, control chars | Decode exactly once; ambiguity/control chars rejected. |
| SP-06 | U | `hysteria2://` and `hy2://` with encoded auth, default port, SNI, obfs; URI certificate pin supplied separately | Supported fields form a canonical node; `pinSHA256` fails closed until exact sing-box mapping is reviewed. |
| SP-07 | U | Hysteria2 userpass, IPv6 literal, port hopping supported by pinned schema | Correct mapping and config validation. |
| SP-08 | U | Hysteria2 `insecure=1` | Imported with persistent visible warning; config generation rejects without exact controller-owned approval. |
| SP-09 | U | Invalid Hysteria2 multi-port/unknown obfs/oversized ECH | Rejected or explicitly unsupported; no partial node. |
| SP-10 | U | `naive+https` and `naive+quic` with percent-encoded credentials | Correct canonical Naive mode/TLS/QUIC mapping. |
| SP-11 | U | Naive header contains CR/LF, auth override, invalid token, >16 headers, >8 KiB | Rejected. |
| SP-12 | U | Plain newline list with blank/comment lines | Supported links imported; stable order/names. |
| SP-13 | U | Standard base64 and base64url lists with/without padding/BOM/CRLF | One bounded decode; correct list. |
| SP-14 | U | Nested base64, base64 bomb, 64-KiB line, >2,000 nodes | Bounded rejection. |
| SP-15 | U | Mixed valid/invalid nodes | Result reports exact accepted/rejected counts and reasons; user chooses whether to commit partial valid set. |
| SP-16 | U | Duplicate nodes/names | Deterministic stable IDs; display-name disambiguation; secrets not part of user-visible ID. |

### 4.3 Clash YAML and sing-box JSON

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| PY-01 | U | Clash `proxies` with VLESS REALITY and Hysteria2 | Supported fields mapped; config fixtures validate. |
| PY-02 | U | YAML aliases/recursive alias/depth bomb/duplicate key/custom tag/multi-document | Bounded reject; no file/env evaluation. |
| PY-03 | U | Clash config includes rules, providers, external controller, DNS, scripts, paths | Entire import is rejected because only the top-level `proxies` key is allowed; none executed. |
| PY-04 | U | Clash `type:http` carrying Naive-looking server | Remains unsupported HTTP; never guessed as Naive. |
| PJ-01 | U | sing-box JSON containing standalone supported outbounds | Extract into canonical nodes; tags sanitized. |
| PJ-02 | U | JSON includes imported inbound/API/service/route/log path | Those objects never enter generated config. |
| PJ-03 | U | Supported outbound references detour/resolver/file path/unknown object | Reject node rather than preserve reference. |
| PJ-04 | U | Duplicate keys, huge number, NaN/infinite, excessive depth/string | Strict bounded failure. |
| PJ-05 | U | Raw imported JSON intentionally contains a command/path-like tag | Treated as display text only; never reaches command/path execution. |

## 5. Generated configuration tests

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| CG-01 | U/C | VLESS TLS fixture | Deterministic JSON; `sing-box check` succeeds. |
| CG-02 | U/C | VLESS REALITY + Vision fixture | `flow`, SNI, uTLS, public key, short ID preserved; check succeeds. |
| CG-03 | U/C | VLESS WS/gRPC fixtures | Check succeeds; no unsupported silent fallback. |
| CG-03A | U | Empty/omitted gRPC service and WS Host authorities with port/bracketed IPv6 | Accepted and mapped; malformed Host/control injection rejected. |
| CG-03B | U | Clash HY2 with `port` + `ports` and numeric `hop-interval`; ranged interval | Both ports validate, `ports` wins, fixed seconds normalize; interval range rejected. |
| CG-03C | U | URI/JSON/Clash `insecure`, exact approval, wrong-node or changed-security approval | Default reject; exact approval succeeds; mismatch and stale approval reject. |
| CG-04 | U/C | Hysteria2 TLS, obfs, IPv4/IPv6, hopping fixtures | Check succeeds for supported combinations. |
| CG-05 | U/C | Naive HTTPS/QUIC fixtures with adjacent pinned `libcronet.dll` | Check succeeds; package asserts DLL presence. |
| CG-06 | U | Each config has distinct `http-in`, `socks-in`, authenticated `health-in`, loopback-only listens | Structural assertion passes. |
| CG-07 | U | Attempt to configure listener on `0.0.0.0`/LAN | Generator API cannot represent it; validation fails. |
| CG-08 | U | `route.final` for global Direct/VPN | Always explicit `direct`/`selected`, never dependent on outbound order. |
| CG-09 | U | Health inbound route | First immutable matching route is `selected`; no direct/fallback alternative. |
| CG-10 | U | Same app in Direct and VPN lists | Canonical policy resolver reports conflict; no ambiguous config emitted. |
| CG-11 | U | Full process path with spaces/case difference/nonexistent path | Canonical Windows normalization; nonexistent path visible but safe. |
| CG-12 | U | Pinned 1.13 target | No 1.14-only fields; schema/version lint passes. |
| CG-13 | C | Invalid canonical node forced into generator | `sing-box check` failure blocks process start and returns sanitized cause. |
| CG-14 | U | Imported raw `route`, `inbounds`, `services`, file paths | Absent from generated output. |
| CG-15 | U | IPv6 enabled/disabled policy | Both families configured when enabled; explicit no-IPv6 policy when disabled. |
| CG-16 | U/C | TUN DNS policy=VPN | 1.13 `local` bootstrap + HTTPS remote schema validates; selected server uses bootstrap resolver; remote DNS is detoured only to selected. |
| CG-17 | U/C | TUN DNS policy=CurrentNetwork | Only reviewed local/current-network resolver path is emitted; UI warning flag is mandatory. |
| CG-18 | U | Imported node attempts to replace DoH server/name/path/detour | Cannot affect product-owned DNS constants or routing. |

## 6. Runtime and no-false-connected tests

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| HC-01 | C | Engine process starts but listener never opens | Never `Connected`; child terminated, clean error. |
| HC-02 | C | Listener opens but selected server rejects credentials | End-to-end proof fails; concrete sanitized protocol error. |
| HC-03 | C | Local health endpoint is reachable directly but selected outbound is broken | Forced health route fails; no direct fallback. |
| HC-04 | C/W | HTTPS 204 request through authenticated `health-in`/selected outbound | Only after success may state become `Connected`. |
| HC-05 | C | Probe DNS/connect/TLS/body stalls | One total deadline; cancellation; rollback. |
| HC-06 | C | Probe returns unexpected status/oversized body/redirect loop | Failure; no connected state. |
| HC-07 | C | Core exits immediately after successful response | State check catches death; no connected state. |
| HC-08 | C/W | Mode ownership changes between probe and publish verification | `Degraded`/rollback, not `Connected`. |
| HC-09 | C | Two consecutive periodic failures | `Degraded`; next successful fresh proof returns to Connected according to policy. |
| HC-10 | C | Egress-IP endpoint unavailable but 204 proof succeeds | Connected with `VPN egress IP unavailable`, not a fabricated IP. |
| HC-11 | W | Current network already traverses another VPN | Direct baseline labeled `current network egress`; selected proof remains independently routed through `health-in`. |
| HC-12 | C | Server TCP connect/ICMP succeeds while protocol auth fails | UI never uses TCP/ICMP as proof or protocol latency. |
| HC-13 | C | Latency result resolves to private/fake-TUN address | Result discarded; UI shows unavailable rather than 1–4 ms. |

## 7. System Proxy ownership and coexistence tests

All W/H proxy tests snapshot the exact WinINet per-connection state before execution and verify final equality.

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| PX-01 | U | Serialize/normalize every flags/server/bypass/PAC/autodetect combination | Lossless round trip and equality semantics. |
| PX-02 | U | Atomic journal interrupted before rename | Original journal remains valid or no journal; never truncated accepted state. |
| PX-03 | W | No prior proxy; RouteDeck starts System Proxy | Journal `Prepared` before write, exact published snapshot after refresh, then traffic proof. |
| PX-04 | W | v2rayN proxy is active before RouteDeck takeover | Capture it as original only after explicit user takeover; RouteDeck endpoint becomes exact current state. |
| PX-05 | W | RouteDeck stops while current equals published | Exact original restored and verified; journal deleted. |
| PX-06 | W | Current already equals original at stop/recovery | Idempotent success; unrelated state untouched. |
| PX-07 | W | Repeated connect/disconnect/stop | Serialized/idempotent; no leaked listener/journal. |
| PX-08 | W | User edits proxy while RouteDeck runs | Immediate `Degraded — changed by another app`; stop does not overwrite edit. |
| PX-09 | W | v2rayN stops after RouteDeck starts and restores stale proxy | Ownership watcher detects displacement; no false Connected; journal retained. |
| PX-10 | W | Foreign proxy happens to use same port but different mapping/bypass/PAC | Not considered owned; no restore. |
| PX-11 | W | Proxy query returns access/type/partial failure | Hard conflict; no write/restore. |
| PX-12 | W | Crash after journal `Prepared`, before Windows write | Startup sees current=original, clears safely. |
| PX-13 | W | Crash after Windows write, before journal `Applied` | Startup compares exact published state and restores original. |
| PX-14 | W | Crash with a foreign later state | Startup preserves foreign state and journal; actionable recovery UI. |
| PX-15 | W | System Proxy points RouteDeck but core dies | Watcher reports dead listener immediately and attempts owned restoration; never remains green. |
| PX-16 | W | HTTP and SOCKS ports already occupied | Startup fails before proxy write; owning foreign processes untouched. |
| PX-17 | W/H | Browser honors Windows proxy | Browser proof/IP changes through selected node. |
| PX-18 | W/H | App ignores Windows proxy/uses direct UDP | UI does not claim capture; diagnostics explain System Proxy limitation. |
| PX-19 | U/W | Global Direct, one app VPN in System Proxy | Best-effort behavior labeled accurately; never promoted to reliable full split tunneling. |
| PX-20 | W | Stop with restoration conflict | Preserve journal/evidence; stop/retain listener according to currently published endpoint without dead-proxy window. |
| PX-21 | U/W | Active RAS connection has distinct per-connection proxy state | Hard unsupported conflict; RouteDeck does not partially write LAN or RAS state. |
| PX-22 | U/W | Existing proxy/PAC/autodetect changes after takeover preview | Snapshot-bound consent becomes stale; no Windows write. |
| PX-23 | W | GUI is killed while the exact RouteDeck proxy is published | Ephemeral unprivileged guardian restores exact original promptly; next startup verifies clean journal state. |
| PX-24 | W | Guardian dies while GUI/core remain alive | Immediate Degraded; controlled exact recovery; never leave a green or dead published endpoint. |
| PX-25 | W | Policy rewrites WinINet immediately after RouteDeck set | Exact reread fails or watcher detects displacement; no write loop and no blind reclaim. |
| PX-26 | U/W | Journal has foreign ACL/owner, reparse, invalid DPAPI, over-size, truncation, or unknown schema | Quarantine/RecoveryRequired; no Windows write or secret disclosure. |
| PX-27 | W | WinINet or listener ownership changes after HTTPS proof but before final publish | Post-proof recheck blocks Connected and begins exact recovery. |

## 8. TUN privilege, routes, DNS, and routing tests

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| PR-01 | U | GUI executable manifest | `asInvoker`, `uiAccess=false`. |
| PR-02 | W | Enable TUN | One on-demand UAC prompt; no service/task/startup entry installed. |
| PR-03 | W | User denies/cancels UAC | Clean `UAC cancelled`; no process/adapter/route/journal leak. |
| PR-04 | W | Helper starts fixed verified engine | Engine/config/package identity accepted; listener/adapter/routes verified. |
| PR-05 | U/W | Renderer supplies arbitrary executable path/args/env/shell metacharacters | IPC schema rejects/unrepresentable; nothing executed. |
| PR-06 | U/W | Renderer supplies registry root/service/route command/arbitrary file path | Rejected/unrepresentable. |
| PR-07 | W | Replace engine/DLL after UI validation before helper launch | Helper re-verifies and refuses (TOCTOU test). |
| PR-08 | W | Swap/reparse generated config path | Helper uses validated handle/private object or rejects identity change. |
| PR-09 | W | Named-pipe connection from another user/anonymous | ACL/authentication denies. |
| PR-10 | W | Same-user stale session/nonce replay | Session challenge rejected after first use/expiry. |
| PR-11 | W | PID reused after parent exits | Parent creation-time mismatch causes cleanup; no stale authorization. |
| PR-12 | W | GUI crashes/forced termination | Helper detects it; Job Object kills core; route/adapter cleanup verified. |
| PR-13 | U/W | Helper is unsigned, wrong signer/version, wrong exact hash, or has an invalid component manifest | Release build refuses before UAC/state mutation; test-signed development helper is limited to disposable VM. |
| PR-14 | U/W | Pipe squatting, remote client, second instance, wrong peer image, stale sequence, duplicate/unknown fields, or over-size frame | Fixed ACL/peer authentication/closed schema rejects the session; no mutation. |
| PR-15 | W | Renderer or stale controller substitutes a config handle | Only a native registered handle from the authenticated GUI is duplicated; type/file ID/DACL/reparse/hash/schema mismatch is rejected. |
| PR-16 | W | Core attempts work before Job assignment or spawns an early child | Suspended create, Job assignment, then resume prevents escape; closing the job kills the full tree. |
| TN-01 | U | Preflight route/adapter fixtures: no other tunnel | Unique prefixes/interface selected. |
| TN-02 | U/W | RouteDeck example prefix already present | Choose non-overlapping prefix or refuse; never overwrite route. |
| TN-03 | W | TUN start with IPv4+IPv6 | Both captured according to policy; no family leak. |
| TN-04 | W | IPv6 explicitly disabled | No silent IPv6 direct leak; UI reflects disabled state. |
| TN-05 | W | `strict_route=true` DNS leak checks | DNS follows intended RouteDeck handling; known incompatible app warning available. |
| TN-06 | W | Selected server route could recurse into RouteDeck TUN | Interface binding prevents loop; end-to-end proof succeeds. |
| TN-07 | W | Default Direct, selected browser VPN | Browser egress is selected; unrelated test app follows direct/current-network egress. |
| TN-08 | W | Default VPN, selected browser Direct | Browser follows direct/current network; unrelated app uses selected egress. |
| TN-09 | W | Match by full path with two same-name executables | Only configured path matches. |
| TN-10 | W | Process starts after connection, restarts, has spaces/unicode path | Policy continues to apply. |
| TN-11 | W | TCP and UDP/QUIC traffic for both routing defaults | Both obey supported outbound/routing behavior; limitations explicit. |
| TN-12 | W | LAN access with LAN=Direct versus FollowDefault | Exact configured behavior; no accidental management/LAN loss. |
| TN-13 | W | Network changes Wi-Fi/Ethernet while connected | Re-evaluate upstream, degrade during ambiguity, re-prove before green. |
| TN-14 | W | Sleep/resume | Stale adapter/routes reconciled; new proof required. |
| TN-15 | W | Core crashes while TUN active | Job/helper cleanup and `Degraded/Disconnected`, no green state. |
| TN-16 | W | Normal stop | Adapter/routes/DNS gone before helper exits; repeated stop succeeds. |
| TN-17 | W | Simulated reboot/power loss with journal | Next startup finds no live owner, reconciles safely, never deletes foreign routes. |
| TN-18 | W | DNS policy=VPN with default Direct + one VPN app | All captured DNS traverses selected while payload split remains correct; UI explains that Direct apps' DNS also uses VPN. |
| TN-19 | W | DNS policy=CurrentNetwork with VPN app | Payload split remains correct; observable current-network DNS and warning are accepted behavior, never described as leak-free. |
| TN-20 | U/W | Dynamic IPv4/IPv6 prefix and interface-name allocation across occupied adapter/route fixtures | Random `/30` and `/126` do not overlap; interface name is session-unique; fixed sample values never reach production. |
| TN-21 | W | Adapter/route/DNS/best-path state changes between consent and helper launch | Preflight hash/revalidation fails before TUN mutation and requires a new user choice. |
| TN-22 | W | Route/interface/address notification while Connected | Immediate Degraded; exact state and outbound are re-proved before green returns. |
| TN-23 | U/W | Residual or foreign route shares RouteDeck name, prefix, metric, or index but not complete LUID/GUID/row identity | Rollback leaves it untouched and preserves journal/evidence. |
| TN-24 | W | Foreign System Proxy remains enabled during RouteDeck TUN | UI labels nested/best-effort; per-app acceptance is not claimed because traffic may be attributed to the foreign proxy core. |
| TN-25 | W | Helper or OS dies during each TUN journal phase | Job cleanup and startup reconciliation remove only exact owned state; ambiguity becomes RecoveryRequired. |

## 9. Coexistence with v2rayN/another VPN

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| CO-01 | W/H | v2rayN System Proxy active; RouteDeck only starts local core/ports | Both listeners coexist; Windows remains owned by v2rayN; RouteDeck does not claim system capture. |
| CO-02 | W/H | Explicit RouteDeck System Proxy takeover | Prior exact v2rayN state journaled; RouteDeck owns global state; restore returns exact v2rayN snapshot if unchanged. |
| CO-03 | W/H | v2rayN changes proxy after takeover | RouteDeck degrades and refuses blind restore. |
| CO-04 | W | Another TUN/default VPN detected, choose Cancel | No UAC/state mutation. |
| CO-05 | W/H | Another VPN active, choose current path/nested | RouteDeck selected-server connection may traverse upstream VPN; UI labels nested; selected outbound proof passes. |
| CO-06 | W/H | Another VPN active, choose physical NIC | Exact physical interface bound, revalidated prelaunch; selected proof bypasses upstream when routing permits. |
| CO-07 | W | Selected physical NIC disconnects | RouteDeck degrades/stops safely; does not silently switch through foreign tunnel. |
| CO-08 | W | Ambiguous equal-metric defaults/tunnel adapter identity | Explicit choice required; no automatic mutation. |
| CO-09 | W | Other VPN starts or stops while RouteDeck TUN runs | Route/ownership watcher detects change; re-proof or degrade; no false green. |
| CO-10 | W | Prefix, DNS, or default-route conflict discovered post-start | Rollback RouteDeck-owned state only; preserve other VPN. |
| CO-11 | H | User's real v2rayN remains running throughout non-mutating local listener/protocol test | No process termination or setting change; selected node can still be validated through explicit local health proxy. This is permitted before the Windows-mode VM gate because it publishes neither System Proxy nor TUN. |
| CO-12 | W | Foreign System Proxy feeds a foreign core while RouteDeck TUN is active | RouteDeck observes and explains the attribution boundary; browser-specific rules are not certified reliable. |

## 10. Protocol end-to-end acceptance

Real server credentials are never committed or printed. W uses dedicated test credentials; H uses user-provided existing nodes and redacted diagnostics.

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| E2-01 | W/H | VLESS + REALITY + Vision over System Proxy health inbound | Full HTTPS proof, credible route-check latency, egress IP when endpoint available. |
| E2-02 | W/H | Same VLESS node in TUN | Full proof plus browser/app routing case. |
| E2-03 | W/H | Hysteria2 over System Proxy health inbound | Full proof; UDP protocol error clearly surfaced if blocked. |
| E2-04 | W/H | Hysteria2 in TUN | Full proof and UDP/QUIC routing test. |
| E2-05 | W/H | Naive HTTPS with adjacent pinned `libcronet.dll` | Full proof; no missing-library fallback. |
| E2-06 | W/H | Naive QUIC if supplied by fixture | Full proof or explicit network/protocol failure; never direct fallback. |
| E2-07 | W/H | Wrong VLESS UUID/REALITY key/HY2 password/Naive password | Never Connected; sanitized protocol-specific failure. |
| E2-08 | W/H | TLS certificate failure with `insecure=false` | Fail closed; no auto-toggle. |
| E2-09 | W/H | Same node with user-imported `insecure=true` | Works only if user accepted persistent warning; diagnostics retain warning without secret. |
| E2-10 | W/H | Switch node/protocol while connected | Quiesce, restore/stop old session, validate/prove new; rollback leaves deterministic state. |

## 11. Crash, shutdown, and fault injection

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| CR-01 | U | Failure injected at every connection state transition | Deterministic rollback; journal phase accurately represents durable state. |
| CR-02 | W | Kill UI during config validation | No global state change, no orphan. |
| CR-03 | W | Kill UI after listener, before System Proxy publish | Child terminated; proxy unchanged. |
| CR-04 | W | Kill UI after System Proxy publish | Startup/guardian restores only exact owned state. |
| CR-05 | W | Kill UI during proxy restore | Reconciliation resolves exact original/published/foreign cases safely. |
| CR-06 | W | Kill elevated helper during TUN start | Job kills child; partial adapter/routes removed or flagged with exact manual recovery. |
| CR-07 | W | Kill UI and helper while TUN connected | OS/process cleanup verified; startup scans residual state. |
| CR-08 | W | Disk full/access denied during journal/config write | No Windows state mutation; actionable error. |
| CR-09 | W | Corrupt/truncated/unknown-version journal | Quarantine and show manual recovery; never overwrite current state. |
| CR-10 | W | Shutdown/logout notification | Bounded cleanup attempt; durable evidence preserved if Windows ends process early. |
| CR-11 | W | Engine ignores graceful stop | After owned state restoration, bounded terminate via Job Object; no dead published proxy. |
| CR-12 | U/W | Concurrent Connect/Disconnect/Retry clicks | Serialized state machine; one owner/session; idempotent result. |

## 12. Secrets, logging, and diagnostics tests

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| SE-01 | U | Corpus places secrets in URI userinfo/query/fragment, JSON/YAML fields, headers, nested errors | Redacted before log/event/export. |
| SE-02 | U | Mixed-case and percent-encoded secret keys | Redacted after safe parse without revealing decoded value. |
| SE-03 | U | sing-box stderr repeats UUID/password/server URI | Structured sanitizer removes it before persistence/UI. |
| SE-04 | U | Subscription fetch error contains full URL | User sees only a finite code, stage, and localization key; URL, host, status text, and secret are absent. |
| SE-05 | W | At-rest node/subscription files inspected as another user | DPAPI/ACL prevents useful disclosure. |
| SE-06 | W | Runtime config ACL and lifecycle | Current user/elevated helper only; removed after stop when possible. |
| SE-07 | U | Redacted diagnostics export | Contains version/hash prefix/stages/errors, never credentials/raw configs/captured IP. |
| SE-08 | U | Clipboard raw export | Explicit warning and deliberate action required; redacted is default. |
| SE-09 | U | UI toast with malicious node name/HTML/control chars | Rendered as text, bounded/opaque/readable; no injection or secret spill. |
| SE-10 | U | Logs under repeated failures | Size/retention bounded; redaction invariant remains. |

## 13. UI-facing correctness and resizing checks

| ID | Tier | Case | Expected result |
| --- | --- | --- | --- |
| UI-01 | U/manual | State labels for every state-machine stage | No green Connected before proof; Degraded distinct from Connected. |
| UI-02 | manual | System Proxy mode page | Clearly states app compliance limitation and best-effort per-app behavior. |
| UI-03 | manual | TUN toggle | Explains UAC, no permanent service, and detected other-VPN choices before prompt. |
| UI-04 | manual | Global routing control | `Everything else: Direct/VPN` visible; app overrides unambiguous. |
| UI-05 | manual | Proxy conflict | Shows current ownership loss, safe choices, and does not bury action under translucent toasts. |
| UI-06 | manual | Narrow/minimum window, 100/125/150/200% scaling, long RU/EN text | All controls reachable; scrolling correct; no clipped dialogs/toasts. |
| UI-07 | manual | Protocol/import errors | Opaque, high-contrast, selectable details; sensitive text redacted. |
| UI-08 | manual | Latency/IP | Labels distinguish route check, VPN egress, and current-network egress; unavailable is `—`. |

## 14. Final host smoke sequence

Run only after independent security review and the hard VM gate in section 2.1 passes:

1. Record (do not alter) current processes, WinINet proxy snapshot, adapters, IPv4/IPv6 routes, DNS, and RouteDeck ports; redact addresses in saved diagnostics.
2. With the user's other VPN still running, start RouteDeck core in local-only mode. Verify distinct HTTP/SOCKS/health ports and prove VLESS, Hysteria2, and Naive through the explicit health proxy without publishing System Proxy or TUN.
3. Test System Proxy only after the UI presents existing ownership and the user explicitly chooses takeover. Verify browser egress, ownership watcher, exact restore, and v2rayN displacement behavior.
4. Test TUN only after route preflight presents nested/physical/cancel and the user selects one. The first reliable per-app host case runs without a foreign TUN or foreign System Proxy. Verify both routing defaults, a selected browser app, IPv4/IPv6, DNS, and exact cleanup; destructive sleep/crash/network-flap cases remain VM-only.
5. Stop RouteDeck. Assert no RouteDeck process/listener/adapter/route/journal remains unless a deliberate proxy conflict retained evidence. Assert the other VPN process and state were not stopped or modified outside the user's explicit choice.
6. Repeat one clean connect/disconnect to prove recovery is not dependent on the first run.

Any unexplained host-state difference, missing proof, foreign-state overwrite, secret in diagnostics, or green state during failure blocks release.
