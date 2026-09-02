# Safe Windows mode ownership

- Status: normative implementation design
- Scope: Windows 10/11 x64 System Proxy and TUN ownership
- Engine baseline: pinned sing-box 1.13.21 Windows x64 artifact
- Security boundary: ordinary RouteDeck/Tauri process remains `asInvoker`

This document refines the Windows sections of [the core specification](core-spec.md)
and the acceptance gates in [the test matrix](test-matrix.md). If an implementation
choice conflicts with this document, it must fail closed until the discrepancy is
reviewed.

## 1. Safety invariants

1. Local listeners, Windows System Proxy, and TUN are three different scopes. A
   successful local proxy proof does not prove either Windows mode owns traffic.
2. The ordinary GUI is never elevated. System Proxy changes only the current user's
   WinINet state. TUN uses a fixed on-demand elevated helper and installs no service,
   task, startup entry, or persistent privileged process.
3. A mode becomes `Connected` only after a selected-outbound HTTPS proof and a second
   exact verification of the child, listeners, journal, and mode-owned Windows state.
4. Every Windows mutation is preceded by a durable journal containing the exact
   original state and the exact intended state. Restore is compare-before-write and
   compare-before-restore.
5. A name, port, prefix, PID, or interface index alone never proves ownership. Process
   creation time, file identity, session identity, and complete state identity are
   required where applicable.
6. A later user or VPN change is foreign state. RouteDeck degrades immediately and
   never overwrites that state during stop or recovery.
7. Two local proxy listeners may coexist on different ports. Windows exposes one
   effective System Proxy configuration per user, and two TUN/default-route owners are
   not assumed compatible.
8. Windows mutation code is behind mockable native traits. Unit tests never query or
   change live proxy, registry, routes, DNS, adapters, services, or VPN processes.

## 2. Native ownership boundary

Keep protocol parsing and config generation independent from Windows state. The native
controller owns a serialized mode operation and calls narrow platform interfaces such
as:

```text
ProxyBackend       query / publish exact snapshot / refresh
ProxyJournalStore  prepare / advance / reconcile / quarantine
ProxyGuardian      apply / restore / report exact ownership
TunPreflight       read-only adapters, routes, DNS, and best paths
TunHelperTransport authenticated fixed-schema helper session
ModeOwner          publish / prove / stop / reconcile
```

The renderer may request product operations using opaque native IDs. It cannot provide
an executable path, registry root, proxy string, bypass list, PAC URL, pipe name,
interface name, route, DNS address, config path, service name, shell command, arguments,
environment, or output path. The controller resolves all OS objects from its private
state.

All connect, switch, disconnect, retry, guardian, and startup-reconcile operations use
one controller operation lock. Results and events carry a monotonic revision and a
session ID so stale UI work cannot publish an older ownership result.

## 3. Windows System Proxy

### 3.1 WinINet API and connection scope

Use Unicode `InternetQueryOptionW` and `InternetSetOptionW` with
`INTERNET_OPTION_PER_CONNECTION_OPTION` and an
`INTERNET_PER_CONN_OPTION_LISTW`. Microsoft defines a null `pszConnection` as the
default/LAN connection. Do not write the Internet Settings registry keys directly and
do not modify WinHTTP proxy state.

The first release manages only the default/LAN connection. If an active RAS connection
has a distinct per-connection proxy configuration, RouteDeck reports an unsupported
connection conflict rather than partially changing several connection records.

The query reads:

- `INTERNET_PER_CONN_FLAGS_UI`, falling back to `INTERNET_PER_CONN_FLAGS` only when the
  UI query is unavailable;
- raw `INTERNET_PER_CONN_FLAGS`, which is the value restored;
- `INTERNET_PER_CONN_PROXY_SERVER` and `INTERNET_PER_CONN_PROXY_BYPASS`;
- `INTERNET_PER_CONN_AUTOCONFIG_URL` and
  `INTERNET_PER_CONN_AUTODISCOVERY_FLAGS`;
- settable secondary auto-config URL and reload-delay fields when supported by the OS.

WinINet allocates queried strings; every returned allocation is released with
`GlobalFree`. Read-only auto-detection history is diagnostic metadata and is not part of
equality because Windows may update it concurrently.

```text
ProxySnapshot {
  connection: DefaultLan,
  flags_ui,
  flags_restore,
  proxy_server: NullableString,
  proxy_bypass: NullableString,
  auto_config_url: NullableString,
  auto_discovery_flags,
  auto_config_secondary_url: Unsupported | NullableString,
  auto_config_reload_delay: Unsupported | Value,
}
```

Foreign strings are preserved exactly as returned. Do not reorder proxy mappings or
bypass entries. Equality is field-for-field after only documented, deterministic API
normalization such as the query's null representation. A partial query, inconsistent
flags, unsupported value type, access failure, or invalid string is a hard conflict.

Official references:

- [`INTERNET_PER_CONN_OPTION_LISTW`](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw)
- [`INTERNET_PER_CONN_OPTIONW`](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)
- [WinINet option flags](https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags)

### 3.2 Published snapshot and explicit takeover

RouteDeck constructs, rather than imports, the published state:

```text
flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
server: http=127.0.0.1:<http-port>;https=127.0.0.1:<http-port>
bypass: a fixed, versioned, reviewed local/private bypass policy
```

The SOCKS listener remains available for manual clients but is not published as the
Windows HTTP proxy. PAC and automatic discovery flags are disabled while RouteDeck
owns the setting, but their inactive values are retained in the snapshot so restoration
is lossless.

If the current snapshot has a manual proxy, PAC URL, or automatic discovery enabled,
the UI shows a non-secret summary and requires explicit takeover. Consent is represented
by a short-lived native token bound to the RouteDeck session and a hash of the complete
observed snapshot. Immediately before mutation, the guardian re-queries the snapshot
and requires the same hash. A changed snapshot invalidates consent.

Publishing is one per-connection set operation followed by
`INTERNET_OPTION_SETTINGS_CHANGED`, `INTERNET_OPTION_REFRESH`, and an authoritative
re-query. RouteDeck proceeds only when the re-query exactly equals the journaled
published state. A policy or another client that immediately changes the setting causes
`ProxyConflict`; it is never fought by a write loop.

### 3.3 Durable journal

The journal lives below the current user's local application-data directory, never next
to the portable executable. Its parent directory and file have explicit restrictive
ACLs, are checked for reparse points and ownership, and accept only a regular bounded
file. The payload is protected with DPAPI CurrentUser because captured proxy and PAC
URLs may contain sensitive information.

```text
ProxyJournal {
  schema_version,
  app_build,
  session_uuid,
  generation,
  owner_pid,
  owner_process_creation_time,
  created_at,
  phase: Prepared | Applied | Restoring | Conflict,
  original: ProxySnapshot,
  published: ProxySnapshot,
  published_listener: { http_port, core_pid, core_process_creation_time },
  original_hash,
  published_hash,
}
```

Updates use a create-new temporary file, a bounded complete write,
`FlushFileBuffers`, and an atomic replace/rename with write-through semantics. Windows
state is not changed unless durable `Prepared` already contains both snapshots. Unknown,
truncated, undecryptable, over-sized, or invalid-version journals are quarantined and
cause `RecoveryRequired`; their contents are not treated as permission to write.

The state sequence is:

```text
query exact original
  -> persist Prepared(original, published)
  -> compare current == original
  -> set published + refresh + query exact
  -> persist Applied
  -> prove traffic
  -> compare journal/current/listeners/process again
  -> Connected(SystemProxy)
```

### 3.4 Compare-before-restore and recovery

Stop and startup reconciliation use the same truth table regardless of the recorded
phase:

| Current WinINet state | Action |
| --- | --- |
| exactly `published` | Persist `Restoring`, restore exact `original`, refresh, re-query, then delete journal. |
| exactly `original` | Cleanup is already complete; delete the journal after validation. |
| anything else | Preserve journal and evidence, write nothing, enter `ProxyConflict`. |
| unreadable or partial | Preserve journal and write nothing; enter `RecoveryRequired`. |

This covers a crash after `Prepared`, a crash after Windows accepted the new state but
before `Applied`, and a crash during restore. No recovery action has a generic force
option. A narrowly designed future reclaim operation must still bind user consent to the
complete current snapshot.

A watcher re-queries WinINet periodically while ownership is claimed. A Windows settings
notification may wake the watcher but is never trusted as the state itself. Any mismatch
immediately removes the green state. If Windows still points to RouteDeck, restoration
must complete before the local core is terminated so Windows is not left with a dead
proxy. If Windows contains foreign state, RouteDeck may stop its core but preserves the
journal and does not alter that state.

### 3.5 Ephemeral proxy guardian

Startup reconciliation alone can leave a dead localhost proxy between a GUI crash and
the next launch. System Proxy therefore uses a separate, fixed, unprivileged
`routedeck-proxy-guardian` process. It is ephemeral: it installs no service, scheduled
task, startup entry, or persistent process.

The guardian starts before publication and is the component that captures, journals,
publishes, verifies, watches, and restores WinINet state. It accepts only a typed session
request with an opaque session ID and a controller-registered listener port. It builds
the proxy string and bypass list itself. It monitors the GUI PID and process creation
time; on GUI death it restores only an exact published snapshot. If both processes or
the OS fail, the durable journal remains for startup reconciliation.

The guardian is a separately verified sidecar and uses authenticated, bounded IPC like
the TUN helper, without elevation. A guardian failure while the GUI is alive immediately
degrades the mode and starts exact controlled recovery. Combining the guardian with the
elevated TUN helper is rejected because it unnecessarily enlarges the privileged binary.

### 3.6 Ownership proof and limitations

System Proxy ownership is true only when all are current for the same session:

- the journal is valid and `Applied`;
- the authenticated guardian is alive;
- WinINet exactly equals `published`;
- the published HTTP listener belongs to the expected live core process;
- all local listener ownership checks pass;
- the HTTPS request forced through `health-in` and `selected` succeeds;
- the core, listener ownership, guardian, journal, and WinINet snapshot still pass after
  that request.

The UI still states that compliant applications may ignore System Proxy or send QUIC/UDP
directly. Mode ownership is not proof that every application is captured.

## 4. TUN elevation boundary

### 4.1 Fixed helper and launch

TUN uses a separate minimal Rust executable with no Tauri or WebView code. The GUI
manifest remains `asInvoker`; the helper has a reviewed administrator manifest and is
started only after an explicit TUN action using a fully qualified fixed path and
`ShellExecuteExW` with the `runas` verb. The caller retains the returned process handle.
UAC cancellation returns a typed `UacCancelled` result and leaves no journal, process,
adapter, route, or DNS change.

The portable release is built in two passes: first the helper, then the GUI with the exact helper
SHA-256 embedded. Before UAC the GUI requires that exact hash, a fixed sibling path, a regular
non-reparse file and a held handle that denies write/delete replacement through launch. Missing
or mismatched hashes fail closed. Authenticode may be recorded as additional provenance but is
not required for a locally built portable pair. The helper still authenticates the GUI peer and
independently verifies the pinned engine, DLL, config and protected session identity.

The helper never accepts an executable path, arbitrary command, arguments, environment,
working directory, config path, registry path, route command, interface command, service
name, or destination path.

Official references:

- [`SHELLEXECUTEINFO`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow)
- [Application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests)

### 4.2 Authenticated named-pipe protocol

The GUI creates the pipe before UAC with a random fixed-prefix name,
`FILE_FLAG_FIRST_PIPE_INSTANCE`, one instance, duplex message or explicit length-framed
mode, overlapped I/O, bounded timeouts, and `PIPE_REJECT_REMOTE_CLIENTS`. Its explicit
security descriptor grants only the launching user SID, Administrators, and SYSTEM the
minimum required rights. The Windows default pipe ACL is forbidden because it grants
read access to Everyone and anonymous users.

After connection, both sides verify peer PID, process creation time, image file identity,
and fixed sibling image identity. The pipe server uses `GetNamedPipeClientProcessId`; the helper
performs the corresponding server-process check. A fresh random challenge is sent inside
the authenticated pipe, never on the command line. The session admits one start,
monotonic request sequence numbers, bounded request IDs, one-time nonces, and expiry.

The command line contains only a strictly validated opaque session UUID, pipe suffix,
and parent PID/creation-time tuple. It contains no secret and no filesystem path selected
by a renderer.

```text
Hello / Challenge
StartTun { session_id, registered_config_handle_id, upstream_choice_id, preflight_hash }
StopTun  { session_id }
Status
```

Frames use a versioned closed schema, `deny_unknown_fields`, duplicate-key rejection,
strict enum and string bounds, a small total size cap, and no trailing data. Unknown
versions, messages, or state transitions are rejected. A stale nonce, stale parent,
replayed `StartTun`, or second client cannot mutate state.

Official references:

- [`CreateNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [`GetNamedPipeClientProcessId`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [Named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

### 4.3 Config and engine handles

The renderer never supplies a config path. The native controller creates a private,
bounded, regular config file and retains a handle that denies write and delete sharing.
After peer authentication, the helper duplicates the native registered handle from the
verified GUI process and validates file type, size, file ID, owner/DACL, reparse status,
hash, and the strict RouteDeck-generated config schema.

The helper resolves the engine and DLL only from the embedded reviewed component lock. It opens
and holds both without write/delete sharing, verifies exact sizes, hashes, file IDs, and
package-relative identities, then revalidates immediately before launch. It invokes only
fixed `sing-box check` and run argument shapes, fixed environment, and a fixed working
directory.

The core is created suspended, assigned to a helper-owned Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then resumed. The helper monitors both
pipe and GUI PID plus process creation time to prevent PID-reuse authorization. Closing
the helper's final job handle terminates the entire core process tree.

## 5. TUN preflight and other-VPN coexistence

### 5.1 Read-only preflight

Before UAC, enumerate IPv4 and IPv6 state using `GetAdaptersAddresses`,
`GetIpForwardTable2`, interface metric APIs, and `GetBestRoute2` for every resolved
selected-server address. Preserve interface LUID and GUID as identity; interface index
and display name are descriptive only. Observe DNS servers from adapter state.

Tunnel detection is a warning signal, not ownership proof. Consider tunnel/PPP interface
types, point-to-point traits, active default routes, effective route plus interface
metrics, and the actual best route to the selected server. Do not identify or terminate a
VPN merely from a process or adapter name.

Allocate a random unused RFC1918 `/30` and ULA `/126` by checking every adapter unicast
prefix and route prefix. Fixed sample addresses are forbidden in production. Use a
session-unique bounded interface name. Refuse before UAC on:

- any candidate prefix overlap;
- a stale RouteDeck adapter/session not exactly owned by a journal;
- no usable upstream;
- ambiguous equal-metric defaults without an explicit user choice;
- inconsistent IPv4 and IPv6 upstream choices;
- a selected physical interface that cannot be re-identified exactly.

Official references:

- [`GetAdaptersAddresses`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)
- [`GetIpForwardTable2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2)
- [`GetBestRoute2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)
- [`NotifyRouteChange2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)

### 5.2 Upstream choices

When another default tunnel or VPN is likely, no route option is preselected:

1. **Cancel** makes no change and is the safe default.
2. **Nested/current path** uses reviewed automatic interface detection. The selected
   outbound may itself traverse the current VPN; the UI labels the result nested.
3. **Physical interface** uses an explicitly selected, verified up, non-loopback,
   non-tunnel Ethernet/Wi-Fi interface. Its LUID/GUID, state, and route are revalidated
   immediately before UAC and again by the helper. The pinned sing-box config uses the
   reviewed `route.default_interface` or outbound `bind_interface` representation.

The complete preflight snapshot is hashed into the user's choice. Any relevant route,
adapter, DNS, or best-path change before launch invalidates it and returns to preflight.
While connected, route, interface, and address notifications immediately remove the
green state, trigger a new snapshot, and require a fresh traffic proof before recovery.

The generated configuration follows the pinned sing-box 1.13 schema and uses dynamic
addresses, the session-unique interface name, `auto_route`, and reviewed `strict_route`
semantics. The selected server path must bypass the RouteDeck TUN. IPv4 and IPv6 are
both captured, or IPv6 is explicitly disabled and verified. See the official
[sing-box TUN documentation](https://sing-box.sagernet.org/configuration/inbound/tun/).

### 5.3 Foreign System Proxy while TUN is active

A foreign Windows System Proxy is not merely cosmetic. A proxy-aware browser first
connects to that foreign localhost listener, so RouteDeck TUN may observe the foreign
proxy core rather than the browser process. This can invalidate per-application routing
expectations even when both products' processes remain running.

TUN preflight therefore reports an active foreign System Proxy separately. Leaving it
enabled is an explicitly labelled nested/best-effort configuration, not a reliable
per-app test. RouteDeck never silently disables or takes over the foreign proxy. Reliable
per-app acceptance is tested with no foreign System Proxy or through the separately
consented System Proxy ownership flow.

## 6. TUN journal, rollback, and recovery

The elevated helper durably records:

```text
TunJournal {
  schema_version,
  session_uuid,
  parent/helper/engine identity,
  preflight_hash,
  phase: Prepared | Starting | Applied | Stopping | Conflict,
  chosen_prefixes,
  upstream_interface_luid_and_guid,
  expected_interface_name,
  observed_owned_interface_luid_and_guid,
  exact_owned_route_keys,
  expected_dns_policy,
}
```

The pre-start snapshot and journal are durable before the helper starts the core. After
startup, the helper observes the adapter/route difference and requires the exact expected
interface, IPv4/IPv6 routes, upstream bypass, and DNS policy before the controller can
prove traffic.

Normal stop is:

1. reject new work and stop periodic probes;
2. request helper shutdown;
3. gracefully stop the core, then close the Job Object after a bounded timeout;
4. verify that exact owned adapter, routes, and DNS effects disappeared;
5. remove the journal only after verified cleanup;
6. terminate remaining local listeners and publish `Disconnected`.

RouteDeck does not delete by interface name, index, prefix, route destination, or metric
alone. A narrowly reviewed cleanup may remove a route only when its interface LUID/GUID
and complete route identity exactly equal the journaled owned row. Otherwise the helper
preserves evidence and reports `RecoveryRequired` with manual guidance.

On GUI death the helper closes the job, verifies cleanup, records the outcome, and exits.
On reboot or next launch, absent objects mean cleanup is complete. Exact stale objects
require a new, narrow elevated `CleanupStaleSession(journal_digest)` after user
confirmation. Any mismatch is foreign and remains untouched.

## 7. Ownership proof and mode state

Recommended mode proof rows are:

```text
engine_config
engine_process
http_listener
socks_listener
health_listener
selected_outbound_https
windows_proxy_journal
windows_proxy_snapshot
proxy_guardian
tun_adapter
tun_ipv4_routes
tun_ipv6_routes
tun_dns_policy
upstream_path
```

Only the rows applicable to the requested mode participate. A TUN adapter or a System
Proxy mapping alone is never sufficient. The final state transition performs the HTTPS
proof first, then rechecks process, listener, journal, and all mode rows. Ownership loss
degrades immediately; probe failure uses the bounded health policy. Recovery always
requires a new fresh proof.

## 8. Release risks

### 8.1 P0 — release blockers

1. Incomplete proxy/PAC/RAS snapshot can overwrite foreign user state.
2. GUI crash can leave a dead System Proxy unless guardian and startup reconciliation
   pass crash tests.
3. An elevated helper that accepts renderer-controlled paths or commands is a privileged
   confused deputy.
4. A writable portable directory creates helper, engine, DLL, and config TOCTOU risk;
   exact hashes, held handles, and identity revalidation are mandatory.
5. Default named-pipe ACLs, unauthenticated peers, nonce replay, or PID reuse can authorize
   a foreign process.
6. TUN route recursion, one-family capture, or incorrect DNS can leak traffic or remove
   connectivity while the UI is green.
7. Rollback based on a name, port, prefix, or index can delete another VPN's state.
8. `Connected` before exact post-proof mode verification is a false security claim.
9. Secrets in command lines, journals, pipe traces, events, or diagnostics are release
   blockers.
10. Foreign System Proxy plus RouteDeck TUN cannot be labelled reliable per-app routing.

### 8.2 P1 — high-priority correctness risks

- delayed observation of a proxy or policy displacement;
- GPO/PAC automatic rewrite and WinHTTP/RAS scope confusion;
- interface index reuse, equal metrics, route-family asymmetry, or prefix collision;
- selected physical interface loss or network change;
- `strict_route` incompatibility with software such as VirtualBox;
- UAC cancellation or helper partial start;
- bounded cleanup during shutdown, logout, sleep, and resume;
- app/helper/component-manifest version mismatch;
- watcher cancellation or leaked ownership tasks;
- another VPN starting or stopping during the RouteDeck session.

P1 items need deterministic coverage and a clear degraded/recovery path. A P1 becomes P0
when it can overwrite foreign state, leak traffic while green, or cross the privilege
boundary.

## 9. Mandatory safe test order

### 9.1 U — deterministic tests, no Windows mutation

- round-trip every flags/proxy/bypass/PAC/autodetect/null-empty snapshot combination;
- exercise the compare-before-write/restore truth table in every journal phase;
- inject interruption, disk-full, access, corruption, and rename failures;
- serialize concurrent connect, stop, retry, guardian death, and reconcile events;
- fuzz closed IPC frames, duplicate keys, unknown fields, replay, stale parent, and limits;
- use route/adapter fixtures for equal metrics, IPv4/IPv6 disagreement, index reuse,
  prefix overlap, physical loss, and a foreign TUN;
- prove rollback fixtures cannot select a foreign route or adapter.

### 9.2 C — core integration, still no Windows mutation

- run the pinned engine's config check on generated dynamic TUN fixtures;
- prove only loopback listeners and controlled local health endpoints;
- verify the selected outbound rule cannot fall back to direct.

### 9.3 W — mandatory disposable Windows VM gate

Only after independent security review and all U/C cases pass:

1. Use a clean VM snapshot to test exact WinINet publish, refresh, proof, restore, and
   final before/after equality.
2. Test proxy/PAC/autodetect combinations, a simulated second proxy, concurrent foreign
   edits, guardian death, GUI forced termination, and every journal crash gap.
3. Test missing/mismatched helper-hash rejection, UAC cancel, pipe ACL attacks, peer identity,
   nonce replay, engine/config replacement, PID reuse, and suspended Job launch.
4. Test clean TUN IPv4/IPv6, DNS policies, both routing defaults, per-app routes, route
   recursion prevention, core/helper/UI crashes, and exact cleanup.
5. Test sleep/resume, network changes, physical-interface loss, shutdown interruption,
   and startup stale-session reconciliation.
6. Restore a snapshot with a second VPN/proxy installed; test Cancel, nested, physical,
   equal-metric ambiguity, prefix conflict, foreign System Proxy, and the other VPN
   starting/stopping.
7. Assert no RouteDeck service, task, startup entry, process, listener, adapter, route,
   DNS effect, or unexplained journal remains after every case.

### 9.4 Hard VM gate for the main PC

**Do not publish Windows System Proxy or start RouteDeck TUN on the user's main PC until
all U/C tests, the independent helper/ownership security review, and every applicable W
test above pass in both the clean and second-VPN VM snapshots.** Local-only protocol
testing through explicit RouteDeck ports is allowed because it does not mutate global
Windows state.

Before the VM gate passes, the following are forbidden on the main PC:

- any System Proxy `InternetSetOptionW` call;
- PAC, automatic-discovery, or existing-proxy takeover;
- real `runas` TUN helper activation;
- adapter, route, DNS, service, registry, task, or startup mutation;
- stale-session cleanup or forced restoration;
- forced crash, power-loss, sleep/resume, NIC flap, or another-VPN race while RouteDeck
  claims a Windows mode;
- physical-interface bypass, route collision, and IPv6 leak experiments.

Direct registry writes, service/task installation, arbitrary route commands, force
restore, and automatic termination or reconfiguration of another VPN are forbidden in
all environments for the first release.

### 9.5 H — minimal authorized host smoke after the VM gate

1. Capture a read-only, redacted baseline. Do not stop or reconfigure the other VPN.
2. Re-run local-only selected-outbound proofs on distinct ports.
3. Test System Proxy only after the UI identifies current ownership and the user gives
   snapshot-bound takeover consent. Keep the test short and verify exact restoration.
4. Test TUN only after read-only preflight, explicit upstream choice, and a clean ability
   to recover. The first reliable per-app host test runs without a foreign TUN or foreign
   System Proxy.
5. Stop RouteDeck and assert exact cleanup plus unchanged foreign VPN state. Repeat one
   clean connect/disconnect to prove recovery is not first-run dependent.

Any unexplained host difference, cleanup uncertainty, foreign overwrite, secret in
diagnostics, or green state without exact post-proof ownership blocks release.
