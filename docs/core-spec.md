# RouteDeck core and Windows integration specification

- Status: implementation baseline
- Target: Windows 10/11 x64, portable first release
- Reviewed against upstream documentation: 2026-09-01
- Engine baseline: sing-box 1.13.19 stable

## 1. Non-negotiable product invariants

1. RouteDeck is an unprivileged Tauri controller around a pinned, separately reviewed sing-box binary. It does not embed or reimplement proxy protocols.
2. A running process, an open port, or a created TUN adapter is **not** a successful connection. `Connected` requires an end-to-end request through the selected outbound.
3. System Proxy and TUN are different capabilities:
   - System Proxy affects only applications that honor the current user's Windows proxy configuration (or are explicitly configured to use RouteDeck's local proxy).
   - TUN captures IP traffic and is the only mode in which RouteDeck promises reliable per-process routing.
4. The ordinary GUI process always runs `asInvoker`. TUN elevation is requested on demand and the first release installs no service, driver, scheduled task, startup entry, or other persistent privileged component.
5. RouteDeck never executes a downloaded subscription as a sing-box configuration. It parses supported node definitions into a small internal model and generates its own configuration.
6. RouteDeck restores Windows state only when the current state still exactly matches state it wrote. It never blindly overwrites another VPN's, v2rayN's, or the user's later change.
7. All local listeners bind only to loopback. A port collision or an inability to prove ownership is a hard startup failure.

These rules implement the repository policy and [ADR-0001](adr/0001-portable-system-proxy-and-uac-tun.md).

## 2. Engine artifact, version pin, and provenance

### 2.1 Selected upstream artifact

Use the official no-suffix Windows x64 release asset:

`https://github.com/SagerNet/sing-box/releases/download/v1.13.19/sing-box-1.13.19-windows-amd64.zip`

The no-suffix Windows `amd64` release is the upstream pure-Go build and includes `libcronet.dll`. Naive outbound support requires this official variant and requires `libcronet.dll` beside `sing-box.exe` (or on `PATH`). Do not use the generic default build tags from a source build: upstream documents that the ordinary non-Windows tag set does not include Naive. See [Naive outbound](https://sing-box.sagernet.org/configuration/outbound/naive/) and [build from source](https://sing-box.sagernet.org/installation/build-from-source/).

Version 1.13.19 is the latest stable release visible on 2026-09-01. The upstream release is immutable and points to signed commit `b5ebaa1`; the GitHub page marks the signature verified. Do not consume 1.14 alpha/beta builds in a production package. See the [official v1.13.19 release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.19).

This version supports the required outbound types:

- [VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), including `xtls-rprx-vision` and TLS/REALITY;
- [Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/);
- [Naive](https://sing-box.sagernet.org/configuration/outbound/naive/) (introduced in 1.13.0).

### 2.2 Lock file and update policy

Add a reviewed repository lock (suggested path: `engine/sing-box.lock.json`) before packaging. It must contain:

```json
{
  "version": "1.13.19",
  "releaseTag": "v1.13.19",
  "releaseCommit": "b5ebaa1",
  "assetName": "sing-box-1.13.19-windows-amd64.zip",
  "assetUrl": "https://github.com/SagerNet/sing-box/releases/download/v1.13.19/sing-box-1.13.19-windows-amd64.zip",
  "archiveSha256": "<reviewed exact digest>",
  "files": {
    "sing-box.exe": "<reviewed exact digest>",
    "libcronet.dll": "<reviewed exact digest>"
  }
}
```

The digest placeholders are a release-blocking item, not permission to skip verification. Populate them only in the packaging change that obtains the artifact.

Artifact update rules:

1. A developer explicitly selects an immutable stable upstream release. No `latest` URL, floating version, npm hook, application startup, or frontend build may download it.
2. Compare the asset name and digest with GitHub's immutable release metadata, independently download the exact asset in CI, compute SHA-256, and review the tag/commit provenance. Record both archive and extracted-file digests.
3. CI downloads only the exact `github.com/SagerNet/sing-box/releases/download/vX.Y.Z/...` URL, verifies the archive digest **before extraction**, rejects unexpected archive entries/path traversal, then verifies both extracted files.
4. The packaged app verifies `sing-box.exe` and `libcronet.dll` against the embedded lock before every launch. Missing, extra replacement, or mismatched files produce `Engine integrity check failed`; they are never executed.
5. Updating sing-box is a normal reviewed pull request with protocol fixtures and the full regression matrix. RouteDeck has no silent engine auto-updater.
6. Preserve upstream licenses/notices in the portable distribution. Do not call the product or binary an official SagerNet client.

Authenticode may be recorded as additional evidence if present, but the reviewed SHA-256 pin is authoritative. A signature alone does not replace the hash pin.

## 3. Trust boundaries and threat model

### 3.1 Assets to protect

- subscription URLs and bearer tokens;
- VLESS UUIDs, Hysteria2 passwords, Naive usernames/passwords;
- REALITY public-key/short-id configuration and any TLS certificate pins;
- the current user's Windows proxy state;
- elevated TUN/routes/DNS state;
- the integrity of `sing-box.exe`, `libcronet.dll`, and generated configuration;
- browsing destinations and diagnostics.

### 3.2 Adversaries and failures in scope

| Threat/failure | Required control |
| --- | --- |
| Malicious or malformed subscription | Bounded download/decode/parse; no raw config execution; strict protocol allow-list; reject unsupported fields rather than silently weakening them. |
| YAML aliases/deep nesting/base64 bomb | Disable or cap aliases; maximum depth, scalar length, node count, decoded size, and total nodes. |
| Subscription URL redirects or local metadata access | `https`/`http` only; redirect and timeout caps; resolve and block link-local/metadata/loopback/private destinations by default; explicit advanced opt-in for LAN subscription servers. |
| Tampered bundled engine/library | Exact archive and extracted-file SHA-256 pins; runtime verification before launch. |
| Local port squatting | Bind only `127.0.0.1`/`::1`; preflight ports; fail if occupied; random credentials on internal health listener. |
| UI/webview compromise | GUI remains unprivileged; narrow typed commands; no arbitrary command/path/env/registry/root accepted by elevated component. |
| Privilege confused deputy | Elevated helper validates a fixed operation schema, package root, engine hashes, config schema, parent identity, and pipe ACL. |
| Concurrent VPN changes | Compare-before-write and compare-before-restore; durable journal; live ownership watcher; conflict state, never blind force. |
| Crash/power loss | Atomic journals, job-object process ownership, startup reconciliation, idempotent connect/disconnect. |
| False green state | End-to-end outbound proof plus mode-specific state verification; continuous degradation detection. |
| Secret disclosure in logs/UI | Central structured redaction before serialization; no raw subscription/body/config in diagnostics. |

Local processes running as the same Windows user can generally inspect that user's memory/files and are not treated as a strong isolation boundary. Nevertheless, loopback listeners must not expose credentials to other users and the elevated helper must authenticate the launching user/session.

### 3.3 Explicitly out of scope for the first release

- automatic censorship circumvention tuning, packet fragmentation, or speculative anti-DPI presets;
- arbitrary imported sing-box services, inbound servers, scripts, file paths, rule sets, or detour chains;
- permanent SYSTEM service installation;
- a claim that two VPN/TUN clients always coexist;
- reliable per-app routing for applications that do not enter RouteDeck in System Proxy mode.

## 4. Runtime architecture

```text
Tauri UI (unprivileged)
  -> Core controller (unprivileged Rust)
       -> subscription fetch/parser -> canonical Node records
       -> config generator -> private runtime config
       -> sing-box child (System Proxy mode)
       -> Windows proxy owner/journal
       -> health checker through private health inbound
  -> Elevated helper (TUN only, UAC on demand)
       -> validates fixed request/config/engine hashes
       -> owns sing-box in a kill-on-close Job Object
       -> reports adapter/route/readiness/probe state over restricted named pipe
```

The UI renders controller state; it does not infer connectivity from child/log text. All state transitions originate in the Rust controller.

### 4.1 Connection state machine

```text
Disconnected
  -> Preparing
  -> ValidatingConfig
  -> StartingCore
  -> VerifyingListener
  -> PublishingModeState       (System Proxy write or TUN adapter/routes)
  -> ProvingTraffic
  -> Connected

Any pre-proof failure -> RollingBack -> DisconnectedWithError
Ownership or probe loss while connected -> Degraded
Stop -> Quiescing -> RestoringOwnedState -> VerifyingRestoration
     -> StoppingCore -> Disconnected
```

`Connected` requires all of the following:

1. engine integrity verification passed;
2. `sing-box check -c <generated-config>` succeeded using the same pinned binary;
3. the expected child is alive and all expected loopback listeners are accepting;
4. mode state is exact: our Windows proxy snapshot is current, or the expected RouteDeck TUN adapter/routes exist;
5. a fresh HTTPS request succeeded through the private health inbound, which is structurally forced to the selected outbound;
6. the response met status/content bounds and the request nonce/correlation appears in controller tracing without secrets.

If the selected protocol cannot pass the proof, RouteDeck must show the concrete stage and sanitized sing-box error. It must not fall back to `direct`.

## 5. Canonical application model

The importer output is a typed model, not arbitrary JSON:

```text
Node {
  id: stable hash of normalized non-secret identity,
  display_name,
  protocol: Vless | Hysteria2 | Naive,
  server: hostname-or-IP,
  server_port / server_ports,
  credentials: protocol-specific secret fields,
  tls: { enabled, server_name, alpn, insecure, certificate_pin, utls, reality },
  transport: protocol-specific closed enum,
  origin: { subscription_id, source_format, imported_at },
}

RoutePolicy {
  default: Direct | Vpn,
  apps: [{ canonical_exe_path, process_name, action: Direct | Vpn }],
  lan: Direct | FollowDefault,
  ipv6: Enabled | Disabled,
  dns: Vpn | CurrentNetwork,
}
```

Validation rules include DNS-name/IP syntax, port `1..65535`, UUID syntax, bounded strings/arrays, compatible protocol/transport combinations, and TLS verification on by default. `insecure=true` is imported but must be visibly marked; RouteDeck never turns it on implicitly. Unknown required fields or unsupported transports cause a per-node rejection with a useful reason.

## 6. Subscription ingestion

### 6.1 Fetch boundary

- Accept only `https://` and, behind an explicit insecure warning, `http://` subscription URLs.
- Do not use the Windows System Proxy implicitly. The user may choose `Direct/current network` or `through active RouteDeck`; this makes behavior deterministic when v2rayN is present.
- Limit redirects to 3; only `http`/`https` targets; re-run address policy after every redirect.
- Suggested limits: 15 s total, 5 MiB compressed body, 10 MiB decoded text, 2,000 nodes, 64 KiB per line/scalar, nesting depth 32.
- Reject invalid UTF-8 except an optional UTF-8 BOM. Never execute content sniffed as HTML.
- Parse in memory, commit the new node set atomically only after the full parse/validation result is available. A failed refresh retains the prior working snapshot.

### 6.2 Format detection order

1. Strict sing-box JSON object (`outbounds` array) or array of supported outbound objects.
2. Clash/Mihomo YAML with a top-level `proxies` array.
3. Plain UTF-8 newline-delimited share links.
4. Strict standard/base64url decoding followed by newline-delimited share links.

Ambiguous input is rejected, not repeatedly decoded until it happens to parse. Mihomo officially documents YAML, URI-list, and base64-wrapped URI-list provider content; see [proxy provider content](https://wiki.metacubex.one/config/proxy-providers/content/).

### 6.3 Share links

#### VLESS

Accept `vless://` according to the Project X [VLESS sharing-link standard](https://xtls.github.io/en/development/protocols/vless.html). Required: UUID, host, port. Support and preserve the common standardized query fields needed by the target engine: `security`, `encryption`, `flow`, `type`, `sni`, `alpn`, `fp`, `pbk`, `sid`, `host`, `path`, and `serviceName`. Percent-decode exactly once. Reject unsupported security/transport combinations; never silently downgrade REALITY, TLS, or certificate verification.

Map REALITY to sing-box client TLS `reality.enabled`, `public_key`, and `short_id`; map Vision to `flow: xtls-rprx-vision`. The upstream sing-box VLESS schema explicitly supports this flow and TLS configuration.

#### Hysteria2

Accept `hysteria2://` and `hy2://` using the official [Hysteria2 URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/): percent-encoded auth/userpass, hostname/port (default 443), `obfs`, `obfs-password`, `sni`, `insecure`, `pinSHA256`, `ech`, and fragment display name. Multi-port syntax must map only if representable by the pinned sing-box Hysteria2 schema; otherwise reject with an explanation. Do not import client bandwidth values from ad-hoc query extensions.

`hysteria2+realm` is not in the MVP allow-list unless the pinned sing-box outbound schema and fixtures explicitly cover it.

#### Naive

Prefer canonical sing-box JSON for Naive. For compatibility, accept strict `naive+https://` and `naive+quic://` links, mapping user/password/host/port, fragment, and the bounded `extra-headers` extension to the sing-box Naive outbound. Treat this as a **de-facto compatibility format**, not an official standard: the published `naive+` URI is a closed proposal rather than normative NaiveProxy documentation. The official NaiveProxy client itself uses `https://user:pass@host` or `quic://...` proxy URIs; see its [README](https://github.com/klzgrad/naiveproxy/blob/master/README.md) and [USAGE](https://github.com/klzgrad/naiveproxy/blob/master/USAGE.txt).

Reject CR/LF in headers, invalid header names, duplicate authorization headers, and more than 16 headers/8 KiB total. Never allow imported headers to affect subscription fetching or RouteDeck health endpoints.

### 6.4 Clash/Mihomo YAML

Read only `proxies`; ignore no field silently. Do not import `rules`, `rule-providers`, `proxy-providers`, `external-controller`, scripts, paths, or DNS/inbound settings. Supported mappings:

- `type: vless`: server/port/uuid/flow/network/TLS/servername/alpn/client fingerprint/REALITY and supported WS/gRPC transport fields;
- `type: hysteria2`: server/port(s)/password/obfuscation/SNI/certificate verification and supported hopping fields;
- a documented RouteDeck `type: naive` extension only; ordinary `type: http` is not assumed to be Naive because that would silently change protocol semantics.

Mihomo's official schemas are the source for field names: [VLESS](https://wiki.metacubex.one/en/config/proxies/vless/) and [Hysteria2](https://wiki.metacubex.one/config/proxies/hysteria2/).

### 6.5 sing-box JSON

Extract only standalone `vless`, `hysteria2`, and `naive` outbounds that validate against the pinned-version allow-list. Reject outbounds with detours, arbitrary resolver references, filesystem certificate/key paths, unsupported multiplex/transport options, or references to objects outside the imported outbound. Never preserve imported tags as command/path material.

Imported `inbounds`, `route`, `dns`, `services`, `experimental`, logging, API listeners, and file paths are never executed. The supported upstream top-level structure and `sing-box check` command are documented in the [sing-box configuration introduction](https://sing-box.sagernet.org/configuration/).

## 7. Generated sing-box configuration

The generator owns every field. It emits JSON for the pinned 1.13 schema and then runs `sing-box check`. Do not emit 1.14-only fields such as TUN `dns_mode` while pinned to 1.13.19.

### 7.1 Local listeners

Use separate ports and tags:

```json
{
  "inbounds": [
    { "type": "http",  "tag": "http-in",   "listen": "127.0.0.1", "listen_port": 2080 },
    { "type": "socks", "tag": "socks-in",  "listen": "127.0.0.1", "listen_port": 2081 },
    { "type": "http",  "tag": "health-in", "listen": "127.0.0.1", "listen_port": 0,
      "users": [{ "username": "health", "password": "<per-session random>" }] }
  ]
}
```

`listen_port: 0` above expresses controller intent; if the pinned engine does not expose the chosen port, the controller reserves/selects an unused ephemeral port and writes the explicit value before `check`. The health listener is never published as System Proxy. The official [HTTP](https://sing-box.sagernet.org/configuration/inbound/http/), [SOCKS](https://sing-box.sagernet.org/configuration/inbound/socks/), and [mixed](https://sing-box.sagernet.org/configuration/inbound/mixed/) inbounds define the underlying listener behavior.

Do not use sing-box `set_system_proxy`; RouteDeck owns Windows compare/journal semantics itself.

### 7.2 Outbounds and routing

Emit exactly the selected protocol outbound plus an explicit direct outbound:

```json
{
  "outbounds": [
    { "type": "<vless|hysteria2|naive>", "tag": "selected", "...": "canonical node fields" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "remote-dns",
    "rules": [
      { "inbound": ["health-in"], "action": "route", "outbound": "selected" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "process_path": ["<explicit direct apps>"], "action": "route", "outbound": "direct" },
      { "process_path": ["<explicit VPN apps>"], "action": "route", "outbound": "selected" }
    ],
    "final": "<direct|selected>"
  }
}
```

`route.final` is always explicit; upstream otherwise uses the first outbound. Process rules precede the final route. Prefer canonical full executable paths; retain process names only as a user-visible fallback with a collision warning. The official route schema documents [`final` and interface binding](https://sing-box.sagernet.org/configuration/route/) and Windows [`process_name`/`process_path` rules](https://sing-box.sagernet.org/configuration/route/rule/).

The internal health rule is immutable and first: its only legal outbound is `selected`. No generated path from `health-in` may reach `direct`.

### 7.3 DNS for the pinned 1.13 schema

For TUN, emit the 1.13 DNS server schema and a `hijack-dns` rule. Do not rely on the 1.14 TUN `dns_mode` field. The shape is:

```json
{
  "dns": {
    "servers": [
      { "type": "local", "tag": "bootstrap-dns", "prefer_go": true },
      {
        "type": "https", "tag": "remote-dns",
        "server": "<reviewed DoH IP>", "server_port": 443, "path": "/dns-query",
        "tls": { "enabled": true, "server_name": "<reviewed DoH name>" },
        "detour": "selected"
      }
    ],
    "final": "remote-dns",
    "strategy": "prefer_ipv4"
  }
}
```

The selected outbound's own server lookup explicitly uses `domain_resolver: bootstrap-dns`; this breaks the bootstrap loop. The DoH server uses a reviewed literal IP plus TLS server name and is detoured through `selected`. DoH provider/name/IP are product constants covered by fixtures, not subscription-controlled values. The official 1.12+ schemas document [DNS](https://sing-box.sagernet.org/configuration/dns/), [local DNS](https://sing-box.sagernet.org/configuration/dns/server/local/), [DNS over HTTPS](https://sing-box.sagernet.org/configuration/dns/server/https/), and the [`hijack-dns` route action](https://sing-box.sagernet.org/configuration/route/rule_action/).

Windows commonly centralizes DNS through the DNS Client service, so per-process DNS attribution is not a safe promise. RouteDeck therefore exposes an explicit TUN DNS policy:

- `VPN` (privacy default): all captured DNS uses `remote-dns` through the selected node, including lookups for apps whose payload route is Direct. No automatic direct fallback occurs if selected DNS fails.
- `Current network`: use only `bootstrap-dns`; warn that names requested by VPN-routed apps may be visible to the current network or upstream VPN.

System Proxy does not change Windows DNS and makes no DNS-leak claim. Applications may resolve before issuing HTTP CONNECT or may send hostnames to RouteDeck.

### 7.4 TUN addition

TUN mode adds a uniquely named inbound similar to:

```json
{
  "type": "tun",
  "tag": "tun-in",
  "interface_name": "RouteDeck",
  "address": ["172.31.255.1/30", "fd7a:52d3:9c10::1/126"],
  "mtu": 1500,
  "auto_route": true,
  "strict_route": true,
  "stack": "system"
}
```

Addresses are examples, not constants: preflight must choose non-overlapping RFC1918/ULA prefixes and persist them for the session. `strict_route` prevents unsupported traffic and reduces Windows multihomed DNS leakage but may break applications such as VirtualBox, so the UI must expose a troubleshooting note. Upstream documents that `auto_route` sets the default route and requires `auto_detect_interface`, `default_interface`, or outbound `bind_interface` to prevent loops; see [TUN auto-route and strict-route](https://sing-box.sagernet.org/configuration/inbound/tun/).

## 8. Mode semantics and routing UI contract

### 8.1 System Proxy

- Publish `http=127.0.0.1:<http-port>;https=127.0.0.1:<http-port>` with a conservative localhost/private bypass list.
- Keep SOCKS on its separate port for manual clients; Windows System Proxy does not become a SOCKS-only configuration.
- All compliant applications enter RouteDeck, but applications may ignore Windows proxy settings, use QUIC/UDP directly, or implement their own proxy stack.
- Per-process rules may be evaluated for connections that enter the local listener, but the UI labels them **best effort** in this mode. RouteDeck does not claim browser-only or full-device capture until the proof is performed for the target app or TUN is used.
- Default `Direct` means compliant traffic enters the local proxy and is routed direct unless an applicable app rule selects VPN. Default `VPN` routes compliant traffic through the selected node unless an app rule selects Direct.

### 8.2 TUN

- Per-process Direct/VPN rules and the default route are authoritative for traffic captured by the TUN.
- The UI exposes one clear global choice: `Everything else: Direct | VPN`; app rows override it.
- The selected server's own connection must bypass the RouteDeck TUN using `route.auto_detect_interface`, explicit physical `default_interface`, or outbound `bind_interface`.
- IPv4 and IPv6 must both be configured or IPv6 must be explicitly disabled. Never show connected while one enabled family leaks due to missing route/DNS handling.
- DNS policy is shown separately because Windows DNS cannot be promised to follow per-process payload routing. The default is `DNS via VPN`; `Current network` carries an explicit leak warning.

## 9. Windows System Proxy ownership

Use WinINet's `INTERNET_OPTION_PER_CONNECTION_OPTION` APIs to query/set the current user's flags, proxy server, and bypass values. Microsoft recommends the per-connection option API over `INTERNET_OPTION_PROXY`, and requires a refresh after global changes. Do not directly edit registry values: Microsoft warns clients not to depend on the implementation storage. See [setting/retrieving Internet options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options) and [WinINet option flags](https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags).

Treat the relevant state as one normalized snapshot:

```text
ProxySnapshot {
  flags (direct/proxy/auto-config),
  proxy_server,
  proxy_bypass,
  auto_config_url,
  autodetect,
}
```

### 9.1 Durable journal

Before writing, atomically persist:

```text
ProxyJournal {
  schema_version,
  session_uuid,
  owner_pid + owner_process_start_time,
  created_at,
  phase: Prepared | Applied | Restoring,
  original: exact normalized snapshot,
  published: exact intended RouteDeck snapshot,
}
```

Write temporary file, flush, atomically rename, then make the Windows change. After writing, broadcast/refresh via the documented WinINet APIs, re-read, and require an exact match before proceeding. Protect the journal against cross-user access: an original proxy/PAC URL may itself be sensitive, and the journal is security-sensitive state evidence.

### 9.2 Compare-before-write/restore

- Start with no existing RouteDeck journal: capture current state as `original`, persist `Prepared`, set `published`, verify exact, mark `Applied`.
- Stop/recovery when current equals `published`: restore `original`, refresh, verify exact, then delete journal.
- Current equals `original`: cleanup is already complete; delete journal.
- Current is anything else: another actor changed it. Do not restore. Keep the journal and enter `ProxyConflict`; offer `Reclaim RouteDeck proxy` or instructions, never an unbounded force-write.
- Any unreadable/partially queryable state is a hard conflict, not permission to overwrite.

A watcher periodically and on network/settings notifications re-reads the snapshot. If v2rayN stops after RouteDeck starts and restores an older proxy, the current state no longer equals `published`; RouteDeck immediately becomes `Degraded — System Proxy was changed by another app`. This specifically prevents the prior false-connected failure.

Two local proxy listeners on different ports can coexist. Two effective Windows System Proxy owners cannot: the system-wide setting can publish only one endpoint set. RouteDeck must state this explicitly.

## 10. TUN elevation and other-VPN coexistence

### 10.1 UAC-on-demand helper

The GUI manifest remains `asInvoker`. Launch the fixed helper with the Windows `runas` verb only when the user enables TUN; Windows then displays UAC. Microsoft documents both [`runas`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea) and execution-level manifests in [application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests).

The helper accepts only typed operations such as `StartTun(session_id, config_handle, parent_identity)` and `StopTun(session_id)`. It must not accept an executable path, shell command, arbitrary arguments/environment, registry path, interface command, or output path from the renderer.

IPC uses a per-session named pipe with an explicit ACL restricted to the launching user SID, Administrators, and SYSTEM; do not rely on the permissive default descriptor. Microsoft notes that a default named-pipe ACL grants read access to Everyone and anonymous users; see [named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

The helper owns sing-box in a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and monitors the GUI PID **and process creation time** to avoid PID-reuse mistakes. Windows documents that closing the last such job handle terminates all associated processes; see [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

### 10.2 Preflight and upstream interface choice

Before elevation, enumerate IPv4/IPv6 adapters and routes, occupied RouteDeck prefixes, default routes, and likely tunnel adapters. Windows provides `GetAdaptersAddresses` and `GetIpForwardTable2`; adapter/route metrics influence the preferred route. See [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses), [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/getipforwardtable2), and [interface metrics](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-interface-metric).

Offer these explicit policies when another VPN/default tunnel is detected:

1. **Use current network path (nested)**: `auto_detect_interface=true`; selected server traffic may itself travel through the already active VPN. UI says this is nested and measures the actual result.
2. **Use physical adapter**: user selects a verified up, non-loopback, non-tunnel NIC; set `route.default_interface` (or outbound `bind_interface`) to its exact current interface identifier. Revalidate immediately before launch.
3. **Cancel**: safe default when ownership is ambiguous or routes overlap.

Do not assume a different local port makes two TUNs compatible. Refuse startup on prefix collision, missing usable upstream, multiple ambiguous equal-metric defaults without a user choice, an existing `RouteDeck` adapter/session not owned by the journal, or a post-start route table that does not match the intended policy.

v2rayN in System Proxy-only mode does not inherently prevent RouteDeck's local listeners or TUN core from starting, but its global proxy ownership may conflict with RouteDeck System Proxy and its subscription-fetch path must not be inherited accidentally.

## 11. Proof-of-traffic and latency

### 11.1 Startup proof

The controller starts a request through authenticated `health-in`. A first route rule forces that inbound to `selected`; generated-config validation asserts that no direct or fallback route can match it. Use an HTTPS endpoint with a bounded body and an expected status (for example, a reviewed configurable `204` endpoint). Require:

- DNS, connect, TLS, request, and response within one total deadline (suggested 8 s startup, 5 s periodic);
- expected HTTP status/body bound;
- child still alive and no protocol/TLS/REALITY error correlated with the attempt;
- mode ownership still exact after the probe.

This proves application data traversed the selected outbound. A TCP connect to the server, ICMP echo, or DNS resolution alone never proves VPN traffic.

### 11.2 Egress IP and displayed latency

- Fetch an egress-IP endpoint through `health-in`; label it `VPN egress IP`. It is display evidence and may be unavailable without invalidating a successful 204 proof.
- An optional explicit-direct baseline must use a separate `direct-health-in` forced to `direct`, not the Windows System Proxy. When another TUN/VPN is upstream, label it `current network egress`, not `real ISP IP`.
- Display latency as `route check`, measured around the full HTTPS proof. Do not show raw TCP-to-server/ICMP values as VPN latency, and never accept fake-TUN/private/reserved destination results as node latency.
- Periodic failures move `Connected -> Degraded` after a small bounded threshold; immediate ownership loss degrades without waiting. Recovery requires a fresh successful end-to-end proof.

## 12. Stop, crash, and startup recovery

Normal stop order is fixed:

1. reject new UI work and stop periodic probes;
2. restore owned System Proxy state or request elevated TUN shutdown;
3. verify Windows proxy/adapter/routes are restored/removed;
4. stop local listeners/core;
5. remove journals only after verified cleanup.

If System Proxy restoration conflicts, keep the core/listener alive when practical so a still-published RouteDeck endpoint does not become a dead proxy. Show actionable conflict state. If the currently published state is foreign, RouteDeck may stop its core but must preserve the journal/evidence and must not alter foreign state.

For TUN, the elevated helper terminates sing-box on GUI death through its job object; ephemeral process-owned TUN state should disappear with the process. The helper verifies adapter/routes after stop and reports incomplete cleanup. Following OS crash/reboot, startup reconciliation enumerates adapters/routes and journals before allowing a new session.

Every connect/disconnect/reconcile operation is serialized and idempotent. Repeated stop after verified cleanup succeeds without changing unrelated state.

## 13. Secret storage, diagnostics, and redaction

- Store long-lived secrets under the current user's profile, not beside the portable executable. Protect subscription URLs and canonical node records with Windows DPAPI `CurrentUser`; use restrictive file ACLs and atomic writes.
- Generated configs live in a per-session private directory, are deleted after shutdown where possible, and are treated as secrets. The elevated helper receives a validated handle/session reference, not a renderer-supplied arbitrary path.
- Never put credentials, UUIDs, share links, subscription URLs, query strings, proxy auth, headers, full generated config, or response bodies in logs.
- Central redaction occurs before formatting/export and covers URI userinfo, URL query/fragment, `uuid`, `password`, `auth`, `token`, `pbk`, `sid`, certificate material, headers, and nested error causes.
- Diagnostics may include protocol type, sanitized host hash, port, engine version/hash prefix, route mode, listener ports, state-machine stage, Windows error code, and redacted sing-box error category.
- Clipboard export is explicit, warns that secrets may be present, and offers redacted export by default.

## 14. Implementation gates

No host-changing test or release build proceeds until all are true:

1. pinned archive/extracted-file digests are reviewed and locked;
2. parsers pass hostile-input, differential fixture, and secret-redaction tests;
3. generated configs for every supported protocol pass the pinned `sing-box check` in CI;
4. Windows proxy ownership and crash recovery pass deterministic mock tests;
5. elevated helper command schema/ACL/path/hash handling receive independent security review;
6. privileged TUN and concurrent-VPN tests first pass in an isolated Windows VM;
7. the package has no unexpected listeners, services, startup tasks, or writes outside documented per-user locations.

The detailed acceptance cases are in [test-matrix.md](test-matrix.md).

## 15. Primary references

- sing-box: [configuration structure/check](https://sing-box.sagernet.org/configuration/), [route](https://sing-box.sagernet.org/configuration/route/), [route rules](https://sing-box.sagernet.org/configuration/route/rule/), [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/), [dial fields](https://sing-box.sagernet.org/configuration/shared/dial/), [VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), [Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/), [Naive](https://sing-box.sagernet.org/configuration/outbound/naive/), [TLS/REALITY](https://sing-box.sagernet.org/configuration/shared/tls/), [build variants](https://sing-box.sagernet.org/installation/build-from-source/), [v1.13.19 release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.19).
- Link/provider formats: [Project X VLESS](https://xtls.github.io/en/development/protocols/vless.html), [Hysteria2 URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/), [Mihomo provider content](https://wiki.metacubex.one/config/proxy-providers/content/), [Mihomo VLESS](https://wiki.metacubex.one/en/config/proxies/vless/), [Mihomo Hysteria2](https://wiki.metacubex.one/config/proxies/hysteria2/), [NaiveProxy README](https://github.com/klzgrad/naiveproxy/blob/master/README.md).
- Windows: [WinINet options](https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags), [setting/retrieving options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options), [ShellExecute `runas`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea), [application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests), [named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses), and [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/getipforwardtable2).
