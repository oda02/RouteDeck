# TUN server switching, first stage

Changing the selected server in an active TUN session keeps the same sing-box
process, helper, TUN adapter, routes, DNS configuration and local listeners.
New connections use the new server after a separate HTTPS check. Existing TCP
connections and UDP associations remain on their original outbound while it is
available. They are not migrated to a new external IP. A failed old server, an
expired UDP association, or a game's own session policy can still disconnect a game.

## Session contract

- At connect time, snapshot the confirmed server library and configuration
  identities. Prepare supported, approved profiles; the selected profile must
  be representable. An inactive unapproved/unrepresentable profile is excluded,
  never weakened to make the session start.
- One `selected` selector carries user traffic; one independent `candidate`
  selector serves an authenticated loopback probe inbound. Both set
  `interrupt_exist_connections: false`. The ordinary health inbound always
  follows `selected` and cannot fall back to direct.
- Verify the exact owned control/probe listeners and capture identity. Select
  the candidate, read it back, and run the fixed HTTPS proof. Only then change
  `selected`, read it back and prove the selected path through a fresh health
  request. A successful switch keeps the session ID, child PID and adapter LUID.
- An ambiguous PUT response is reconciled with GET. If selection cannot be
  confirmed, restore the old selector and read it back. If restoration is also
  uncertain, retain the TUN session in Degraded and require explicit disconnect;
  never silently stop/start or publish green readiness. Monitor results from
  before any switch attempt cannot overwrite its outcome.
- All prepared REALITY exits share one Xray process with distinct loopback SOCKS
  inbounds and exact inbound-to-outbound rules. Xray stays alive until disconnect.
  Each remote exit is physically bound; loopback bridge connections are unbound.
- Existing stop/recovery ownership remains responsible for restoring system
  state before terminating listeners. No service is installed, and ordinary
  Tauri remains unprivileged.

The library limit remains 2000 profiles; the helper's 1 MiB configuration limit
also applies. Construction bounds accumulated config size before launch. Keeping
prepared exits and old connections costs more memory than one selected exit.
Old exits are retained until explicit disconnect in this stage, even after their
connections finish. There is no idle-exit eviction or dynamic profile insertion.
Large secret sets use the existing redactor's fail-closed saturation behavior.

Updated/new profiles require an explicit reconnect to load a new snapshot. A
switch to an absent or changed identity fails without restarting TUN. Changing
capture mode, routing, TUN stack, or relevant Naive UDP settings still reconnects;
source refresh/deletion retains the existing library workflow. System Proxy
server switching keeps its existing restart behavior. Automatic best-server
selection and per-application profiles are outside this stage.

## Control-plane security review

The renderer command accepts only a session ID and a confirmed node ID. It cannot
choose a URL, API path, token, port, executable, configuration or system setting.
Native requests use only fixed selector paths on an owned IPv4 loopback listener,
with a random per-session 192-bit bearer token, no environment proxy, no redirects,
bounded response reads and finite timeouts. Tokens/configs remain in protected
session storage and are redacted from process diagnostics. The API has no UI,
download configuration, persistent cache or allowed public web origin.

The elevated helper validates the exact new selector/API/probe shapes and every
member against the existing closed single-profile validator. It rejects direct
selector members, duplicate/foreign tags, API exposure, downloads/files/plugins,
port collisions, altered credentials and physical bindings, and changes to the
mandatory health, DNS and own-prefix rules. Only the validated new fields are
removed when reducing to existing validation. No elevated API accepts commands
or caller-selected filesystem locations. Same-user native compromise remains
outside the existing helper threat model.

## Verification

Deterministic tests cover candidate failure, successful/repeated switching,
post-selection failure and rollback, lost replies, uncertain rollback, stale
session/profile IDs, stale monitor results, disconnect ordering, and hostile
helper configurations. Frontend tests cover rapid selection, candidate failure
followed by another selection, and disconnect during a pending switch. Browser
fixtures assert server selection uses `switch_tun_server` without stop/start.

The explicit integration script hashes existing runtime executables/libraries
against the committed locks. It downloads nothing, creates no TUN and sends only
loopback fixture traffic. With sing-box 1.13.21 it verifies authentication,
independent candidate selection, new TCP/UDP using the new exit, and existing
TCP/UDP staying on their original exits across forward and reverse switches.
Only its own child is stopped. Optional generated-config checks use sing-box
`check` and Xray `run -test`; they do not launch a TUN session.

```powershell
$env:ROUTEDECK_SWITCH_FIXTURE_DIR = Join-Path $PWD '.cache/server-switch-fixtures'
cargo test --locked --offline --manifest-path src-tauri/Cargo.toml --lib export_server_switch_fixtures -- --ignored
python scripts/test-server-switch.py --runtime-root <existing-portable-directory> --generated-dir $env:ROUTEDECK_SWITCH_FIXTURE_DIR
```

Actual Windows TUN switching and preservation of a real game lobby have **not**
been established by these checks. Before privileged testing, review the changed
helper boundary and hostile-input tests in an isolated Windows environment.
Acceptance must record unchanged child PID/interface LUID, continued game traffic,
new connections through the selected exit, failed candidates, rapid switching,
and verified disconnect cleanup. Do not interpret localhost evidence as a TUN
capture or game-session guarantee.

Sources: [sing-box selector](https://sing-box.sagernet.org/configuration/outbound/selector/),
[Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/),
[pinned selector implementation](https://github.com/SagerNet/sing-box/blob/v1.13.21/protocol/group/selector.go).
