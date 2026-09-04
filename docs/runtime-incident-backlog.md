# Runtime incident backlog

## 2026-09-04: empty subscription state on one portable launch

Status: **unresolved; restart workaround observed, no fix established**.

Confirmed facts for portable source commit `486d6ab`:

- One running instance displayed zero confirmed nodes and an empty technical journal,
  including after refreshing diagnostics. A new URL import returned the generic
  subscription-fetch failure message. It was not in recovery-required state.
- The existing local subscription file remained present and unchanged. A read-only
  check using the current Rust storage loader and subscription parser accepted format
  version 1, with 14 nodes and zero rejected entries. No credentials or server details
  were printed or copied into the repository.
- The application identifier was unchanged, and the portable build enabled Tauri's
  production `custom-protocol` feature. Source inspection found no build-folder-specific
  subscription path. The actual resolved path inside the affected process was not
  captured, so a runtime path mismatch was neither demonstrated nor ruled out.
- After a normal UI exit and relaunch of the **same executable**, the UI restored all
  14 nodes and the two saved application-routing exceptions. No rebuild, saved-data
  edit, subscription re-import, or network-configuration change was needed.

Workaround: try a normal exit and relaunch once before resetting local state or
re-importing the subscription. This single observation is not evidence that the
underlying startup or fetch issue is fixed. The relationship between the empty startup
state and the failed HTTPS import remains unknown.

Next diagnostic work:

1. Record a startup storage outcome for every attempt: `not_found`, `restored` with
   node count, or a finite read/schema/parse failure category. Include build identity
   and a privacy-safe resolved-storage identity so a different data root can be proven
   rather than inferred. Preserve this startup record when connection logs are cleared.
2. Record a sanitized, finite subscription-fetch cause (for example DNS, connect, TLS,
   HTTP status, or timeout) and effective direct/proxy transport class. Do not log the
   subscription URL, response body, server names, credentials, or personal paths.
3. If it recurs, capture those diagnostics before restarting and compare them with
   the successful relaunch. Keep the original saved subscription untouched.

## 2026-09-04: HTTPS import DNS argument and proxy-selection failures

This is separate from the unresolved empty-startup-state incident above.

- A read-only diagnostic under the actual interactive Windows account reproduced
  direct-path import failure before HTTP: `WSAStartup=0`, `GetAddrInfoExW=10022`
  (`WSAEINVAL`). WinINet per-connection FLAGS and FLAGS_UI reported direct-only while
  the current manual proxy settings had an enabled, parseable local proxy. RAS was
  inactive. The same import through that explicitly selected existing local proxy
  returned HTTP 200; no provider-side workaround was needed.
- A localhost-only A/B check isolated the DNS call defect: identical name, namespace,
  and hints with the old synchronous call plus non-NULL timeout returned 10022;
  changing only timeout to NULL returned success. The corrected asynchronous resolver
  also resolves localhost successfully without an external endpoint.
- A follow-up under the interactive account used the corrected production proxy
  provider automatically, with no manual proxy override: it selected the local proxy
  despite the informational WinINet flags still reporting direct-only, returned
  HTTP 200, and parsed 14 nodes with zero rejected entries. The corrected native
  localhost self-test returned two addresses, both loopback. This was a read-only
  diagnostic import; it did not replace the saved subscription.
- The resolver now follows the documented asynchronous callback pattern, with a
  bounded caller wait and exact-handle cancellation. Callback-owned query buffers,
  result list, event, Winsock reference, and one of four outstanding-request permits
  remain alive until native completion, even after timeout or cancellation failure.
  There is no abandoned worker thread or unbounded cancellation wait.
- Deterministic tests cover immediate completion/error, callback-before-return,
  completion during wait/cancellation, late completion, cancellation failure/missing
  handle, resource release, and the outstanding-request cap. A real localhost-only
  test covers the Windows API shape. Successful application-level re-import must
  still be verified in the rebuilt portable; these tests do not establish that the
  unrelated startup-state incident is fixed.

Windows API reference: [GetAddrInfoExW asynchronous example and cancellation lifetime](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw).

## 2026-09-04: TUN VLESS startup proof fails after the tunnel transition

Status: **a concrete DNS-routing defect is identified; live TUN recovery is not yet verified**.

Confirmed observations on portable source `9b74499`:

- The selected VLESS REALITY node failed the first private-health HTTPS proof after
  TUN startup. The ordinary unproxied TUN proof had not run. Xray's sanitized log
  showed the loopback SOCKS request reaching its selected outbound and starting the
  remote TCP dial; this does not distinguish DNS lookup, TCP connect, and REALITY
  handshake completion.
- The saved endpoint was a hostname. A read-only lookup outside RouteDeck TUN found
  one real IPv4 address, not a fake-IP address. Separate TCP connection controls with
  the original route and an explicitly bound physical interface both succeeded.
- A disposable diagnostic using the current parser/config generator, pinned Xray,
  an ephemeral loopback SOCKS listener, and the fixed HTTPS proof endpoint compared
  three paths without enabling TUN or changing Windows settings. Hostname/unbound
  timed out; hostname/physical-bound and frozen-IPv4/physical-bound both returned
  HTTP 204. The frozen case retained the original REALITY server name. These results
  establish that the selected VLESS credentials and bound physical path can work;
  they do not establish that TUN works or prove why the unbound control timed out.
- Each diagnostic child was stopped and its protected temporary session removed.
  No subscription contents, endpoints, credentials, personal paths, or captured IPs
  were written into this incident record.

Source-confirmed defect and focused change:

- The generated DNS rule matched `protocol: dns`, but there was no preceding sniff
  action. The pinned TUN inbound creates initially unclassified metadata. Its router
  only performs protocol sniffing for a matched sniff action, and the protocol matcher
  compares that metadata field. Consequently raw DNS to the TUN virtual DNS address
  misses the DNS rule and reaches the subsequent own-prefix drop rule.
- Match TCP and UDP destination port 53 on `tun-in` directly, after the private-health
  rule and before the own-prefix guard. Keep the guard, physical binding, DNS policy,
  and System Proxy behavior unchanged. The elevated validator rejects the obsolete
  protocol-only shape and extra narrowing conditions.
- Do not attribute this defect to sing-box `local` DNS automatically recursing into
  its own TUN. The pinned Windows resolver excludes its registered own interfaces;
  its DNS exchanges use the configured dialer. It can still enumerate DNS servers on
  other eligible adapters, so interface binding is not equivalent to selecting only
  that adapter's DNS list. No resolver-policy expansion is part of this fix.

An opt-in loopback-only data-plane regression using pinned sing-box 1.13.21 confirmed
the behavior with a local fake DNS responder and no TUN or Windows settings changes:

| Generated rule under test | UDP DNS answer | TCP DNS answer | Upstream fixture requests |
| --- | --- | --- | --- |
| Old protocol-only DNS selector, destination port 53 | No | No | 0 |
| New TCP/UDP port 53 selector, destination port 53 | Yes | Yes | 2 |
| New selector, destination port 54 control | No | No | 0 |

Every fixture child stopped and every protected temporary session was removed. The
reproducible opt-in example is `src-tauri/examples/diagnose_dns_hijack.rs`; it uses only
fixture names/addresses and never loads the saved subscription. Unit tests additionally
reject the old selector, extra protocol predicates, altered scope/port, and wrong order.

Remaining acceptance gate: test the rebuilt application on the user-authorized TUN
path. Require both selected-outbound HTTPS and actual TUN traffic proof, followed by
verified owned-state cleanup. Neither the no-TUN baseline nor the loopback regression
establishes successful live TUN operation.

Pinned source references: [TUN inbound metadata](https://github.com/SagerNet/sing-box/blob/v1.13.21/protocol/tun/inbound.go),
[route/sniff execution](https://github.com/SagerNet/sing-box/blob/v1.13.21/route/route.go),
[protocol matcher](https://github.com/SagerNet/sing-box/blob/v1.13.21/route/rule/rule_item_protocol.go),
[Windows local DNS selection](https://github.com/SagerNet/sing-box/blob/v1.13.21/dns/transport/local/resolv_windows.go),
[local DNS exchanges](https://github.com/SagerNet/sing-box/blob/v1.13.21/dns/transport/local/local_shared.go).

## 2026-09-04: elevated helper disconnects during activation

Status: **the observed helper exit cause remains unknown; control-plane diagnostics
and bounded transport are added, not a claim of recovered live TUN connectivity**.

- A later live attempt stopped before sing-box/TUN startup with named-pipe Windows
  error 232 (`ERROR_NO_DATA`). The Xray sidecar had started. This is a different
  failure phase from the earlier selected-outbound HTTPS timeout.
- Local named-pipe tests reproduce 232 when a client connects and closes before
  server acceptance. On this Windows build an unconnected NOWAIT pipe returned
  `ERROR_PIPE_LISTENING`; the documented available-to-connect success behavior was
  not reproduced. Neither result identifies why the actual elevated helper exited.
  Client handles opened with CreateFile use blocking wait mode by default; inheriting
  the server's NOWAIT mode is not an established cause.
- Helper IPC now uses overlapped PIPE_WAIT handles with bounded connects and whole-
  frame deadlines. Partial reads/writes cannot reset the frame deadline. An incomplete
  operation closes/poisons its transport, with exact-operation cancellation. A single
  reaper retains native buffers, OVERLAPPED, event and duplicated handle until native
  completion. At most eight active or cancel-pending operations are retained; no
  unbounded per-request worker is created. Healthy established-session idle does not
  expire a frame deadline: the deadline starts with the first byte, while verified
  parent-process death and pipe closure remain observable.
- Authentication still requires the fixed verified helper image, exact launched
  process PID, pipe peer PID, process creation time and protocol/session handshake.
  Parent validation is not relaxed. Finite helper exit codes distinguish pipe-server
  PID lookup, parent open/creation/image checks, same-directory/name checks, nonce
  creation and Hello write. The GUI may report that finite exit reason instead of a
  secondary pipe error; no arbitrary native error text, paths or subscription data
  are exposed. Running-channel failures retain the engine-process stage rather than
  being mislabeled as startup failures.
- The exact GUI-only `--diagnose-tun-helper` switch performs the existing elevated
  helper/Hello authentication without reading configuration or subscription data,
  inspecting routes, sending a challenge or sending StartTun. It closes the channel
  and waits at most eight seconds for that exact child to exit. Output is a finite
  handshake result and safe failure category. It still invokes standard Windows UAC
  and is therefore an explicit, reviewed manual diagnostic, not an automatic test.
- Local unprivileged tests cover pending/already-connected acceptance, early close,
  prefix/body deadlines, blocked writes, malformed frame size, idle/parent exit,
  cancellation failure with late completion, bounded permits and poisoned reuse.
  These tests never start a VPN or change Windows networking. Live handshake and
  subsequent end-to-end TUN acceptance remain pending user-authorized testing.

Windows references: [ConnectNamedPipe return semantics](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe),
[named-pipe client default wait mode](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client).
