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
