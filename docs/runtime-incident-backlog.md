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
