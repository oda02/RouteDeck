# TUN runtime verification

RouteDeck treats Windows TUN as an owned, fail-closed session. The ordinary GUI remains
unprivileged; the reviewed elevated helper owns only the adapter created for the current
session and never stops, disables, deletes, or rewrites a foreign adapter or VPN service.

Before UAC, RouteDeck reads the adapter and route tables. An active foreign full-tunnel
adapter (including split `/1` capture routes) blocks startup with an actionable conflict.
The default-route snapshot is hashed into the helper request and recomputed after UAC, so
a route change while the prompt is open requires a fresh attempt.

After sing-box starts, the helper requires exactly one adapter named `RouteDeck`, records
its LUID and owned route keys, and verifies all of the following before reporting the core
as usable:

- the recorded LUID is still the only `RouteDeck` adapter;
- owned routes cover representative public destinations for every address family enabled
  by the protected TUN config (an IPv4-only config does not require IPv6);
- `GetBestRoute2` selects that exact LUID for each enabled family;
- no foreign full-tunnel adapter became active.

The GUI then makes both proofs: the authenticated loopback health request proves the
selected outbound, while a separate HTTPS request with automatic and explicit proxies
disabled proves the ordinary Windows network path. The helper reads interface counters
immediately before and after the latter request. `TunReady` requires the same owned LUID
and advancing counters; a successful local health proxy alone can never turn TUN green.
The periodic monitor repeats route ownership and unproxied capture verification.

Startup verification failure stops sing-box and waits for the exact owned adapter to
disappear. Normal stop uses the same bounded wait. RouteDeck does not delete an adapter as
a fallback: if the exact owned LUID remains or another same-name adapter appears, the
journal is preserved and the controller reports recovery instead of touching foreign
state.

On the next app start, RouteDeck removes a stale session directory only when its strict
versioned TUN journal still identifies the engine process, creation time, adapter LUID,
owned route keys, and config digest, while Windows proves that the recorded process,
same-name adapter, and routes are all gone. A live or reused PID, identity mismatch,
same-name adapter, remaining route on the recorded LUID, missing journal, reparse point,
or unrecognized file is preserved as a recovery conflict. Recovery removes only the
recognized RouteDeck config and journal files; it never deletes adapters or routes.
