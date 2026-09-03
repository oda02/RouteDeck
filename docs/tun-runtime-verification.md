# TUN runtime verification

RouteDeck treats Windows TUN as an owned, fail-closed session. The ordinary GUI remains
unprivileged; the reviewed elevated helper owns only the adapter created for the current
session and never stops, disables, deletes, or rewrites a foreign adapter or VPN service.

Before UAC, RouteDeck reads the adapter and route tables. It selects the active physical
Ethernet or Wi-Fi interface owning the effective IPv4 path and records its alias, index,
and LUID. An active foreign full-tunnel adapter (including split `/1` capture routes)
blocks startup with an actionable conflict. The exact interface identity, protected
config hash, and default-route snapshot are hashed into the helper request and recomputed
after UAC, so a rename, replacement, or route change while the prompt is open requires a
fresh attempt.

Native sing-box outbounds use the sealed physical alias instead of route auto-detection.
For VLESS REALITY, the local sing-box-to-Xray SOCKS bridge stays unbound; only Xray's real
VLESS outbound plus sing-box direct/bootstrap egress bind to the physical interface.
System Proxy mode is unchanged and continues to follow the current Windows path.

After sing-box starts, the helper requires exactly one adapter named `RouteDeck`, records
its LUID and owned route keys, and verifies all of the following before reporting the core
as usable:

- the recorded LUID is still the only `RouteDeck` adapter;
- owned routes cover representative public destinations for every address family enabled
  by the protected TUN config (an IPv4-only config does not require IPv6);
- `GetBestRoute2` selects that exact LUID for each enabled family;
- the sealed physical alias, interface index, and LUID still identify the same active
  hardware adapter, and an interface-constrained best-route query remains usable;
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
