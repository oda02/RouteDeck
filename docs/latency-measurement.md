# Connection evidence and steady response time

RouteDeck exposes two independent measurements. Neither is a promise of latency
to an arbitrary game server or website.

| Measurement | Purpose | Includes setup? | Display |
| --- | --- | --- | --- |
| Full HTTPS proof (`routeCheckMs`) | Prove selected-outbound Internet access | Yes, CONNECT/TLS and any necessary DNS | Status / diagnostics |
| Steady response (`steadyLatencyMs`) | Approximate request/response delay on an established connection through the selected outbound | Unmeasured warmup; three subsequent responses only | Home and active server row |

Both target the existing fixed Google endpoint
`https://www.gstatic.com/generate_204`. A different site's route, server processing,
or game transport can produce different results. Direct ICMP to the VPN host would
measure only part of the path and does not demonstrate usable proxy connectivity.

## Steady measurement

- Runs after a successful periodic connection/ownership proof, outside the controller
  lock. Initial connection readiness does not wait for this optional measurement.
- Uses one warmup request followed by three measured, fully consumed HTTP/1.1 204
  responses. The median is displayed; setup time is never subtracted heuristically.
- One loopback relay connection is forwarded to the authenticated selected-outbound
  health listener. Additional connections are rejected and invalidate the result.
  This prevents a client's transparent cold reconnect from entering the samples.
- The relay endpoint stays bound for its lifetime; it does not become available for
  another listener to receive proxy credentials during an internal reconnect. On
  Windows, `SO_EXCLUSIVEADDRUSE` is set before binding, including protection from
  forced `SO_REUSEADDR` rebinding by another process.
- The measurement has a shared three-second budget, bounded buffers, fixed destinations,
  normal certificate verification and no redirect following or public configurable URL.
- The result is accepted only for the same live session/generation in a ready state.
  Stop, transitions and failed proofs clear it. Missing results display an em dash;
  the UI never substitutes the larger full-proof duration.
- An optional measurement failure cannot make a proven connection fail, and a small
  response time cannot replace the original proof required for Connected.

## Reference checked

The pinned [sing-box 1.13.21 URL-test implementation](https://github.com/SagerNet/sing-box/blob/v1.13.21/common/urltest/urltest.go)
also performs an HTTP request and includes connection establishment in its timing.
Its number should not be treated as interchangeable with steady game latency.
RouteDeck keeps its existing reachability evidence and adds a separately named metric.

[Microsoft's socket ownership documentation](https://learn.microsoft.com/en-us/windows/win32/winsock/so-exclusiveaddruse)
explains why an ordinary bound Windows socket is insufficient to prevent forced
rebinding and why exclusive address use must be set before `bind`.

Tests use synthetic controller responses and explicit local socket fixtures. They do
not connect to Google, start a VPN or change Windows networking. Live Internet results
must be checked in the user's normal RouteDeck session.
