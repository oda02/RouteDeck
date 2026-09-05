# Discord and zapret coexistence: observed checks

Date: 2026-09-05. User-authorized live connectivity and Discord launch testing.

## Configuration observed

- RouteDeck was connected in TUN mode with Hysteria2. The default application route
  was direct; Discord was not among the applications routed through the VPN.
- TUN used the system stack, strict routing, current-network DNS and a physical
  Ethernet upstream. Direct application traffic still traverses the TUN stack.
- The running Flowseal zapret service used the ALT4 strategy from release 1.10.0.
  Its saved service command line had no interface restriction or custom raw filter.
  The elevated process's command line was unavailable through the unprivileged
  process query; the service registry configuration supplied the actual evidence.

## Results

With both TUN and zapret left running, tested ordinary sockets through TUN, the
existing local HTTP inbound using the direct route, and the authenticated health
inbound forced through the selected Hysteria2 outbound. No new listeners were opened.

| Check | TUN / direct | HTTP / direct | Selected Hysteria2 |
| --- | --- | --- | --- |
| Discord gateway discovery HTTPS | 200 | 200 | 200 |
| Update host HTTPS, root URL | 404 | 404 | 404 |
| CDN HTTPS, root URL | 403 | 403 | 403 |
| Chromium page request to Discord app | 200 | 200 | 200 |
| Anonymous gateway WebSocket | Hello, opcode 10 | Hello, opcode 10 | Hello, opcode 10 |

The CDN and update root statuses establish a TLS/HTTP response, not successful asset
or update retrieval. No account credentials or Discord tokens were used by probes.
The selected-outbound WebSocket initially failed before local proxy authentication
was established; after an HTTPS authentication warmup it received Hello normally.
That first fixture result does not demonstrate a Hysteria2 or Discord failure.

Computer-use inspection confirmed a blank Discord window. Reloading that window and
opening Discord again exposed a main-process JavaScript error, `callback already
pending`. A subsequent Discord-only process restart reached the sign-in screen while
TUN and zapret remained active. No cache/profile data was deleted and no logout action
was taken. The reason account sign-in was then requested was not established.
The most recent logged gateway session examined had successfully reached Ready;
generic error counts in the log did not establish a current gateway outage.

## Follow-up after reboot

The user rebooted Windows and the old v2rayN/Xray processes were no longer present.
A saved manual loopback proxy nevertheless remained enabled in the current user's
legacy registry settings, with no listener at that endpoint. WinInet reported direct
mode, so these two sources disagreed. With the user's explicit authorization, a
guarded maintenance script saved the exact prior state and disabled the stale manual
proxy flag, notified WinInet, and verified both views were disabled. RouteDeck,
sing-box, zapret and the adapters were left running. The source of the stale setting
was not established. Windows proxy settings persist independently of their process;
RouteDeck's normal publication path refuses to overwrite an enabled foreign proxy.

The browser failure persisted after that cleanup. The following repeat used an
active Hysteria2 TUN session with **default selected outbound and no application
rules**. This differs from the earlier direct-default session. Both existing local
HTTP inbounds now used the selected Hysteria2 outbound.

| Fresh installed Yandex profile | Discord | YouTube |
| --- | --- | --- |
| Ordinary sockets through TUN | ERR_SSL_PROTOCOL_ERROR | ERR_SSL_PROTOCOL_ERROR |
| Existing ordinary HTTP inbound, selected Hysteria2 | 200 | 200 |
| Authenticated health HTTP inbound, selected Hysteria2 | 200 | Page load timeout; inconclusive |

Computer-use inspection of the user's browser reproduced the Discord TLS error
after a normal reload. YouTube displayed its no-connection screen. A separate
Python TLS fixture also timed out through TUN, but returned HTTP 200 for both sites
through the ordinary HTTP inbound. Both CONNECT-by-domain and CONNECT-by-the-locally-
resolved-IP succeeded, retaining the original TLS server name and certificate
verification. The session configuration remained unchanged during this fixture.

These results implicate the client-to-TUN path rather than Hysteria2 or the server
alone. They do not prove which component is responsible. ALT4 applies fake and
multisplit processing without an interface restriction; its interaction with the
system TUN stack is a testable hypothesis. A user-operated, brief zapret-only off/on
comparison was requested, leaving RouteDeck's server and TUN session unchanged.
No such service operation has been performed by the agent. Restricting zapret to
the verified physical interface would be a subsequent experiment if that comparison
supports the hypothesis; it must retain processing of direct physical traffic.

The user subsequently confirmed that disabling only zapret removed the failure.
After restarting zapret, pages continued to load briefly and then failed again.
This supports an interaction between the two components; retained connections or
browser state can explain the temporary success, but that mechanism was not traced.

The user also reports that v2rayN works with the unchanged zapret configuration.
The saved v2rayN state examined had TUN disabled, an unset sing-box stack preference,
and a generated Xray local-proxy configuration, so it cannot identify the earlier
successful TUN setup. Official v2rayN 7.24.8 code selects `gvisor` when its sing-box
stack setting is empty; it also has a separate Xray-native TUN generation path.
RouteDeck previously fixed sing-box to `system`. A closed, opt-in `gvisor` choice is
being added for a controlled RouteDeck-side comparison, keeping the existing `system`
default and preserving zapret configuration. This is an experiment, not a verified
compatibility fix. Real privileged TUN acceptance remains a manual/isolated check.

References for comparison: [v2rayN sing-box inbound generation](https://github.com/2dust/v2rayN/blob/7.24.8/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxInboundService.cs),
[default stack list](https://github.com/2dust/v2rayN/blob/7.24.8/v2rayN/ServiceLib/Global.cs#L529),
[Xray inbound generation](https://github.com/2dust/v2rayN/blob/7.24.8/v2rayN/ServiceLib/Services/CoreConfig/V2ray/V2rayInboundService.cs).

## gVisor and the remaining YouTube failure

The user subsequently enabled the delivered gVisor option and reported that Discord
desktop and its website worked, while YouTube media still failed. A fresh, temporary
installed-browser profile was tested with the same active gVisor/Hysteria2 session,
selected default route and unchanged zapret. The configuration was verified unchanged
across the comparison. The public video document loaded in all three cases:

| Browser path | Video response bytes | Buffered media | Observed limit |
| --- | --- | --- | --- |
| TUN, ordinary browser defaults | 0 | 0 seconds | Media requests failed with `ERR_FAILED` |
| TUN, QUIC disabled in this temporary browser only | about 723 KB | 20 seconds | Player subsequently paused |
| Existing ordinary HTTP proxy, same selected outbound | about 720 KB | 20 seconds | Player subsequently paused |

This is evidence for a QUIC/UDP-path compatibility problem, not proof of continuous
playback or identification of the failing component. No successful HTTP/3 response
was captured in the failing case. The user later reported that the YouTube document
also stopped loading, consistent with an intermittent failure but not diagnostic of
the exact cause.

The user's saved generated v2rayN configuration contained an unconditional routing
rule blocking UDP destination port 443. This is a concrete difference from RouteDeck's
previous configuration; it is not a claim that every v2rayN installation or VPN client
ships that default. The stock v2rayN TUN samples examined did not contain that rule;
the active persisted routing rules can supply it. Its original preset/import provenance
was not established. Computer Use launched the installed Chrome, but URL-policy
verification stopped further interaction, so no playback result is claimed for that
Chrome window.

At the user's request, RouteDeck now provides typed, editable TUN traffic rules with
UDP 443 blocking enabled on migration from older preferences. Explicit removal or
disabling survives subsequent launches. Blocking uses an immediate reject response
instead of silent loss, allowing clients that support it to fall back to TCP. Rules
are confined to the TUN inbound, after mandatory DNS, own-prefix and IPv6 guards,
and before application exceptions. They do not match sing-box's outer Hysteria2
transport or the ordinary/health HTTP inbounds. This remains a compatibility measure;
QUIC-only client applications may require disabling it.

References: [sing-box 1.13.21 reject behavior](https://raw.githubusercontent.com/SagerNet/sing-box/v1.13.21/docs/configuration/route/rule_action.md),
[v2rayN 7.24.8 Xray routing generation](https://github.com/2dust/v2rayN/blob/7.24.8/v2rayN/ServiceLib/Services/CoreConfig/V2ray/V2rayRoutingService.cs),
[v2rayN stock TUN rules](https://raw.githubusercontent.com/2dust/v2rayN/7.24.8/v2rayN/ServiceLib/Sample/SampleTunRules).

## Follow-up after enabling the traffic rule

The user initially reported continued failure, then reported recovery after several
minutes. Read-only inspection confirmed the delivered traffic-rules build, gVisor
and the exact enabled UDP 443 reject rule in the active configuration. This session
used a VLESS/Xray SOCKS bridge, with a direct default and an explicit installed Yandex
browser application rule through the selected outbound. This differs from the prior
Hysteria2 session and cannot establish an isolated before/after protocol comparison.

A fresh temporary installed Yandex profile through ordinary TUN loaded the public
video document in about 3 seconds and received about 1.1 MB of media, buffering
20 seconds without failed media requests. The player subsequently paused, so continuous
playback remains unverified. The ordinary local HTTP inbound also loaded and buffered
media. Explicitly disabling QUIC in another temporary profile buffered media but had
additional HTTP 403/aborted media requests; it was not uniformly better. The session
configuration was unchanged across this completed comparison. An earlier attempt to
add authenticated health-in browser coverage stalled; only that temporary test browser
was terminated. No result is claimed for that attempt.

The minutes-long recovery was not captured. Retained browser connection/alternative-
service state and retries are plausible, not proven; a server or route change is also
a confounder. Chromium has broken-alternative-service state with expiry/backoff, but
that mechanism does not imply that TCP fallback should always wait several minutes.
No user browser profile/cache, Windows DNS cache, VPN state or zapret setting was
changed. Further reproduction should retain the same server and rules and compare
the affected browser session against a fresh temporary profile during the failure.

Reference: [Chromium broken alternative service state and timers](https://chromium.googlesource.com/chromium/src/+/HEAD/net/http/broken_alternative_services.cc).

## Reproduced DNS failure after apparent recovery

The subsequent gVisor/Hysteria2 session used a direct default, selected-outbound
exceptions for the affected browser and desktop clients, and the enabled TUN UDP
443 reject rule. The user reported YouTube and ChatGPT failing and then recovering
while investigation was in progress. No Windows/browser cache was cleared and no
VPN, zapret or routing configuration was changed. Ordinary read requests can warm
caches; this is not evidence of a permanent repair.

During the failure, the affected browser in a fresh temporary profile failed to
resolve YouTube even with QUIC disabled. The existing ordinary HTTP proxy loaded
the video document and about 720 KB of media with 20 seconds buffered; the player
paused, so continuous playback was not established. The authenticated selected
HTTP CONNECT path returned YouTube HTTP 200 while local resolution failed.
ChatGPT returned HTTP 403 after successful TLS on the raw probes: this is an HTTP
response, not proof that TUN or TLS failed, and does not establish browser usability.

Raw DNS queries, with transaction IDs checked and no address contents exported,
showed these differences without changing the active session:

| Resolver/path | YouTube A/AAAA result |
| --- | --- |
| TUN DNS peer, queried over UDP and TCP | A returned NXDOMAIN; AAAA returned addresses |
| Physical adapter's IPv6 link-local DNS, via existing engine | NXDOMAIN over both UDP and TCP |
| Same adapter's IPv4 DNS, via existing engine | Initially addresses over UDP and TCP; later UDP returned NXDOMAIN while TCP still returned addresses |
| Separate sing-box explicit IPv4 TCP DNS transport, relayed through the existing SOCKS inbound | All 12 YouTube queries across three rounds returned addresses in 0–31 ms |

The last comparison disabled only the temporary engine's own DNS cache. It covered
UDP and TCP clients and both A and AAAA questions. ChatGPT's 12 queries also returned
addresses; Discord's A queries returned addresses and AAAA returned valid NOERROR
with no records. Those empty AAAA responses are not name errors. Temporary engines
were stopped, and active session bytes and the reviewed engine hash were unchanged.

A separate engine bound directly to the physical interface timed out for all three
sites. The same upstream answered through the existing engine. The active TUN's DNS
leak protection is a possible explanation, not proven by this test. Consequently,
the relay comparison validates the DNS transport choice but is not acceptance of a
new privileged TUN session. The standalone `local` comparison likewise timed out;
it must not be used as a clean before/after reproduction of the running engine.

In pinned sing-box 1.13.21, Windows `local` DNS gathers resolver addresses from
eligible adapters. It does not restrict that list to RouteDeck's sealed physical
adapter merely because the outbound socket is interface-bound. The resolver stops
on the first response without a transport error, including NXDOMAIN. Windows does
not enable resolver rotation or populate the search-suffix list in this version;
neither round-robin selection nor a suffix race is established here.

The implemented repair selects the first usable IPv4 DNS address on the sealed physical
adapter and uses TCP port 53 for TUN bootstrap/current-network resolution. It keeps
the same network DNS provider and independently verifies the address in the helper.
It changes no Windows DNS configuration and does not flush shared caches. It retains
`local` for System Proxy and for adapters without an eligible IPv4 DNS address.
Diagnostics record only `tun_dns=physical_ipv4_tcp` or
`tun_dns=local_fallback_no_ipv4`, without exporting the resolver address. Startup
revalidates the DNS snapshot; a later DHCP DNS refresh alone does not terminate a
healthy active session. Reconnect selects the current resolver again.

Limits: the component causing the observed UDP/NXDOMAIN discrepancy remains
unidentified. TCP to a single resolver is not resolver failover; networks that block
TCP DNS or change resolver addresses need further handling. This change must be
tested with a user-started new TUN session, repeated server/mode transitions and
actual browser use before claiming the intermittent symptom resolved. Existing
browser/Windows negative entries may outlive the engine restart. Do not automatically
clear shared DNS state or weaken strict routing to mask them.

References: [pinned Windows DNS discovery](https://raw.githubusercontent.com/SagerNet/sing-box/v1.13.21/dns/transport/local/resolv_windows.go),
[pinned resolver response handling](https://raw.githubusercontent.com/SagerNet/sing-box/v1.13.21/dns/transport/local/local_shared.go),
[pinned resolver configuration and offset](https://raw.githubusercontent.com/SagerNet/sing-box/v1.13.21/dns/transport/local/resolv.go).

## Limits and next decision

This does not reproduce or rule out intermittent conflicts during a VPN transition,
authenticated session resumption, update installation, or voice/UDP traffic. No sign-in,
messages, calls, packet capture or service restarts were performed. The only
network-setting change was the explicitly authorized stale manual-proxy cleanup
described above. The existing VPN and zapret processes remained running.

There is currently insufficient evidence to change zapret's interface filter or weaken
strict routing. The user-operated gVisor comparison and UDP 443 compatibility rule
are described above. If the failure returns, distinguish a fresh launch
from an already-running Discord session, and collect the contemporaneous error before
changing one variable at a time. Any future physical-interface filter must preserve
zapret processing of direct Discord traffic leaving that physical interface.

References: [Flowseal project](https://github.com/Flowseal/zapret-discord-youtube),
[winws interface filters](https://github.com/bol-van/zapret/blob/master/docs/windows.md),
[sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/).
