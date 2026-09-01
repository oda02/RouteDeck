# Home overrides

- Home owns the only global connection CTA. Its label/state pair is
  Connect → Connecting… → Disconnect; “Connected” appears only after verification.
- Order: connection summary, server selector, mode selector, persistent mode limitation,
  primary CTA, proof card, routing summary, latest opaque error.
- Proof rows must remain visible without opening Diagnostics: Core, Local proxy/TUN,
  Windows mode, selected-outbound HTTPS proof, and VPN egress IP. The IP may be
  unavailable after a successful proof; that alone does not make the session fail.
- When disconnected, show the last verified outbound IP as “Last check”, never as live.
- Do not use a decorative hero, speed gauge, map, or large animated power glyph.
