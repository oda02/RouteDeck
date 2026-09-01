# Routing overrides

- Primary action: Apply changes. Until applied, show a persistent “Unsaved changes” label.
- The first control is Default route: Direct or VPN. Its current effective value is
  repeated in the summary; there is no ambiguous Auto default in the first release.
- Application rules override the default. Each row shows app icon/name/path and a
  three-state control: Inherit, Direct, VPN.
- When System Proxy is selected, retain configured app rules but mark them “Best effort
  for proxy-aware apps — reliable enforcement requires TUN”. Do not imply full per-app
  capture, but do not claim that rules evaluated for traffic entering the proxy are inert.
- Running-app discovery is secondary and must not remove rules for closed applications.
