# Routing overrides

- Autosave after a short editing pause; feedback stays beside the title. Navigation
  must not lose pending edits. A late completion must never overwrite a newer draft.
- Compact 52 px application rows: name, route select and remove. Search names/paths;
  reveal full paths on demand. Keep one column at every width for predictable scanning.
- Routes: inherit the default, direct, VPN. Do not mislabel an inherited route as VPN.
- Explain System Proxy's limited TCP scope once in an expandable scope note.
- Persist before reconnect. Serialize with connect/disconnect; failed stop prevents start.
- Distinguish saved-but-unapplied rules from successful runtime application.
- Running-app picker supports batch addition and refreshing discovery. Closed apps
  retain their saved rules.
- Keep traffic rules in a compact, collapsed section below application exceptions.
  Its summary shows the rule count and calls out UDP 443 blocking only when the first
  enabled rule matching that network/port blocks it.
- Traffic-rule rows expose enabled state, network, port, action, edit/delete, and
  simple ordering because the first match wins. Limit the list to 32 rules.
- Add/edit uses an accessible dialog and applies a validated local draft only on
  confirmation. Ports are 1–65535; port 53 is reserved for protected DNS handling.
- Explain that traffic rules apply only to TUN, before application exceptions and
  after protected DNS/IPv6 handling. UDP 443 blocking may encourage TCP fallback
  for YouTube; QUIC-only applications may require disabling it.
- Keep Naive UDP-over-TCP in a collapsed compact section. It applies to every Naive
  profile and requires a compatible SagerNet UoTv2 server such as sing-box; plain
  Naive/Caddy does not gain it automatically. Application UDP still requires TUN,
  and traffic rules continue to run.
- List gVisor first in the TUN stack selector and label it as recommended while
  retaining the explicit System option.
