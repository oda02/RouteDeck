# Home overrides

- Connection hero shows actual status, active server/source and active mode.
  Desired selection appears separately; a pending selection is never called active.
- One large Connect/Disconnect action (60px minimum); during startup the same
  area cancels pending connection intent. A failed stop never starts another core.
- Order: actual connection and action, server picker, mode selector and concise
  capture limitation, actionable error, compact routing shortcut.
- Choosing a different server or mode while connected reconnects automatically.
  Disconnected changes only update the selection. TUN still uses normal UAC.
- Show the optional steady response to Google through the selected outbound while
  verified. The clickable metric explains three samples on one established connection.
  Missing samples show an em dash, never the larger full-proof duration. No invented
  ICMP ping, speed gauge, or timestamp. Cold proof timing lives in Diagnostics.
- Home server picker returns Home after choosing, including the current server.
- Use a quiet high-contrast hero, no map, ornamental charts or decorative animation.
