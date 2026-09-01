# Diagnostics overrides

- Primary action: Run connection check. Copy sanitized report is secondary.
- Show the connection proof pipeline in order with state, measured value, timestamp,
  duration, and a plain-language failure. Preserve successful earlier steps.
- Logs are collapsed by default, selectable, searchable, and secret-redacted before
  rendering or copying. Never display subscription URLs, UUID credentials, passwords,
  private keys, or full authorization headers.
- External VPN/proxy detection is informational unless it blocks ownership or routing;
  then show an opaque warning with the specific safe recovery action.
