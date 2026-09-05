# Servers overrides

- Primary action: Add server. Add subscription is a visible secondary action.
- One library groups servers under collapsible, named source headers. Search covers
  names, protocols, and group names and reveals matching groups while searching.
- Each server row exposes name, protocol text, source, measured HTTPS latency, active state
  and selected state. A tiny colored flag/dot is never the only identifier.
- `—` means unmeasured or unsupported; never show fake local/fake-DNS latency.
- Groups over 100 rows render progressively with a labeled "show more" control;
  search matches the entire library before rendering and resets the visible limit.
  Preserve native keyboard navigation and focus when expanding the list.
- Manual import accepts share links (including Naive HTTPS / QUIC) or JSON text;
  subscription import accepts an HTTPS URL. Both use labeled, uncontrolled secret
  inputs with autocomplete disabled and clear them after parsing or on close.
- Import previews accepted protocol counts and skipped entries, with an optional group
  name. Confirmation appends a new group and preserves existing servers and selection.
  Format validation must not imply a successful real connection.
- Cancel remains available during preview loading. Saving is non-cancellable, with
  progress feedback and a disabled close control until the result is known.

- Subscription headers expose refresh and delete. Missing private URL prompts once;
  deletion requires a concrete group confirmation. Active deletion disconnects;
  refresh reconnects if that source was active and the user has not cancelled.
- Page opened from navigation stays open on selection and preserves scroll/search.
  Page opened as Home picker returns Home; a visible Back action cancels picking.
- Anchor hidden native radios inside relative-position labels. Outer window frames
  use overflow: clip; never permit browser focus to scroll the app frame itself.
- Dialogs/toasts are document portals. Background is inert during a dialog; focus
  returns with preventScroll. Toasts clear on navigation and hide behind dialogs.
