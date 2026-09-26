# Themed controls

- Replace the seven native dropdown popups with one themed select-only combobox.
  Preserve existing routing drafts, settings saves, labels, and selected values.
- Keep focus on its trigger. Support arrows, Home/End, typeahead, Enter/Space,
  Escape and Tab; pointer highlighting never applies a choice by itself.
- Use existing surface/text/accent tokens in both themes. Portal popups past
  scrolling card boundaries; clamp them to the viewport and dismiss on outside
  interaction, page scroll or resize. Honor reduced motion.
- Use a green keyboard focus ring and a stable application-dialog close target.
  Windows' native title-bar close control is outside this web UI change.
- Verify synthetic browser keyboard/mouse behavior, modal dismissal, focus,
  dark/light 360/1000 px screenshots and hover. No native tunnel/network actions.

Scoped UI/UX Pro Max guidance: keyboard navigation, visible focus, semantic
theme tokens, stable hit targets, and reduced motion. Keep RouteDeck's existing
compact design; add no dependencies or generated design system.
