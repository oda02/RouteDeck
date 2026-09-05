# RouteDeck design system

> Source of truth for every RouteDeck surface. Before implementing a screen, read
> `pages/<screen>.md`; page rules override this file only where they differ.

Generated from UI/UX Pro Max on 2026-09-01 for a compact vertical Windows VPN/proxy
utility. Design dials: variance 4/10, motion 4/10, density 6/10. The generated
recommendation (minimal single column, dark-first, one primary CTA, Inter) is adapted
to an offline desktop utility: use Windows system typography and lightweight CSS
motion rather than external fonts or full-page animation libraries.

## Product principles

1. **Proof before confidence.** “Connected” means the core, local ingress, selected
   Windows mode, and outbound verification all succeeded. A running process alone is
   never presented as a successful connection.
2. **One primary action.** Each screen has at most one filled action. On Home it is
   Connect/Disconnect; all other actions are secondary or tertiary.
3. **Limitations stay visible.** System Proxy explicitly says that only proxy-aware
   applications are covered. Per-app routing says that reliable enforcement requires
   TUN. Never hide these facts in a tooltip.
4. **Errors are readable and recoverable.** Critical notices are opaque, persistent,
   state what failed, and offer a concrete next action. Toasts are supplementary.
5. **Compact, never cramped.** Every interactive target is at least 44 x 44 px, with
   an 8 px gap where targets touch. Long content scrolls; controls never clip.

## Visual language

- Center width-limited pages within the main content viewport at every window size.
  Navigation remains outside that viewport; only main content and dialogs scroll.
- Keep native window, WebView and document fills aligned with the selected theme.
  Scrollbars use the theme's subdued green with native high-contrast fallback.
- Browser navigation/printing context menus are suppressed; application context
  handlers and keyboard editing remain available. Packaged launches have no console.

- Style: quiet, technical minimalism; dark-first with an accessible light mapping.
- Shape: restrained 6/10/14 px radii. No pill containers around every element.
- Icons: one outline SVG family (Lucide), 1.75 px stroke, 18/20/24 px glyph tokens.
  No emoji, raster UI icons, or icon-only navigation.
- Surfaces are opaque. Blur is permitted only for a modal scrim, never behind text.
- Color is never the sole status cue: pair it with a label and icon.
- Avoid decorative glows, gradients, glassmorphism, and animated background effects.

## Semantic color tokens

Components consume semantic tokens only; do not hard-code palette values in JSX.

### Dark theme (default)

| Token | Value | Use |
|---|---:|---|
| `--bg-canvas` | `#0B0E14` | Window background |
| `--bg-surface` | `#131821` | Cards and controls |
| `--bg-elevated` | `#1A202B` | Menus and dialogs |
| `--bg-hover` | `#222A36` | Hover/selected-neutral |
| `--border-subtle` | `#344052` | Dividers and card edges |
| `--border-strong` | `#5B687B` | Inputs and active boundaries |
| `--text-primary` | `#F4F7FB` | Primary text |
| `--text-secondary` | `#AAB4C3` | Supporting text |
| `--text-disabled` | `#748092` | Disabled text; pair with disabled semantics |
| `--accent` | `#74E09A` | Primary action and connected status |
| `--on-accent` | `#07130C` | Text/icons on accent |
| `--focus` | `#8AB4FF` | Keyboard focus ring |
| `--danger-bg` | `#32171B` | Opaque critical notice |
| `--danger-border` | `#A94956` | Critical notice border |
| `--danger-text` | `#FFD5D8` | Critical notice text |
| `--warning-bg` | `#332713` | Opaque warning notice |
| `--warning-border` | `#9A742A` | Warning notice border |
| `--warning-text` | `#FFE1A4` | Warning notice text |
| `--info-bg` | `#15253C` | Opaque information notice |
| `--info-border` | `#416DA4` | Information notice border |
| `--info-text` | `#CEE2FF` | Information notice text |

### Light theme mapping

| Token | Value |
|---|---:|
| `--bg-canvas` | `#F4F7FB` |
| `--bg-surface` | `#FFFFFF` |
| `--bg-elevated` | `#FFFFFF` |
| `--bg-hover` | `#E9EEF5` |
| `--border-subtle` | `#CDD5E1` |
| `--border-strong` | `#7A8798` |
| `--text-primary` | `#111827` |
| `--text-secondary` | `#4B5565` |
| `--text-disabled` | `#7B8491` |
| `--accent` | `#147A3D` |
| `--on-accent` | `#FFFFFF` |
| `--focus` | `#175CD3` |
| `--danger-bg` | `#FFF1F2` |
| `--danger-border` | `#C94152` |
| `--danger-text` | `#7D1D2A` |
| `--warning-bg` | `#FFF7E6` |
| `--warning-border` | `#A96900` |
| `--warning-text` | `#664300` |
| `--info-bg` | `#EBF4FF` |
| `--info-border` | `#2463A8` |
| `--info-text` | `#173F6A` |

Validate every foreground/background pair with automated contrast tests: normal text
at least 4.5:1, large text and non-text control boundaries at least 3:1.

## Typography

- Family: `"Segoe UI Variable", "Segoe UI", Inter, system-ui, sans-serif`.
  Do not fetch Google Fonts; portable/offline startup must be deterministic.
- `--type-caption`: 12 px / 16 px / 500.
- `--type-label`: 13 px / 18 px / 600.
- `--type-body`: 14 px / 21 px / 400.
- `--type-body-strong`: 14 px / 21 px / 600.
- `--type-title`: 18 px / 24 px / 650.
- `--type-display`: 24 px / 30 px / 700.
- Use tabular figures for latency, ports, IP addresses, byte counts, and timers.
- Allow Windows text scaling to 200%. Prefer wrapping to truncation; if a server name
  must truncate, expose its full value through accessible name and tooltip.

## Spacing and sizing

| Token | Value | Use |
|---|---:|---|
| `--space-1` | 4 px | Tight internal gap |
| `--space-2` | 8 px | Icon gap / target separation |
| `--space-3` | 12 px | Compact control inset |
| `--space-4` | 16 px | Screen gutter / card padding |
| `--space-5` | 20 px | Section gap |
| `--space-6` | 24 px | Major separation |
| `--control-min` | 44 px | Minimum hit target and input height |
| `--window-min-width` | 360 px | Hard minimum client width |
| `--window-min-height` | 560 px | Hard minimum client height |
| `--window-default-width` | 420 px | Default compact width |
| `--window-default-height` | 720 px | Default compact height |
| `--content-wide-max` | 760 px | Wide content cap |

## Radius, elevation, and layers

- `--radius-sm: 6px`; `--radius-md: 10px`; `--radius-lg: 14px`.
- `--shadow-popover: 0 12px 32px rgb(0 0 0 / 0.36)` (dark) and 0.18 (light).
- `--z-content: 0`, `--z-sticky: 10`, `--z-popover: 20`,
  `--z-dialog: 40`, `--z-toast: 50`.
- Do not create arbitrary z-index values or nested translucent stacking contexts.

## Motion

- `--motion-fast: 120ms`; `--motion-normal: 180ms`; `--motion-slow: 240ms`.
- Use `cubic-bezier(.2,.8,.2,1)` for entrances and state changes; opacity and transform
  only. Never animate layout dimensions or the entire route with an overlay.
- Press feedback must appear within 100 ms and must not shift layout bounds.
- Continuous animation is restricted to an active progress spinner.
- Under `prefers-reduced-motion: reduce`, remove transforms and use effectively instant
  opacity changes. Functional state changes remain immediately perceivable.

## Global component rules

- Native semantic elements first: `button`, `input`, `select`, `nav`, `main`, `dialog`.
- Every control has visible hover, pressed, disabled, and `:focus-visible` states.
  Focus ring: 3 px `--focus` with 2 px canvas offset.
- Primary button: filled accent, on-accent text, 44 px minimum height, full width in
  compact layout. While pending, keep its width stable, disable it, show progress, and
  announce the updated label.
- Secondary button: surface background and strong border. Tertiary button: text/icon
  with a 44 px hit area. Destructive action never shares accent styling.
- Cards are non-interactive by default. Do not apply hover elevation/cursor unless the
  whole card is actually a button or link.
- Inputs have persistent labels and helper/error text. Placeholder is an example, not
  a label. Validate on blur or submit, not on each keystroke.
- Dialogs use an opaque elevated surface and a 55% black scrim. At minimum height they
  scroll internally, keep title/actions visible, trap focus, close on Escape when safe,
  and return focus to the trigger.
- Critical errors do not auto-dismiss. Informational toasts use an opaque elevated
  surface, `aria-live="polite"`, and dismiss after 5 seconds; they never steal focus.

## Responsive shell

- 360–559 px: single column; labeled five-item bottom navigation; 16 px gutters.
- 560–719 px: single column with slightly wider cards; labeled bottom navigation.
- 720 px and wider: 176 px labeled navigation rail plus one content column; hide the
  bottom navigation. Do not turn the utility into a multi-column dashboard.
- Header and navigation stay fixed; only `main` scrolls. Reserve their exact height so
  the first and last controls never sit underneath them.
- A screen may add a sticky primary action only when it does not duplicate the Home
  connection action and its scroll container reserves the action bar height.

## Non-negotiable anti-patterns

- No green “Connected” state before outbound verification.
- No hidden System Proxy or TUN limitation text.
- No translucent error cards or overlapping stacked toasts.
- No protocol/status meaning communicated by color alone.
- No icon-only top-level navigation, emoji icons, or hover-only affordances.
- No controls below 44 x 44 px, horizontal page scrolling, clipped dialogs, or fixed
  footers covering content.
- No remote font dependency, GSAP/page overlay transition, decorative motion, or glow.
- No raw subscription secrets in the UI, clipboard action, or diagnostic export.
