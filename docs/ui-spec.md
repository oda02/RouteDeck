# RouteDeck UI/UX specification

Status: implementation-ready v1 specification  
Target: Windows desktop, Tauri + React, compact resizable utility  
Design source: `../design-system/routedeck/MASTER.md` and page overrides  
Primary language for examples: Russian; all layout must also tolerate English strings

## 1. Product intent

RouteDeck is a small, trustworthy controller for a sing-box core. The UI is not allowed
to equate “the core process started” with “the VPN works.” Its central job is to let a
person choose a server and traffic policy, then make the effective state obvious.

V1 top-level destinations:

1. Home — connect, select mode/server, see proof.
2. Servers — import, refresh, measure, select.
3. Routing — choose Direct/VPN default and per-app exceptions.
4. Settings — behavior, ports, coexistence, appearance, advanced options.
5. Diagnostics — run and inspect a secret-safe end-to-end check.

The first release deliberately does not include maps, bandwidth charts, marketing
content, theme decoration, proxy-group graph editors, or protocol-specific tuning on
the Home screen.

## 2. Important operating truths surfaced by the UI

### System Proxy

- RouteDeck can run its own local HTTP/SOCKS proxy on ports different from another
  client. That does **not** mean both apps can own the Windows system proxy setting at
  once: Windows exposes one effective system proxy configuration.
- If another client owns that setting, RouteDeck may still start and prove its local
  proxy by making an explicit test request through its own port. It must not say that
  ordinary apps are routed through RouteDeck until the Windows setting points to and
  is owned by RouteDeck.
- System Proxy covers only applications that honor Windows proxy configuration.
  It cannot promise reliable OS-wide or arbitrary per-process routing.

Persistent compact copy on Home and Routing:

> Системный прокси работает только в приложениях, которые используют настройки
> прокси Windows. Для надёжных правил по приложениям выберите TUN.

### TUN

- TUN is the mode for reliable default-route and per-app rules.
- It may require elevation and can conflict with routes or DNS installed by another
  VPN. Coexistence is detected and tested; it is not assumed.
- If TUN cannot prove the expected outbound path, status is Degraded or Failed, not
  Connected, even when the adapter exists.

Persistent compact copy before first TUN activation:

> TUN перехватывает системный трафик и может запросить права администратора.
> RouteDeck проверит маршрут и отменит изменения, если запуск не завершится.

## 3. Window and shell

### Window bounds

- Minimum: 360 x 560 px. Resizing below either dimension is prevented by Tauri.
- Default: 420 x 720 px, centered on first launch; restore last valid bounds later.
- Recommended compact range: 400–520 x 640–820 px.
- Wide adaptation begins at 720 px. Content caps at 760 px and remains left-aligned
  after the navigation rail; it does not stretch into a dashboard.
- The native title bar remains usable for move/minimize/maximize/close. Do not create
  tiny custom window buttons.
- Closing behavior is explicit in Settings (“Hide to tray” or “Exit”) and is never
  changed silently.

### Shell regions

- App header: 52 px, opaque canvas surface. Product name, concise global status, and
  optional overflow button. Global status is text plus icon, not a colored dot alone.
- Main: the only page scroll container. It has 16 px compact gutters, 20 px wide
  gutters, and enough bottom inset to clear fixed navigation/action bars.
- Compact navigation: opaque 60 px bottom bar, five equal 44 px minimum targets with
  Lucide icon and short label: Главная, Серверы, Правила, Настройки, Статус.
- Wide navigation: 176 px left rail with the same icons and full labels. Current page
  uses `aria-current="page"`, stronger text, icon, and a 3 px accent indicator.
- Save the scroll position per destination and restore it when navigating back.

## 4. Narrow wireframes

The wireframes describe hierarchy, not literal ASCII borders or production copy.

### 4.1 Home — disconnected

```text
┌ RouteDeck                              Отключено ┐
│                                                   │
│  ГЛАВНАЯ                                         │
│  [ Server: NL / VLESS                         > ] │ 44
│                                                   │
│  Режим                                            │
│  [ Системный прокси ] [ TUN ]                     │ 44
│  [i] Системный прокси работает только в           │
│      приложениях с поддержкой прокси Windows.     │
│                                                   │
│  [                 Подключить                  ]  │ 48 primary
│                                                   │
│  Проверка подключения                             │
│  ┌ Ядро              Не запущено                 ┐│
│  │ Локальный прокси   —                          ││
│  │ Режим Windows      Не применён                ││
│  │ VPN-маршрут        Не проверялся              ││
│  │ VPN egress IP      Последний: 203.0.113.10    ││
│  └  Проверено 18 мин назад                       ┘│
│                                                   │
│  Маршрутизация                     [Настроить >]  │
│  По умолчанию: Напрямую · 2 приложения через VPN │
│                                                   │
├ Главная  Серверы  Правила  Настройки  Статус ─────┤
```

The server selector is a secondary control, not a second green button. “Last IP” is
visually and semantically historical.

### 4.2 Home — connecting and verified

```text
┌ RouteDeck                          Подключение… ┐
│  NL / VLESS                                      │
│  Системный прокси                                │
│  [        Проверяется внешний маршрут…        ] │ disabled primary
│                                                  │
│  Проверка подключения                            │
│  ✓ Ядро              Запущено                    │
│  ✓ Локальный прокси   127.0.0.1:2080             │
│  ✓ Режим Windows      RouteDeck владеет прокси   │
│  · VPN-маршрут        HTTPS-проверка…            │ polite live region
│  — VPN egress IP      Ожидание                   │
└──────────────────────────────────────────────────┘

┌ RouteDeck                          Подключено  ┐
│  [                Отключить                  ] │ primary neutral/danger-safe
│  Проверка подключения                           │
│  ✓ Ядро              Запущено                   │
│  ✓ Локальный прокси   127.0.0.1:2080            │
│  ✓ Режим Windows      Активен                    │
│  ✓ VPN-маршрут        Проверен через NL          │
│  ✓ VPN egress IP      198.51.100.24              │
│                         Проверено 8 сек назад    │
└─────────────────────────────────────────────────┘
```

Connected is allowed only after every proof required by the selected mode is `pass`.
Disconnect is the single primary action but uses a neutral filled surface by default;
red is reserved for destructive/unsafe actions, not routine disconnection.

### 4.3 Home — external proxy conflict / opaque error

```text
┌ Не удалось применить системный прокси           ┐ opaque danger surface
│ Другой клиент изменил прокси Windows на          │
│ 127.0.0.1:10808. RouteDeck не будет              │
│ перезаписывать его автоматически.                │
│                                                  │
│ Локальный прокси RouteDeck работает на :2080,    │
│ но приложения Windows пока его не используют.    │
│                                                  │
│ [Повторить проверку] [Открыть диагностику]       │
└──────────────────────────────────────────────────┘
```

The card is fully opaque. It remains until resolved/dismissed explicitly, wraps rather
than truncates, and is reachable in document order. Raw backend errors may appear only
inside a collapsed “Technical details” section after sanitization.

### 4.4 Servers

```text
┌ RouteDeck                               Серверы ┐
│  [          Импортировать подписку           ] │ primary
│  [ Поиск…                               ] [↻]  │ labeled a11y refresh
│  Подписка: My provider · обновлено 12 мин назад │
│                                                  │
│  (•) NL / VLESS                                 │ selected radio row
│      VLESS · Reality                    84 ms    │
│      Проверено 14:32                             │
│  ( ) DE / Hysteria2                             │
│      Hysteria2                          121 ms   │
│      Проверено 14:31                             │
│  ( ) FI / Naive                                 │
│      Naive                              —        │
│      Ещё не проверено                            │
│                                                  │
│  [Проверить видимые серверы]                     │ secondary
├ Главная  Серверы  Правила  Настройки  Статус ────┤
```

Latency means a bounded remote probe through/against the actual node, not a connection
to a fake-DNS or local TUN address. Show `—`, timeout, or unsupported instead of a
misleading 1 ms. Timestamp is mandatory so stale values are recognizable.

### 4.5 Routing

```text
┌ RouteDeck                               Правила ┐
│  Маршрут по умолчанию                           │
│  [ Напрямую ] [ Через VPN ]                     │ 44 radio group
│  Сейчас: весь трафик напрямую, кроме 2 правил   │
│                                                  │
│  [i] Правила по приложениям надёжно работают    │
│      только в TUN. В системном прокси это        │
│      best effort для proxy-aware приложений.     │
│                                                  │
│  Приложения                         [+ Добавить] │ secondary
│  Firefox                                          │
│  C:\…\firefox.exe                                │
│  [ Наследовать | Напрямую | VPN ]                │
│  Telegram                                         │
│  C:\…\Telegram.exe                               │
│  [ Наследовать | Напрямую | VPN ]                │
│                                                  │
│  Несохранённые изменения                         │
│  [              Применить изменения           ] │ primary
├ Главная  Серверы  Правила  Настройки  Статус ────┤
```

“Direct by default, selected apps via VPN” is achieved by selecting `Напрямую`, setting
the desired app rows to `VPN`, and using TUN. The summary always states that effective
policy in plain language.

### 4.6 Settings

```text
┌ RouteDeck                            Настройки ┐
│  Общие                                          │
│  [✓] Запускать свёрнутым                         │
│  При закрытии  [ Скрыть в трей             v ]  │
│                                                  │
│  Подключение                                    │
│  Локальный HTTP-порт [ 2080                   ] │
│  Локальный SOCKS-порт [ 2081                  ] │
│                                                  │
│  Совместимость с другими VPN                    │
│  (•) Никогда не перезаписывать чужой прокси     │
│  ( ) Всегда спрашивать                          │
│  [i] Windows использует один системный прокси.  │
│                                                  │
│  [> Расширенные настройки]                      │
│                                                  │
│  [                Сохранить                   ] │ primary only when dirty
│                                                  │
│  Опасная зона                                   │
│  [Сбросить локальное состояние…]                │ danger secondary
└─────────────────────────────────────────────────┘
```

If settings autosave in the implementation, remove the Save button and show a brief
opaque success toast; never mix autosave and an apparently required Save action.

### 4.7 Diagnostics

```text
┌ RouteDeck                               Статус ┐
│  [          Запустить полную проверку        ] │ primary
│  Последняя проверка: 14:38:02 · 4,2 с          │
│                                                  │
│  ✓ Конфигурация       sing-box принял config   │
│  ✓ Ядро               PID 4820 · running       │
│  ✓ Локальный ingress  HTTP :2080 · 12 ms       │
│  ! Режим Windows      внешний прокси :10808    │
│  ✓ VPN-маршрут        выбранный outbound · 842 ms│
│  — VPN egress IP      endpoint недоступен       │
│                                                  │
│  Другой VPN обнаружен                            │ opaque warning
│  Его системный прокси сейчас активен.            │
│  [Повторить после отключения]                    │ secondary
│                                                  │
│  [Копировать безопасный отчёт]                   │ secondary
│  [> Технический журнал]                          │
└─────────────────────────────────────────────────┘
```

The pipeline preserves successful steps and shows the exact failed boundary. “Copy”
must serialize the already-redacted diagnostic model, never copy raw rendered logs.

## 5. Wide wireframe (720 px and above)

```text
┌────────────────────────────────────────────────────────────────────┐
│ RouteDeck                                      Подключено · NL      │
├────────────────┬───────────────────────────────────────────────────┤
│ ▣ Главная      │  ГЛАВНАЯ                                          │
│ ○ Серверы      │  [Server selector                               ]  │
│ ⇄ Правила      │  [System Proxy] [TUN]                             │
│ ⚙ Настройки    │  [                 Disconnect                  ]  │
│ ⓘ Статус       │                                                    │
│                │  [Proof card, max content width 560 px]           │
│                │  [Routing summary]                                │
│                │                                                    │
└────────────────┴───────────────────────────────────────────────────┘
```

The glyphs above are placeholders for Lucide SVGs, not literal emoji/symbol assets.
At wide width the hierarchy remains one content column. Dialogs remain at 480 px max
unless a path/log viewer genuinely needs up to 640 px.

## 6. State and component contracts

### 6.1 Connection state machine

Canonical UI state:

```ts
type ConnectionPhase =
  | 'disconnected'
  | 'validating-config'
  | 'starting-core'
  | 'checking-local-ingress'
  | 'applying-windows-mode'
  | 'verifying-outbound'
  | 'connected'
  | 'degraded'
  | 'disconnecting'
  | 'blocked-by-conflict'
  | 'failed';

type ProofState = 'idle' | 'running' | 'pass' | 'warn' | 'fail' | 'skipped';

interface ConnectionProof {
  id:
    | 'config'
    | 'core'
    | 'local-ingress'
    | 'windows-mode'
    | 'outbound-proof'
    | 'egress-ip';
  state: ProofState;
  summary: string;
  value?: string;
  checkedAt?: string;
  durationMs?: number;
  recoveryAction?: { label: string; action: string };
}
```

Invariants:

- `connected` requires pass for config, core, local ingress, selected Windows mode,
  and the selected-outbound HTTPS proof. Egress IP is display evidence: it may be
  unavailable after a successful bounded proof without invalidating the connection.
- The selected server name or remote server IP is not proof that user traffic uses it.
- A test explicitly sent through RouteDeck's local proxy can prove core/outbound health,
  but cannot prove Windows ownership; represent those as separate rows.
- `degraded` means traffic may work but one non-optional claim cannot be proved. It uses
  warning language, never green Connected treatment.
- Disconnecting keeps the last proof visible but marks it historical. If restoration
  fails, keep a persistent error explaining exactly which Windows state remains.
- Retrying is idempotent; its button shows pending state and cannot queue duplicate runs.

### 6.2 `AppShell`

Contract:

- Inputs: active destination, global phase, window width, unread critical count.
- Compact output: header + main + bottom navigation; wide output: header + rail + main.
- Navigation labels are always visible. No hamburger is used for five primary screens.
- On route change, focus moves to the screen `h1` and the previous screen's scroll is
  saved. Mouse navigation may retain focus on the activated destination.

### 6.3 `ConnectionAction`

- Exactly one per Home screen.
- States: connect, pending with specific phase label, disconnect, disconnecting, retry.
- Minimum 48 px height and stable dimensions. `aria-busy` during pending; `aria-live`
  announces phase transitions without repeating faster than once per meaningful step.
- A failed connect returns focus to the action only if focus was not moved by the user;
  the inline error is announced with `role="alert"`.

### 6.4 `ModeSelector`

- Semantic radio group with two 44 px options: System Proxy and TUN.
- Changing mode while connected opens a confirmation dialog that describes the brief
  traffic interruption and rollback plan. It does not silently reconnect.
- The limitation/privilege note below the group changes immediately and remains visible.
- If TUN privilege is unavailable, keep it selectable so the user can learn why, but
  block Apply/Connect with a clear recovery action rather than a dead disabled control.

### 6.5 `ConnectionProofCard`

- Input: ordered `ConnectionProof[]`, overall phase, live/historical flag.
- Each row: state icon, plain label, value/summary, optional timestamp, optional action.
- State icon plus text: pass “Готово”, running “Проверка”, warn “Требует внимания”,
  fail “Ошибка”, skipped “Не проверялось”.
- Updates use a polite live region. A new failure uses one alert announcement; repeated
  polls must not repeatedly announce the same error.

### 6.6 `OpaqueNotice`

Variants: info, warning, error, success. All use fully opaque semantic backgrounds.

- Required: concise title and explanatory body.
- Optional: one primary recovery action, one secondary navigation action, expandable
  sanitized details, explicit close when dismissal is safe.
- Critical connection errors stay inline until resolved/dismissed. They do not time out.
- Text wraps at any window width. Actions stack vertically below 400 px when their
  translated labels would collide.
- Error uses `role="alert"`; warning/status uses `role="status"` as appropriate.

### 6.7 `ToastRegion`

- Supplementary confirmations only: settings saved, report copied, refresh complete.
- Opaque elevated surface, one visible toast plus a short queue; do not stack errors over
  server rows. Position above fixed navigation with 16 px inset.
- Auto-dismiss after 5 seconds, pause on hover/focus, provide a 44 px close target.
- `aria-live="polite"`, `aria-atomic="true"`; never move focus automatically.

### 6.8 `ServerRow`

- Semantic single-select radio/listbox behavior. The entire 56 px+ row is selectable.
- Name, protocol, source, latency state/value, verification timestamp, selected text.
- Server flag is decorative unless country is absent from text. Protocol is always text.
- Context menu is secondary and fully keyboard-accessible; primary selection does not
  require opening it.

### 6.9 `DefaultRouteControl` and `AppRuleRow`

- Default route is a Direct/VPN radio group. It is always explicit.
- App rule is Inherit/Direct/VPN. `Inherit` resolves to the displayed default summary.
- Effective result is shown as text after each rule, especially when current mode cannot
  enforce it.
- App path wraps or middle-ellipsizes visually; full path remains in accessible name and
  tooltip. Remove is a labeled menu action or 44 px button, not a tiny `x`.

### 6.10 `ImportSubscriptionDialog`

- Initial focus is the dialog title or first method control. Methods: URL, clipboard,
  local file. Each has a visible label.
- URL is treated as a secret: mask user info/query in previews and never echo it into an
  error. Clipboard is read only after explicit button activation.
- Validate, then show counts by supported/unsupported protocol before the user confirms.
- Error belongs next to the failing field and the first invalid field receives focus on
  submit. Escape/Cancel always remains available before commit.

### 6.11 `ConfirmDialog`

- Names the action and concrete consequence. Button labels are verbs, not Yes/No.
- Default focus is the safe action. Destructive/force action is visually separated.
- If another VPN owns Windows state, wording never encourages blind overwrite; offer a
  safe retry after the user changes external state.

### 6.12 `OtherVpnPreflightDialog`

Shown before UAC whenever TUN preflight detects another likely tunnel/default route. It
does not claim that two VPNs will or will not work merely from adapter presence.

```text
┌ Обнаружен другой VPN ────────────────────────────┐
│ RouteDeck нашёл активный туннель «v2rayN/TUN».   │
│ Выберите, как подключать выбранный сервер:       │
│                                                  │
│ ( ) Через текущий VPN                            │
│     RouteDeck будет вложен в существующий путь.  │
│ ( ) Через физический адаптер                     │
│     [ Wi-Fi · Intel…                         v ]  │
│     Попытаться обойти текущий VPN.               │
│                                                  │
│ RouteDeck перепроверит интерфейс перед запуском. │
│ [Отмена]                         [Продолжить]     │
└──────────────────────────────────────────────────┘
```

- No route option is preselected when ownership is ambiguous; default focus is Cancel.
- “Current VPN” labels the result as nested if proof succeeds. It does not call the
  baseline address a real ISP IP.
- “Physical adapter” lists only verified up, non-loopback, non-tunnel interfaces and
  shows enough adapter identity to avoid guessing. Revalidate immediately before UAC.
- Prefix/DNS collision or no usable upstream produces an opaque blocking explanation,
  not a force checkbox. RouteDeck changes no adapter/route state before Continue + UAC.
- If another VPN appears or disappears later, show Degraded, rerun proof, and offer the
  same safe decision flow. Do not silently change the user's chosen path.

## 7. Effective routing presentation

The Routing summary is derived from configuration plus runtime mode, never stored as an
independent optimistic string.

| Default | App rule | TUN effective route | System Proxy presentation |
|---|---|---|---|
| Direct | Inherit | Direct | “Direct; proxy-aware behavior may vary” |
| Direct | VPN | VPN | “Best effort for proxy-aware apps; reliable only with TUN” |
| VPN | Inherit | VPN | “VPN for proxy-aware applications” |
| VPN | Direct | Direct | “Best effort for proxy-aware apps; reliable only with TUN” |

Home summary examples:

- `По умолчанию: напрямую · Firefox и Telegram через VPN (TUN)`
- `По умолчанию: через VPN · 3 исключения напрямую (TUN)`
- `Системный прокси · 2 правила best effort; для гарантии нужен TUN`

## 8. Feedback and copy rules

Every operational failure has four pieces:

1. What failed: “Не удалось применить системный прокси”.
2. Why, in user language: “Другой клиент изменил настройки Windows”.
3. What works/remains: “Локальный прокси RouteDeck продолжает работать на :2080”.
4. Safe next step: “Отключите системный прокси в другом клиенте и повторите проверку”.

Forbidden copy:

- “Something went wrong.”
- “Connected” based solely on remote endpoint metadata.
- “Ping 1 ms” when the test hit a local/fake-DNS address.
- “Force restore” without naming the exact setting and conflict.
- Raw exception text as the only error, especially if it contains a subscription secret.

Use Russian sentence case. Avoid all-caps error titles, excessive punctuation, and
protocol jargon when a plain-language equivalent exists. Technical details remain
available for diagnosis but are secondary.

## 9. Keyboard and accessibility

- Logical Tab order follows visual order. No positive `tabIndex`.
- All actions use native buttons/links/inputs; pointer interactions have keyboard parity.
- `Alt+1` through `Alt+5` may switch top-level destinations if they do not conflict with
  Tauri/Windows access keys; expose shortcuts in tooltips and Settings.
- Enter/Space activates the focused control. Never bind bare Enter globally to Connect,
  because it can cause an accidental network state change.
- Escape closes popover/dialog only when safe. A dirty or destructive flow confirms.
- Focus is trapped in dialogs and returned to the invoking control on close.
- Every icon-only utility button has a localized accessible name and tooltip; top-level
  navigation is never icon-only.
- Segmented controls use `radiogroup`/`radio` semantics with selected state announced.
- Lists expose selected, disabled, busy, and expanded states. Status updates use polite
  live regions; new actionable errors use one non-repeating alert.
- All targets are at least 44 x 44 px, including close, overflow, reveal, refresh, and
  remove. Maintain at least 8 px between adjacent targets.
- Focus ring is never removed. It must remain visible against dark and light surfaces.
- At Windows text scale 200%, text wraps, cards grow, and the main area scrolls. No
  required label or action may be ellipsized out of reach.
- High Contrast/forced-colors mode uses system colors, visible borders, and native focus;
  do not rely on background fills that forced-colors will remove.
- `prefers-reduced-motion` disables transforms and screen transitions; spinners may use a
  static progress glyph plus text if the OS requests reduced motion.

## 10. Resize acceptance matrix

| Viewport / condition | Navigation | Layout expectation | Must pass |
|---|---|---|---|
| 360 x 560 minimum | 5-item bottom bar | One column, 16 px gutter; page scroll only | No horizontal scroll; CTA, error actions, and dialogs remain reachable; bottom content clears nav |
| 420 x 720 default | Bottom bar | One column, comfortable card rhythm | Home server/mode/CTA/proof summary visible with at most a short scroll; no overlap |
| 560 x 640 short-medium | Bottom bar | One column, content max 520 px | Dialogs cap to viewport and scroll internally; sticky action does not cover last field |
| 719 x 720 edge | Bottom bar | One centered column | No one-pixel overflow or navigation flicker while resizing across breakpoint |
| 720 x 640 wide threshold | 176 px rail | Rail + one content column | Bottom nav fully removed from layout/a11y tree; main has independent scroll |
| 900 x 800 wide | Rail | Content capped at 760 px | Cards do not stretch into sparse two-column dashboard; dialogs remain readable |
| 360 x 560 at 200% text | Bottom bar | Growing cards and wrapping labels | Every destination and action accessible by scrolling; no clipped mode labels or toast |
| Any size, long RU/EN strings | Adaptive | Actions stack below 400 px | No action text collision; full server/app name accessible |
| Any size, reduced motion | Same | No transform/page animations | State remains perceivable; pending feedback still present |
| Any size, forced colors | Same | System colors/borders | Current nav, selection, focus, pass/fail distinguishable without color alone |

### Resize test procedure

1. Drag continuously between 360 and 900 px during each connection phase.
2. Open every dialog at 360 x 560 and with 200% Windows text scaling.
3. Populate one server/app/error string with at least 80 characters and a Windows path.
4. Verify Tab order before and after the 720 px nav breakpoint.
5. Verify only one navigation representation exists in the accessibility tree.
6. Confirm no scroll position reset on resize or destination round-trip.
7. Confirm error/toast surfaces remain opaque over moving server content.

## 11. UI acceptance scenarios

### A. Healthy System Proxy

1. Select System Proxy and Connect.
2. CTA progresses through named phases without layout shift.
3. Core, local proxy, Windows ownership, and outbound IP pass.
4. Connected appears only after step 3.
5. The persistent limitation still says only proxy-aware applications are covered.

### B. Another VPN owns System Proxy

1. RouteDeck starts its local proxy on its own port and tests it explicitly.
2. Windows ownership proof reports the observed foreign endpoint without changing it.
3. Home shows blocked/degraded, not Connected.
4. Opaque notice explains that distinct local ports do not provide two simultaneous
   Windows system proxies and offers safe retry/Diagnostics.
5. Closing/dismissing the notice does not discard recovery state.

### C. Direct by default, browser through VPN

1. Routing default is Direct; browser rule is VPN.
2. With System Proxy selected, the summary says rules are best effort for proxy-aware
   applications and that reliable enforcement requires TUN.
3. With TUN selected and verified, Home says “Direct by default · Browser via VPN”.
4. Diagnostics proves both an explicitly routed app/probe and the default route where
   backend support exists; otherwise it clearly labels unverified scope.

### D. TUN conflict

1. Existing VPN routes/DNS are detected.
2. RouteDeck attempts only its documented safe coexistence path.
3. If proof fails, it rolls back owned changes and shows exactly what remains.
4. Adapter existence alone never produces Connected.

### E. Failed VLESS, working Hysteria2

1. Both server rows retain independent last-check status.
2. VLESS failure displays the failing boundary (config, dial, TLS/Reality, timeout) after
   sanitization; it does not silently fall back to direct traffic.
3. Switching to Hysteria2 and succeeding does not overwrite the VLESS diagnostic.

### F. Honest latency

1. Timeout renders “Тайм-аут”, unsupported renders `—`, stale values include timestamp.
2. Local/fake-DNS/intercepted targets are rejected and never displayed as node latency.
3. Sorting places unavailable values after real measured values.

## 12. Privacy and safety presentation

- Mask subscription URLs after host (for example `provider.example/••••`) and provide a
  Reveal action only where necessary, with explicit user intent.
- Diagnostic exports are redacted before they reach React. UI performs an additional
  conservative display mask but is not the security boundary.
- Never show complete UUIDs/passwords/private keys in notifications, tooltips, recent
  activity, or accessible labels.
- Any prompt to overwrite/restore Windows proxy names observed and intended endpoints,
  explains risk, and defaults to Cancel.
- On exit with active routing, show progress and final restoration result. If safe exit
  cannot be guaranteed, keep the window open with an opaque blocking explanation.

## 13. Implementation review checklist

- [ ] One filled primary CTA per screen maximum.
- [ ] `Connected` derives from the complete proof invariant.
- [ ] System Proxy and TUN limitations are persistently visible.
- [ ] Direct-by-default plus selected-app VPN flow is discoverable in Routing.
- [ ] All notices/toasts are opaque; critical errors persist and remain readable.
- [ ] Minimum targets are 44 x 44 px with keyboard and visible focus states.
- [ ] Compact, short, wide, 200% text, reduced-motion, and forced-colors cases pass.
- [ ] No emoji/UI raster icons, remote fonts, page-overlay animation, or decorative glow.
- [ ] Server latency includes state and timestamp and never substitutes local interception.
- [ ] Secrets are redacted before display/copy; raw exception strings are not primary UI.
- [ ] Navigation state, focus, and scroll position survive resize and route changes.
- [ ] User-facing claims match actual backend proof, including coexistence with another VPN.
