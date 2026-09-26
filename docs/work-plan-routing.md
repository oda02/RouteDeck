# Routing changes in one batch

## Problem and scope

On main, routing edits autosave after 500 ms and each effective change can
restart an active tunnel. Existing PR #3 stages application picker selections,
but route dropdowns, deletion, traffic rules and advanced preferences still
restart the connection during editing.

## Chosen interaction

- Keep one application-owned draft for the whole Rules page. Add/remove apps,
  change default/app routes, traffic rules, TUN stack and Naive preferences
  without writing preferences or touching the active session.
- Explicit **Apply rules** saves one batch and reconciles the active connection
  once through the existing serialized controller. An effective no-op does not
  restart the connection. Changes irrelevant to System Proxy do not restart it.
- **Discard changes** restores the last persisted configuration; it is disabled
  while a submitted batch is applying. Edits made during Apply remain a new draft
  and are never submitted by the previous operation's completion.
- Navigation retains the draft and shows an accessible pending-rules button in
  the header. Closing/reloading the application discards an unsubmitted draft;
  the UI states this explicitly. Applied rules use existing local persistence.
- The application picker toggles applications directly in the shared page draft.
  Refresh keeps choices, search and existing results. Done, X, Escape and backdrop
  close retain that draft. There is one final **Apply rules** action on the page;
  **Discard changes** reverts all draft edits. No picker action reconnects.
- Persistence errors preserve the draft for explicit retry. Saved changes remain
  saved if reconnect fails; the UI reports the failure. Retained old TUN rules
  remain pending and retrying the same batch must reconcile them again. Existing
  recovery-required/conflict gates still prevent unsafe starts.

## Work and verification

- [x] Inspect main and existing PR #3; reuse its committed work in an isolated
  managed checkout, preserving original working files and remote history.
- [x] Implement full-page draft, explicit Apply/Discard and pending indication.
- [x] Add fixture coverage crossing the old debounce: zero writes/restarts during
  edits, one save/restart on Apply, picker close preservation, page draft cancellation,
  navigation, storage failure retry, delayed Apply with newer edits, and layouts.
- [x] Add deterministic controller regression for retrying an identical saved
  batch while the retained TUN still uses the previous rules.
- [x] Run production frontend build and 128 Node tests without native networking.
- [x] Pass 68 blocked-network browser scenarios and inspect rendered fixture
  previews at 360 px and 1000 px, with no clipping or horizontal overflow.
- [x] Pass the existing PR #3 periodic monitor fake-runtime regression with
  locked offline Rust dependencies; no engine or host integration invoked.
- [x] Complete independent architectural and rendered-preview review: no blockers.
- [ ] Update existing PR #3 and await the required Windows CI before merging.

No dependencies or privileged interfaces changed. No real engine, UAC prompt,
proxy setting, route, DNS, adapter, service or active VPN process was touched.
Preview screenshots contain synthetic applications and fixture servers only.
