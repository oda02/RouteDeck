# Application picker follow-up

- Clicking an application immediately toggles its rule in the shared routing
  draft. Closing the dialog keeps picks; the page owns Apply and Discard.
- Exact-path and existing filename rules show their selected state. A filename
  rule covers the executable even after its folder changes; selecting it again
  removes the matching rule from the draft instead of adding a duplicate.
- Keep the dialog at a bounded height with fixed header/search/refresh/footer
  and one scrollable list. Search and row keyboard focus rings stay inside their
  boundaries. Refresh retains previous results, search, scroll and counts while
  its fixed button shows progress; errors keep previous results available.
- Compact the page Apply bar while retaining the single batch operation and
  explicit discard. Existing draft lifetime and System Proxy scope remain visible
  in the routing explanation.
- Verify 80 synthetic applications with long version paths, actual wheel input,
  search/selection/close, failed refresh and a changed-folder filename rule. Check
  1000×600, 800×500, 360×640, 125–150% viewport equivalents and actual CSS zoom
  at short height. Dark/light screenshots are inspected, not inferred.

No new dependencies, native app launch or host networking changes. The optional
`node scripts/preview-app-picker.mjs` serves synthetic IPC on loopback port 1423
for interactive review; fixture code is absent from the production bundle.

Verification: 144 Node tests, 105 blocked-external-network browser scenarios
(including 16 focused picker cases), and production build/bundle checks pass.
Independent review reproduced the original clipping and wheel failure, then
verified the corrected picker; the team lead also exercised search, scrolling,
refresh, close and one final Apply in the synthetic browser preview.
