# CI, releases and updates

## Current workflow

- Every branch push and pull request runs Windows CI. A newer push cancels an
  older run for the same ref. CI does not create GitHub releases.
- CI verifies synchronized versions, deterministic frontend/native tests, all
  native targets, isolated browser scenarios, production frontend boundaries, GUI/helper provenance and ZIP
  packaging. Dependency installation uses lock files and disables npm lifecycle
  scripts. VPN engines are not downloaded or run by CI.
  The pinned Playwright Chromium browser is acquired in an explicit test step.
- The Windows artifact is `RouteDeck-<version>-windows-x64.zip` with `SHA256SUMS.txt`.
  CI artifacts expire after seven days. They contain the controller and its exact
  helper, dependency notices/source material and runtime pins, without user state
  or external engines. For new installations see `docs/portable-release.txt`.
- A pushed `vX.Y.Z` tag runs the same build and publishes a stable GitHub Release
  only after it succeeds. `vX.Y.Z-alpha.N`, `-beta.N`, and `-rc.N` publish GitHub
  prereleases and do not become the stable latest release.
- A tag must exactly match the versions in npm, Cargo and Tauri. Existing releases
  and assets are never overwritten by the publishing script. To fix a published
  binary, use a new version and tag. Do not move a release tag.
- Builds use read-only GitHub permissions; only the final release publishing job
  receives `contents: write`. Actions are pinned to reviewed commit hashes.

## Preparing a version

From a clean working branch:

```powershell
node scripts/release-version.mjs set 0.2.0-beta.1
node scripts/release-version.mjs check
git add package.json package-lock.json src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/tauri.conf.json
git commit -m "Release 0.2.0-beta.1"
git push
```

The tool changes only the application version in five files, including both lock
files; it does not resolve dependencies. Merge the reviewed change into `main` and
wait for green CI. To publish that exact commit:

```powershell
git switch main
git pull --ff-only
node scripts/release-version.mjs check v0.2.0-beta.1
git tag -a v0.2.0-beta.1 -m "RouteDeck 0.2.0-beta.1"
git push origin v0.2.0-beta.1
```

For a stable release use `0.2.0` / `v0.2.0` instead. Changing a version or pushing a
normal commit alone does not publish anything. Preview users can install a stable
release with the same numeric version; stable users are not offered previews.

## Application update behavior

The version appears next to the RouteDeck name and in Settings → RouteDeck updates.
The application checks the fixed public `oda02/RouteDeck` GitHub latest-release API
at startup and every six hours while open. Automatic checks can be disabled and
the preference persists. Manual checks remain available. Checks are bounded,
coalesced and rate limited; a retry within 60 seconds may reuse the last result.

Only a strictly newer stable release is offered. Drafts, prereleases, malformed
versions and foreign release URLs are rejected. A repository without an accessible
stable release reports that no public stable release exists, not that a download
was found. No GitHub token is stored in the application.

The current download button opens the fixed GitHub Releases page. It does not
disconnect the VPN, download code automatically or overwrite a running portable
folder. Keep the old folder until the new one works; move/copy the existing reviewed
`engine` and `xray` directories into the new folder as the archive README describes.
If runtime pins change, obtain the matching upstream files instead of retaining
an incompatible version. Preferences/subscriptions remain in Windows user data.

## Next installation phase

The standard Tauri Windows updater targets installer artifacts and verifies a
mandatory update signature. A portable installation needs a deliberate replacement
and rollback design for the GUI, matching elevated helper and reviewed engines.
That phase should provide a pinned signing key, staged verification, clean owned
VPN teardown, replacement after process exit and rollback on failure. Checksums
in the current release are integrity evidence, not independent update signatures.
No private signing key or update-install privilege was introduced in this phase.

External engine redistribution remains separate from controller packaging; see
`docs/portable-compliance-plan.md`. The controller notice inventory records supplied
and reviewed upstream texts, its scope and provenance; it is not a blanket legal
compliance claim or a license grant for RouteDeck's own source.

## Hosting and verification

The repository is public after a bounded scan of working source and reachable Git
history for credentials. GitHub provides standard hosted runners free for public
repositories, subject to concurrency, execution and service limits; larger runners
are billed separately. This is not unlimited execution of arbitrary jobs.

References: [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[release management](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository),
[Tauri updater and signing](https://v2.tauri.app/plugin/updater/).
