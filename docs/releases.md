# CI, releases and updates

## Current workflow

- Pull requests and pushes to `main` run Windows CI. Updating an open PR
  cancels its older CI run. A push to a feature branch is checked through its
  PR. Use **CI → Run workflow** to check a branch manually.
- The required `build / windows` check validates versions and runs deterministic
  frontend/native tests, all-target checks, isolated browser scenarios, and
  packaging, provenance and publishing fixtures. It also validates the production
  frontend bundle. Dependency installation uses lock files and disables npm
  lifecycle scripts. Playwright acquires the pinned Chromium in its own step.
- Pushes to `main` also build and package the complete portable distribution.
  To test real packaging before a merge, choose the branch in **Run workflow**
  and enable **Also build the full portable distribution**. The packaging steps
  verify reviewed VPN engines against committed size/SHA-256 pins, collect the
  notices and corresponding sources, and package the engines without executing them.
- The Windows artifact is `RouteDeck-<version>-windows-x64.zip` with `SHA256SUMS.txt`.
  CI artifacts expire after one day; published release assets remain available.
  They contain the controller and its exact
  helper and updater, pinned sing-box/Cronet and Xray, dependency notices and runtime pins,
  without user state. Extract the ZIP and run `routedeck.exe`; see
  `docs/portable-full-release.txt`. Corresponding runtime source archives and an
  inventory are published alongside it. Source downloads are optional for users
  who only want to run the application.
- A pushed `vX.Y.Z` tag uses the unexpired portable artifact from a successful
  push-triggered CI run on `main` for that exact commit. If that run is still
  in progress, Release waits up to 30 minutes. If the artifact is unavailable,
  Release runs the full build for the tag. Both paths check the source commit
  and version inside the ZIP before signing or publishing. If a selected
  artifact disappears before download, rerun all Release jobs to select again.
  `vX.Y.Z-alpha.N`, `-beta.N`, and `-rc.N` publish GitHub prereleases and do
  not become the stable latest release. The first public full
  portable is prepared as 0.1.1; the earlier 0.1.0 controller-only workflow was
  cancelled before publication. Its existing tag is preserved.
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

The tool updates the application version in five files, including both lock
files, without resolving dependencies. Merge the reviewed change into `main`.
To publish that exact commit, push the version tag. Release can wait for the
same commit's portable artifact while CI finishes.

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

Available stable updates download in the background when automatic checks are
enabled. A pinned Ed25519 public key verifies the detached descriptor for the
complete portable ZIP and every bundled file. After explicit VPN disconnection
and applying or discarding pending drafts, the user selects **Обновить и
перезапустить**. An unprivileged standalone updater waits for the exact GUI
process to exit, replaces the verified complete folder, and restarts the GUI.
It never silently reconnects the VPN. The full bundle includes matching GUI,
helper, updater, `engine` and `xray` files; do not mix versions.

**0.1.3 is the first signed updater-capable release.** Users of 0.1.2 and earlier
must download the complete ZIP and extract it into a new folder once.
The 0.1.3 and 0.1.4 preparation code requests a DELETE directory handle that
conflicts with the running process's working-directory handle. Install 0.1.5
manually once using the complete ZIP in a new empty personal folder; those older
binaries cannot receive this repair through their own preparation path.
Built-in updates require a local portable tree owned by the current user or
Administrators, without untrusted write/delete/ACL grants on its folders and files.
Extract inside the user's personal folder and check its permissions rather than
assuming every drive, Downloads/Desktop location or app-data folder is private.
Unsafe permissions produce a fixed recovery message; RouteDeck never changes the
existing folder's ACL or relocates it automatically.
Preferences/subscriptions remain in Windows user data. Changed or extra bundle
files require a manual full-ZIP update in a new folder. Previous/staging folders
retain manual repair evidence and consume disk space; automatic rollback and
garbage collection are outside this implementation. Incomplete replacements
refuse to launch and provide a manual repair path.

Only trusted stable tag publishing receives `ROUTEDECK_UPDATE_SIGNING_KEY`; PR
builds never receive it. `SHA256SUMS.txt` is integrity metadata; the detached
Ed25519 signature authenticates update metadata. See
[the release-signing workflow](portable-updater-release.md) and
[implementation/qualification limits](portable-updater.md). No real isolated
signed N→N+1 GUI-restart qualification has been performed or claimed.

Runtime acquisition is separate from dependency installation and frontend builds.
Only the exact reviewed files are packaged, together with upstream notices and
directions to corresponding source materials; see `docs/portable-compliance-plan.md`.
Notice inventories record supplied texts, scope and provenance; they are not a
blanket legal compliance claim or a license grant for RouteDeck's own source.

## Hosting and verification

The active `Protect main` repository ruleset requires a pull request, resolved
review conversations and a successful `build / windows` check from GitHub Actions
(app ID 15368), tested against the latest base branch. Direct pushes, force pushes
and branch deletion are blocked; there are no bypass actors. A second person's
approval is optional so a sole maintainer can merge their own tested PR. These
rules target `refs/heads/main`; version tags keep the release workflow described
above. Inspect the live rules in
[repository settings](https://github.com/oda02/RouteDeck/settings/rules/22347978).

The repository is public after a bounded scan of working source and reachable Git
history for credentials. GitHub provides standard hosted runners free for public
repositories, subject to concurrency, execution and service limits; larger runners
are billed separately. Artifact storage has separate plan allowances, so temporary
CI artifacts use a one-day retention period. This is not unlimited execution of
arbitrary jobs or unlimited temporary artifact storage.

References: [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[release management](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository),
[Tauri updater and signing](https://v2.tauri.app/plugin/updater/).
