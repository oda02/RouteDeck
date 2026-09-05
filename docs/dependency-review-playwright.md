# Dependency review: Playwright 1.62.1

Reviewed 2026-09-05 before adding the browser-test dependency.

- Package: `playwright@1.62.1`, exact dev dependency, Apache-2.0.
- Ownership/source: published under the Playwright npm organization by the
  Microsoft Playwright maintainers; repository and homepage point to
  `microsoft/playwright` and `playwright.dev`. The upstream `v1.62.1` release
  commit is verified on GitHub.
- Registry integrity: `sha512-0M+L3LAD8/nm554LOla9Ayx0j0tmFZ0FBcoQ7F1VuVHpM/XpiC8RcDzBQB8W5+hA8L22THxELzeF+2WcUzvcLg==`.
- Required transitive dependency: exact `playwright-core@1.62.1`, Apache-2.0,
  integrity `sha512-wPYSwEBJY9GHraISXqyqtx0na0LpO3XEX7jNDhntbex7tzUS7kLnZsOlFruFJB4Hi/rhDMjXGqHewDZ68nYZVw==`;
  it declares no further dependencies or lifecycle scripts.
- Optional dependency: `fsevents@2.3.2`, MIT, macOS-only, integrity
  `sha512-xiqMQR4xAeHTuB9uWm+fFRcIOgKBMiOBP+eXiyT7jsgVCq1bkVygt00oASowB7EdtpOHaaPgKt812P9ab+DDKA==`.
  It has an `install` script (`node-gyp rebuild`) but is omitted on Windows.
- Lifecycle/download decision: installed with `npm install --save-dev --save-exact
  playwright@1.62.1 --ignore-scripts`. The package install did not download or
  execute browsers. CI acquires Chromium separately with the pinned local CLI.
- Runtime scope: test/development only. The production bundle check confirms it
  is absent from the application bundle.

Sources: official npm registry metadata, the upstream package manifest at tag
`v1.62.1`, and the Microsoft Playwright GitHub release.
