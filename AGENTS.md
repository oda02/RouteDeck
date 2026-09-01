# RouteDeck repository rules

These rules apply to the entire repository.

## Product boundary

- RouteDeck is a Windows desktop controller for a separately distributed, reviewed `sing-box` binary.
- Keep the ordinary Tauri process unprivileged. System Proxy uses only the current user's Windows settings. TUN elevation is requested on demand and must never silently install a persistent service.
- A green “Connected” state requires an end-to-end probe through the selected outbound. A running child process alone is not proof of connectivity.
- System Proxy and TUN are different capabilities. Never present System Proxy as full-device or reliable per-app tunnelling.

## Dependency safety

- Pin direct JavaScript and Rust dependencies. Commit both `package-lock.json` and `Cargo.lock` whenever dependencies are resolved.
- Do not add or update a package without reviewing its official source, ownership, integrity metadata, transitive impact, and lifecycle scripts.
- Never use `npx`, `npm update`, floating versions, or unrelated convenience packages. Run npm with lifecycle scripts disabled unless a reviewed build explicitly requires one.
- Do not download or execute `sing-box`, WinTUN, installers, or other binaries as part of dependency installation or a frontend build.

## Privilege and secret safety

- Keep elevated APIs narrow and typed. Do not accept caller-controlled commands, executable paths, service names, registry roots, or arbitrary filesystem locations.
- Treat subscription URLs, credentials, share links, REALITY keys, UUIDs, and logs containing them as secrets. Redact before logging or exporting diagnostics.
- Never modify Windows proxy settings, routes, DNS, adapters, services, registry, or running VPN processes in unit tests.
- Before privileged host testing, complete security review and hostile-input tests in an isolated Windows environment.

## State ownership and recovery

- Before changing system state, record the exact prior state and a unique ownership marker durably.
- Restore only state RouteDeck demonstrably owns. If another VPN or the user changed state concurrently, preserve evidence and ask instead of overwriting foreign state.
- Stop order is: stop accepting new work, restore owned system state, verify restoration, then terminate local listeners/processes.
- All connect/disconnect operations must be idempotent and safe after partial failure or crash.

## Change discipline

- Add tests for parsing, routing, state ownership, teardown, and every trust-boundary change.
- Keep protocol parsing separate from runtime control; keep Windows integration behind a small platform boundary.
- No network access in deterministic unit tests. Integration tests must use explicit fixtures or user-authorized endpoints.
- Do not commit generated binaries, credentials, real subscription contents, local machine paths, or captured IP addresses.
