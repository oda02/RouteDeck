# Session cleanup in 0.1.2

The previous version could leave an elevated helper's journal unreadable to the
ordinary GUI. Its recovery parser also only understood the old TUN directory
shape, so an abandoned sealed Xray copy blocked the whole next launch.

Private session directories and config files now name the current account SID
explicitly, including inherited access for helper-created files. They no longer
depend on the elevated file owner's `OWNER RIGHTS` identity. Ordinary Tauri stays
unprivileged; this change adds no service, elevated command, polling or installer.

Each newly created session has a small, synced ownership record containing its
random directory identity, account SID and config digest. It contains no server
credentials. The existing directory/config handles deny DELETE while active;
recovery acquires DELETE access before accepting any cleanup plan. A surviving
GUI, helper or checked configuration therefore prevents cleanup without relying
on a stale PID alone.

On startup or explicit recovery, the existing recovery path recognizes these
records, helper subdirectories and sealed sing-box/Xray copies. It accepts only
fixed relative filenames, bounded metadata and matching config/runtime digests.
Unknown records, changed files, reparse points and active leases are preserved.
All candidates are inspected before any file is removed. TUN journals still
require proof that the owned adapter/routes and original engine have disappeared.
A reused PID is treated as a different process and is never terminated.

Cleanup removes only session files, retains ownership evidence until the end,
and closes deletion handles before removing parent directories. It does not
alter Windows networking or terminate foreign processes. An empty session root
returns immediately, without querying adapters, routes or processes. Normal
shutdown still removes its own files and needs no recovery on the next launch.

Readable legacy TUN journals retain their existing strict recovery path. Legacy
files without enough ownership evidence, including already unreadable journals
created by older versions, remain a manual recovery case; the new release does
not silently change their ACLs or discard them. The affected local legacy state
must be reviewed separately from this code change.

## Validation and security review

Deterministic Windows fixtures cover normal teardown, abandoned local and nested
helper directories, live leases, unknown files, changed digests, wrong identities,
missing records, interrupted cleanup, and preservation when an owned route remains.
Network/process observations in combined recovery tests are injected fixtures.
The account SID ownership assertion also runs on the isolated Windows CI runner.
No unit test changes host networking or starts an engine.

An explicitly enabled integration test uses already reviewed, hash-pinned runtimes:

```powershell
$env:ROUTEDECK_RUNTIME_FIXTURE_ROOT = '<existing complete portable directory>'
cargo test --locked --offline --manifest-path src-tauri/Cargo.toml --lib reviewed_runtime_teardown_and_crash_recovery -- --ignored
```

It binds only loopback, exercises both real launchers' check/start/stop cleanup,
and checks removal of abandoned sealed copies. It creates no TUN, performs no
external requests and stops only its own child processes. Actual elevated TUN
traffic is not implied by these loopback checks.
