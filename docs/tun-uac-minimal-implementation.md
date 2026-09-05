# Minimal on-demand UAC implementation for TUN

## Goal

The ordinary RouteDeck Tauri/WebView process stays at `asInvoker`. Pressing the existing
TUN button starts one fixed, short-lived administrator helper through the standard
Windows UAC dialog. No service, scheduled task, startup entry, driver installer, or
background privileged process is installed.

The UI remains simple:

1. Select TUN and press Connect.
2. Windows shows its normal UAC dialog.
3. Cancelling reports `TUN was not started` and changes no system state.
4. Disconnecting stops the helper-owned engine and verifies cleanup.

The current `start_tun` implementation is only a temporary scaffold: it requires the
entire RouteDeck process to already be elevated. It must be replaced, not exposed as a
second user workflow.

## Smallest acceptable process boundary

```text
unprivileged RouteDeck GUI
  |-- validates routing and generated config
  |-- creates one authenticated named-pipe session
  |-- ShellExecuteExW(fixed helper, verb = "runas")
  |
  `---- fixed-schema IPC ----> elevated routedeck-tun-helper.exe
                               |-- revalidates GUI, config and fixed components
                               |-- starts only sing-box with the fixed run shape
                               |-- owns the sing-box Job Object
                               `-- stops/cleans up on StopTun, pipe loss or GUI death
```

For VLESS/REALITY, the existing Xray loopback bridge can remain an unprivileged GUI-owned
process. Only the sing-box process that creates the TUN device crosses the elevation
boundary.

Do not relaunch the Tauri executable as administrator. That would give the WebView and
renderer-facing command surface administrator rights.

## Closed protocol

The helper command line contains only:

```text
--session <canonical UUID>
--pipe-suffix <32 lower-hex chars>
--parent-pid <decimal u32>
--parent-created <decimal u64 FILETIME>
```

It contains no URL, credential, config path, executable path, registry path, interface
name, service name, shell command, or environment value.

The GUI creates the pipe before UAC. The pipe has one instance,
`FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, bounded messages and an
explicit DACL for the launching user, Administrators and SYSTEM. Peer authentication
uses PID, process creation time and fixed sibling image identity. The GUI additionally
verifies the helper's exact build-pinned SHA-256. The helper does not verify a pinned
GUI hash; this is not mutual binary authentication. Its elevated configuration boundary
therefore independently rejects unknown nested fields, file-output options and unsupported
protocol capabilities before launching the engine. Native code already running as the
same user remains outside the portable application's isolation guarantee.

Version 3 messages are a length-prefixed, size-limited JSON schema with
`deny_unknown_fields`:

```text
HelperHello { protocol_version, session, helper_pid, helper_created, nonce }
GuiChallenge { protocol_version, session, request_id, challenge, expires_at }
StartTun {
  protocol_version,
  session,
  request_id,
  challenge,
  config_handle_id,
  config_len,
  config_sha256,
  preflight_sha256,
  upstream_choice: Physical { interface_luid, interface_index, interface_alias }
}
Started { request_id, engine_pid, engine_created, adapter_identity, journal_digest }
StopTun { protocol_version, session, request_id }
Stopped { request_id, cleanup: Complete | Conflict }
Status { protocol_version, session, request_id }
State { request_id, phase, engine_pid, cleanup, capture }
Failure { request_id, code, safe_detail }
```

`config_handle_id` is the native-controller-owned handle value in the already verified
GUI process, not a renderer value and not a path. The helper opens the authenticated GUI
with only the required process rights, duplicates this handle, then validates file type,
size, hash, file identity, DACL and strict RouteDeck-generated TUN schema. A derived file
name may be passed to sing-box only after resolving it from that held handle; the helper
never accepts a path in IPC.

The helper accepts exactly one `StartTun`, monotonic request IDs, one active session and
idempotent `StopTun`. Frames above 32 KiB, duplicate/unknown JSON fields, stale nonce,
expired challenge, repeated start, second client and unexpected state transitions are
rejected before mutation.

## Files and integration order

New isolated files can be written first:

- `src-tauri/src/tun_helper_protocol.rs` — closed message types, bounds and state machine.
- `src-tauri/src/tun_helper_client.rs` — unprivileged pipe server, fixed helper discovery,
  exact embedded-hash verification, `ShellExecuteExW("runas")`, helper process handle and IPC.
- `src-tauri/src/tun_helper_server.rs` — peer authentication, duplicated-handle/config
  validation, fixed sing-box launch, Job ownership, journal and exact cleanup checks.
- `src-tauri/src/bin/routedeck-tun-helper.rs` — minimal native entry point; no Tauri/WebView.
- `src-tauri/manifests/routedeck-tun-helper.manifest` — `requireAdministrator` for only the
  helper binary. The main app remains `asInvoker`.
- the GUI build embeds the exact helper SHA-256 after building the helper first.

Shared-file registration happens only after those modules pass their isolated tests:

- `Cargo.toml`: declare the helper binary and only the required existing `windows-sys`
  features (`Win32_UI_Shell`, `Win32_Security_WinTrust`, plus already used pipe/process
  APIs). Do not add a shell/process helper crate.
- `build.rs`: embed the administrator manifest only in the helper; keep the Tauri manifest
  `asInvoker`.
- `lib.rs`: register the native helper client module, never expose helper primitives as
  Tauri commands.
- `application.rs`: replace `TunPrivilegeControl::is_elevated` with a native
  `TunHelperLauncher`. For `RuntimeMode::Tun`, the launcher returns a `ManagedChild` whose
  PID is the helper-reported sing-box PID and whose lifecycle is the authenticated helper
  session. System Proxy and local proxy keep `VerifiedEngineLauncher` unchanged.
- `engine_runtime.rs`: share only the reviewed fixed engine/config verification and launch
  primitives needed by the helper. Keep their visibility crate-private.

The existing renderer command remains `start_tun(node_id, TunRouting)`. No new command,
path, or executable selector is added to the frontend contract.

## Launch and cancellation

Before UAC, the GUI performs read-only network preflight, creates and validates the TUN
config, opens and holds its config handle, creates the pipe, and verifies the exact helper
embedded hash and file identity. It creates no journal and changes no adapter, route or DNS
state.

`ShellExecuteExW` uses:

- a fully qualified application-owned helper path;
- verb `runas`;
- `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`;
- the fixed bounded argument shape above;
- no caller-provided working directory or environment.

If it fails with `ERROR_CANCELLED` (1223), return typed `UacCancelled`, close the pipe and
handles, and restore the prior disconnected status. This is a normal cancellation, not a
diagnostic failure. Any other launch failure is `HelperLaunchFailed` with a redacted safe
detail.

The helper creates the durable journal only after peer/config/component revalidation and
immediately before starting sing-box. It creates sing-box suspended, assigns the process
to a helper-owned `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job, then resumes it. The helper
monitors the authenticated GUI process and pipe; either disappearing closes the Job and
triggers exact cleanup verification.

## Threats covered by the narrow design

- A compromised renderer cannot choose a command, binary, path, registry root, route,
  service or environment because none exists in the Tauri/helper API.
- Pipe squatting and a same-machine remote client are rejected by first-instance creation,
  the explicit ACL, remote rejection and peer identity checks.
- PID reuse and stale/replayed messages are rejected by process creation time, session,
  nonce, expiry and monotonic request IDs.
- Helper replacement is rejected by the exact SHA-256 embedded in the GUI build. The GUI holds
  the verified helper without write/delete sharing through launch; the fixed engine retains its
  separate reviewed lock and held handles.
- GUI/helper/core crashes close the Job. Cleanup removes only exact journaled adapter,
  route and DNS identities; mismatches become `RecoveryRequired` and are not overwritten.
- UAC cancellation happens before journal or network mutation.

The design does not claim to defeat an already compromised administrator, kernel, or
native process with equivalent same-user rights. It avoids adding privilege to those
conditions rather than presenting impossible isolation claims in the UI.

## Tests required before registration

Deterministic unit tests (no UAC or network mutation):

- protocol round trips and maximum frame size;
- reject unknown/duplicate fields, trailing bytes, bad UUID/hex/lengths and oversized
  strings;
- reject replay, stale challenge, wrong session, non-monotonic request ID, second start
  and invalid state transitions;
- `ERROR_CANCELLED` maps only to `UacCancelled`;
- fixed argument encoder/parser cannot represent a path, quote, separator or extra flag;
- helper client rollback closes all handles and leaves no journal on every pre-start
  failure;
- fake helper start/stop is idempotent and reports engine PID separately from helper PID;
- renderer hostile-input tests prove `start_tun` still accepts only `node_id` and typed
  `TunRouting`.

Windows integration tests in a disposable snapshot after independent review:

1. Cancel UAC and verify no helper/sing-box, adapter, route, DNS, journal, service, task or
   startup entry.
2. Approve once and verify exactly one helper and one helper-owned sing-box Job.
3. Verify helper and engine PID/creation-time ownership, adapter/routes/DNS and an HTTPS
   proof through the selected outbound before green state.
4. Repeated Connect/Disconnect/Stop are idempotent.
5. Kill GUI, helper and engine separately and verify Job/adapter/route/DNS cleanup.
6. Change a foreign route concurrently and verify RouteDeck preserves it and reports a
   conflict rather than overwriting it.
7. Replace helper/config/engine between checks and verify refusal before mutation.
8. Confirm no service, scheduled task, startup entry or persistent helper remains.

Build the portable pair with `scripts/build-local-portable.ps1`. It uses the isolated
`src-tauri/target/portable/release` staging directory so a currently running development copy
cannot lock or contaminate either artifact. It first builds the helper, computes SHA-256, then
builds the production frontend and only the GUI Rust target with that exact digest embedded. The
second pass deliberately names `--bin routedeck`, so it cannot rewrite the pinned helper; the
script then verifies that the helper did not change between passes. Authenticode is optional
additional provenance, not a launch
requirement. The script also writes `routedeck-build.json`; pass a new `TargetRoot` to
`scripts/assemble-portable.ps1` to create the complete sibling layout with pinned sing-box,
Xray, and license files. On the normal development PC, run only unit tests and build checks. The first real
UAC/TUN test still belongs in the disposable Windows snapshot required by `AGENTS.md`; after the
exact-hash pair passes those tests, the ordinary live test is simply Connect, approve the
standard UAC prompt, verify traffic, then Disconnect and inspect exact cleanup.
