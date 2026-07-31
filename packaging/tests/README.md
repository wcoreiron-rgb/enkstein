# Native executor isolation tests

These exercise the Local Executor's real process behaviour against real
processes. They are not unit tests: pytest stubs the bridge boundary because CI
has no desktop broker, so these are what actually prove the native guarantees.

## macOS

```bash
swiftc -O packaging/tests/macos_exec_isolation.swift -o /tmp/mac_iso && /tmp/mac_iso
```

Provisions its own temp project root plus a sibling directory standing in for
another tenant, then asserts:

| Check | Guarantee |
| --- | --- |
| `successful_command` / `failing_command` | exit status is reported faithfully |
| `timeout` | killed at the deadline, not left running |
| `cancellation` | terminated on request |
| `child_process_cleanup` | a grandchild is reaped via process-group kill |
| `output_truncation` | output bounded to 20000 bytes |
| `env_isolation` | no host credential/env leaks into the child |
| `containment_read_denied` | another tenant's file is unreadable |
| `containment_write_denied` | writes outside the root fail and create nothing |
| `containment_write_allowed` | writes inside the root still work |
| `deny_read_*` | `~/.ssh`, Keychains, Desktop, `~/.aws`, shell history unreadable |

Expected output ends with `ALL_PASS`.

## Windows

```powershell
pwsh -NoProfile -File packaging/tests/windows_exec_semantics.ps1
```

Covers the allowlist, argument limits, argv literalness (no shell injection),
cleared environment, timeout, cancellation, whole-tree termination, output
truncation, and the pinned working directory.

## Isolation posture: macOS and Windows are NOT equivalent

Every execution result carries an `isolation` field. Do not treat them as the
same guarantee.

**macOS — `"sandbox"`.** A seatbelt profile denies network outright, denies all
filesystem reads outside an explicit allowlist (system/runtime paths, the
approved root, and a single `literal` entry for the root's parent that Node's
`uv_cwd` requires), and confines writes to the approved root.

**Windows — `"containment"`.** Job Object whole-tree termination, argv-only
execution, an allowlisted program, a cleared environment, and a working
directory pinned to a non-reparse-point approved root. It does **not** restrict
reads outside the root and does **not** block network access. `sandboxed` is
reported `false` and `isolation` is `"containment"` so no caller mistakes it for
the macOS guarantee. Parity requires an AppContainer profile or a Windows
Sandbox/container host.

A broker that predates the `isolation` field is treated as `"containment"`, the
weaker claim.

## Verification status

macOS results here were produced on a real macOS host. The Windows script's
semantics were verified through .NET/pwsh on macOS; the Job Object path itself
has **not** been executed on a real Windows host. Until it is, do not describe
the Windows Local Executor as verified.
