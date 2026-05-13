# NetBSD Cells: System Overview

This document describes how the current cells stack behaves as a whole. It is
the reference for architecture boundaries, state semantics, reconciliation, and
the stable read interface used by humans and automation.

## 1. Start with the mental model

Cells in this tree are not a single binary. They are a layered system with a
clear split between desired state and runtime state:

```text
  CLI / TUI
    - cellman
    - cellui
         |
         v
  control-plane library and command backend
         |
         v
  runtime control tool
    - cellctl
         |
         v
  kernel isolation and accounting
    - secmodel_cell
```

The practical workflow is simple:

1. Declare intent in Lua files under `/etc/cellman/*.lua`.
2. Reconcile that intent into runtime with `cellman apply`.
3. Observe and operate with `cellman`, `cellui`, and `cellctl`.

This flow is the heart of the v3 design: file-first desired state, explicit
runtime convergence, and predictable machine-readable output.

## 2. Responsibilities by component

### `secmodel_cell` (kernel)

- Enforces cell-aware authorization and process isolation rules.
- Maintains kernel-side membership and telemetry counters.
- Serves as the final authority for low-level isolation behavior.

### `cellctl` (runtime control)

- Creates, destroys, starts, stops, and supervises runtime cell instances.
- Exposes runtime facts and counters consumed by higher layers.
- Bridges userland orchestration and kernel isolation primitives.

### `cellman` (declarative control plane)

- Loads desired state from Lua documents.
- Builds typed in-memory state and read snapshots.
- Performs reconciliation (`apply`), backup/restore, and system operations.
- Exposes a stable CLI contract (`--view`, `-o`, `-T`, `-H`).

### `cellui` (interactive frontend)

- Uses the same API/backend path as `cellman`.
- Presents read snapshots and lifecycle actions in a curses interface.
- Consumes typed `libcellman` API snapshots for cells, storage, and backups.

## 3. Desired state, runtime state, and read state

The system uses three related but distinct data domains.

- Desired state: what you declare in `cell(...)`, `volume(...)`, and
  `apply(...)` Lua documents.
- Runtime state: what currently exists and is mounted/running under
  `/var/cellman/*`.
- Read state: merged snapshots returned by `cellman ... list/show` commands.

Keeping these domains separate avoids ambiguous behavior. Operators can reason
about "what I asked for" versus "what currently exists" without guessing.

## 4. Command surface at a glance

Top-level `cellman` command groups:

- `apply`
- `cell`
- `volume`
- `system`

Alias verbs (`list`, `start`, `stop`, `restart`, `shell`) are routed to
equivalent `cell <verb>` operations.

Desired-state mutation from CLI is intentionally blocked for `cell create|set|edit`
and `volume set|edit`. The expected workflow is to edit Lua files, then run
`cellman apply`.

## 5. State semantics

### Cell states

Cell labels are derived from declaration presence, rendered runtime presence,
and desired-running intent (`autostart_set && autostart`):

| Manifest present | Runtime rendered | Desired running | State |
| --- | --- | --- | --- |
| yes | yes | yes | managed |
| yes | yes | no | parked |
| yes | no | yes | pending |
| yes | no | no | declared |
| no | yes | n/a | orphaned |
| no | no | n/a | absent |

### Volume states

Volume labels are derived from declaration presence plus runtime existence:

| Manifest present | Runtime present | State |
| --- | --- | --- |
| yes | yes | managed |
| yes | no | pending |
| no | yes | orphaned |
| no | no | absent |

The important operator takeaway is that state labels are semantic, not cosmetic.
They encode whether intent and runtime currently agree.

## 6. Runtime filesystem layout

The runtime model is intentionally explicit and inspectable:

```text
/etc/cellman/
  *.lua

/var/cellman/
  base/<release>-<arch>/
  releases/<release>/<arch>/{base,etc[,xbase]}.tar.xz
  cells/<name>/
    root/
    overlay/
    state/
      manifest.sha256
      service.sha256
      policy.sha256
      apply.sha256
  volumes/<name>/

/var/backups/cellman/
  overlays/<name>_<timestamp>.tar.gz
  volumes/<name>_<timestamp>.tar.gz
```

The stored hash files are not implementation noise; they are part of drift
detection and reconcile decisions.

## 7. Reconciliation model (`cellman apply`)

`cellman apply` is the convergence engine. In broad terms it does the following:

1. Load and validate desired documents.
2. Build dependency order from `depends_on`.
3. Reconcile volumes first, then cells.
4. Compare persisted and freshly computed hashes.
5. Run apply actions and lifecycle changes where drift requires it.
6. Persist updated hashes after successful convergence.

Notable exit behavior:

- `0`: converge succeeded
- `1`: converge failed
- `2`: `--dry-run` detected drift

That `2` return code is deliberate and useful for CI/pipeline gating.

## 8. Stable read contract

All read commands are built around the same output controls:

- `--view` chooses a logical projection (`compact`, `desired`, `runtime`,
  `merged`)
- `-o` selects explicit fields
- `-T` emits TSV
- `-H` removes the TSV header row (valid only with `-T`)

Formatting rules that scripts should rely on:

- booleans are `1` or `0` in TSV
- booleans are `YES` or `NO` in human tables
- `age` is raw seconds in TSV and humanized in table output

For automation, always pass explicit `--view` and explicit `-o` to avoid hidden
assumptions about defaults.

## 9. Safety and policy invariants

The stack enforces fail-closed checks in multiple layers. Highlights:

- Resource names must match `[A-Za-z0-9._-]`.
- Mount targets must be absolute paths.
- Forbidden mount targets include `/`, `/dev*`, and `/.overlay*`.
- Overlapping mount targets in one cell are rejected.
- Host-path mounts require `CELL_ALLOW_HOST_MOUNTS=YES`.
- Destructive operations require explicit confirmation flags (for example
  `--yes`).

These rules are operational guardrails, not optional style guidance.

## 10. Relationship with `cellui`

`cellui` is a frontend over the same backend contracts, not a separate control
plane. It reads and writes through typed `libcellman` API calls for cells,
storage, and backups.

Because the UI no longer parses CLI text output, compatibility now hinges on API
row structures and semantic contracts rather than TSV column ordering. If you
change read-model semantics or API row fields, treat `cellui` adapter mapping as
part of the same change.
