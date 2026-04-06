# NetBSD Cells: Developer Architecture

This guide is for contributors working on the implementation. It explains where
the important logic lives, how requests flow through the stack, and what to keep
stable when extending behavior.

## 1. Source map

Kernel model:

- `sys/secmodel/cell/*`
- `sys/sys/cell.h`

Runtime control tool:

- `usr.sbin/cellctl/cellctl.c`

Control plane and apply engine:

- `usr.sbin/cellman/main.c`
- `usr.sbin/cellman/api/*`
- `usr.sbin/cellman/commands/*`
- `usr.sbin/cellman/dsl_lua.c`
- `usr.sbin/cellman/state.c`
- `usr.sbin/cellman/model.c`
- `usr.sbin/cellman/apply_exec.c`
- `usr.sbin/cellman/apply_exec_tokens.inc`
- `usr.sbin/cellman/apply_exec_actions.inc`
- `usr.sbin/cellman/template.c`
- `usr.sbin/cellman/proc_exec.c`
- `usr.sbin/cellman/fs_util.c`

Interactive frontend:

- `usr.sbin/cellui/*`

## 2. Request flow and dispatch layering

Both CLI and TUI eventually use the same backend path:

```text
cellman main.c
  -> cellman_api_dispatch(...)
     -> API route tables (apply/cell/volume/system + aliases)
        -> command dispatch and route logic (commands/*)
           -> backend execution (snapshot, reconcile, backup, system ops)
```

`cellui` links against the same API surface, so behavior differences between CLI
and TUI are mostly presentation concerns, not independent command semantics.

## 3. DSL load pipeline

The DSL path is intentionally deterministic:

```text
state_load_dir(dir)
  -> discover *.lua in sorted order
  -> parse with dsl_lua.c sandbox/builders
  -> append typed documents to state lists
  -> reject invalid names and duplicates
```

Key boundaries:

- `dsl_lua.c` handles parsing and validation into typed structures.
- `model.c` and `cellman.h` define and manage in-memory IR types.
- `state.c` handles directory loading, ordering, and state assembly.

## 4. Snapshot and read-model internals

Read commands combine desired and runtime information.

Cell snapshot pipeline:

```text
desired docs
  + runtime list (cellctl list -T)
  + runtime stats (cellctl stats -T)
  -> merged snapshot table
  -> projection by view and field selection
```

Volume snapshot pipeline:

```text
desired volume docs
  + runtime presence/mount/path data
  + manifest reference data
  -> merged snapshot table
```

State labels are produced by pure derivation functions. Keep this logic explicit
and side-effect free so behavior remains testable and easy to reason about.

## 5. Apply engine internals

Entry point: backend apply handler in `commands/*`, with execution logic in
`apply_exec.c` and helper include units.

High-level shape:

```text
load desired state
  -> compute dependency order
  -> compare hash groups
  -> run apply actions if required
  -> enforce lifecycle transitions
  -> run health checks
  -> persist new hash state
```

Hash groups are persisted per cell under
`/var/cellman/cells/<name>/state/`:

- `manifest.sha256`
- `service.sha256`
- `policy.sha256`
- `apply.sha256`

These hashes are central to convergence behavior. Treat changes here as
contract-level changes.

## 6. Runtime identity and tokens

`supervise.run_as` is resolved into UID/GID/group context used by lifecycle and
apply behavior.

The runtime exports identity to actions via environment and token namespaces,
including:

- `CELLMAN_RUN_UID`, `CELLMAN_RUN_GID`, `CELLMAN_RUN_GROUPS`
- token equivalents `run_uid`, `run_gid`, `run_groups`

If you change identity resolution, verify both process execution and templating
paths.

## 7. Safety-critical validation zones

Important fail-closed checks are spread across parser and backend layers:

- DSL name validation and duplicate rejection
- token validation and rendering errors
- mount policy checks (`/`, `/dev*`, `/.overlay*`, overlap detection)
- host-path mount gating (`CELL_ALLOW_HOST_MOUNTS=YES`)
- destructive confirmation requirements (`--yes`)

Do not weaken these checks without a very strong, explicit design reason.

## 8. How to place new code

Use this quick placement guide:

- New CLI verb or alias -> `commands/command_route.c` and command modules.
- API surface changes -> `api/*` and `cellman_api.h`.
- Read-model field logic -> `commands/command_backend.c` and runtime snapshot
  helpers.
- DSL schema/action parsing -> `dsl_lua.c` plus model definitions.
- Apply action semantics -> `apply_exec_actions.inc`.
- Token behavior -> `apply_exec_tokens.inc`.
- Generic process/filesystem helpers -> `proc_exec.c` or `fs_util.c`.

## 9. Field and DSL extension checklist

When adding or changing read fields:

1. Update field definitions and view defaults in backend tables.
2. Keep TSV names stable unless a contract break is intentional.
3. Verify `cellui` adapter mappings if API row fields or semantics changed.
4. Update docs in this directory.

When adding DSL keys or new apply action types:

1. Extend parser behavior in `dsl_lua.c`.
2. Extend typed model structures.
3. Include data in hashing and drift logic where relevant.
4. Implement runtime behavior in apply/backend code.
5. Document semantics and examples.

## 10. Non-negotiable compatibility rules

Preserve these properties unless you are deliberately versioning a new contract:

- deterministic DSL load order
- fail-closed validation behavior
- explicit confirmation for destructive operations
- stable machine-readable output contracts (`--view`, `-o`, `-T`, `-H`)

These rules keep the stack scriptable, debuggable, and safe to operate.
