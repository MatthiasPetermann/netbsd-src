# Celladm Migration Specification (Replace `cellman`/`libcellman`, Keep `cellctl` + `secmodel_cell`)

## 1. Purpose and scope

This document defines the target operating model for NetBSD Cells after removing the `cellman` + `libcellman` control plane while preserving:

- `secmodel_cell` as kernel isolation and policy authority
- `cellctl` as runtime control interface

It specifies the new host-side control tool `celladm`, the declarative configuration format under `/etc/cells`, generated per-cell `rc.d` services, readonly-root/overlay lifecycle behavior, migration paths, and rollback approach.

This is a developer handoff specification, not an implementation sketch.

## 2. Problem statement and design goals

### 2.1 Current pain points

The existing stack introduces operational and maintenance complexity through:

- Lua DSL parsing and apply planning (`/etc/cellman/*.lua`)
- broad reconciliation semantics (`cellman apply --all`) that couple declaration, orchestration, and execution
- control-plane API coupling into higher-level tools that should not survive the cutover

### 2.2 Design goals

1. **Keep the kernel/runtime boundary stable**: retain `secmodel_cell` + `cellctl` contracts.
2. **Replace DSL with explicit files**: use static unit-like config (`quadlet`-style philosophy) under `/etc/cells`.
3. **Return to shell-centric host orchestration**: generation and runtime glue in predictable shell scripts.
4. **Use native NetBSD service semantics**: boot through `rc`, manual operation through `service`.
5. **Move from global apply to per-cell lifecycle**: each cell is an explicit service unit.
6. **Embed readonly-root handling in service lifecycle**: each generated service must own mount/unmount behavior.
7. **Constrain moving parts**: `celladm` as the only orchestration generator/manager.

## 3. Keep/drop boundary

### 3.1 Keep

- `sys/secmodel/cell/*` and `share/man/man9/secmodel_cell.9`
- `usr.sbin/cellctl/*`
- kernel/userland ABI via `security.models.cell.*` sysctl interface

### 3.2 Remove

- `usr.sbin/cellman/*` (including DSL parser, backend, apply engine, backup wrappers)
- `libcellman` compatibility surface (`cellman_api.h` and linked archive usage)
- centralized rc entry `etc/rc.d/cellman`
- `/etc/cellman/*.lua` as source-of-truth configuration model

### 3.3 Consequence

Any consumer currently linked to `libcellman` (notably `cellui`) is out of scope for migration and must be removed from the shipped base system together with `cellman`.

## 4. Target architecture

```text
admin edits /etc/cells/*.cell + optional hooks/assets
                |
                v
             celladm
      (validate + generate + manage rootfs)
                |
                +--> /etc/rc.d/cell_<name>  (generated)
                +--> /var/cells/... runtime layout
                |
                v
        /etc/rc + service(8) lifecycle
                |
                v
             cellctl
                |
                v
          secmodel_cell
```

## 5. Functional equivalence map (old -> new)

| Existing capability (`cellman`) | New model (`celladm`) |
| --- | --- |
| Lua documents (`cell`, `volume`, `apply`) | Explicit per-cell `.cell` files + optional shell hooks |
| `cellman apply --all` reconciliation | `celladm generate` + `service cell_<name> start` |
| single `cellman` boot service | generated per-cell `rc.d` services |
| `depends_on` graph in DSL | `require=`/`before=` in config -> rc `REQUIRE`/`BEFORE` |
| mount spec parsing in DSL | explicit mount entries in static config |
| readonly/overlay materialization by backend | readonly/overlay setup in generated rc methods |
| `cellman cell start/stop/restart` | `service cell_<name> start|stop|restart` |
| system bootstrap in `cellman system bootstrap` | `celladm bootstrap` (shell-based host preparation) |
| backup wrappers | out of scope for `celladm` v1; no backup/restore feature parity target |

## 6. Configuration model under `/etc/cells`

### 6.1 Directory contract

```text
/etc/cells/
  cells.d/
    <name>.cell
  defaults.conf       (global defaults)
  hooks/
    <name>/
      pre-start
      post-start
      pre-stop
      post-stop
```

`/etc/cells/cells.d/*.cell` is the authoritative desired state.

### 6.2 `.cell` format principles

- line-oriented key/value (no embedded DSL interpreter)
- deterministic parse order
- unknown keys fail validation
- explicit booleans (`yes|no`), lists (`space` or comma separated by key contract)
- no implicit runtime mutation side effects at parse time

### 6.3 Required keys (v1)

- `name=` (must match filename stem)
- `root_base=` (readonly base selector, default from global)
- `autostart=` (`yes|no`)
- `command=` (service payload command)

### 6.4 Optional keys (v1)

- `profile=` (`low|medium|high`) -> `cellctl create -l`
- `reserved_ports=` -> `cellctl create -r`
- `rlimit_nofile=`, `rlimit_as=`, `rlimit_core=` -> `cellctl create -N/-A/-C`
- `run_uid=`, `run_gid=`, `run_groups=` -> `cellctl supervise -U/-G/-g`
- `log_facility=`, `log_stdout_level=`, `log_stderr_level=`, `log_tag=`
- `require=` (service dependencies)
- `after=` / `before=` (ordering)
- `mount=` (repeatable; see mount grammar)
- `healthcheck=` (optional shell check invoked after start)
- `local_dev=` (`yes|no`, default yes)

### 6.5 Mount grammar

Repeatable key:

- `mount=<abs-path> <target> <ro|rw>`

Validation invariants:

- target must be absolute
- target cannot be `/`, `/dev`, `/dev/*`, `/.overlay`, `/.overlay/*`
- overlapping targets within one cell are rejected
- source must be an absolute host path

## 7. Filesystem and runtime layout (new canonical paths)

```text
/etc/cells/...              # desired state
/var/cells/
  base/<release>-<arch>/    # readonly prepared base with writable links
  releases/<release>/<arch>/
  cells/<name>/
    root/                   # nullfs ro mount of base
    overlay/                # writable upper tree
    state/                  # generated metadata/hashes/runtime markers
```

No legacy `/var/cellman/*` compatibility links are provided.

## 8. Readonly-root + overlay lifecycle contract

Each generated `rc.d` script must implement the following contract itself.

### 8.1 Start phase

1. Validate config and prerequisites (`secmodel_cell` loaded, base exists, required paths exist).
2. Ensure per-cell dirs:
   - `/var/cells/cells/<name>/root`
   - `/var/cells/cells/<name>/overlay`
3. Ensure overlay writable subtree baseline:
   - `etc var tmp home root usr/pkg opt var/run var/log`
   - `tmp` mode `01777`
4. Mount readonly base on `root` (`nullfs` with `ro`).
5. Mount overlay onto `root/.overlay` (`nullfs` rw).
6. Initialize per-cell `/dev` when `local_dev=yes`:
   - tmpfs mount
   - `MAKEDEV std ptm`
   - ptyfs on `/dev/pts`
7. Apply declared mounts into `root/<target>`.
8. Create cell via `cellctl create ... -n <name> <root>` when missing.
9. Start supervised payload via `cellctl supervise ...`.
10. Run optional healthcheck.

### 8.2 Stop phase

1. Stop supervised workload (via `cellctl destroy` or targeted supervision stop logic).
2. Unmount all mountpoints under `root`, deepest path first.
3. Ensure `.overlay` and `root` mounts are removed.
4. Leave overlay content intact.

### 8.3 Restart phase

Equivalent to stop then start.

### 8.4 Failure behavior

- partial start failure must rollback mounts created in current transaction
- if cell create succeeded but supervise failed, cell must be destroyed
- no silent continuation on critical mount or policy errors

## 9. `celladm` responsibilities

`celladm` is a shell-first management tool with deterministic output and subcommands.

## 9.1 Command set (minimum)

- `celladm validate`:
  - parse/validate `/etc/cells` model
  - print structured errors (`file:key:reason`)
- `celladm generate`:
  - generate/update `/etc/rc.d/cell_<name>` from configs
  - write generated header with source hash
  - write directly into `/etc/rc.d` (no staging directory)
  - remove stale generated scripts for removed cells
- `celladm bootstrap`:
  - ensure module activation policy (`secmodel_cell`)
  - prepare base/releases dirs
  - fetch/extract base sets
  - enforce writable-link base shaping
- `celladm rootfs <name> prepare|verify|repair`:
  - explicit readonly-root/overlay management
- `celladm list`:
  - compact desired/runtime view for operators

## 9.2 Generation semantics

For each `name` in `cells.d` create `/etc/rc.d/cell_<name>` with:

- `name="cell_<name>"`
- generated `rcvar` (for autostart wiring)
- `start_cmd`, `stop_cmd`, `status_cmd`
- `required_files="/etc/cells/cells.d/<name>.cell"`
- `REQUIRE`/`BEFORE` derived from config dependency fields

Generated scripts must be idempotent and safe for repeated `service ... start`.

## 10. rc integration model

### 10.1 Boot behavior

At boot, native `rc` executes generated enabled services based on dependency order.
No global `apply --all` equivalent is required.

### 10.2 Manual behavior

Operators control a single cell via:

- `service cell_<name> start`
- `service cell_<name> stop`
- `service cell_<name> restart`
- `service cell_<name> status`

### 10.3 Enable/disable model

Autostart intent from `.cell` is rendered to rc-compatible defaults:

- `cell_<name>=YES|NO` in defaults/local rc.conf fragments

`celladm generate` owns regeneration and drift correction of generated rc artifacts.

## 11. Migration strategy (single-path hard switch)

Only one migration mode is supported.

- remove `cellman` + `libcellman` + `cellui` from build/install sets
- migrate configs to `/etc/cells` before first reboot on new image
- bootstrap with `celladm bootstrap && celladm generate`
- boot and operate exclusively via generated per-cell rc services

No dual-stack, adapter mode, or compatibility bridge is supported.

## 12. Migration workflow

1. Deploy image containing `celladm` and no `cellman`/`cellui` components.
2. Ensure `/etc/cells/cells.d/*.cell` is present and validated (`celladm validate`).
3. Generate rc scripts via `celladm generate` (directly into `/etc/rc.d`).
4. Reboot validation (boot-time start order, mounts, healthchecks).

## 13. Rollback strategy

If migration fails operationally:

1. disable generated `cell_<name>` services
2. keep `/var/cells` runtime data; do not destructive-clean overlays by default
3. rollback by booting a previous system image/release artifact

No in-place rollback to a legacy `cellman` control plane is supported.

## 14. Non-functional requirements

- deterministic generation (same input -> byte-identical scripts)
- explicit failure messages suitable for automation
- no hidden network activity except `bootstrap` fetch path
- strict root-only operations for runtime mutations
- bounded shell implementation complexity (no embedded interpreters)

## 15. Security and safety invariants

- enforce valid resource naming (`[A-Za-z0-9._-]`)
- enforce mount target restrictions
- avoid exposing host-global read interfaces to non-host cells (retain kernel policy)

## 16. Packaging/build integration impacts (future implementation checklist)

Expected tree changes during implementation:

- remove `cellman` entries from `usr.sbin/Makefile`, rc/defaults/mtree/set lists
- add `celladm` binary, manpage, examples, and generated rc integration policy
- update references in `doc/specs/cells/*`
- remove `cellui` from build/install/distribution sets

## 17. Open questions to resolve during implementation

1. Which minimal read/status interface should `celladm` expose for operators (if any) beyond rc/service tooling?
2. Is a one-time config conversion tool required in-tree, or is manual migration acceptable for the first rollout?
3. Which release engineering gate verifies generated rc scripts in distribution sets?

## 18. Acceptance criteria

The migration is complete when all are true:

- no `cellman`/`libcellman`/`cellui` binaries or docs are shipped
- cells are declared only via `/etc/cells/*.cell`
- per-cell generated `rc.d` scripts are the only boot/manual lifecycle path
- readonly-root + overlay lifecycle succeeds through generated services
- runtime operations rely only on `cellctl` + `secmodel_cell`
- developer documentation is sufficient to implement and operate the model without reading removed `cellman` internals
