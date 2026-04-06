# NetBSD Cells: Operations Runbook

This runbook is written for real operator workflows: bootstrap, change rollout,
verification, backup/restore, and failure handling.

The design assumption is simple: desired state is file-based, and runtime
changes are applied explicitly through `cellman`.

## 1. Day-0 bootstrap

Bring up a new host in this order:

```text
bootstrap host -> author DSL -> dry-run -> apply -> verify
```

```sh
doas cellman system bootstrap

# write /etc/cellman/*.lua

cellman apply --dry-run --all
doas cellman apply --all

cellman cell list --view compact
cellman volume list --view merged
```

Bootstrap prepares the expected directory layout and baseline runtime resources
under `/var/cellman` and `/var/backups/cellman`, plus the DSL root under
`/etc/cellman`.

## 2. Everyday change workflow

Treat the change loop as a disciplined cycle, not a one-off command:

1. Edit one or more Lua documents.
2. Review your diff.
3. Run `cellman apply --dry-run --all`.
4. Run `doas cellman apply --all`.
5. Verify with read views and targeted checks.

If dry-run reports drift, that is expected for pending changes. If apply still
fails after a clean dry-run, move into the troubleshooting flow later in this
document.

## 3. Reading system state correctly

Use table output for humans and TSV for scripts.

Human-oriented commands:

```sh
cellman cell list --view compact
cellman cell show web --view merged
cellman volume list --view merged
```

Automation-oriented commands:

```sh
cellman cell list --view runtime -T -H -o name,state,running,cid,procs,cpu1s,cpu10s,memory,age
cellman volume list --view merged -T -H -o name,state,mounted,refs,path,used_by
```

Automation rules worth enforcing in scripts:

- always set `--view`
- always set explicit `-o`
- prefer `-T -H` for stable parsing

## 4. Runtime lifecycle operations

Per-cell lifecycle:

```sh
doas cellman cell start web
doas cellman cell stop web
doas cellman cell restart web
cellman cell shell web
```

Bulk lifecycle:

```sh
doas cellman cell start --all
doas cellman cell stop --all
doas cellman cell restart --all
```

State labels summarize intent vs reality:

- `managed`: declared, rendered, and desired running
- `parked`: declared and rendered, but desired stopped
- `pending`: declared and desired running, but not rendered yet
- `declared`: declared only
- `orphaned`: runtime exists without declaration
- `absent`: neither declaration nor runtime

## 5. Apply modes and operator intent

Core shape:

```sh
cellman apply [--all|<name>...] [--dry-run] [--force] [--restart-changed] [--silent|-v|-vv]
```

How to choose flags:

- `--dry-run`: planning and drift detection without writing runtime
- `--force`: execute apply actions even when apply hash is unchanged
- `--restart-changed`: include policy drift in restart behavior
- `-v`/`-vv`: raise detail for investigations and change windows

Exit codes are operationally meaningful:

- `0`: success
- `1`: failure
- `2`: dry-run found drift

## 6. Running one apply plan directly

Run a named apply document:

```sh
doas cellman cell plan run web
```

Run from a specific file:

```sh
doas cellman cell plan run web --file /path/to/apply.lua
```

Ephemeral execution mode:

```sh
doas cellman cell plan run web --ephemeral
```

Use this path for focused maintenance operations when full converge is not the
best operational fit.

## 7. Backups and restores

Volume backups:

```sh
doas cellman volume backup create data
cellman volume backup list data -T -H
doas cellman volume backup restore data --latest --yes
doas cellman volume backup delete data --latest --yes
```

Overlay backups:

```sh
doas cellman cell backup create web
cellman cell backup list web -T -H
doas cellman cell backup restore web --latest --yes
doas cellman cell backup delete web --latest --yes
```

Guardrails are strict by design:

- destructive restore/delete operations require explicit confirmation
- volume restore/delete is blocked while mounted
- overlay backup/restore is blocked while the cell is running or overlay is
  mounted

## 8. Cleanup and reset operations

Selective reset:

```sh
doas cellman system reset --cells --yes
doas cellman system reset --volumes --yes
```

Full reset:

```sh
doas cellman system reset --cells --volumes --yes
```

Orphan cleanup:

```sh
doas cellman cell remove --orphans --yes
doas cellman volume remove --orphans --yes
```

Treat these operations as deliberate recovery/maintenance actions and always run
them with clear scope.

## 9. Troubleshooting sequence

A reliable debugging flow looks like this:

```text
cellman cell list --view merged
  -> cellman apply --dry-run --all
  -> cellctl list -T and cellctl stats -T
  -> cellman cell show <name> / cellman cell shell <name>
  -> inspect DSL and /var/cellman/cells/<name>/state/*.sha256
```

Frequent root causes:

- broken dependencies in `depends_on`
- invalid mount targets or host-mount policy violations
- unresolved `run_as` identity
- source file drift for `copy`/`untar`/`template`/`script` inputs

## 10. `cellui` in operations

`cellui` is excellent for situational awareness and quick lifecycle operations,
especially during incident triage. It refreshes continuously and presents both
cell and storage views.

For scripts and audits, still prefer explicit `cellman ... -T -H -o ...`
commands, because they are easier to version and review.
