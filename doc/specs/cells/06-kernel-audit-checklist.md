# NetBSD Cells: Kernel Audit Checklist

This checklist is for reviewing the kernel isolation model and its userland
control contract before merge/release.

Scope:

- `sys/secmodel/cell/*`
- `sys/sys/cell.h`
- `usr.sbin/cellctl/cellctl.c`

It is written as a practical pass/fail list. Treat each item as required unless
explicitly waived with rationale.

## 1. Core invariants

- [ ] Cell identity is exactly one `cellid_t` per credential.
- [ ] `CELLID_HOST` (0) remains reserved for host context.
- [ ] Host root bypass semantics are intentional and unchanged.
- [ ] Kernel/userland ABI names under `security.models.cell.*` are unchanged.
- [ ] `sys/sys/cell.h` layout changes are treated as ABI-impacting changes.

## 2. Locking and concurrency invariants

- [ ] Global lock order is preserved everywhere: `proc_lock` -> `cell_lock`.
- [ ] No path acquires `proc_lock` while holding `cell_lock`.
- [ ] `destroy` and membership checks execute in one atomic transaction path.
- [ ] `enter` cannot commit membership to a cell that is concurrently destroyed.
- [ ] Hold counters are balanced on all success and error paths.
- [ ] `KASSERT` lock assumptions remain accurate after refactors.

## 3. Lifecycle and transaction behavior

- [ ] Cell lifecycle states are explicit and monotonic in transactions.
- [ ] `destroy` only removes cells after state gate + hold/member re-check.
- [ ] `enter` validates privilege, current membership, and target state before
      commit.
- [ ] Credential commit uses clone/replace flow with clean rollback on error.
- [ ] Unload is refused while active cell entries exist.

## 4. Input and ABI hardening

- [ ] `create` flags reject unknown bits.
- [ ] Reserved-port payload rejects zero, duplicates, and out-of-range counts.
- [ ] Rlimit fields are consistent with declared flags.
- [ ] Fixed-size text fields from userland require bounded NUL termination.
- [ ] Text fields reject forbidden control characters (at least newline).
- [ ] Sysctl handlers enforce exact expected payload sizes where required.

## 5. Sysctl/read-path robustness

- [ ] `list` snapshot uses sequence-based retry across lock drop/reacquire.
- [ ] Snapshot size calculations are overflow-checked.
- [ ] Copyout paths free temporary buffers on all exits.
- [ ] Read contracts used by `cellctl` remain stable:
  - `security.models.cell.create`
  - `security.models.cell.destroy`
  - `security.models.cell.id`
  - `security.models.cell.list`

## 6. Policy and audit behavior

- [ ] Process/system/network decisions remain fail-closed where specified.
- [ ] Deny counters are atomically incremented.
- [ ] Deny logs are rate-limited and do not flood under repeated rejects.
- [ ] Rate limiting is scope-aware (process/system/network).
- [ ] Policy helpers remain declarative and easy to audit (action matrices,
      req filters).

## 7. Module lifecycle hygiene

- [ ] `secmodel_cell_init` fully initializes lock/callout/key state.
- [ ] `secmodel_cell_start` reports listener registration failures.
- [ ] Partial listener startup failures unwind cleanly.
- [ ] Init failure path deregisters secmodel and releases initialized resources.
- [ ] Stop path unlistens, halts callout, deregisters key, and frees entries.

## 8. `cellctl` compatibility checks

- [ ] `cellctl create/list/exec/supervise/destroy/stats` still operate without
      interface changes.
- [ ] `cellctl` error handling still maps kernel failures to actionable output.
- [ ] No behavioral regressions for host-root-only operations.

## 9. Minimal verification routine

Run this routine before sign-off:

1. Build kernel module:
   - `nbmake -C sys/modules/secmodel_cell dependall all`
2. Create and inspect:
   - `doas cellctl create -n audit-test /path/to/cell-root`
   - `cellctl list -T`
3. Enter and inspect id behavior:
   - `doas cellctl exec audit-test id`
4. Verify destroy busy semantics:
   - start long-running process in cell, confirm destroy returns busy.
5. Stop process and destroy:
   - `doas cellctl destroy audit-test`
6. Verify deny telemetry path:
   - trigger known deny and inspect `cellctl stats` plus system log rate limit.

## 10. Review artifacts to attach

- [ ] Diff summary with rationale per touched file.
- [ ] Build log excerpt for `secmodel_cell` module.
- [ ] Command transcript for section 9 routine.
- [ ] Explicit statement of ABI compatibility status.

If any checklist item fails, record the failure and block release until fixed or
waived with documented risk acceptance.
