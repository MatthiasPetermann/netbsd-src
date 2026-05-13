# NetBSD Cells Documentation

This directory is the living documentation set for the cells stack in this
source tree.

The documents are written for day-to-day engineering work: they explain how the
system is supposed to behave, how operators run it safely, and where
contributors should make changes when they extend it.

## Reading map

- `01-system-overview.md`
  - Start here for architecture, vocabulary, and behavioral contracts.
- `02-dsl-and-desired-state.md`
  - Explains the Lua format under `/etc/cellman/*.lua` and how input becomes
    runtime behavior.
- `03-operations-runbook.md`
  - Practical day-0/day-2 procedures, including apply, backups, and recovery.
- `04-developer-architecture.md`
  - Internal module map and extension guidance for contributors.
- `05-history-and-evolution.md`
  - Historical context and design rationale from earlier generations.
- `06-kernel-audit-checklist.md`
  - Security and robustness review checklist for `secmodel_cell` and
    `cellctl` compatibility.

## Scope and source of truth

The implementation described here is the combination of:

- `sys/secmodel/cell/*` and `sys/sys/cell.h` (`secmodel_cell` kernel model)
- `usr.sbin/cellctl/cellctl.c` (runtime control and counters)
- `usr.sbin/cellman/*` (declarative control plane and apply engine)
- `usr.sbin/cellui/*` (interactive terminal frontend)

Desired state is authored in `/etc/cellman/*.lua`.
Runtime state is materialized under `/var/cellman/*`.
