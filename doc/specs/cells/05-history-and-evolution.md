# NetBSD Cells: History and Evolution

This file captures historical context for the current implementation. The goal
is to preserve design memory without mixing legacy detail into day-to-day
operator and developer references.

## 1. Timeline

```text
v1 -> v2 -> v3 (current)
```

## 2. v1: shell-first experimentation

v1 was first and foremost an experimental generation focused on kernel-side
possibilities. At that time the effort still used the naming
"jails for netbsd": `secmodel_jail` in the kernel, with `jailctl` and
`jailmgr` in userland.

Beyond authorization with `kauth`, v1 also explored deeper interventions in hot
paths for resource allocation:

- memory accounting experiments touching UVM-related paths
- CPU accounting experiments touching run queue behavior
- prototype NPF syntax extensions to allow/deny traffic per cell

These experiments were technically valuable, but they became a delivery blocker
for the central goal: lightweight operational process isolation that could be
shipped safely.

The reason was practical. UVM and run queue interventions require deeper design
work, broader test matrices, and careful side-effect analysis. v1 therefore
remained explicitly experimental rather than production-focused.

`jailmgr` in this phase was a thin shell wrapper around `jailctl`: it could
download userland bits and handle boilerplate administration to get a working
cell quickly.

## 3. v2: stronger control-plane shape

During the transition to v2, the project was renamed following BSD community
feedback to avoid confusion with the FreeBSD jail implementation.

v2 narrowed scope toward features that were both high-value and realistically
deliverable in the near term. Kernel-side implementation concentrated on `kauth`,
targeted security hardening, and pragmatic tooling.

Architecture in v2 looked like this:

- `secmodel_cell` and `cellctl` as the low-level pair
- `cellmgr` as a shell-based orchestration layer
- `cellui` as a curses C frontend

`cellui` could already interact with orchestration, but it did so indirectly:
starting `cellmgr` as a subprocess and speaking over stdin/stdout IPC.

`cellmgr` also already supported declarative desired state through shell-style
configuration files with dedicated file extensions.

Over time, however, `cellmgr` grew into a roughly 7000-line shell monolith,
which proved difficult to maintain. Limited type safety in shell made larger
refactors and correctness work increasingly expensive.

## 4. v3: declarative, typed, and contract-oriented

The current generation focuses on four principles:

1. Desired state is file-first and declarative (`/etc/cellman/*.lua`).
2. Runtime convergence is explicit (`cellman apply`).
3. Read output contracts are stable for automation.
4. Safety checks fail closed by default.

v3 is therefore a deliberate rework. `cellmgr` is removed and replaced by
`cellman`. The naming is intentional and inspired by `podman`: a practical,
operator-facing management tool with clear verbs and predictable behavior.

`cellman` is implemented in C. Desired state is declared with a dedicated DSL,
readable in a style that feels close to HCL-like infrastructure configuration.
Implementation remains base-system friendly: a Lua interpreter is embedded into
the C program and exposed through a restricted runtime, so the project gets a
structured, extensible configuration language without introducing a bespoke
parser.

Operationally, v3 keeps familiar capabilities from v2 while modernizing the
engine: apply-based convergence, runtime start/stop actions, boot-time
autostart, volume and mount management, and backup automation (especially for
volumes).

One key architectural shift is `libcellman`: core domain logic now lives in a
shared library consumed by both CLI and TUI. This removes the old subprocess IPC
boundary for `cellui`, which improves responsiveness and simplifies integration.
In parallel, `cellui` itself was cleaned up and hardened, including a smoother
user experience for temporary entry into cells.

## 5. Why history is isolated in one document

Keeping historical narrative in a dedicated file has two benefits:

- current operational docs stay implementation-accurate and focused
- historical reasoning remains available when evaluating architectural trade-offs

That split helps teams move fast on current behavior without repeatedly
re-litigating old implementation details in every spec page.

## 6. Durable design lessons

Across all generations, a few lessons keep repeating:

- predictable interfaces matter more than clever shortcuts
- typed boundaries reduce operational surprises
- declarative intent and explicit reconciliation scale better than ad-hoc runtime
  mutation
- safety defaults should be hard to bypass accidentally

These lessons are reflected directly in the v3 structure and should guide future
changes as the stack evolves.
