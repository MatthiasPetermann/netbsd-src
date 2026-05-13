# NetBSD Cells: DSL and Desired State

This document explains how desired state is authored, loaded, validated, and
translated into runtime behavior.

The short version is: Lua files under `/etc/cellman` describe intent, and
`cellman` turns that intent into typed state and reconcile actions.

## 1. Where desired state lives

By default, desired state is loaded from:

- `/etc/cellman/*.lua`

The root can be overridden with:

- `CELLMAN_DSL_DIR`

Files are loaded in deterministic sorted path order, and only regular `*.lua`
files are considered.

Why this matters: deterministic loading keeps behavior repeatable and makes
drift/debug sessions predictable.

## 2. Top-level document types

The DSL recognizes three top-level builders:

- `cell("name", { ... })`
- `volume("name", { ... })`
- `apply("name", { ... })`

Within cell mount lists, two helper constructors are also used:

- `volume("name", { target = "/path", mode = "ro|rw" })`
- `host("/host/path", { target = "/path", mode = "ro|rw" })`

Names are validated and duplicates of the same kind and name are rejected.

## 3. Cell documents

A cell document declares lifecycle intent, policy knobs, supervise settings,
dependencies, and mounts.

```lua
cell("web", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "80,443",
    rlimit_nofile = "4096",
    rlimit_as = "1073741824",
    rlimit_core = "0",
  },
  supervise = {
    cmd = "/usr/sbin/httpd -X -f /var/www/conf/httpd.conf",
    run_as = "cell:www:www",
    log = {
      facility = "daemon",
      stdout_level = "info",
      stderr_level = "err",
      tag = "web",
    },
  },
  depends_on = { "db" },
  healthcheck = "test -f /var/www/index.html",
  mounts = {
    volume("web-data", { target = "/var/www", mode = "rw" }),
    host("/srv/shared", { target = "/shared", mode = "ro" }),
  },
})
```

Common fields include:

- `autostart`
- `create.profile`, `create.reserved_ports`, and create-time rlimits
- `supervise.cmd`, `supervise.run_as`, and optional log attributes
- `depends_on`
- `healthcheck`
- `mounts`

## 4. Volume documents

A volume document declares runtime storage intent and optional mode metadata.

```lua
volume("web-data", {
  mode = "0755",
})
```

Volume docs are intentionally small. They focus on identity and ownership model,
while usage relationships are expressed from cell mounts.

## 5. Apply documents

An apply document describes convergent file/process actions for one cell.

```lua
apply("web", {
  pkg("nginx"),
  dir("/var/www", { mode = "0755", owner = "{{run_uid}}", group = "{{run_gid}}" }),
  copy("./assets/index.html", "/var/www/index.html", { mode = "0644" }),
  template("./templates/app.env.tmpl", "/etc/app.env", {
    mode = "0640",
    tokens = {
      app_name = "web",
      pkg_path = from_env("PKG_PATH"),
    },
  }),
  script("./scripts/bootstrap.sh", {
    args = { "--mode", "prod" },
    env = { APP = "{{cell_name}}" },
    timeout = 300,
  }),
})
```

Supported helpers include:

- `pkg`, `exec`, `dir`, `line`, `symlink`
- `copy`, `untar`, `file`, `patch`, `template`, `script`
- `from_env` for token values

The apply layer is designed for idempotent convergence. Operations are parsed
into typed action records before execution.

## 6. Tokens and templating

Template placeholders use `{{token_name}}` syntax.

Runtime-provided tokens include:

- `cell_name`, `cell_root`, `manifest_dir`, `release`, `arch`
- `run_uid`, `run_gid`, `run_groups`

Action-local overrides can be provided in
`template(..., { tokens = { ... } })`, with values as literal strings or
`from_env("ENV_NAME")`.

Token behavior is fail-closed:

- unknown token -> error
- malformed token name -> error
- unterminated token expression -> error

## 7. Source path resolution

For source-based actions (`copy`, `untar`, `template`, `script`):

- absolute paths are used as-is
- relative paths are resolved from the current DSL file directory

This path resolution is also included in apply hashing, which means source-file
changes naturally trigger drift.

## 8. DSL sandbox and safety

The Lua environment is intentionally restricted. Dangerous globals and libraries
such as `dofile`, `load*`, `require`, `os`, `io`, `debug`, and `package` are
blocked.

The goal is practical: a declarative configuration language that remains
predictable, reviewable, and safe for production control-plane use.

## 9. How DSL becomes runtime behavior

The translation pipeline is straightforward:

```text
Lua files
  -> dsl_lua.c parses builder calls
  -> typed document objects
  -> state.c assembles cellman_state
  -> backend compares desired vs runtime
  -> apply/lifecycle actions converge runtime
```

The system does not execute raw Lua logic as business flow. It extracts a typed
intermediate model and then runs explicit backend behavior over that model.

## 10. Worked workflow

A practical project layout often looks like this:

```text
01-volume-data.lua
02-cell-web.lua
03-apply-web.lua
```

Typical converge cycle:

```sh
cellman apply --dry-run --all
doas cellman apply --all
cellman cell show web --view merged
```

This loop keeps intent in versioned files and runtime changes explicit at apply
time.
