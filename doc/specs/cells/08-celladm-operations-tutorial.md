# NetBSD Cells with `celladm`: Operations Tutorial

This document is a hands-on operations tutorial for:

- `secmodel_cell` (kernel isolation)
- `cellctl` (runtime control)
- `celladm` (host-side configuration and service generation)

It explains:

1. on-disk layout,
2. configuration parameters,
3. day-0/day-1/day-2 workflows,
4. common failures and fixes.

## 1) Operating model in one sentence

You declare cells in `/etc/cells/cells.d/*.cell`,
`celladm generate` creates `rc.d` services `cell_<name>`,
and day-to-day operations run through `service cell_<name> start|stop|status`.

## 2) Disk layout

### 2.1 Desired state (`/etc/cells`)

```text
/etc/cells/
  defaults.conf              # global defaults
  cells.d/
    <name>.cell              # one file per cell
  hooks/
    <name>/
      pre-start
      post-start
      pre-stop
      post-stop
```

### 2.2 Runtime (`/var/cells`)

```text
/var/cells/
  releases/<release>/<arch>/     # downloaded set archives (base/etc/xbase)
  base/<release>-<arch>/          # prepared readonly base layer
  cells/<name>/
    root/                         # mountpoint for readonly base
    overlay/                      # writable upper tree
    state/                        # runtime metadata
```

## 3) `defaults.conf`: global parameters

File: `/etc/cells/defaults.conf`

Example:

```conf
root_base=/var/cells/base/11.0_RC4-amd64
local_dev=yes
release=11.0_RC4
machine_arch=amd64
netbsd_mirror=
bootstrap_include_xbase=yes
```

Meaning:

- `root_base=`
  - Default for `root_base` in `.cell` files.
  - Must point to an existing base path.
- `local_dev=yes|no`
  - Default for local `/dev` setup in the cell.
- `release=`
  - Used by `celladm bootstrap` (set path selection).
- `machine_arch=`
  - Used by `celladm bootstrap` (set path selection).
- `netbsd_mirror=`
  - Optional mirror for set downloads.
  - Empty means CDN default.
- `bootstrap_include_xbase=yes|no`
  - Controls whether `xbase.tar.xz` is fetched and extracted.

Note: `NETBSD_MIRROR` in the environment overrides `netbsd_mirror` from `defaults.conf`.

## 4) `.cell` file: parameters and meaning

File: `/etc/cells/cells.d/<name>.cell`

### 4.1 Required fields

- `name=`
  - Must match the filename stem (without `.cell`).
- `root_base=`
  - Absolute path to the base layer (or provided by default).
- `autostart=yes|no`
- `command=`
  - Payload command executed inside the cell.

### 4.2 Common optional fields

- `profile=low|medium|high`
- `reserved_ports=...`
- `rlimit_nofile=...`
- `rlimit_as=...`
- `rlimit_core=...`
- `run_uid=...`, `run_gid=...`, `run_groups=...`
- `log_facility=...`, `log_stdout_level=...`, `log_stderr_level=...`, `log_tag=...`
- `require=...`, `after=...`, `before=...`
- `local_dev=yes|no`

### 4.3 Mounts

Syntax:

```conf
mount=<host-abs-path> <cell-abs-target> <ro|rw>
```

Example:

```conf
mount=/var/www/httpd /var/www/httpd rw
mount=/etc/resolv.conf /etc/resolv.conf ro
```

Important rules:

- Source and target must be absolute paths.
- Forbidden targets: `/`, `/dev`, `/dev/*`, `/.overlay`, `/.overlay/*`.
- Overlapping mount targets in one cell are invalid.

## 5) Day-0 tutorial (first setup)

### Step 1: Configure defaults

Populate `/etc/cells/defaults.conf` for your host (`release`, `machine_arch`, optionally `root_base`).

### Step 2: Run bootstrap

```sh
doas celladm bootstrap
```

What it does:

- checks/loads `secmodel_cell`,
- downloads set archives to `/var/cells/releases/<release>/<arch>/`,
- extracts into `/var/cells/base/<release>-<arch>/`,
- applies writable-link shaping in the base layer.

### Step 3: Define the first cell

Example file:

```text
/etc/cells/cells.d/httpd.cell
```

Template in-tree:

```text
/etc/cells/cells.d/httpd.cell.example
```

### Step 4: Validate configuration

```sh
celladm validate
```

### Step 5: Generate services

```sh
doas celladm generate
```

Result:

```text
/etc/rc.d/cell_httpd
```

### Step 6: Start the cell

```sh
doas service cell_httpd start
```

### Step 7: Verify status

```sh
service cell_httpd status
cellctl list
celladm list
```

## 6) Day-1/Day-2 operations

### Roll out a config change

```sh
$EDITOR /etc/cells/cells.d/httpd.cell
celladm validate
doas celladm generate
doas service cell_httpd restart
```

### Control a single cell

```sh
doas service cell_httpd start
doas service cell_httpd stop
doas service cell_httpd restart
service cell_httpd status
```

### Explicit rootfs lifecycle

```sh
doas celladm rootfs httpd verify
doas celladm rootfs httpd repair
```

## 7) Example: simple base `httpd`

Equivalent in spirit to the old `cellman` sample.

File `/etc/cells/cells.d/httpd.cell`:

```conf
name=httpd
root_base=/var/cells/base/11.0_RC4-amd64
autostart=yes
profile=medium
reserved_ports=8080
local_dev=yes
log_facility=local1
log_stdout_level=info
log_stderr_level=err
log_tag=cell-httpd
command=/usr/libexec/httpd -I 8080 -X -f -s /var/www/httpd
mount=/var/www/httpd /var/www/httpd rw
require=NETWORKING
before=SERVERS
```

Prepare host payload:

```sh
doas mkdir -p /var/www/httpd
doas cp /usr/share/examples/cellman/httpd/assets/index.html /var/www/httpd/index.html
```

Then:

```sh
celladm validate
doas celladm generate
doas service cell_httpd start
```

## 8) Troubleshooting

### `root_base:not found`

`root_base` points to the wrong release/arch path.

Check:

```sh
ls /var/cells/base
```

Fix `root_base` or rerun `celladm bootstrap` with matching defaults.

### `secmodel_cell not available`

Check:

```sh
modstat | grep secmodel_cell
cellctl list
```

If the module is present but `cellctl list` fails, verify kernel/runtime compatibility.

### Start failure around `/dev/pts`

With `local_dev=yes`, `/dev` is mounted as tmpfs and then `/dev/pts` is mounted.
Retry stop/start and inspect mounts if state is inconsistent.

### `service cell_<name> stop` appears ineffective

The stop path first terminates matching `cellctl supervise` monitor processes and then unmounts.
If leftovers remain, inspect `cellctl list` and `mount` output.

## 9) Production checklist

- Pin `release` and `machine_arch` in `defaults.conf`.
- Set `root_base` explicitly and verify after bootstrap.
- Run `celladm validate` before every `generate`.
- Operate cells via `service cell_<name>` only.
- Include both `cellctl list` and `celladm list` in runbooks.
