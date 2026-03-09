# cellmgr v2 CLI

`cellmgr` exposes a unified resource-oriented CLI for desired and runtime
cell/volume/storage operations.

Each cell uses a writable overlay mounted at `/.overlay` inside the cell root.
Standard writable paths (`/etc`, `/var`, `/tmp`, `/home`, `/root`,
`/usr/pkg`) are symlinked into that overlay.

## Top-level commands

- `cellmgr system bootstrap [--xbase]`
- `cellmgr cell ...`
- `cellmgr volume ...`
- `cellmgr system reset ...`
- `cellmgr apply ...`

Volume backups are written to `/var/backups/cellmgr/volumes` as
`<volume>_YYYYmmddHHMMSS.tar.gz`.
Overlay backups are written to `/var/backups/cellmgr/overlays` as
`<cell>_YYYYmmddHHMMSS.tar.gz`.

## Read model

Read commands are `list`, `show`, and `fields` on `cell` and `volume`.

- Default output: human-readable table
- Machine output: `-T` for TSV
- TSV headers are on by default; use `-H` to suppress headers
- `--view merged|desired|runtime` selects projection scope
- `-o field1,field2,...` selects output fields and order

## Mutation model

Mutations accept `--scope`:

- `desired`: desired state only
- `runtime`: runtime state only
- `both`: desired + runtime effect

Typical examples:

```sh
cellmgr cell create web --cmd '/usr/libexec/httpd -I 8080 -X -f -s /var/www/web' --scope both
cellmgr cell list --view merged
cellmgr cell list --view merged -T -H -o name,cid,procs,cpu1s,age,running,manifest
cellmgr volume create web-data -m 0755 --scope both
cellmgr volume backup create web-data
cellmgr volume backup list web-data
cellmgr volume backup restore web-data --latest --manifest --yes
cellmgr volume backup delete web-data --from web-data_20260313014700.tar.gz --yes
cellmgr cell backup create web
cellmgr cell backup restore web --latest --manifest --yes
cellmgr system reset --scope both --yes
cellmgr apply --dry-run --all
cellmgr apply --all
```

## IPC integration

Long-lived clients can use a persistent control channel via:

```sh
cellmgr ipc serve --stdio
```

and fall back to one-shot commands when unavailable.

Example query used by interactive clients:

```sh
cellmgr cell list --view merged -T -H -o name,cid,refs,procs,root,autostart,create_profile,create_reserved_ports,create_rlimit_nofile,create_rlimit_as,create_rlimit_core,supervise_cmd,cpu1s,cpu10s,memory,age,running,manifest
```
