# cellweb

`cellweb` is a standalone Go web server for operating NetBSD Cells through
`cellmgr`, inspired by `cellui`.

This directory is intentionally **not** wired into the global NetBSD build.
Use the local `Makefile` only.

## Features

- Login against local users via PAM (NetBSD+cgo build)
- Session-backed authenticated web UI
- Persistent per-session `cellmgr ipc serve --stdio` bridge
- Runs every `cellmgr` command as the authenticated local user
- Cell operations: start, stop, restart, all-variants, `apply --all`
- Storage operations: backup create/restore/delete for volumes and overlays
- System view with NetBSD-native CLI telemetry (FFS filesystems, RAM/swap, interfaces, I/O)
- Live dashboard with 4s refresh cadence

## Build

```sh
cd usr.sbin/cellweb
make build
```

Default output binary: `usr.sbin/cellweb/dist/cellweb-netbsd-amd64`

If you need a host-native binary for local execution/testing:

```sh
make build-host
```

Output binary: `usr.sbin/cellweb/cellweb`

### Cross-build on Linux for NetBSD/amd64

```sh
cd usr.sbin/cellweb
make build-netbsd-amd64
```

Output binary: `usr.sbin/cellweb/dist/cellweb-netbsd-amd64`

This target uses `CGO_ENABLED=0`, so PAM authentication is not available in that
binary. For a PAM-capable cross build, use `make build-netbsd-amd64-cgo` with a
working NetBSD cross C toolchain (configurable via `NETBSD_CC`).

## Run

```sh
./cellweb
```

Default runtime profile:

- TLS: enabled (`-tls=true`)
- HTTPS UI bind: `0.0.0.0:18443` (`-https-listen`)
- HTTP bootstrap/redirect bind: `0.0.0.0:18088` (`-http-listen`)
- PKI dir: `/var/db/cellweb/pki`
- Secure cookies mode: `auto`

First-time trust typically starts from the HTTP bootstrap page URL shown in
startup output (no TLS exception required), then continues on HTTPS.

### Useful flags

- `-tls true|false` (default `true`)
- `-https-listen <ip:port>` (default `0.0.0.0:18443`)
- `-http-listen <ip:port>` (default `0.0.0.0:18088`)
- `-pam-service login` (default from `CELLWEB_PAM_SERVICE` or `login`)
- `-admin-user <name>` + `-admin-pass <password>` (optional startup fallback credentials)
- `-secure-cookies-mode auto|on|off` (default `auto`, use `on` to always force)
- `-command-timeout 35s`

## TLS (self-contained)

`cellweb` can run without a reverse proxy and provide its own local PKI.
TLS mode is now simple and explicit:

- `-tls=true`: HTTPS is enabled.
- `-tls=false`: plain HTTP only (main UI listens on `-http-listen`).

### Modes

- `selfsigned` is selected automatically when `-tls=true` and no `-tls-cert/-tls-key` are provided.
- `manual` is selected automatically when both `-tls-cert` and `-tls-key` are provided.
- `off` is selected automatically when `-tls=false`.

### Plain HTTP mode

```sh
./cellweb -tls=false -http-listen 127.0.0.1:18088
```

In this mode, `-http-listen` is the main UI listener and no HTTPS bootstrap
redirect listener is started.

### Self-signed mode quick start

```sh
./cellweb
```

Equivalent explicit form:

```sh
./cellweb \
  -tls true \
  -https-listen 0.0.0.0:18443 \
  -http-listen 0.0.0.0:18088 \
  -pki-dir /var/db/cellweb/pki \
  -secure-cookies-mode auto
```

Optional helper flags:

- `-tls-san host.example.net,192.0.2.10`
- `-tls-export-ca /tmp/cellweb-root-ca.crt`
- `-http-listen 0.0.0.0:18088`

When TLS is enabled in `selfsigned` mode, the HTTP listener on `-http-listen` serves a
bootstrap page at `/bootstrap` (also reachable via `/`) with:

- short trust instructions,
- a Root CA download button (`/.well-known/ca.crt`),
- and a button to continue to the HTTPS login page.

Other HTTP paths are redirected to HTTPS.

If your browser already cached HSTS for a hostname, use the server IP on the
same HTTP bootstrap port/path to fetch the CA cert.

When `-tls-san` is omitted, `cellweb` automatically adds `<hostname>.local`
(short hostname, without domain) to SANs for mDNS-friendly access.

### Hostname/SAN matching

The URL host must be present in the server certificate SAN list.

Example for `https://vhost.local:18443/`:

```sh
./cellweb \
  -tls true \
  -https-listen 127.0.0.1:18443 \
  -http-listen 127.0.0.1:18088 \
  -pki-dir /var/db/cellweb/pki \
  -tls-san vhost.local,localhost,127.0.0.1
```

If SAN does not match the URL host, browsers show a domain error (for example
Firefox: `SSL_ERROR_BAD_CERT_DOMAIN`).

The generated root certificate subject is:

- Organization: `Petermann Digital`
- Common Name: `NetBSD Cells Appliance Local Root CA`

To verify SAN entries:

```sh
openssl x509 -in /var/db/cellweb/pki/server.crt -noout -ext subjectAltName
```

### First-time browser trust bootstrap

1. Open the HTTP bootstrap URL from startup output.
2. Download the Root CA certificate from the bootstrap page.
3. Compare the downloaded CA fingerprint with the startup fingerprint shown over SSH/console.
4. Import the Root CA into browser/OS trust store.
5. Open/reload `https://<host>:<port>/` and continue without warnings.

Do not trust the downloaded CA without an out-of-band fingerprint check.

In `selfsigned` mode, `cellweb` prints a compact startup bootstrap output to
standard output: Root CA fingerprint + HTTP bootstrap URL.

HSTS is enabled whenever TLS is enabled.

If you only change SANs, `cellweb` can rotate `server.crt` while keeping the same
`ca.crt`, so browser trust usually remains valid.

If PAM is unavailable in the running binary (for example `CGO_ENABLED=0` cross-build),
set startup admin credentials to enable login:

```sh
./cellweb -admin-user root -admin-pass 'strong-secret'
```

Equivalent env vars are also supported:

- `CELLWEB_TLS`
- `CELLWEB_HTTPS_LISTEN`
- `CELLWEB_HTTP_LISTEN`
- `CELLWEB_PKI_DIR`
- `CELLWEB_TLS_CERT`
- `CELLWEB_TLS_KEY`
- `CELLWEB_TLS_SAN`
- `CELLWEB_TLS_EXPORT_CA`
- `CELLWEB_SECURE_COOKIES_MODE`
- `CELLWEB_ADMIN_USER`
- `CELLWEB_ADMIN_PASS`

## Security model

- Authentication uses PAM APIs (no direct passwd file parsing)
- Optional startup admin credentials can be enabled when PAM is unavailable
- Runtime commands are dispatched over `cellmgr` IPC frames (HELLO/CALL/RET/ERR)
- Session cookie is `HttpOnly` + `SameSite=Strict`
- Session `Secure` attribute is managed by `-secure-cookies-mode`
- CSRF token required for state-changing API calls
- Commands are executed without shell interpolation (`execve` argument vector)
- Per-IP login throttling after repeated failures

## Notes

- Interactive `cellmgr cell shell` and `cellmgr cell edit` flows still belong to
  TTY tooling (`cellui`) and are currently marked as non-HTTP actions.
- If `cellweb` is not started as root, switching to another authenticated UID/GID
  for command execution may fail with permission errors.
