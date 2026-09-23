# Deploying CryptoMon

Everything in this directory exists to move CryptoMon from "a thing you run
in a terminal on the machine you are sitting at" to "a service other people
can reach". That is a change of threat model, not a change of convenience,
and the files here are written as security artifacts.

```
deploy/nginx/cryptomon.conf            the server blocks, TLS, rate limits
deploy/nginx/proxy-to-cryptomon.conf   the proxy settings, included per location
deploy/nginx/security-headers.conf     response headers, and why each one
deploy/systemd/cryptomon-api.service   the HTTP service, no privilege at all
deploy/systemd/cryptomon-sensor.service the eBPF sensor, the privileged half
deploy/systemd/api.env.example         configuration and secrets for the API
deploy/systemd/sensor.env.example      configuration and secrets for the sensor
../create-service.sh                   installs all of the above
```

## The short version

```bash
sudo ./create-service.sh --nginx
sudo $EDITOR /etc/cryptomon/api.env          # DB_URL, API_KEY, ROOT_PATH
sudo $EDITOR /etc/cryptomon/sensor.env       # DB_URL, CRYPTOMON_IFACE
sudo $EDITOR /etc/nginx/conf.d/cryptomon.conf   # server_name, certificates
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl enable --now cryptomon-api cryptomon-sensor
```

Nothing starts until you have filled those files in. That is deliberate: the
script this replaces installed a unit containing a literal `<password>`
placeholder and started it, so the service failed on every boot until
somebody hand-edited a root-owned file.

## The subpath

CryptoMon can be served at `https://host/cryptomon/` rather than at a domain
root. Two values make that work and **they must agree**:

| where | what |
|---|---|
| `/etc/cryptomon/api.env` | `ROOT_PATH=/cryptomon` |
| `/etc/nginx/conf.d/cryptomon.conf` | `location /cryptomon/`, marked `PREFIX` |

Set `ROOT_PATH=` (empty) and `location /` to serve at the root.

They have to agree because the application generates absolute URLs and
nothing on the wire tells it where it lives. `fapi/app/uploads.py` redirects
to `request.url_for('report', ...)` after an upload; `upload.html` posts to
`action=""`; FastAPI composes the `openapi.json` URL that `/docs` fetches.

### Why not `X-Forwarded-Prefix`?

Because uvicorn does not read it. uvicorn 0.30's
`ProxyHeadersMiddleware` handles `X-Forwarded-For` and `X-Forwarded-Proto`
and has no notion of a prefix at all — grep
`uvicorn/middleware/proxy_headers.py` and there is nothing else in the file.
The nginx config sends the header anyway, for whatever ends up in front of
this later, but on this stack it is inert. Any guide that tells you to set
`X-Forwarded-Prefix` and stop there is describing a different server.

Writing our own middleware to read it would make the prefix
attacker-controlled by anything that can reach uvicorn directly: the header
would then steer the post-upload `Location`, the OpenAPI `servers` entry and
every generated link. That is a URL-forgery primitive in exchange for saving
one line of configuration.

### Why not `uvicorn --root-path`?

Two reasons.

**It is not available to the documented entry point.** `api.py` calls
`uvicorn.run()` programmatically and reads `HOST` and `PORT` from
`fapi/config`. Running the `uvicorn` CLI instead would mean the address and
port are configured in two places.

**It needs the opposite nginx config, and fails more quietly.** The two
mechanisms are not interchangeable:

- `FastAPI(root_path=...)` sets `scope["root_path"]` and leaves
  `scope["path"]` alone. Starlette removes the prefix before routing with
  `re.sub(r"^" + root_path, "", path)`, which does nothing when the prefix is
  not there — so this works whether nginx passes the URI through or strips
  the prefix first.
- `uvicorn --root-path` **prepends** the value to the path it received
  (`full_path = self.root_path + path` in
  `uvicorn/protocols/http/h11_impl.py`). It only lands correctly if nginx has
  already stripped the prefix. Point it at an nginx that passes the URI
  through and you get `/cryptomon/cryptomon/analyse/`.

**Do not set both.** With the shipped nginx config, `--root-path` on top of
`ROOT_PATH` doubles the path and every page 404s.

Measured, on this repository, with a real uvicorn:

| arrangement | `GET /cryptomon/analyse/` | `POST`, `Location:` |
|---|---|---|
| `ROOT_PATH=/cryptomon`, nginx passes through | 200 | `https://host/cryptomon/analyse/reports/<id>` |
| `ROOT_PATH=` unset, nginx passes through | **404** | — |
| `ROOT_PATH=` unset, nginx strips | 200 | `https://host/analyse/reports/<id>` — **wrong, silently** |

The shipped config does not strip, which makes the middle row the failure
you get when you forget: a 404 on the first page you open, rather than a site
where every page renders and only the links are one level out. A
configuration that is wrong should break where it is wrong.

One consequence worth knowing: because the strip is a no-op when the prefix
is absent, an app running with `ROOT_PATH=/cryptomon` still answers
`/analyse/` on its own loopback socket. That is not extra exposure — uvicorn
binds `127.0.0.1` and nginx forwards only the prefixed location — but
`/analyse/` answering is not evidence that `ROOT_PATH` is unset.

## Proxy headers

None of the `X-Forwarded-*` headers nginx sets have any effect unless uvicorn
trusts the connection. It runs with `--proxy-headers` by default through
`uvicorn.run()`, and trusts `127.0.0.1` only. If nginx is on another host,
set `FORWARDED_ALLOW_IPS` to its address in `api.env`.

**There is no warning when this is wrong.** The headers are simply discarded:
every client appears to be the proxy in the logs, and the redirect after an
upload comes back `http://` on an `https` site.

Note also that Starlette builds `request.base_url` — and so every absolute
URL from `url_for` — from the **`Host`** header, not `X-Forwarded-Host`. The
config passes `Host $host` unchanged for that reason.

## Numbers that have to stay in step

| nginx | application | what happens when they disagree |
|---|---|---|
| `client_max_body_size 257m` | `MAX_UPLOAD_BYTES=268435456` | nginx rejects a legal upload with its own unstyled HTML 413, and the app's message — which names the limit and suggests `editcap -c` — never runs |
| `proxy_read_timeout 300s` | `ANALYSIS_TIMEOUT_SECONDS=120` | nginx answers 504 for an analysis that finished; the report exists, the user is told it failed, and the retry costs another subprocess |

`client_max_body_size` is deliberately **larger** than `MAX_UPLOAD_BYTES`,
not equal to it: nginx counts the whole multipart body and the application
counts only the file, so at exactly the limit the two disagree by a few
hundred bytes in the direction that shows the user the wrong error page.

`tests/test_deployment.py` reads both numbers out of `fapi.config.settings`
and parses the nginx files, so changing a default in `fapi/config` fails the
test suite rather than a deployment.

## systemd

### Two units, not one

The old `cryptomon.service` ran the eBPF sensor and the HTTP API in one
process tree, as root. The sensor needs `CAP_BPF`, `CAP_PERFMON` and
`CAP_NET_ADMIN` to load and attach a BPF program; the API needs no capability
at all. Splitting them means the half that accepts uploads from the network
is the half with an empty `CapabilityBoundingSet`, and cannot open so much as
a raw socket — `RestrictAddressFamilies` denies `AF_PACKET` and `AF_NETLINK`
on the API unit and permits them only on the sensor.

### Secrets

`Environment=` writes its value into the unit file, which is `0644` under
`/etc/systemd/system` and is printed by `systemctl show` and `systemctl cat`
to any user who asks. `EnvironmentFile=` is read by PID 1 **before** the drop
to `User=`, so:

```
/etc/cryptomon/api.env      0600 root:root
/etc/cryptomon/sensor.env   0600 root:root
```

works, and the service account cannot open the file it was configured from.

Be honest about what this does not fix: the value still lands in the process
environment, and root can read it out of `/proc/<pid>/environ`. It is kept
out of `ps`, out of the unit, and out of `systemctl`, which is where it was
leaking. A password that must never appear in a process environment needs
systemd's `LoadCredential=` plus an application that reads a credential file,
which `fapi/config` does not do today.

The API and the sensor get **separate** files. The sensor needs the database
credential and nothing else; a process holding `CAP_BPF` has no business
holding the key that guards the HTTP side. Give the sensor its own MongoDB
user, too.

#### `config-secrets.sh`

The repository root still has `config-secrets.sh`, which is:

```bash
export DEBUG_MODE=True
export DB_URL="mongodb+srv://<user>:<Password>@<uri>/cryptomon?..."
export DB_NAME="cryptomon"
```

It does not conflict with the `EnvironmentFile` approach because it does not
interact with it at all — **a variable exported in your shell does not reach
a systemd unit.** They are for two different things: `config-secrets.sh` is
for running `python3 ./api.py` by hand, and `/etc/cryptomon/api.env` is for
the service.

It is worth knowing what it costs, though. Sourcing it puts the password into
your shell's environment, which every process you start from that shell
inherits, and if you type it rather than source it, into your shell history.
`start_cryptomon.sh` is better in that respect — it prompts with `read -sp` —
but then exports the result the same way. Neither is wrong for interactive
use; neither should be how a service gets its credentials.

Also note `DEBUG_MODE=True` in that file: `api.py` passes it to uvicorn as
`reload=`, which starts a file watcher. Fine locally, not what you want on a
host behind nginx. `api.env.example` sets `DEBUG_MODE=false`.

### `PrivateTmp` and `UPLOAD_DIR`

`UPLOAD_DIR` defaults to `/tmp/cryptomon-uploads`. The API unit sets
`PrivateTmp=yes`, which gives the service a `/tmp` in a mount namespace that
is **destroyed when the service stops**. Left at the default, that means:

- every report disappears on restart, while the upload form goes on telling
  the user they are kept for `REPORT_RETENTION_HOURS`;
- `ls /tmp/cryptomon-uploads` from a shell shows nothing, which reads as a
  broken feature rather than as a namespace.

The answer is **not** to turn `PrivateTmp` off — a report holds SNI, which is
browsing history, and `/tmp` is world-writable. `api.env.example` sets

```
UPLOAD_DIR=/var/lib/cryptomon/uploads
```

and the unit's `StateDirectory=cryptomon` creates and owns
`/var/lib/cryptomon` at `0700` on every start. That also satisfies
`ProtectSystem=strict`, under which anything not explicitly made writable
returns `EROFS` — which would surface as a 500 on the first upload, not as a
startup failure.

If you point `UPLOAD_DIR` somewhere else, add a `ReadWritePaths=` line. And
do not use a `~` path: `fapi/app/uploads.py` calls `expanduser()` on it and
`ProtectHome=yes` makes `/home` invisible.

### The one hardening line that would break things

`SystemCallFilter=~@resources` appears in nearly every systemd hardening
guide. **Do not add it to the API unit.**

`pcapscan/sandbox.py` bounds each analysis by having the worker call
`setrlimit()` on itself — `RLIMIT_AS` and `RLIMIT_CPU` — rather than through
`preexec_fn`, for the threading reason documented at the top of that file.
`setrlimit` and `prlimit64` are both in `@resources`. And
`pcapscan.sandbox.apply_limits()` is written to survive a limit it cannot
set:

```python
except (ValueError, OSError):
    continue
```

So with `@resources` filtered, `setrlimit` returns `EPERM`, the exception is
swallowed, and every analysis runs with no memory ceiling and no CPU ceiling.
Reports still come out correct. The only symptom is that the protection the
upload path is built on is no longer there.

`tests/test_deployment.py` fails if that directive is added.

The same care applies in the other direction on the sensor unit:
`ProtectKernelTunables=yes` remounts `/sys/kernel/debug` read-only, and bcc
attaches probes by writing to `/sys/kernel/debug/tracing` — so the sensor
would start, stay running and capture nothing. And
`MemoryDenyWriteExecute=yes` would stop bcc compiling BPF C with LLVM in
process. Both are correct on the API unit and wrong on the sensor, which is
why a hardening block should never be copied between two services just
because they share a name.

### `DynamicUser` instead of a fixed account

`DynamicUser=yes` works here and is the more modern choice. It allocates a
uid per start and implies several of the directives the unit sets by hand.
If you prefer it:

```ini
# /etc/systemd/system/cryptomon-api.service.d/dynamic-user.conf
[Service]
User=
Group=
DynamicUser=yes
```

`StateDirectory=cryptomon` still works — systemd keeps the real directory
under `/var/lib/private/` and binds it into the service's namespace, so
reports survive restarts. The reason the shipped unit does not use it is that
a fixed uid is easier to reason about when an operator has pointed
`UPLOAD_DIR` somewhere of their own, and it makes `ls -l` on the report
directory mean something.

### Checking your work

```bash
systemd-analyze verify /etc/systemd/system/cryptomon-api.service
systemd-analyze security cryptomon-api.service
journalctl -u cryptomon-api -f
```

`systemd-analyze verify` catches a misspelt directive, which systemd
otherwise reports only as a journal warning at first start — while running
the service anyway with that line ignored. A hardening directive that is
silently ignored is worse than one that is absent, because it is in the file
and everybody believes it.

## nginx

### What you must change

`server_name` (two places), `ssl_certificate` and `ssl_certificate_key` — all
marked `REPLACE` — and the subpath if it is not `/cryptomon`, marked
`PREFIX`. Nothing else in the file is site-specific.

Install the two snippets alongside it:

```
/etc/nginx/conf.d/cryptomon.conf
/etc/nginx/cryptomon/proxy-to-cryptomon.conf
/etc/nginx/cryptomon/security-headers.conf
```

`create-service.sh --nginx` does this.

### Rate limiting

One `POST` to the upload route spawns a subprocess that may run for
`ANALYSIS_TIMEOUT_SECONDS` and allocate up to 2 GiB. A `GET` of the same path
renders a template. nginx cannot match on method in `limit_req`, so the
config makes the *key* do it: a `limit_req_zone` whose key evaluates to the
empty string does not count the request, so a `map` on `$request_method`
yields `$binary_remote_addr` for `POST` and `""` for everything else.

Defaults: 6 uploads a minute with a burst of 2, and at most 4 concurrent
uploads per address. Both answer `429`, not nginx's default `503` — a limited
client is being asked to slow down, not told the service is broken, and the
difference decides whether a script backs off or retries immediately.

### Upload buffering

`proxy_request_buffering off`. With nginx's default, a 256 MiB capture is
written to nginx's temp directory in full before nginx opens a connection
upstream, and uvicorn then writes it again to `UPLOAD_DIR` — two copies on
disk for one upload — and the application's mid-stream size check cannot fire
until nginx has already accepted every byte.

What that gives up: nginx cannot retry against another upstream (there is
one), and a slow client holds a uvicorn connection rather than an nginx one
(which is what `limit_conn` is for).

### Logging

The access log format redacts report ids:

```
/cryptomon/analyse/reports/REDACTED
```

A report id is the only credential guarding a report, and a report holds the
server names found in somebody's capture. Logging it verbatim copies that
credential into a file with a different retention policy from the report —
`REPORT_RETENTION_HOURS` sweeps the report after a day while logrotate keeps
the access log for weeks, so the log would outlive the thing it grants access
to.

### Security headers

See the comments in `security-headers.conf`; every header there is justified
by something this application does, and the ones that are deliberately absent
(`X-XSS-Protection`, COOP/COEP, `X-Permitted-Cross-Domain-Policies`) are
listed with the reason.

Two things to know about that file:

- It is `include`d in each `location` rather than set once at server level,
  because **`add_header` does not accumulate across nesting levels in
  nginx**. A `location` that adds one header of its own silently drops every
  header inherited from the `server` block, so a config that sets HSTS at
  server level and `Cache-Control` inside the upload location serves the
  report page with no security headers at all, and nothing reports an error.
- The CSP allows `style-src 'unsafe-inline'` because `base.html` carries its
  stylesheet in an inline `<style>` block. That is a real weakening. The fix
  is to serve the stylesheet as a file; until somebody does, the comment in
  that file says so rather than pretending otherwise.

## What was verified, and how

The nginx config in this directory has been run: nginx 1.27 in a container,
in front of a real uvicorn serving this application with
`ROOT_PATH=/cryptomon`, with only the substitutions this README tells an
operator to make (`server_name`, the two certificate paths, the upstream
address).

| check | result |
|---|---|
| `GET /cryptomon/analyse/` | 200, form renders, `action=""` |
| `POST /cryptomon/analyse/` | 303, `Location: https://host/cryptomon/analyse/reports/<32 hex>` |
| following that redirect | 200; `/json` 200 |
| `GET /cryptomon/docs` | 200, and the page fetches `/cryptomon/openapi.json` |
| `openapi.json` `servers` | `[{"url": "/cryptomon"}]` |
| `/cryptomon/redoc`, `/cryptomon/data/` | 200 — routes the config never names |
| `GET /cryptomon` | 308 to `/cryptomon/` |
| `GET /` , `/wp-admin` | connection closed, no response (444) |
| `http://…/cryptomon/analyse/` | 308 to `https://` |
| 2 MiB POST to `/cryptomon/data/` | **413 from nginx** (server limit 1m) |
| 2 MiB POST to `/cryptomon/analyse/` | **422 from the application** — the body reached it |
| 8 rapid POSTs | `200 200 200 429 429 429 429 429` |
| 8 rapid GETs of the same path | `200` × 8 — the method-keyed limit works |
| access log | `GET /cryptomon/analyse/reports/REDACTED` |
| TLS | TLS 1.3, `TLS_AES_256_GCM_SHA384`, X25519; TLS 1.1 refused |

Two things that did not work first time, both now documented where they
matter:

**`$host` drops the port.** Served on `:18443` for the test, the
post-upload `Location` came back as `https://cryptomon.example.org/…` with
no port, because `$host` is the Host header with the port stripped. Correct
for a deployment on 443 and wrong for any other port; see the comment on the
`Host` header in `proxy-to-cryptomon.conf`.

**`FORWARDED_ALLOW_IPS` fails silently.** With every header set correctly
and only that variable naming an address the proxy does not connect from,
the redirect came back as `http://` on an https site and uvicorn logged
every client as the proxy. No error, no warning, in either log. This is the
most likely thing to get wrong when nginx is not on the API's loopback.

## What has not been verified

Written and tested on macOS. The `root_path` behaviour, the URL generation
and the numeric agreements between nginx and `fapi/config` were all exercised
against a real uvicorn and are covered by `tests/test_deployment.py`.

**The systemd units have not been run.** `systemd-analyze verify` was not
available without fetching a package, so it has not been run against them
either — `create-service.sh` runs it at install time, which is where it will
first happen. They have been checked for syntax
and their directives are individually documented, but no `systemctl start`
has happened and `systemd-analyze verify` has not been run against them on
this machine. The sensor's `SystemCallFilter` in particular is the line most
likely to need adjusting for your kernel and bcc version: if the sensor dies
at startup with an unexpected `EPERM`, set `SystemCallLog=@privileged`
temporarily and read `journalctl -u cryptomon-sensor` to see which call it
wants.
