# Configuration

Everything is configured through environment variables. There is no
configuration file, no `--config` flag and no settings UI.

## The variable names carry no prefix

`READ_ONLY`, not `CRYPTOMON_READ_ONLY`. `API_KEY`, not `CRYPTOMON_API_KEY`.
The field names in `fapi/config/__init__.py` *are* the environment variable
names, and pydantic-settings is configured with no `env_prefix`.

This is worth stating loudly because the project has already made the mistake
once: the error message the API returns for a refused write used to name
`CRYPTOMON_READ_ONLY` and `CRYPTOMON_API_KEY`, neither of which exists. An
operator following it exactly would have set two variables that do nothing,
seen no change, and concluded the guard could not be turned off. The message
was corrected; the lesson is in a comment at the top of `fapi/app/security.py`.

```console
$ export DB_URL=mongodb://127.0.0.1:27017 DB_NAME=cryptomon   # both required

$ CRYPTOMON_READ_ONLY=false python -c 'from fapi.config import settings; print(settings.READ_ONLY)'
True
$ READ_ONLY=false python -c 'from fapi.config import settings; print(settings.READ_ONLY)'
False
```

Two consequences of how pydantic-settings reads them:

* **Names are matched case-insensitively.** `read_only=false` works as well
  as `READ_ONLY=false`. Use the upper-case spelling; it is what every unit
  file and every example in this repository uses.
* **No `.env` file is read.** `Settings` declares no `env_file`, so a `.env`
  sitting next to `api.py` is ignored entirely — verified. The `.env` that
  `docker/env.example` tells you to create is read by *docker compose*, which
  then passes the values into the container's environment, which is a
  different mechanism arriving at the same place. Outside compose, export the
  variables, or put them in a systemd `EnvironmentFile` as
  [`deploy/systemd/api.env.example`](../deploy/systemd/api.env.example) does.

## The API and the dashboard

`DB_URL` and `DB_NAME` are **required and have no default**. Without them
nothing that imports `fapi.config` will start, including `api.py` and
`cryptomon.py`:

```
pydantic_core._pydantic_core.ValidationError: 2 validation errors for Settings
DB_URL
  Field required [type=missing, ...]
DB_NAME
  Field required [type=missing, ...]
```

| Variable | Default | What it does | When to change it |
|---|---|---|---|
| `DB_URL` | *required* | The MongoDB connection string, credentials included. | Always. |
| `DB_NAME` | *required* | The database inside it. The collection is always `cryptomon`. | Always. |
| `HOST` | `127.0.0.1` | The address uvicorn binds. | Only with something in front of it. Setting `0.0.0.0` publishes the API — and the dashboard, whose first panel is a list of server names taken from SNI — on every interface. An earlier release defaulted to `0.0.0.0` with unauthenticated `POST`, `PUT` and `DELETE` on `/data`; that is why the default is what it is. |
| `PORT` | `8000` | The port uvicorn binds. | When 8000 is taken. |
| `ROOT_PATH` | `""` (domain root) | The path prefix this service is mounted under behind a reverse proxy: `/cryptomon` for `https://host/cryptomon/`. | When nginx serves it on a subpath. It **must** equal the `location` prefix in the nginx config; [deploy/README.md](../deploy/README.md#the-subpath) explains why one of the pair alone is not enough. |
| `READ_ONLY` | `true` | Refuses `POST /data/`, `PUT /data/{id}` and `DELETE /data/{id}` with 403. Reads are always open. | Only if something genuinely needs to write records over HTTP. The sensor writes to MongoDB directly and does not use this API, so most deployments never need to change it. |
| `API_KEY` | `""` (off) | When set, mutating routes *and* the upload route require a matching `X-API-Key` header, compared with `secrets.compare_digest`. | Set it before the service is reachable from anywhere but localhost. Note the consequence: the browser upload form cannot send a header, so with a key set uploads have to come from `curl`. The form says so. |
| `UPLOADS_ENABLED` | `true` | The `/analyse/` capture-upload UI. On by default because the service binds loopback, so the thing to opt into is exposure rather than the feature. | Turn it off for a deployment that only ever serves the API and the dashboard. |
| `UPLOAD_DIR` | `/tmp/cryptomon-uploads` | Where captures are spooled and reports kept. Captures are deleted the moment they are analysed; only the report remains. | Under systemd, always. `cryptomon-api.service` sets `PrivateTmp=yes`, so `/tmp` is a namespace destroyed on every restart and reports would vanish while the form went on promising they were kept. The unit's `StateDirectory=` provides `/var/lib/cryptomon/uploads`. |
| `MAX_UPLOAD_BYTES` | `268435456` (256 MiB) | The upload cap, enforced *while the stream is read* — bytes are counted as they arrive and the partial file is removed the moment the cap is passed. | When your captures are bigger. Keep `client_max_body_size` in nginx strictly larger, or nginx refuses the upload with its own unstyled 413 before the application can answer. |
| `ANALYSIS_TIMEOUT_SECONDS` | `120` | Wall-clock ceiling for analysing one capture, passed to `pcapscan.sandbox`. | For very large captures. Keep nginx's `proxy_read_timeout` above it, or nginx answers 504 for work that finished. |
| `REPORT_RETENTION_HOURS` | `24` | How long an uploaded capture's report is kept before the sweep deletes it. `0` keeps them forever. | Shorten it if reports are sensitive; a report holds the SNI of every connection in the capture. The upload form states the value *before* the file is chosen. |
| `RETENTION_SWEEP_MINUTES` | `15` | How often that sweep runs. It runs inside the API process, so a deployment cannot end up serving a form that promises expiry while nothing expires anything. | Rarely. |
| `DATA_RETENTION_HOURS` | `0` (keep everything) | Expiry for the **live MongoDB collection**. When set, it becomes a MongoDB TTL index on `expires_at`, so the server does the deleting whether or not the API is running. | Only deliberately. The default is not an oversight: silently discarding a monitoring database would destroy the historical series this project exists to build. |
| `APP_NAME` | `Cryptomon API` | A label. Nothing depends on it. | Never, in practice. |
| `DEBUG_MODE` | `false` | Passed to uvicorn as `reload=`, which starts a file watcher and restarts the process on change. | Locally, while editing. Never on a host that anybody else can reach. Note that `config-secrets.sh` in the repository root sets `DEBUG_MODE=True`. |

`ROOT_PATH` is validated rather than trusted. starlette strips the prefix
with a regular expression it builds by interpolation and without
`re.escape`, so a value containing `.`, `+` or `(` would silently match paths
it was never meant to. A bad value is a startup failure with a message
instead of a routing bug at run time:

```console
$ ROOT_PATH=/crypto.mon python -c 'import fapi.config'
...
pydantic_core._pydantic_core.ValidationError: 1 validation error for Settings
ROOT_PATH
  Value error, ROOT_PATH must be a plain absolute path such as '/cryptomon':
  a leading slash, no trailing slash, and only letters, digits, underscore
  and hyphen in each segment. Got '/crypto.mon'. [type=value_error, ...]
```

## Which ports the sensor watches

Two more variables, read by `cryptomon/ports.py` and compiled into the eBPF
program. They also carry no prefix, for the same reason.

| Variable | Default | What it does |
|---|---|---|
| `TLS_PORTS` | `443,990,3389,8080,8443` | TCP ports the kernel filter forwards TLS handshakes from. |
| `SSH_PORTS` | `22` | The same, for SSH. |

Comma-separated, 1–65535, at most 64 entries. Unset means the defaults;
setting one to an empty string is an error rather than "watch nothing",
because the generated C needs at least one comparison to be C at all.

```console
$ TLS_PORTS=443,8443,9443 python -c 'from cryptomon.ports import tls_ports; print(tls_ports())'
(443, 8443, 9443)
```

Parsing is deliberately strict, because the failure it prevents is silent: a
sensor watching the wrong ports reports no handshakes, and no handshakes
looks exactly like a quiet network. Every rejection names the variable and
the offending text.

Each of these raises, with the traceback ending in the line shown:

```console
$ TLS_PORTS=443,https python -c 'from cryptomon.ports import tls_ports; tls_ports()'
ValueError: TLS_PORTS: 'https' is not a port number
$ TLS_PORTS=4_43 python -c 'from cryptomon.ports import tls_ports; tls_ports()'
ValueError: TLS_PORTS: '4_43' is not a port number
$ TLS_PORTS=70000 python -c 'from cryptomon.ports import tls_ports; tls_ports()'
ValueError: TLS_PORTS: port 70000 is outside 1-65535
$ TLS_PORTS= python -c 'from cryptomon.ports import tls_ports; tls_ports()'
ValueError: TLS_PORTS: empty. Unset the variable to use the defaults.
```

`4_43` is rejected on purpose: `int()` accepts underscores as digit
separators and non-ASCII digits, so `int('4_43')` is 443 and so is
`int('４４３')`. A port list is operator input that ends up compiled into a
kernel program. It should mean what it looks like or be refused.

**Only 443 is justified by measurement.** Of 1260 sessions across the twelve
corpus captures, 1248 are to port 443 and the other 12 are to ephemeral
ports. Nothing in the corpus touches 990, 3389, 8080, 8443 or 22. The other
defaults are conventions, and 8080 is the weak one — it is conventionally
*plaintext* HTTP, and TLS there is a local habit. It stays because removing a
default changes what existing deployments see, and because the cost is
bounded: the program still requires a record beginning `0x16 0x03 0x0[1-4]`
before it submits anything, so plaintext HTTP on 8080 produces no events. It
is not free, though. On a host with busy 8080 traffic, `TLS_PORTS=443` is now
one variable away.

The offline analyser has **no port filter at all**. It looks at every TCP
stream and decides from the bytes, which is why those 12 ephemeral-port
sessions appear in offline numbers and could never appear in live ones.

## The sensor's interface

`CRYPTOMON_IFACE` is read by systemd, not by Python. The unit interpolates it
into the command line:

```
ExecStart=/opt/cryptomon/.venv/bin/python /opt/cryptomon/cryptomon.py -i ${CRYPTOMON_IFACE}
```

There is no default and no sensible guess. If it is unset or empty,
`cryptomon.py` falls back to prompting with `input()` — and under systemd
there is no terminal, so the unit dies on every start with an `EOFError`
traceback that says nothing about a missing interface. `ip -br link` will
tell you the name.

## uvicorn's own variables

`FORWARDED_ALLOW_IPS` is read by uvicorn, not by `fapi.config`. It decides
which addresses uvicorn will believe `X-Forwarded-For` and `X-Forwarded-Proto`
from; the default, `127.0.0.1`, is right when nginx is on the same host. If
nginx is elsewhere and this is not set, every forwarded header is discarded
without a warning, every client appears to be the proxy, and the redirect
after an upload comes back as `http://` on an `https` site. Do not set it to
`*` on a host where anything else can reach port 8000.

## Where to put these

| | |
|---|---|
| A shell, for a moment | `export DB_URL=…` before `python api.py` |
| systemd | A mode-0600 `EnvironmentFile`. [`deploy/systemd/api.env.example`](../deploy/systemd/api.env.example) and [`sensor.env.example`](../deploy/systemd/sensor.env.example) are annotated line by line, and are the most complete worked configuration in the repository. |
| Docker | `docker/.env`, from `docker/env.example`, read by compose. |

Secrets belong in a file the service account itself cannot open, not in
`Environment=` lines in a unit — those are world-readable through
`systemctl show`. `create-service.sh` and [deploy/README.md](../deploy/README.md)
cover that in detail; the previous version of that script wrote a literal
`<password>` into a unit and started it.
