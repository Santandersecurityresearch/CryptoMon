# Troubleshooting

Everything here is a failure this project has actually hit, recorded in a
commit message, a module docstring or a code comment. Symptoms are quoted as
they appear.

**Contents**

* [Installing and starting](#installing-and-starting)
* [The sensor sees nothing](#the-sensor-sees-nothing)
* [The offline analyser](#the-offline-analyser)
* [The API and the dashboard](#the-api-and-the-dashboard)
* [Uploads](#uploads)
* [Behind nginx](#behind-nginx)
* [Numbers that look wrong but are not](#numbers-that-look-wrong-but-are-not)

---

## Installing and starting

### bcc will not install, or will not compile (issue #26)

The most common way to get stuck with this project, and it has several
distinct shapes.

```
Exception: bcc is not available, so the live monitor cannot start. It is
Linux-only and comes from your distribution rather than pip: run
ubuntu-setup.sh, or `apt-get install bpfcc-tools python3-bpfcc`. Parsing a
capture offline does not need it.
```

**First: you may not need it.** bcc exists only to load the kernel filter. If
what you have is a capture file, `python -m pcapscan capture.pcap` answers
the same question, reads more of the handshake than the live sensor could
have, and needs no root, no kernel and no bcc. If what you have is a network,
read on.

**`pip install bcc` does not work and does not fail loudly.** There is a
package on PyPI called `bcc`; it is unrelated. The eBPF bindings come from
the distribution and are called `python3-bpfcc`, pulled in by `bpfcc-tools`.
This project's own `bom.json` records the PyPI name, which is a known defect
in that file.

```bash
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-generic
```

**`Unable to find kernel headers.`** bcc compiles the program against the
headers of whatever kernel it finds, at load time. Install the headers for
the kernel that is actually running:

```bash
uname -r                                        # what is running
ls /lib/modules/$(uname -r)/build               # headers, if present
sudo apt-get install -y linux-headers-$(uname -r)
```

In a container `uname -r` is the *host's* kernel and no such package exists,
which is why the project's own images install `linux-headers-generic`
instead. `ubuntu-setup.sh` uses the `$(uname -r)` form, so that line is the
one that fails inside a container.

**Errors from inside `include/linux/bpf.h`.** Not your program:

```
kernel 6.17.0-1022-azure, headers /lib/modules/6.17.0-1022-azure/build
include/linux/bpf.h:384:  invalid application of 'sizeof' to an incomplete
                          type 'struct bpf_wq'
include/linux/bpf.h:1036: use of undeclared identifier 'BPF_LOAD_ACQ'
```

This is a bcc that is *older than the running kernel* and cannot parse its
headers. It is what happens on a machine whose kernel is newer than its
distribution's `python3-bpfcc` — a GitHub runner, for instance, which is
where this project first hit it. The answer is to pin the environment, not
to weaken the program: run the sensor in a container built from a fixed base
image with `linux-headers-generic`, which is what
[`docker/Dockerfile.sensor`](../docker/Dockerfile.sensor) does.

**Find out in one command whether eBPF works here at all:**

```bash
docker build -f docker/Dockerfile.sensor -t cryptomon-sensor .
docker run --rm --cap-add BPF cryptomon-sensor
```

```
OK    compiles
OK    verifies as SOCKET_FILTER (fd=5)
OK    verifies as SCHED_CLS (fd=5)
```

That is the image's default command. It compiles the filter and puts it past
the verifier in both attach modes, touching no interface and no database. If
it prints those three lines, the kernel half of CryptoMon works on this host
and anything still wrong is configuration. If it does not, the output says
which of the three steps failed.

> Not verified on this machine — quoted from `docker/README.md`.

### `ubuntu-setup.sh` printed errors and exited 0

It has no `set -e`. Several lines fail on Ubuntu 24.04 and are passed over in
silence — a kernel-specific `linux-tools` package pinned to 5.15, three
`-12`-suffixed LLVM packages, and the `snap install bpftrace` line that
carries a `# TODO - find out why this doesn't work` comment in the source.
None of those three is needed. What matters is that `bpfcc-tools` and the
kernel headers installed. See
[install.md](install.md#ubuntu-setupsh-honestly) for the line-by-line
reading.

It also does not install `uvicorn`, `jinja2`, `python-multipart` or
`cryptography`, so `python api.py` will not start after it alone. Follow it
with `pip install -r requirements.txt`.

### `error: externally-managed-environment`

Recent distributions refuse `pip install` into the system Python (PEP 668).
Use a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### `ValidationError: DB_URL Field required`

```
pydantic_core._pydantic_core.ValidationError: 2 validation errors for Settings
DB_URL
  Field required [type=missing, ...]
DB_NAME
  Field required [type=missing, ...]
```

`DB_URL` and `DB_NAME` have no defaults and are validated at import, so
anything that imports `fapi.config` needs them — including `cryptomon.py`,
which needs them for real, and including commands that will never touch the
database. Export both. There is no `.env` file support; see
[configuration.md](configuration.md).

### `ModuleNotFoundError: No module named 'cryptomon'` when running tests

Run `python -m pytest`, not `pytest`. `python -m pytest` puts the working
directory on `sys.path`; the console script does not. `pytest.ini` sets
`pythonpath = .` to cover both, so if you are seeing this, check you are in
the repository root.

---

## The sensor sees nothing

The sensor starts, prints nothing alarming, and the collection does not grow.
This looks the same as a quiet network, which is why several of the causes
below have explicit counters.

### The unit dies on every start with an `EOFError`

`CRYPTOMON_IFACE` is unset or empty. `cryptomon.py` falls back to prompting
with `input()`, and under systemd there is no terminal. The traceback says
nothing about a missing interface. `ip -br link` will tell you the name.

### The program loaded and attached, and nothing arrives

The usual cause under Docker or a restricted capability set is **`CAP_BPF` +
`CAP_NET_RAW` without `CAP_PERFMON`**. The program loads, it attaches, and
the perf ring buffer that carries frames to userspace is never opened —
indistinguishable from an idle interface. The measured table:

| granted | what happens |
|---|---|
| nothing added | `could not open bpf map: skb_events, error: Operation not permitted` |
| `BPF` | the self-check passes; not enough to run |
| `BPF` + `NET_RAW` | `Exception: Could not open perf buffer` |
| `BPF` + `PERFMON` | `Failed to open raw device b'lo': Operation not permitted` |
| `BPF` + `PERFMON` + `NET_RAW` | works |

> Not verified on this machine — measured in `docker/README.md`.

Also check `--network host`. Without it a container watches its own veth pair
and reports a very quiet network.

### The traffic is on a port the filter does not watch

The kernel filter watches `TLS_PORTS` (`443,990,3389,8080,8443`) and
`SSH_PORTS` (`22`). Anything else is invisible to it — not dropped later,
never copied to userspace at all. `TLS_PORTS=443,8443,9443` and restart. A
typo is a startup failure rather than a silent fallback, on purpose:

```
ValueError: TLS_PORTS: 'https' is not a port number
```

The offline analyser has no port filter, so a quick way to find out whether
you are watching the wrong ports is to take a `tcpdump` and run
`python -m pcapscan` over it.

### Records are being dropped under load

At most 1000 inserts may be in flight; past that new records are dropped and
counted. Check `cryptomon.WRITE_STATS`:

| Counter | Means |
|---|---|
| `inserted` | Writes that completed. |
| `failed`, `failed_<ExceptionName>` | Writes that raised. The first of each kind is printed once to stderr. |
| `dropped_backpressure` | Records discarded because 1000 inserts were already outstanding. |

A `failed_OperationFailure` here is usually a MongoDB authentication problem,
which will otherwise be entirely silent — the write future used to be
discarded along with every error in it.

### It sees the handshake but reports a partial one

That is not a fault; it is the single-frame constraint. See
[architecture.md](architecture.md). If you need whole ClientHellos and whole
certificate chains, capture with `tcpdump` and run `pcapscan` over the file.

---

## The offline analyser

### The report has no certificates in it

The whole "Certificate keys" section is **absent**, and nothing says why:

```
Sessions                1
  tls                   1

Key exchange
  performed             1
  …

TLS versions
  TLSv1.2               1
```

`cryptography` is not installed. `pcapscan` treats X.509 parsing as optional
and correctly carries the raw DER onward instead — the record gets
`tls.certificates_der` rather than `tls.certificates` — so nothing errors and
the summary has nothing to count. This is the worst kind of failure
because it is plausible: a CBOM with an empty certificate section does not
read as incomplete, it reads as an estate with no certificate keys.

```bash
python -c "import cryptography; print(cryptography.__version__)"
pip install cryptography
```

The project pins `cryptography>=44.0.2,<45`; the CBOM exporter needs the
`not_valid_*_utc` accessors and `public_key_algorithm_oid` that 44.x has.

The same thing happens in the container if you build with
`--build-arg CERTIFICATES=0`, which is offered precisely so that the 13MB
saving is a choice made by somebody who knows what it costs.

On the **live** path the equivalent is `jc`, which `cryptomon.utils`
uses for its certificate guessing. That one does say so:

```
[!] jc is not installed, so certificates cannot be parsed. Install it with
`pip install jc`.
```

### `unrecognised capture magic`

```
pcapscan: capture.pcap: unrecognised capture magic b'hell'; expected pcap or
pcapng
```

The file is not a capture. Check you did not save a text log with a `.pcap`
name, or truncate a download. Gzip is detected from the magic bytes rather
than the extension, so a gzipped capture with any name works and a `.gz` that
is not gzipped is read as whatever it is.

Given several captures, one unreadable file does not lose the others — the
run continues and exits 1.

### The same captures give different session counts

Analysing twelve captures in one command and analysing them one at a time
give different totals — the per-file total is always the larger — because
several captures are given to one session builder and finished once at the
end. A flow that spans two files is one session in the first case and two
partial ones in the second. That is deliberate: `tcpdump -C` rotates a
capture mid-connection, and finishing after each file would report the two
halves of one handshake as two incomplete sessions.

### `evicted` is large in `--stats`

More simultaneous connections than `--max-flows` (2048). Raise it if you care
about completeness on a busy capture.

---

## The API and the dashboard

### `403 This deployment is read-only`

```json
{"detail": "This deployment is read-only. Set READ_ONLY=false to enable
writes, and set API_KEY as well if the service is reachable from anywhere
but localhost."}
```

Working as designed. `READ_ONLY` defaults to **true**, so an operator opts in
to writes rather than remembering to opt out. Reads are always open.

Before you turn it off, check that you need it: the sensor writes to MongoDB
directly and does not use this API, and `mongoimport` does not either. The
`/data` write routes exist for a client that genuinely posts records over
HTTP, which most deployments do not have.

### Setting `CRYPTOMON_READ_ONLY` changed nothing

The variable names carry **no prefix**. It is `READ_ONLY`, `API_KEY`,
`HOST`, `DB_URL`. A `CRYPTOMON_`-prefixed variable is not read at all:

```console
$ CRYPTOMON_READ_ONLY=false python -c 'from fapi.config import settings; print(settings.READ_ONLY)'
True
$ READ_ONLY=false python -c 'from fapi.config import settings; print(settings.READ_ONLY)'
False
```

This was once wrong in this project's own error message, which named
`CRYPTOMON_READ_ONLY` and `CRYPTOMON_API_KEY` — so an operator following it
exactly would have set two variables that do nothing and concluded the guard
could not be turned off. If you read that instruction anywhere, it is stale.

A `.env` file is not read either. See
[configuration.md](configuration.md#the-variable-names-carry-no-prefix).

### The dashboard is empty

```
No data in this window
Nothing matched the last 24 hours.
The collection itself is not empty: it runs from 2023-06-26 09:25 to
2024-12-11 22:16. Nothing in it falls inside the window above.
Widen the window to cover all of it.
```

The window defaults to 24 hours, and an imported capture carries the
timestamps it was recorded with — which for most captures is not today. The
page says what the collection actually spans and offers a link that widens
the window; that link is `?hours=0`, all of time.

If it says the collection *is* empty, check `DB_NAME`, and check the
collection name: it is always `cryptomon` inside whatever database `DB_NAME`
names, and `mongoimport --collection cryptomon` has to match.

### `mongoimport` said it worked and the dashboard shows nothing

`mongoimport` defaults to `localhost:27017` and to the database `test`. Name
the database:

```bash
python -m pcapscan capture.pcap -f ndjson -q \
  | mongoimport --uri "mongodb://127.0.0.1:27017/cryptomon" --collection cryptomon
```

### The capture-tag filter is empty

Nothing in the shipped pipeline writes a `tag`. It comes from the live
sensor's `data_tag` constructor argument, and `cryptomon.py` passes an empty
string. Add it during import — see
[offline-analysis.md](offline-analysis.md#ndjson-and-the-point-of-it).

### One panel shows an error card

Panels are gathered with `return_exceptions=True` so that one failure does
not blank the page. The card names the panel. Check the API's log: the
usual causes are a pipeline that needs an index that is missing, or a
`MemoryError` from MongoDB because `allowDiskUse` is deliberately off —
a pipeline on this collection that needs 100MB of scratch is a pipeline that
should have had an index, and the error is the signal.

### `503 The stats aggregations are not installed on this deployment`

`fapi/app/stats.py` is missing. The dashboard imports it *inside* the request
handler so that a deployment without it answers a 503 page saying so rather
than failing to start.

### A query parameter was rejected

```
{"detail":"hours must be between 0 and 8760; 0 means all of time."}
{"detail":"limit must be between 1 and 200."}
{"detail":"bucket must be one of day, hour, minute."}
```

Refused rather than clamped, on purpose. A query parameter must not be able
to choose how much work the server does.

### `'$where' is not a queryable field`

The count endpoints accept equality on a known field only — no operators, no
nested documents, no arrays. Both forms used to hand caller-supplied JSON
straight to `count_documents()`, which made `$where` and `$regex` reachable
by anybody who could reach the endpoint. The error names the allowed fields.

---

## Uploads

### `413 The capture exceeds the N-byte limit`

```json
{"detail": "The capture exceeds the 268435456-byte limit. Split it with
`editcap -c`, or raise MAX_UPLOAD_BYTES."}
```

The application's own message, which means the request reached it. Either
split the capture or raise `MAX_UPLOAD_BYTES` — **and raise
`client_max_body_size` in nginx with it.**

### A 413 that is not that message

An unstyled `<html><head><title>413 Request Entity Too Large</title>` page is
**nginx's**, not the application's, and it means `client_max_body_size` is
smaller than `MAX_UPLOAD_BYTES`. nginx refuses the request before the
application ever sees it, and the careful mid-stream check — which counts
bytes as they arrive and removes the partial file the moment the cap is
passed — never runs.

The two must be kept in step, with nginx **strictly greater**:

| | |
|---|---|
| `MAX_UPLOAD_BYTES` | 268435456 (256 MiB) |
| `client_max_body_size` on `location = /analyse/` | `257m` |

Strictly greater and not equal, because nginx measures the whole request body
— multipart boundaries, part headers, the `as_json` field — while the
application measures only the file. At exactly 256 MiB of capture the two
disagree by a few hundred bytes, in the direction that gives the user the
wrong error page. `tests/test_deployment.py` fails if they drift.

### `504 Gateway Time-out` on a capture that finished

`proxy_read_timeout` in nginx is shorter than `ANALYSIS_TIMEOUT_SECONDS`, so
nginx gives up on work the service completed. The shipped config sets
`proxy_read_timeout 300s` against a default `ANALYSIS_TIMEOUT_SECONDS` of
120. Raise one and check the other.

### `401 A valid X-API-Key header is required to upload`

`API_KEY` is set, and the browser form cannot send a header. This is a real
consequence rather than a bug, and the form says so where the file picker
would be: *"This deployment requires an X-API-Key header, so uploads have to
come from a client that can set one — curl rather than this form."*

```bash
curl -s -X POST http://127.0.0.1:8000/analyse/ \
     -H "X-API-Key: $API_KEY" \
     -F "capture=@capture.pcap" -F "as_json=true"
```

Decide which you want: a key, or a usable form. Note that uploads are
deliberately *not* governed by `READ_ONLY` — an upload writes no document, so
refusing it because the database is read-only would answer a different
question.

### `422` with `reason: timeout` or `reason: memory`

The sandbox killed the analysis. The hints in the response say what to do:
`editcap -r` for a smaller slice on a timeout, split the capture on memory. A
capture with very many distinct connections is the usual cause of the latter,
because session records are held until the run finishes.

### `403 Capture upload is disabled`

`UPLOADS_ENABLED=false`.

### Reports vanish on every restart

`UPLOAD_DIR` is under `/tmp` and the service has `PrivateTmp=yes`, which puts
`/tmp` in a namespace destroyed when the service stops. The form goes on
promising the report is kept for `REPORT_RETENTION_HOURS` while it is being
deleted on every restart. Set `UPLOAD_DIR=/var/lib/cryptomon/uploads`, which
`cryptomon-api.service` creates with `StateDirectory=`.

### A report 404s that used to work

Reports are swept after `REPORT_RETENTION_HOURS` (24 by default), and the
404 says so: *"No such report. Reports are not kept indefinitely."* Set it to
`0` to keep them, knowing that a report holds the SNI of every connection in
the capture.

---

## Behind nginx

[deploy/README.md](../deploy/README.md) is the reference. The three that
account for most of it:

### 404 on the first page after setting a subpath

`ROOT_PATH` and the nginx `location` prefix disagree. They are a pair:

| | |
|---|---|
| `/etc/cryptomon/api.env` | `ROOT_PATH=/cryptomon` |
| `/etc/nginx/conf.d/cryptomon.conf` | `location /cryptomon/` |

Empty `ROOT_PATH` and `location /` to serve at the domain root. nginx is
configured to pass the URI *unchanged*, prefix included, so that a forgotten
`ROOT_PATH` fails here, loudly, on the first page — rather than rendering
every page correctly with every generated link one level out, which is the
failure you find days later and mistake for an application bug.

Do **not** also pass `uvicorn --root-path`: that prepends the prefix a second
time. And `X-Forwarded-Prefix` will not help — uvicorn does not read it, on
any version. The header is sent anyway for whatever ends up in front of this
later, and on this stack it is inert.

### Every client appears to be the proxy, and redirects come back as `http://`

`FORWARDED_ALLOW_IPS` does not include nginx's address, so uvicorn discards
`X-Forwarded-For` and `X-Forwarded-Proto` without a warning. The default,
`127.0.0.1`, is right when nginx is on the same host. Do not set it to `*` on
a host where anything else can reach port 8000.

### The service starts and then every analysis is unbounded

Check that no `SystemCallFilter=~@resources` has been added to
`cryptomon-api.service`. It appears in nearly every systemd hardening guide,
and `@resources` contains `setrlimit`, which `pcapscan.sandbox` calls on
*itself* to bound an upload. Filtered, every analysis runs with no memory and
no CPU ceiling, the reports still come out correct, and the only symptom is
that the protection the upload path is built on is gone. A test enforces its
absence.

### The container dies on its first import with `PermissionError`

On `cryptomon/tls_ciphersuites.csv`. `COPY` preserves the source file's mode,
the image runs as an unprivileged uid, and git tracks only the executable
bit — so a file that is mode 0600 in *your* checkout builds an image that
cannot read it, while a fresh clone and CI never reproduce it. Both
Dockerfiles now normalise with `chmod -R a+rX /app`. If you see it, check
`ls -l cryptomon/tls_ciphersuites.csv` in your working tree.

---

## Numbers that look wrong but are not

### "Certificates: unreadable (TLS 1.3) 336 sessions"

Correct, and it will grow. A TLS 1.3 certificate travels inside the encrypted
handshake flight and a passive observer cannot read it. CryptoMon says
"unreadable" rather than reporting nothing, because "not readable" and "not
sent" are different claims.

### `ech_accepted` is always 0

Not evidence of rejection. A server accepting Encrypted ClientHello in a
ServerHello does not echo the extension at all — the acceptance signal is
eight bytes of `ServerHello.random` derived from the inner transcript, which
cannot be checked without the inner hello. `accepted` is only reachable
through a HelloRetryRequest echo.

### The alerts panel is empty

Not evidence that connections closed cleanly. `close_notify` is sent under
the negotiated keys, and the record walker stops at the first encrypted
record, so every alert this tool can see is by construction one sent *during*
a handshake.

### "Sessions" is much larger than the number of TLS connections

Correct, and worth understanding before you divide by it. `pcapscan` now
emits a record for cleartext UDP flows as well as for TLS and SSH handshakes,
so `Sessions` at the top of the summary — and `readiness['sessions']` in the
JSON — counts all of them. Over the project corpus that is 2404 records, of
which 1346 are TLS and 1058 are DNS, NTP, mDNS, NetBIOS and the like.

The key-exchange figures beside it are TLS-only, so they do not sum to it:

```
hybrid 116 + classical 508 + no_key_exchange 722 = 1346   (TLS sessions)
readiness['sessions']                            = 2404   (all records)
```

Use `protocols['tls']`, or the per-protocol breakdown printed under
`Sessions`, as the "all sessions" base. See
[reading-a-report.md](reading-a-report.md#one-base-you-should-not-use-readinesssessions).

### The quantum-safe percentage changed and no traffic did

Check which denominator you are reading. `18.6% of 624 key exchanges
performed` and `8.6% of 1346 TLS sessions` are the same 116 hybrid exchanges,
and `readiness['sessions']` is a third base again — it counts UDP records
too. See
[reading-a-report.md](reading-a-report.md#first-a-percentage-without-its-base-means-nothing).

### A ciphersuite is classified `symmetric`

`TLS_AES_256_GCM_SHA384` names no asymmetric primitive, because in TLS 1.3
the key exchange moved out of the suite and into an extension. It is counted
separately, under `kex_group`.

### An algorithm is `unknown`

CryptoMon does not recognise the name. It is never folded into `classical`,
because an unrecognised algorithm is a gap in the classification table rather
than a finding about the traffic. Worth reporting as an issue, with the name.
