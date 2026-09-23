# The service

```bash
export DB_URL="mongodb://127.0.0.1:27017/cryptomon"
export DB_NAME="cryptomon"
python api.py
```

```
INFO:     Started server process [24436]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

One FastAPI application with three faces on the same port, and they are aimed
at different people.

| Path | What it is |
|---|---|
| `/` | The dashboard. What the collection contains, as a page. |
| `/analyse/` | Upload a capture in a browser, get a report. Needs no database. |
| `/stats/*` | The dashboard's numbers, as JSON. Read-only. |
| `/data/*` | The raw documents. Reads open, writes guarded. |
| `/docs` | The generated OpenAPI documentation. |

It binds `127.0.0.1` by default and writes are refused by default, so out of
the box this is a local tool. Both of those are one variable away from
changing — see [configuration.md](configuration.md) — and
[deploy/README.md](../deploy/README.md) is what to read before anybody else
can reach it.

`DB_URL` and `DB_NAME` are required even for the parts that do not use the
database: `fapi.config` validates them at import.

---

## The dashboard

`http://127.0.0.1:8000/`

It answers the project's question with the denominator beside it, because
that is the only way the number means anything. Rendered from a collection of
1,342 imported session documents:

```
81  quantum-safe key exchanges
13.5%  of 598   of key exchanges performed
 6.0%  of 1,342 of all sessions
  744  performed no key exchange
```

Read "of all sessions" as "of all documents in this window". That is the
right base for a collection of TLS sessions and the wrong one for a
collection that also holds cleartext UDP records, which an import of the
current `pcapscan` output will contain — see
[reading-a-report.md](reading-a-report.md#one-base-you-should-not-use-readinesssessions).
`/stats/overview` reports `protocols` and `by_ptype` beside the total so that
the mix is visible rather than assumed.

Below that: key exchange by group and verdict, the same over time, negotiated
ciphersuites, TLS versions, certificate signing keys, JA4 client
fingerprints, server names, Encrypted ClientHello uptake, and TLS alerts with
the direction they came from.

A window control (`?hours=`) and a capture-tag filter (`?tag=`) apply to
every panel. `hours=0` means all of time, which is a collection scan by
definition; the ceiling is 8760 (a year).

**There is no JavaScript framework, nothing vendored and nothing fetched from
a CDN.** The charts are server-rendered inline SVG. The page renders in full
with JavaScript switched off — verified: the served HTML for the whole-corpus
view contains zero `<script src>`, zero external stylesheets and zero
external URLs. The only script is a short polling loop that refreshes one
panel in place by fetching `/panels/{name}`, which returns an HTML fragment.

**A word on what it shows.** The server-names panel lists SNI, which is
browsing history: which machines contacted which hosts, and when. The service
binds loopback by default and that has not changed, but the first thing an
exposed deployment serves at `/` is a summary of who was talked to. Put it
behind [`deploy/nginx/`](../deploy/nginx/) with `API_KEY` set before you
expose it.

### An empty dashboard is a first-class case

The most likely first experience of this page is somebody who has just
imported a capture from last year, with the window still at its 24-hour
default. A blank page would read as a broken install, so it says what the
collection actually holds instead:

```
No data in this window
Nothing matched the last 24 hours.
The collection itself is not empty: it runs from 2023-06-26 09:25 to
2024-12-11 22:16. Nothing in it falls inside the window above.
Widen the window to cover all of it.
```

That link sets `?hours=0`.

### If one panel breaks

Panels are gathered concurrently with `return_exceptions=True`, and a panel
that raised is drawn as a card naming itself. A dashboard is a monitoring
tool; the moment it is most needed is the moment something is wrong with it,
so one bad panel does not blank the page.

If `fapi/app/stats.py` is absent from a deployment, `/` answers a 503 page
saying exactly that rather than failing to start. The import happens inside
the request handler for that reason.

---

## `/analyse/` — a capture, in a browser

`http://127.0.0.1:8000/analyse/`

Upload a pcap or pcapng and you get the same report `python -m pcapscan`
prints, as a page: what was negotiated, which key exchanges would survive a
quantum computer, which post-quantum offers the server refused, and what is
in the certificate chain.

This is the one part of the service that needs no database at all.

### What happens to an uploaded capture

* **The filename you send is never used.** Not sanitised, not normalised —
  discarded. A name arriving over HTTP is a string chosen by the sender, and
  every path-traversal bug in this class starts with a well-meaning attempt
  to clean one up. Uploads are stored under a 32-hex-character id this
  service generates, and your name is kept only as a label to show back.
* **The size cap is enforced while the stream is read**, not after. Bytes are
  counted as they arrive and the partial file is removed the moment
  `MAX_UPLOAD_BYTES` is passed.
* **Parsing happens in a subprocess** (`pcapscan.sandbox`) that applies its
  own address-space, CPU and wall-clock limits to itself before it imports
  anything. A capture the parser cannot digest costs one subprocess, not the
  service. This bounds resource consumption by a parser assumed to be honest
  but fallible; it is not a boundary against arbitrary code execution, which
  is what the containers in [`docker/`](../docker/README.md) are for.
* **The capture is deleted as soon as it has been analysed.** Only the report
  is kept, and reports are swept after `REPORT_RETENTION_HOURS` (24 by
  default). The form says so *before* the file is chosen, because somebody
  deciding whether to upload a capture of their network needs to know how
  long it will be kept at the moment they are deciding.

### From a script

`as_json=true` returns the report instead of redirecting to its page, so the
same endpoint serves the form and a program:

```console
$ curl -s -X POST http://127.0.0.1:8000/analyse/ \
       -F "capture=@capture.pcap" -F "as_json=true" | python -m json.tool
```

```json
{
  "meta": {
    "generated": "2026-09-23T10:42:00.500695+00:00",
    "tool": "pcapscan",
    "sandbox": {"limits_applied": ["cpu_seconds"], "address_space": 2147483648,
                "cpu_seconds": 120},
    "capture": {"packets": 24, "bytes": 9247, "truncated_tail": 0,
                "oversize_refused": 0, "unknown_blocks": 0, "sections": 1},
    "pipeline": {"frames": 24, "sessions": 1, "sessions_emitted": 1},
    "report_id": "46b77cebec0f00365665cdb273264414",
    "original_filename": "tls13_hello_retry.pcap",
    "bytes": 10164,
    "elapsed_seconds": 0.101
  },
  "summary": { "readiness": { … }, "…": "…" },
  "sessions": [ … ]
}
```

With `API_KEY` set, add `-H "X-API-Key: …"`. The browser form cannot send a
header, so a deployment with a key set accepts uploads from `curl` only; the
form says so rather than failing silently.

A stored report is also available at `/analyse/reports/{id}` as a page and
`/analyse/reports/{id}/json` as JSON.

### What it refuses, and how

| | Status | Body |
|---|---|---|
| Uploads disabled | 403 | `Capture upload is disabled. Set UPLOADS_ENABLED=true to enable it…` |
| `API_KEY` set, header missing or wrong | 401 | `A valid X-API-Key header is required to upload.` |
| Larger than `MAX_UPLOAD_BYTES` | 413 | "The capture exceeds the N-byte limit. Split it with `editcap -c`, or raise MAX_UPLOAD_BYTES." |
| Empty file | 400 | `The uploaded file is empty.` |
| Not a capture | 422 | `{"reason": "not_a_capture", "detail": "…", "hint": "That file is not a pcap or pcapng capture."}` |
| Analysis timed out | 422 | `reason: timeout`, with a hint suggesting `editcap -r` |
| Analysis ran out of memory | 422 | `reason: memory` |

The 422 `detail` carries the sandbox worker's stderr, traceback and all. It
is there so that a capture the parser cannot read produces something you can
act on rather than "no".

Uploads are **not** blocked by `READ_ONLY`. An upload writes no document, so
refusing it because the database is read-only would answer a different
question — and would mean the feature did not work on a default install,
which is the install almost everybody has.

---

## `/stats/*` — the numbers as JSON

Ten read-only panels, every one of them counted by a MongoDB aggregation
pipeline. Nothing pulls documents into Python and counts them: the collection
this serves can be fed at line rate, and a page that reads a million
documents to print twelve numbers is a denial of service anybody can trigger.

```console
$ curl -s http://127.0.0.1:8000/stats/ | python -m json.tool
{
    "panels": ["overview", "key-exchange", "ciphersuites", "tls-versions",
               "certificates", "hosts", "ja4", "alerts", "ech", "timeline"],
    "window_defaults": {"hours": 24, "max_hours": 8760, "limit": 20,
                        "min_limit": 1, "max_limit": 200,
                        "buckets": {"minute": 60, "hour": 3600, "day": 86400}},
    "span": {"first": 1743967494.582705, "last": 1790154907.694991}
}
```

`span` is the whole collection's time range, ignoring the window, so the
first thing a client loads already knows whether the default window can
possibly have anything in it.

Every panel takes `?hours=` (default 24, `0` for all of time, max 8760) and
`?tag=`. The bucketed panels take `?limit=` (1–200, default 20) and the
timeline takes `?bucket=` (`minute`, `hour` or `day`).

Against the same collection of 1,342 imported session documents:

```console
$ curl -s "http://127.0.0.1:8000/stats/key-exchange?hours=0&limit=5"
```

```json
{
  "panel": "key-exchange",
  "window": {"hours": 0, "from": null, "to": 1790160740.080571, "tag": null},
  "total": 598,
  "buckets": [
    {"name": "x25519",                "count": 202, "verdict": "classical"},
    {"name": "secp384r1",             "count": 162, "verdict": "classical"},
    {"name": "secp256r1",             "count": 142, "verdict": "classical"},
    {"name": "X25519MLKEM768",        "count":  45, "verdict": "hybrid"},
    {"name": "X25519Kyber768Draft00", "count":  36, "verdict": "hybrid"}
  ],
  "other": 11,
  "notes": [
    "744 of 1342 documents in this window performed no key exchange (a resumed session, or a frame carrying no key share) and are not counted here.",
    "SSH records the algorithms each side proposed rather than the one chosen, so SSH documents are not counted here.",
    "Documents written by the live eBPF capture are one per frame, so a client hello and its server hello are counted separately; the offline pcapscan import writes one per session. overview.by_ptype says which this collection holds."
  ]
}
```

**Read `notes`.** It is not decoration. Two document shapes share this
collection — the live sensor writes one document per *frame*, `mongoimport`
of `pcapscan` writes one per *session* — and a panel's numbers only mean what
they say for one of the two. `overview.by_ptype` tells you which shape you
have, and every panel whose meaning changes between them says so in `notes`.

`total` is always the number of documents the panel counted. For the panels
that unwind a list, the buckets sum to *occurrences* instead, which is a
different and larger number; those say which is which in `notes`. A
certificate chain contributing three rows to a bar labelled "sessions" is a
lie told in units.

Bad parameters are refused rather than clamped:

```console
$ curl -s "http://127.0.0.1:8000/stats/key-exchange?hours=99999"
{"detail":"hours must be between 0 and 8760; 0 means all of time."}
$ curl -s "http://127.0.0.1:8000/stats/key-exchange?limit=0"
{"detail":"limit must be between 1 and 200."}
$ curl -s "http://127.0.0.1:8000/stats/timeline?bucket=fortnight"
{"detail":"bucket must be one of day, hour, minute."}
```

`?bucket=minute&hours=8760` would be 525,600 gap-filled points, so the
timeline widens its own bucket before the aggregation runs rather than after.
`?bucket=minute&hours=0` over the corpus comes back with
`"bucket_seconds": 86400`. A query parameter must not be able to choose how
much work the server does.

---

## `/data/*` — the raw documents

| | |
|---|---|
| `GET /data/` | The first 100 documents. |
| `GET /data/{id}` | One document. A malformed id is a 404, not a 500. |
| `GET /data/count/?k=…&v=…` | Count, optionally filtered on one field. |
| `POST /data/count/` | Count, with a JSON filter of field/value pairs. |
| `POST /data/`, `PUT /data/{id}`, `DELETE /data/{id}` | Guarded. |

Reads are open. Writes are refused unless an operator opts in:

```console
$ curl -s -X POST http://127.0.0.1:8000/data/ \
       -H 'Content-Type: application/json' -d '{"ptype":"client","ts":1.0}'
{"detail":"This deployment is read-only. Set READ_ONLY=false to enable
writes, and set API_KEY as well if the service is reachable from anywhere but
localhost."}
```

Read-only is the default so that an operator opts *in* to writes rather than
remembering to opt out. When `API_KEY` is also set, writes need the header as
well, compared with `secrets.compare_digest` — plain `==` leaks the key's
prefix through response timing.

The count filter accepts **equality on a known field only**. No operators, no
nested documents, no arrays:

```console
$ curl -s -X POST http://127.0.0.1:8000/data/count/ \
       -H 'Content-Type: application/json' -d '{"$where":"sleep(5000)"}'
{"detail":"'$where' is not a queryable field. Allowed: _id, eth.dst.ipv4, …"}
```

Both count endpoints used to hand caller-supplied JSON straight to
`count_documents()`, which made `{"$where": …}` and `{"ptype": {"$ne": null}}`
available to anybody who could reach them, and a `$regex` against a
collection this size is a trivial denial of service. The allow-list closes
both forms, including the `?k=` one where the filter key was the caller's
choice. The offending field is named in the error; the value never is, so a
payload is not reflected back to whoever sent it.

Note that `/data/` is a thin view over the collection. For anything
analytical, `/stats/` is the endpoint — it is indexed, bounded, and it
answers in milliseconds.

---

## Indexes and retention

Five indexes are created on startup, idempotently and without blocking it:
`ts`, `(ptype, ts)`, `(tag, ts)`, `tls.ciphersuite` and `tls.kex_group`. The
set is deliberately small — each index costs write throughput on a collection
fed at packet rate, so one exists only where a query the API actually exposes
would otherwise scan.

Two retention mechanisms, deliberately with different defaults:

* **Uploaded reports expire** after `REPORT_RETENTION_HOURS` (24), swept by a
  task inside the API process every `RETENTION_SWEEP_MINUTES`. The sweep only
  ever removes `.json` and `.capture` files, because a retention job that
  deletes files it does not recognise is a data-loss incident waiting for the
  wrong `UPLOAD_DIR`.
* **The live collection does not**, unless `DATA_RETENTION_HOURS` is set. When
  it is, it becomes a MongoDB TTL index on `expires_at`, so the server does
  the deleting whether or not this service is running.

## Behind a reverse proxy

Set `ROOT_PATH` to the prefix and make nginx pass the URI unchanged. The two
values are a pair and must agree. [deploy/README.md](../deploy/README.md)
covers why `X-Forwarded-Prefix` is inert on this stack, why `uvicorn
--root-path` is the wrong tool here, and what each way of getting the pair
out of step looks like. The short version of the deciding argument: with
nginx not stripping, a forgotten `ROOT_PATH` is a 404 on the first page; with
nginx stripping and the flag forgotten, every page renders and only the
generated URLs are one level out, which is found days later by a user and
looks like an application bug.
