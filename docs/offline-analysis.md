# Analysing captures offline

```bash
python -m pcapscan capture.pcap
```

`pcapscan` reads a capture file directly. It needs no root, no eBPF, no
interface and no database, it runs anywhere Python 3.10 does, and it uses one
third-party package (`cryptography`, for the X.509 chain). It also sees
considerably more than the live sensor can, because it reassembles TCP before
it parses anything — see [architecture.md](architecture.md).

It ships before any UI because it is the thing that gets automated. A web
form is used by whoever is sitting in front of it; a command that reads a
capture and writes NDJSON on standard output is used by a cron job, a CI step
and a pipeline somebody writes six months from now without asking.

## The report

The default output is a readable summary. This is the committed
HelloRetryRequest fixture — one real handshake, 24 packets:

```console
$ python -m pcapscan tests/fixtures/streams/tls13_hello_retry.pcap
pcapscan: read tests/fixtures/streams/tls13_hello_retry.pcap

Sessions                1
  tls                   1

Key exchange
  performed             1
  none (resumed)        0
  post-quantum          0 (0.0%)
  hybrid                0 (0.0%)
  classical             1 (100.0%)
  unknown               0 (0.0%)
  quantum-safe          0.0% of key exchanges performed

Post-quantum offers refused by the server (1)
  X25519Kyber768Draft00 -> secp256r1   x1
  unreadable (TLS 1.3)  1 sessions

TLS versions
  TLSv1.3               1

Algorithms observed
  ciphersuite    TLS_AES_256_GCM_SHA384               symmetric     1
  key-exchange   secp256r1                            classical     1
```

That is the finding this tool exists to produce, in miniature. The client
offered a post-quantum hybrid group; the server refused it with a
HelloRetryRequest and named a classical curve instead. A reader that sees
only the first ClientHello reports "post-quantum key exchange offered" and
never records that it was turned down — which, for a tool measuring
post-quantum readiness, is the opposite of what happened.

[reading-a-report.md](reading-a-report.md) explains every line of that
output, including why `quantum-safe` is a percentage of *key exchanges
performed* rather than of sessions.

## Output formats

| `-f` | What it is for |
|---|---|
| `summary` | The default. A person reading it. |
| `ndjson` | One JSON document per line, in the same shape the live sensor writes. Streams. The format to pipe into MongoDB. |
| `json` | One document: the records as an array, plus the analysis summary. Streams, with the summary appended at the end. |
| `csv` | One flat row per session. For a spreadsheet. |
| `cbom` | A CycloneDX 1.6 Cryptography Bill of Materials over the whole body of traffic. |

```bash
python -m pcapscan capture.pcap                      # readable report
python -m pcapscan capture.pcap -f csv -o out.csv    # for a spreadsheet
python -m pcapscan capture.pcap -f cbom > cbom.json  # CycloneDX 1.6
python -m pcapscan capture.pcap -f json -o report.json
```

Formats are *discovered* rather than listed: `cbom` appears in `--help` only
when its dependencies are present, so an option that would fail is absent
rather than offered and broken.

### NDJSON, and the point of it

The NDJSON records keep the document shape the live sensor already writes —
`ptype`, `eth.src.ipv4`, `tls.ciphersuite` and the rest in the same places.
That is not nostalgia. It means the offline path feeds the same collection as
the live path, with no translation step:

```console
$ python -m pcapscan *.pcap -f ndjson -q \
    | mongoimport --uri "mongodb://127.0.0.1:27017/cryptomon" --collection cryptomon
connected to: mongodb://127.0.0.1:27017/cryptomon
1260 document(s) imported successfully. 0 document(s) failed to import.
```

(1260 is the whole project corpus. Yours will differ.)

`-q` because the per-file progress goes to standard error and would otherwise
interleave with `mongoimport`'s own output. Note that `mongoimport` defaults
to `localhost:27017` and to the `test` database, so name the database in the
URI or with `--db`.

**Tagging an import.** The dashboard and `/stats` can filter by a `tag`
field, which groups documents by capture run. Nothing in the pipeline writes
one — `tag` is only ever set by the live sensor's `data_tag`, and the shipped
`cryptomon.py` leaves that empty. Add it on the way past:

```bash
python -m pcapscan capture.pcap -f ndjson -q \
  | python -c 'import sys, json
for line in sys.stdin:
    if line.strip():
        print(json.dumps(dict(json.loads(line), tag="office-wifi")))' \
  | mongoimport --uri "mongodb://127.0.0.1:27017/cryptomon" --collection cryptomon
```

### CSV

One row per session, 28 columns, ordered so that the identifying fields come
first and the verdict is visible without scrolling:

```
ts, time, duration, src, src_port, dst, dst_port, protocol, hostname, ech,
ja4, ja4s, tls_version, ciphersuite, kex_group, kex_verdict, resumption,
hello_retry_request, offered_kex_group, retry_kex_group,
certificate_subject, certificate_issuer, certificate_key,
certificate_not_after, certificate_count, proposed_groups,
proposed_ciphersuites, alerts
```

Flat and lossy, deliberately. It exists because the people who most need to
read "which of our connections would survive a quantum computer" open things
in a spreadsheet, and a nested document is not that. List-valued columns are
joined with `;`. The float epoch `ts` is kept *beside* a readable ISO `time`
rather than replaced by it, because a format that cannot round-trip is a
format that quietly loses data.

### CBOM

```bash
python -m pcapscan capture.pcap -f cbom -o cbom.json
```

A CycloneDX 1.6 document with one component per protocol version observed,
one per distinct algorithm, and one per distinct certificate, plus a
dependency graph built from what was seen *together*. "TLS 1.2 depends on
secp256r1" is then a statement about this capture; attaching every algorithm
to every version would be a statement about nothing.

The serial number is derived from the content, so two runs over the same
traffic produce byte-identical documents and a CBOM can be diffed against
last month's — the difference is then a change in the estate rather than a
change in the clock. The timestamp lives in `metadata`, outside the hash.

This is a different document from `bom.json` in the repository root. That one
inventories *this software's* dependencies. This one inventories the
cryptography on *your network*.

## Mirrored and tunnelled traffic

Nobody monitors a corporate network from an endpoint. They configure a SPAN,
RSPAN or ERSPAN session on a switch, or hang a TAP off a link, and the
mirrored traffic arrives somewhere else — encapsulated. The common
encapsulation is ERSPAN, which wraps the whole original Ethernet frame in GRE
inside IP.

`pcapscan` unwraps that before it frames anything, so a capture taken off a
mirror port reports what it carries instead of reporting nothing:

| | |
|---|---|
| GRE | RFC 2784, and everything built on it |
| ERSPAN | Types I, II and III |
| VXLAN | |
| GENEVE | |
| IP-in-IP | RFC 2003 |

You do not ask for this and there is no flag: encapsulated frames are
resolved on the way in, and what a tunnel refuses is counted in the
`tunnel_*` family in `--stats` rather than dropped in silence.

**There is no tunnelled traffic in this project's capture corpus** — zero
packets of IP protocol 47 in any of it, and no VXLAN or GENEVE either. The
fixtures this is checked against are built to the RFCs and committed. They
are not evidence about real switches, and should not be read as any.

This is the offline path only. **The live eBPF sensor is still blind to
tunnels**: the kernel filter reads IP protocol 6 and nothing else, so
encapsulated traffic on a monitored interface produces no events at all.

## Several captures, and captures from a pipe

```bash
python -m pcapscan *.pcap *.pcapng           # analysed as one body of traffic
python -m pcapscan mon-*.pcap -f ndjson      # ditto, as documents
zcat big.pcap.gz | python -m pcapscan -      # from standard input
python -m pcapscan capture.pcap.gz           # gzip, sniffed from the magic
```

pcap and pcapng are both read, gzipped or not, and gzip is detected from the
file's magic bytes rather than its name: a `.pcap` written by
`tcpdump -z gzip` is gzipped, and a `.gz` that is not is a file somebody
renamed.

Several captures given at once are fed to **one** session builder and
finished once at the end, not per file. `tcpdump -C` rotates a capture
mid-connection, and finishing after each part would report the two halves of
one handshake as two incomplete sessions. The practical consequence is worth
knowing: analysing twelve captures together and analysing them one at a time
give different session counts, because flows that appear in more than one
file are merged in the first case and counted twice in the second. The
per-file total is always the larger of the two.

One unreadable file among several does not lose the others, and is not passed
over in silence either:

```console
$ python -m pcapscan notacapture.pcap tests/fixtures/streams/tls13_hello_retry.pcap -f csv -q -o out.csv
pcapscan: notacapture.pcap: unrecognised capture magic b'hell'; expected pcap or pcapng
$ echo $?
1
$ wc -l < out.csv
2
```

Exit status is 0 for a clean run and 1 if any capture could not be read.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `-f`, `--format` | `summary` | One of `summary`, `ndjson`, `json`, `csv`, `cbom`. |
| `-o`, `--output` | stdout | Write here instead. `-` also means stdout. |
| `-q`, `--quiet` | off | Suppress the per-file `pcapscan: read …` progress on stderr. Use it when piping. |
| `--stats` | off | Write the reader and reassembler counters to stderr when the run finishes. |
| `--no-certificates` | off | Skip X.509 parsing; keep the raw DER chain. |
| `--max-stream-bytes` | 16384 | Reassembly buffer per direction, in bytes. |
| `--max-flows` | 2048 | Connections tracked at once. |

`--no-certificates` is the honest way to say "do not look at the
certificates": the record carries `tls.certificates_der`, a list of the raw
DER messages, in place of the parsed `tls.certificates`, so nothing on the
wire is thrown away and whoever reads the record can do as they like with it.
Use it when you do not have `cryptography`, when you want the analysis to
cost less, or when you intend to parse the chain with something else.

`--max-stream-bytes` is 16KB because the whole plaintext handshake fits in
that with room to spare, and past it a stream is bulk transfer rather than
negotiation. Raise it only for a capture with unusually large certificate
chains; raising it raises the memory a hostile capture can make the process
hold.

`--max-flows` bounds an LRU table of connections. A capture with more
simultaneous connections than this evicts the oldest, which is visible as
`evicted` in `--stats`.

## `--stats`, and reading it

```console
$ python -m pcapscan Firefox_Mac.pcap -q --stats -f ndjson -o /dev/null
pcapscan: {'capture_bytes': 5711078, 'capture_oversize_refused': 0,
 'capture_packets': 8582, 'capture_sections': 0, 'capture_truncated_tail': 0,
 'capture_unknown_blocks': 0, 'flows_http': 34, 'flows_not_tls_or_ssh': 30,
 'frames': 8312, 'frames_undecodable': 1, 'sessions': 114,
 'sessions_without_handshake': 12, 'udp_datagrams': 269, 'udp_flows': 19,
 'udp_payload_bytes': 135573, ...}
pcapscan: {'ignored_stateless': 115, 'flows': 262, 'segments': 8197,
 'payload_bytes': 5010119, 'reassembled_bytes': 433416, 'abandoned': 209,
 'resets': 51, 'open_streams': 262, 'held_bytes': 28506,
 'pending_segments': 0}
```

This is a dict, so the exact set of keys depends on what the capture
contained and on which protocol handlers this installation has. The `udp_*`
and `tunnel_*` families in particular are growing as handlers land; treat the
list as self-describing rather than fixed.

The first line is the reader and the session builder, the second the
reassembler. Nothing here is refused silently: every frame that was dropped
is counted somewhere, so a run that quietly discarded data does not look like
a run that saw none.

The counters worth knowing:

| Counter | Means |
|---|---|
| `capture_truncated_tail` | The file was cut off mid-record. A normal thing for an interrupted `tcpdump`, not a corrupt file. |
| `capture_oversize_refused` | A length field said a frame was larger than 1MB. The stream is no longer trusted past that point. |
| `frames_undecodable` | The link layer could not be decoded, or the frame carried no transport header this tool reads. Now a small number, because UDP is decoded rather than dropped. |
| `sessions` vs `sessions_emitted` | TCP flows tracked, against records produced. `sessions_emitted` also includes the UDP records counted by `datagram_sessions_emitted`, so the two are not a like-for-like pair on a capture with UDP in it. |
| `flows_http`, `flows_not_tls_or_ssh`, `flows_stun` | Flows identified as something else, from their bytes, and abandoned. |
| `udp_datagrams`, `udp_flows`, `udp_payload_bytes` | What reached the UDP side. `udp_flows_capped` and `udp_flows_unrecognised` say what it declined to keep. |
| `tunnel_*` | Encapsulated traffic that was refused, and why — see [Mirrored and tunnelled traffic](#mirrored-and-tunnelled-traffic). |
| `abandoned` | Flows dropped on their first segment because they could be told not to carry a handshake. This is what makes the memory ceiling real. |
| `evicted` | Flows pushed out of the LRU table by `--max-flows`. If this is non-zero and you care about completeness, raise it. |
| `held_bytes`, `pending_segments` | What the reassembler was still holding when the run ended. Should be small. |

## How fast, and how much memory

The whole project corpus — twelve captures, 265MB on disk, 159,929 packets —
analyses in **under two seconds**, with certificate parsing on.

The upload sandbox's limits are set against that measurement rather than by
taste: 2 GiB of address space and 120 CPU seconds leave roughly two orders of
magnitude of headroom and still stop a runaway well before it troubles the
host. See [service.md](service.md#what-happens-to-an-uploaded-capture).

## Replaying a capture at the live sensor

```bash
./parse-pcap.sh capture.pcap
```

This replays the capture over the loopback interface for the live eBPF sensor
to parse, which exercises the same code path production uses. It needs root
and the database variables set, and it sees only what a single-packet reader
can see. Prefer `pcapscan` unless you are specifically testing the live path.

> **Not verified on this machine.** `parse-pcap.sh` needs Linux, root, an
> eBPF-capable kernel and bcc.
