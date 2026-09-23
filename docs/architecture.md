# Architecture

There are two ways into this program and they read the same protocol very
differently. Understanding why is the difference between trusting a number
and misreading it.

```
     the wire                              a capture file
         │                                       │
   ┌─────▼──────┐                          ┌─────▼──────┐
   │ eBPF filter│  in the kernel           │ reader     │  pcap / pcapng,
   │ bpf.py     │  one skb at a time       │ reader.py  │  gzip, stdin
   └─────┬──────┘                          └─────┬──────┘
         │ frames whose payload                  │ every frame
         │ *starts with* a handshake       ┌─────▼──────┐
         │                                 │ tunnels.py │  GRE / ERSPAN /
         │                                 │            │  VXLAN / GENEVE
         │                                 └─────┬──────┘
         │                                 ┌─────▼──────┐
         │                                 │ framing.py │  TCP ──┐ UDP ──┐
         │                                 └─────┬──────┘        │       │
         │                                 ┌─────▼──────┐   datagrams.py │
         │                                 │ reassembly │        │       │
         │                                 │ .py        │  TCP ordering  │
         │                                 └─────┬──────┘  per direction │
         │                                 ┌─────▼──────┐               │
         │                                 │ records.py │  TLS records, │
         │                                 │            │  then messages│
         │                                 └─────┬──────┘               │
   ┌─────▼───────────────────────────────────────▼──────┐
   │         cryptomon/parsers/  —  one TLS parser      │
   └─────┬───────────────────────────────────────┬──────┘
         │ one document per frame          ┌─────▼──────┐
         │                                 │ sessions.py│  both directions
         │                                 │            │  paired
         │                                 └─────┬──────┘
   ┌─────▼───────────────────────────────────────▼──────┐
   │   cryptomon/analysis.py  —  one classification     │
   └─────┬───────────────────────────────────────┬──────┘
         │                                       │
     MongoDB  ──────►  /stats, the dashboard   export.py, cbom.py
```

The parsers and the judgement are shared. Only the framing differs, and the
framing is what decides how much there is to parse.

Two stages on the right have no counterpart on the left, and both exist
because the live sensor's filter reads IP protocol 6 and nothing else.
`tunnels.py` unwraps mirrored traffic — GRE, ERSPAN, VXLAN, GENEVE,
IP-in-IP — *before* framing, because unwrapping a tunnel does not produce a
transport header, it produces another whole frame that has to be walked
again; putting that recursion inside `decode_frame` would hand every caller a
recursion it never asked for and make the depth an attacker-controlled
parameter in the hottest function in the project. `datagrams.py` takes the
UDP side, where there is no ordering to recover and no connection to track —
an absence deliberately visible in the type, so nothing downstream can write
code that assumes a stream. The protocol handlers that sit behind it are
landing as this is written and are documented separately.

## Why the kernel filter cannot do better

The eBPF program runs on one `skb` at a time. It has no memory between
packets and no way to acquire one that the verifier would accept, so it can
only forward a frame whose TCP payload *begins* with something recognisable
— a TLS record header (`0x16`, major 3, minor 1–4) or an SSH banner. Anything
that begins mid-message is invisible to it.

That constraint is not negotiable and it is not a bug. A filter that buffered
would be a TCP stack in the kernel, written by us, on the packet path. The
right answer is to keep the filter cheap and do the reassembly where it is
safe to do it — which is what `pcapscan` is.

The cost, measured across the eleven corpus captures:

| | live path | offline path |
|---|---|---|
| ClientHellos reported | 411 | 441 |
| …of which whole | **139** | **441** |
| Certificate messages | **15**, every one a fragment | **93**, whole chains |

A modern ClientHello with post-quantum key shares is around 1.9KB and arrives
in two segments — a 1238-byte one and a 660-byte one. The single-frame parser
reads the first, finds whatever extensions happened to fit, and records them
**as though that were the whole message**. Not missed: reported, incomplete,
and without saying so. Two thirds of the live tool's hello output has been
partial for as long as it has existed. A certificate chain is several
kilobytes and has never once fitted in a single packet.

So "the offline path sees roughly five times as much" is a fair summary of
two numbers: 3.2× the whole ClientHellos and 6.2× the certificate messages.

Three more things only reassembly can see:

* **Both halves of a HelloRetryRequest.** A post-quantum key exchange the
  server *refused* is reported as refused rather than as offered. Getting
  this wrong reverses the finding.
* **Handshakes behind a ChangeCipherSpec.** TLS 1.3 sends a dummy CCS
  mid-handshake so middleboxes see a familiar sequence (RFC 8446 D.4) and
  then carries on in the clear. Reading that CCS the TLS 1.2 way — as "the
  rest is encrypted" — loses every message after it, which is 108
  ClientHellos and 108 ServerHellos across the corpus, and they are the ones
  that matter most. A measured 7% of corpus segments carry a CCS ahead of the
  handshake in the same packet, which the kernel filter can never forward.
* **Traffic on unwatched ports.** The filter has to have a port list, because
  the list is what stops it copying every packet on the interface to
  userspace. The offline analyser has no port filter and identifies protocols
  from the bytes: 13 of 1369 TLS flows in the corpus (0.95%) are on ports the
  filter does not watch.

## Checking the claim against somebody else's implementation

A recall claim is worth exactly as much as its independent check. The offline
path is diffed against **tshark with desegmentation on** over eleven full
captures, in CI, and agrees on 441 ClientHellos and 93 certificate messages.

There is one disagreement in the certificate column and it is ours: on one
flow tshark's desegmenter gives up, because the flow has TSO-offloaded
segments with zero checksums that trip its TCP analysis, and reports no
certificate. `pcapscan` recovers a well-formed 6721-byte chain which
`cryptography` parses without complaint. So the honest form of the claim is
"agrees with tshark on every handshake tshark found, and finds one more".

The oracle has a second CI job that regenerates it with a current tshark and
fails on any difference, because a committed oracle is only an oracle while
it still matches what the reference says.

## What is where

### Shared

| | |
|---|---|
| `cryptomon/parsers/framing.py` | Ethernet, VLAN, IPv4/IPv6, TCP. One decoder for both paths. |
| `cryptomon/parsers/tls.py` | Hello parsing, extensions, ECH. Takes the offset of a handshake message rather than assuming a record at the start of a frame, which is what let the offline walker reuse it unchanged. |
| `cryptomon/parsers/ssh.py` | KEXINIT algorithm lists. |
| `cryptomon/fingerprints.py` | JA4, JA4S, JA3. Pure functions, no I/O, so both paths compute the same string from the same code. |
| `cryptomon/analysis.py` | **The judgement.** Which algorithms survive a quantum computer, and the `Summary` both paths roll up into. |
| `cryptomon/alerts.py` | The IANA alert registry and which combinations are a finding. |
| `cryptomon/ports.py` | The watched port lists, and the generated C for them. |
| `cryptomon/data.py`, `utils.py` | Code-point tables and lookups. |

`cryptomon/analysis.py` is the reason the two halves are one product rather
than two. Counting ciphersuites is arithmetic; saying which of them survive a
cryptographically relevant quantum computer is the question the tool was
built to answer, and it belongs in exactly one place. The CBOM exporter, the
report page, `/stats` and the dashboard all ask it rather than re-implementing
it. `/stats` in particular could have expressed the verdicts as a MongoDB
`$switch` and did not, for the same reason: a second copy in a second
language drifts, and this project has the worked example — the post-quantum
markers have to be matched *and removed* before the classical ones, or every
NIST signature selection reports as a hybrid of itself and DSA. That fix
lives in one function. A `$switch` would not have it.

### The live path

| | |
|---|---|
| `cryptomon/bpf.py` | The kernel C, generated from `ports.py` at import. |
| `cryptomon/__init__.py` | `CryptoMon`: attach, poll the perf buffer, parse, write. |
| `cryptomon.py` | The command line. |

### The offline path

| | |
|---|---|
| `pcapscan/reader.py` | pcap and pcapng, both byte orders, both timestamp resolutions, multiple interfaces and sections, gzip, truncated tails. Streams one frame at a time rather than `rdpcap`-ing a 700MB file into memory. |
| `pcapscan/tunnels.py` | Unwraps GRE, ERSPAN I/II/III, VXLAN, GENEVE and IP-in-IP before framing, so a capture from a switch mirror port reports what it carries. Borrows `framing.walk_network` rather than copying it: every defect that walk has had produced plausible wrong offsets rather than an error, and a second copy would be a second place to reintroduce them. |
| `pcapscan/datagrams.py` | The UDP side: no ordering to recover, no connection to track. |
| `pcapscan/reassembly.py` | Orders the bytes. Not a TCP stack: no windows, no ACK tracking, nothing emitted. Holes held until filled, retransmissions dropped, overlaps trimmed. |
| `pcapscan/records.py` | Walks TLS records, then the handshake messages inside them — two framings that do not line up. One record commonly holds ServerHello, Certificate, ServerKeyExchange and ServerHelloDone together, while one certificate chain routinely spans five records. |
| `pcapscan/protocols.py` | Identifies TLS, SSH, HTTP/1.x, HTTP/2, SMTP, IMAP, POP3, FTP and STUN from bytes, so a flow that carries none of them is abandoned early. |
| `pcapscan/sessions.py` | Pairs the two directions into one record per handshake. |
| `pcapscan/certificates.py` | X.509, via `cryptography`. Optional. |
| `pcapscan/export.py`, `cbom.py` | NDJSON, JSON, CSV; CycloneDX 1.6. |
| `pcapscan/sandbox.py` | Runs the whole pipeline in a subprocess with its own rlimits, for the upload path. |
| `pcapscan/cli.py` | The command line. |

### The service

| | |
|---|---|
| `api.py` | The application, and the router order — `/stats` is declared before the dashboard, because FastAPI matches in declaration order and a root mount declared first would swallow it. |
| `fapi/config/` | Settings. |
| `fapi/app/routers.py` | `/data`. |
| `fapi/app/query.py` | The filter allow-list for the count endpoints. |
| `fapi/app/security.py` | The write guard. |
| `fapi/app/uploads.py` | `/analyse`. |
| `fapi/app/stats.py` | `/stats`, ten aggregation pipelines. |
| `fapi/app/dashboard.py`, `charts.py` | `/`, and the inline SVG. |
| `fapi/app/indexes.py`, `retention.py` | Startup indexes and the expiry sweep. |

## Bounds, everywhere

An offline tool is handed files chosen by somebody else, and a service is
handed uploads chosen by somebody else, so almost every loop here has a
ceiling and almost every ceiling has a comment saying what it costs. The main
ones:

| | |
|---|---|
| 16KB per direction | Reassembly buffer. The whole plaintext handshake fits with room to spare; past it a stream is bulk transfer. `--max-stream-bytes`. |
| 2048 flows | LRU flow table. `--max-flows`. |
| 1MB | Largest frame the reader will accept before it stops trusting the file. |
| 512 certificates, 50 hosts, 32 occurrences | What one `Summary` holds, so analysing a large capture costs a report rather than a second copy of the capture. |
| 2 GiB / 120 CPU-s / 180 wall-s | The upload sandbox, set against the measurement that the whole 265MB corpus analyses in 1.35s. |
| 2000 points | The timeline series, so `?bucket=minute&hours=8760` cannot ask for 525,600. |
| 64 ports | `TLS_PORTS`, so the generated C stays well inside the verifier's instruction limit. |
| 1000 in-flight inserts | The live sensor's write backpressure. |

A flow the reassembler can tell carries nothing wanted is `abandon()`ed on
its first segment, which is what makes the memory ceiling real rather than
nominal: an 80MB capture runs in 0.1s holding 162 bytes at the end, because
62 of its 73 flows were dropped immediately.

## Two document shapes in one collection

This surprises people, so it is worth stating plainly.

| | live sensor | `pcapscan` + `mongoimport` |
|---|---|---|
| `ptype` | `client` or `server` | `session` |
| granularity | one document per **frame** | one document per **handshake** |
| `ts` | set at insertion | from the capture |
| has | the single-frame view of `tls` | `certificates`, `alerts`, `resumption`, `proposed`, `selected`, `ja4s` |

Both are valid and both can live in the same collection, which is
deliberate — the NDJSON export keeps the live path's field paths so that the
two feed one collection without translation. But a panel that assumes one
shape is wrong on somebody's deployment, so `/stats/overview` reports
`by_ptype` and every panel whose meaning changes between the two says so in
its `notes`.

A live document, `ptype: client` — one ClientHello, as the sensor saw it:

```json
{
  "_id": "6682cd75393bb4e863fc0c65",
  "eth": {"src": {"ipv4": "192.168.64.5"},
          "dst": {"ipv4": "3.210.189.242"}},
  "tls": {
    "tls_versions": ["TLSv1.3", "TLSv1.2"],
    "ciphersuites": ["TLS_AES_128_GCM_SHA256", "…"],
    "EtM": false,
    "hostname": "ping.chartbeat.net",
    "groups": ["x25519", "secp256r1", "secp384r1", "secp521r1",
               "ffdhe2048", "ffdhe3072"],
    "kex_group": "x25519",
    "sigalgs": ["ecdsa_secp256r1_sha256", "…"]
  },
  "ptype": "client",
  "ts": 1719848309.166212
}
```

The matching `ptype: server` document is a separate row, joined to it by
nothing:

```json
{
  "_id": "6682cd75393bb4e863fc0c66",
  "eth": {"src": {"ipv4": "3.210.189.242"},
          "dst": {"ipv4": "192.168.64.5"}},
  "tls": {"tls_versions": "TLSv1.2",
          "ciphersuite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
  "ptype": "server",
  "ts": 1719848309.26233
}
```

That is enough to count what clients *offer* and not enough to say what was
*used*, which are different questions. An offline document, `ptype: session`,
carries both halves and what they imply:

```json
{
  "ptype": "session",
  "ts": 1733954736.226069,
  "duration": 0.025676,
  "eth": {"src": {"ipv4": "10.176.24.102", "port": 49492},
          "dst": {"ipv4": "152.199.2.76", "port": 443}},
  "tls": {
    "hostname": "cdn.bizible.com",
    "ech": "offered",
    "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
    "ja4s": "t130200_1302_a56c5b993250",
    "ciphersuite": "TLS_AES_256_GCM_SHA384",
    "kex_group": "secp256r1",
    "tls_versions": ["TLSv1.3"],
    "resumption": "fresh",
    "resumption_evidence": "TLS 1.3 without pre_shared_key",
    "hello_retry_request": true,
    "offered_kex_group": "X25519Kyber768Draft00",
    "retry_kex_group": "secp256r1",
    "certificates_unreadable": true,
    "proposed": { … }, "selected": { … }, "messages": { … }
  }
}
```

`tls.ciphersuite`, `tls.kex_group` and `tls.hostname` stay exactly where the
live tool has always put them, so existing queries and stored data keep
working; everything new hangs off `proposed`, `selected` and `certificates`.

There are also two certificate parsers, for the same historical reason: the
live path uses `cryptomon.utils.cert_guess`, which needs `jc` and guesses at
a chain it can only see a fragment of; the offline path uses
`pcapscan.certificates`, which needs `cryptography` and parses a whole chain.

## What is not here

* **No DTLS.**
* **No decryption**, of anything, anywhere.
* **Nothing over UDP in the live path.** The kernel filter reads IP protocol
  6 and nothing else, so UDP never reaches userspace there. The offline
  analyser does read UDP — see below.
* **No tunnels in the live path either.** Encapsulated traffic on a monitored
  interface produces no events at all. The offline analyser unwraps GRE,
  ERSPAN, VXLAN, GENEVE and IP-in-IP before framing.

IPv6 *is* supported, in both paths, and any older note saying it is a planned
feature is stale. The kernel filter reads every offset from the packet, steps
over stacked VLAN tags, walks the IPv6 extension header chain and refuses
non-initial fragments; the offline framing decoder does the same in Python.
Single-tag VLAN happened to work before that change, because the kernel
strips one 802.1Q tag into `skb` metadata ahead of the filter — which is why
QinQ failed and a single tag did not.
