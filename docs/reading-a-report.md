# Reading a report

A CryptoMon report is full of strings like `X25519MLKEM768`, `hybrid`,
`t13d1516h2_8daaf6152771_02713d6af862`, `resumption: resumed` and
`ech: offered`. This page says what each of them means and which of them
should worry you.

## First: a percentage without its base means nothing

This is the most important idea in the project, and it is not a caveat — it
is the finding.

Over the project's twelve capture corpus, 116 key exchanges used a
post-quantum hybrid group. Here are two true statements about that number:

> **18.6%** of the 624 sessions that performed a key exchange were
> quantum-safe.
>
> **8.6%** of the 1346 TLS sessions were quantum-safe.

They differ because **a resumed session performs no key exchange at all**.
722 of those 1346 performed none — they resumed an earlier one, or the
capture did not contain the exchange. There was no key agreement in them to
be quantum-safe or otherwise. Counting them in the denominator understates
readiness by the resumption rate. Leaving them out overstates the share of
traffic that is actually protected against a store-now-decrypt-later
adversary, because a resumed session's keys descend from the original
exchange, and that exchange was classical.

Which number is right depends on the question:

| The question | The denominator |
|---|---|
| "Are our clients and servers configured to negotiate PQ?" | key exchanges performed |
| "What fraction of this traffic is protected from a future quantum adversary?" | TLS sessions |
| "How much work is left?" | both, stated together |

CryptoMon prints the base beside every figure and never on its own. The
summary says `18.6% of key exchanges performed`, not `18.6%`.
`readiness.quantum_safe_fraction` in the JSON is explicitly over
`key_exchanges_performed`, and `readiness.no_key_exchange` is right beside
it.

If you quote one of these numbers to anybody, quote its base with it.

(Those corpus figures move as protocol handlers are added — a QUIC handshake
is a TLS handshake, so it lands in both the numerator and the TLS
denominator. Re-run `python -m pcapscan` rather than trusting a number
written down here. The *shape* of the argument does not move.)

### One base you should not use: `readiness.sessions`

**`readiness['sessions']` counts every record the run produced, across every
protocol — and every other field in that dict is about TLS.** Over the same
corpus it reads 2404, because the cleartext UDP flows (DNS, NTP, mDNS,
NetBIOS and the rest) are now sessions too. The key-exchange buckets still
sum to the TLS sessions and not to that:

```
hybrid 116 + classical 508 + no_key_exchange 722 = 1346   (TLS sessions)
readiness['sessions']                            = 2404   (all records)
                                         unexplained 1058
```

116 out of 2404 is 4.8%, and it is a number about nothing: a DNS lookup was
never going to negotiate a key exchange, so putting it in the base does not
measure a shortfall, it manufactures one. Use `protocols['tls']` — or the
`Sessions` breakdown at the top of the summary, which lists the protocols
separately for exactly this reason — as the "all sessions" base, and read
`readiness['sessions']` as "records produced".

A third denominator effect worth knowing about: **analysing captures together
and separately gives different session counts.** Several captures fed to one
run are finished once at the end, so a flow that spans two files is one
session; the same captures analysed one at a time produce two partial ones.
The second total is always the larger. Neither is wrong. See
[offline-analysis.md](offline-analysis.md#several-captures-and-captures-from-a-pipe).

## The five verdicts

Every algorithm CryptoMon sees gets exactly one of these. The distinction
between the first three is not cosmetic.

| Verdict | Means | Examples |
|---|---|---|
| `post-quantum` | Believed to resist Shor and Grover, standing alone. | ML-KEM-768, ML-DSA, SLH-DSA, Falcon |
| `hybrid` | A post-quantum algorithm combined with a classical one, so it is no weaker than either. | `X25519MLKEM768`, `X25519Kyber768Draft00`, `sntrup761x25519-sha512@openssh.com` |
| `classical` | Broken by Shor. | RSA, ECDSA, EdDSA, DSA, `x25519`, `secp256r1`, `ffdhe2048` |
| `symmetric` | Names no asymmetric primitive at all. | `TLS_AES_256_GCM_SHA384` |
| `unknown` | Not recognised. Counted, never guessed at. | — |

**`hybrid` is its own answer and not a rounding of either neighbour.** Every
post-quantum key exchange in the corpus is hybrid — there is no
post-quantum-only exchange anywhere in it. Reporting those as `post-quantum`
would overstate deployment; reporting them as `classical` would erase the
work. Hybrid is what the industry is actually shipping, because neither half
is trusted alone yet, and it is what your report will be full of.

**`symmetric` is not "unknown".** A TLS 1.3 ciphersuite name says nothing
about the key exchange, because in TLS 1.3 the suite no longer carries it —
the key exchange moved into an extension. `TLS_AES_256_GCM_SHA384` is a
complete and correct suite name that describes only the record-layer cipher
and the hash. Reporting it as unrecognised would read as a gap in the
classification table, which it is not.

**`unknown` is a gap in CryptoMon's table, not a finding about your
traffic.** It is never folded into `classical`.

There is also `none`, which appears where a *session* is being classified
rather than an algorithm: it means no key exchange was performed. It is kept
separate from every verdict for the reason at the top of this page.

### What to do about each

| You see | It means | Priority |
|---|---|---|
| `classical` key exchange | A quantum adversary recording this traffic today can read it once it has a machine. | This is the population you are trying to shrink. |
| `hybrid` key exchange | Already protected against that adversary. | None. Count it. |
| `post-quantum` refused | Your client offered PQ; the far end said no. | **High.** The fix is somebody else's configuration and they may not know. |
| `classical` certificate key | Signature, not confidentiality. A quantum adversary cannot retroactively forge a signature made today. | Lower than key exchange, but it is the migration with the longest tail. |
| `unknown` | CryptoMon does not recognise the name. | Worth reporting as an issue. |

## Key exchange groups

The `kex_group` field, and the "Key exchange" section of the summary.

| Name | Verdict | What it is |
|---|---|---|
| `x25519` | classical | Curve25519 ECDH. The most common by far. |
| `secp256r1`, `secp384r1`, `secp521r1` | classical | NIST P-256/384/521 ECDH. |
| `X25519MLKEM768` | hybrid | X25519 combined with ML-KEM-768 (the standardised Kyber). The one that is winning. |
| `X25519Kyber768Draft00` | hybrid | The same idea with the pre-standard Kyber draft. Its presence dates a client. |
| `ffdhe2048`, `ffdhe3072` | classical | Named finite-field Diffie–Hellman groups. |
| `ffdhe512`, `ffdhe1024` | classical | Not a named group — the size read off a TLS 1.2 ServerKeyExchange, where the prime is sent inline, so the prime's length is the only thing identifying the strength. **512 bits is broken today, by a classical computer.** |
| `finite field DH` | classical | Finite-field DH whose prime length could not be read. |
| `explicit EC parameters` | classical | A server sending curve parameters inline rather than naming a curve. Deprecated for good reason; rare and worth a look. |
| `none` | — | No key exchange. The session resumed. |

Hybrid is decided by finding both a post-quantum and a classical marker in
the same name — `X25519MLKEM768` is X25519 and ML-KEM-768. The post-quantum
markers are matched **and removed** before the classical ones are looked for,
because ML-DSA and SLH-DSA both end in "dsa" and a naive substring match
would report every NIST signature selection as a hybrid of itself and DSA.

## Certificates

```
Certificate keys
  RSA-2048              274
  RSA-4096               84
  EC-384                 18
  EC-256                 13
  quantum-vulnerable    389 of 389
  unreadable (TLS 1.3)  336 sessions
```

The size travels with the algorithm because it is the only thing that makes
the verdict actionable. Every RSA key is broken by Shor, and the ones that
have to be replaced first are not chosen at random.

**`unreadable (TLS 1.3)` is not "no certificate".** In TLS 1.3 the server's
Certificate message travels inside the encrypted handshake flight, so a
passive observer cannot read it. CryptoMon records `certificates_unreadable`
for those sessions rather than reporting nothing, because "not readable" and
"not sent" are different claims and a readiness report that conflated them
would undercount the certificates in use. Expect this number to be large and
to grow.

An `unreadable` label in the *key* column is different again: it means the
certificate was on the wire and did not decode far enough to have a key.

Certificate keys are a slower-burning problem than key exchange. A signature
made today cannot be retroactively forged by a quantum computer in ten years'
time — the signature only has to be unforgeable while it is being relied on.
Key exchange is the opposite: traffic recorded today can be decrypted later.
That is why the headline on the dashboard is about key exchange.

## Symmetric strength

```
"AES_256 (256 bits, 128 after Grover)": 321
"AES_128 (128 bits, 64 after Grover)": 838
"RC4 (broken independently of any quantum computer)": 10
```

Symmetric ciphers are judged separately, because Grover's algorithm halves an
exhaustive search rather than breaking the algorithm. AES-256 retains 128
bits against it; AES-128 retains 64. Calling AES-128 "quantum-vulnerable"
alongside RSA would be wrong by many orders of magnitude.

RC4, 3DES, single DES and NULL get their own label, because reporting RC4 as
"128 bits, 64 after Grover" would answer the wrong question by a wide margin:
it is not waiting for a quantum computer. `broken_symmetric_ciphers` in the
readiness block counts these, and any non-zero value there is a finding today.

## Resumption

`resumption` is one of `resumed`, `fresh` or `unknown`, and
`resumption_evidence` says how it was decided:

| `resumption` | `resumption_evidence` | Strength |
|---|---|---|
| `resumed` | `server selected pre_shared_key` | Unambiguous. In TLS 1.3 that *is* the acceptance. |
| `resumed` | `inferred: abbreviated handshake, no certificate` | Inferred. A TLS 1.2 abbreviated handshake sends no Certificate. Reliable in practice, and labelled so you know which you got. |
| `fresh` | `TLS 1.3 without pre_shared_key` | Unambiguous. |
| `fresh` | `certificate sent` | Unambiguous. |
| `unknown` | `no server hello` / `handshake incomplete in the capture` | The capture did not contain enough. |

Roughly half the corpus resumes (625 resumed, 535 fresh, 100 unknown out of
1260). If your resumption rate is high, the gap between your two
quantum-safe percentages will be wide, and the "of all sessions" figure is
the more honest one to plan against — resumed sessions inherit their security
from an earlier classical exchange.

## `ech` — Encrypted ClientHello

This field sits directly under `hostname` on purpose, because it is the
qualifier on the hostname.

| Value | Means |
|---|---|
| `offered` | The ClientHello carried the extension with the outer type byte. This is what you will see. |
| `accepted` | A ServerHello or HelloRetryRequest echoed it back. |
| `inner` | An inner-hello type byte seen in plaintext. The message is not what it claims to be. |
| `malformed` | The extension did not parse. |

**While servers decline ECH, the hostname you see is the real one. Once they
accept it, it is a public outer name and the real destination is inside the
encrypted inner hello.** A hostname that quietly stops being the hostname is
unlabelled missing data, which is the defect this whole field exists to
prevent: `www.example.com` alone is a claim, `www.example.com, ech=offered`
is an observation with its uncertainty attached.

Two honest negatives:

* **Absence of `accepted` is not evidence of rejection.** A server accepting
  ECH in a ServerHello does not echo the extension at all — the acceptance
  signal is eight bytes of `ServerHello.random` derived from the inner
  transcript, which a passive observer cannot check without the inner hello
  it is derived from. `accepted` is only reachable through a
  HelloRetryRequest echo. Across the corpus, 465 sessions offer ECH and
  **zero** of 1170 ServerHellos echo it.
* **`grease` is never emitted.** A GREASE ECH is by design a well-formed
  outer hello with a random config id and payload, which is exactly what a
  real one looks like from outside. In aggregate this corpus is plainly
  GREASE — all 465 offers carry a plausible plaintext SNI, 150 distinct
  names, none of them a public outer name — but aggregate is not per-session,
  so no session is labelled `grease` rather than labelled wrongly.

## `ja4`, `ja4s` and `ja3` — which client, and which server

`cryptomon.analysis` answers "what was negotiated". It cannot answer "by
whom", and the second question is what turns a number into an action: *"37%
of sessions offer no post-quantum key share"* is a finding, *"and all of it
is two builds of one browser"* is a ticket.

### Reading a JA4

```
t13d1516h2_8daaf6152771_02713d6af862
│││ │ │ │  │            └─ sha256 of the extension list (SNI and ALPN
│││ │ │ │  │                removed, sorted) + "_" + signature algorithms
│││ │ │ │  │                in wire order, truncated to 12 hex characters
│││ │ │ │  └─ sha256 of the sorted ciphersuite list, truncated
│││ │ │ └─ first and last character of the first ALPN value ("h2")
│││ │ └─ 16 extensions, GREASE excluded, SNI and ALPN included
│││ └─ 15 ciphersuites, GREASE excluded
││└─ "d" = SNI present; "i" = absent
│└─ highest version the client *offers* in supported_versions: TLS 1.3
└─ transport: "t" = TCP
```

That exact string is FoxIO's published Chrome fingerprint, reproduced from a
committed fixture — which is the point of it. A fingerprint that matches what
everybody else records is a joinable identifier; one that is merely
self-consistent is not.

Four details of the specification are easy to read past, and each is pinned
by a golden value in the test suite. The extension *count* includes SNI and
ALPN while the extension *hash* excludes them — the count says how talkative
the client is, the hash must not change when it visits a different host over
a different protocol. Signature algorithms are appended in wire order, not
sorted, because a client's preference order is signal while its extension
order (which Chrome randomises per connection) is not. The version is the
highest offered in `supported_versions`, not the legacy version in the
handshake header, which every modern hello sets to TLS 1.2.

### JA4S

```
t130200_1302_a56c5b993250
│││ │   │    └─ sha256 of the server's extensions, in the order it sent them
│││ │   └─ the one cipher the server chose, in hex (0x1302 =
│││ │       TLS_AES_256_GCM_SHA384)
│││ └─ first/last of ALPN, or "00" for none
││└─ 2 extensions
│└─ TLS 1.3
└─ TCP
```

Servers are far less varied than clients — 45 distinct JA4S across 1170
ServerHellos in the corpus — so JA4S is weak alone and strong paired with the
JA4 of the hello it answered. One server answering two clients differently is
the interesting shape.

### Why JA4 and not JA3

Over the same 1260 hellos: **32 distinct JA4 against 393 distinct JA3.** The
340 Chromium sessions that share one JA4 produce 340 distinct JA3s — one per
connection — because Chrome shuffles its extension order and JA3 hashes that
order. `ja3` is still emitted, because Zeek, Suricata, NetworkMiner and a
decade of threat-intel feeds are keyed on it and a record that cannot be
joined to what you already have is less useful than one that can. It is not
to be trusted for anything security-bearing.

**Neither is authentication.** A hello can be replayed byte for byte, and
several tools exist that do exactly that. A JA4 match is evidence about a
client, never proof about a peer.

## Alerts

```
handshake_failure (server)      29
certificate_unknown (client)    11
inappropriate_fallback (server)  2
```

Plaintext TLS alerts seen during a handshake, with the side that sent them.
The direction is the half that carries the finding: merged, "a middlebox
refused our key share" and "we refused their parameters" are the same row.

**The correlation this exists for** is a post-quantum group offered followed
by a fatal `handshake_failure`. Where that is a server — or, more often, a
middlebox between the two — that cannot cope with a ClientHello carrying a
kilobyte of ML-KEM key share, it is the most actionable thing a readiness
survey produces, because the fix is somebody else's configuration and they do
not know yet.

In this corpus it is not that. All 24 correlated failures are
`dh512.badssl.com` and `dh1024.badssl.com`, deliberately weak test servers,
and the post-quantum offer is incidental — 448 of the 1260 sessions offer
one, because current browsers offer one on every connection. The correlation
is the right thing to compute and this corpus does not contain the
intolerance it looks for. Yours might.

**An empty alerts panel is not evidence that connections closed cleanly.**
`close_notify` is sent under the negotiated keys, and CryptoMon stops reading
a stream at the first encrypted record, so every plaintext alert it can see
is by construction one sent *during* a handshake. `close_notify` never
appearing is a property of where the observer stands, not of the network.

## `hello_retry_request`, `offered_kex_group`, `retry_kex_group`

When these three appear together, you are looking at the single most useful
finding in a readiness survey:

```
hello_retry_request: true
offered_kex_group:   X25519Kyber768Draft00
retry_kex_group:     secp256r1
kex_group:           secp256r1
```

The client offered a post-quantum hybrid. The server sent a
HelloRetryRequest naming a classical curve instead, and the connection
completed on that. In the summary these are collected under:

```
Post-quantum offers refused by the server (61)
  X25519Kyber768Draft00 -> secp384r1   x48
  X25519Kyber768Draft00 -> secp256r1   x11
  X25519MLKEM768 -> secp256r1   x1
  X25519MLKEM768 -> secp384r1   x1
```

A tool that sees only the first ClientHello reports "post-quantum key
exchange offered" and never records that it was turned down. That is the
opposite of what happened, and it is why the offline analyser reassembles
before it parses. Only `pcapscan` can see this; the live sensor cannot.

## TLS versions

`deprecated (RFC 8996)` counts TLS 1.0 and TLS 1.1, which are deprecated
outright. The corpus has 30 such sessions. This is an immediate finding, not
a quantum one, and it usually travels with the weak symmetric ciphers above.

## The readiness block, field by field

`summary.readiness` in the JSON and the report page. Every number here is a
count of sessions unless it says otherwise.

| Field | Means |
|---|---|
| `sessions` | Every record the run produced, **across every protocol** — including cleartext UDP flows that were never going to negotiate anything. Not a base for any percentage here; use `protocols['tls']`. |
| `key_exchanges_performed` | TLS sessions where a key exchange happened. **The denominator for `quantum_safe_fraction`.** |
| `no_key_exchange` | The rest of the TLS sessions. Resumed, or the capture did not contain the exchange. `key_exchanges_performed + no_key_exchange` is the TLS session count, not `sessions`. |
| `post_quantum`, `hybrid`, `classical`, `unknown` | Sessions by key-exchange verdict. |
| `quantum_safe_fraction` | `(post_quantum + hybrid) / key_exchanges_performed`. `null` when nothing performed one. |
| `post_quantum_refused` | HelloRetryRequests that downgraded a PQ offer to a classical group. |
| `certificates_quantum_vulnerable` | Certificate keys judged classical. Counted per certificate, not per session — a chain contributes several. |
| `certificates_post_quantum` | The same for PQ signature keys. Expect 0 for now. |
| `certificates_unreadable` | Sessions whose certificate was inside a TLS 1.3 encrypted flight. |
| `ech_offered`, `ech_accepted` | See above. `ech_accepted` is almost always 0 and that is not evidence of rejection. |
| `deprecated_tls_versions` | TLS 1.0 and 1.1 sessions. |
| `broken_symmetric_ciphers` | Sessions using RC4, 3DES, DES or NULL. Broken today. |
