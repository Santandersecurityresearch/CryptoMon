[![CodeQL](https://github.com/Santandersecurityresearch/CryptoMon/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Santandersecurityresearch/CryptoMon/actions/workflows/github-code-scanning/codeql)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# CryptoMon

Network cryptography monitor, in Python and eBPF.

**This code is pre-production and is intended for demonstration purposes.**

CryptoMon answers one question: *what cryptography is actually in use on this
network, and what fraction of it would survive a quantum computer.* It reads
TLS and SSH handshakes — off the wire with an eBPF filter, or out of a packet
capture — works out what each connection negotiated, and reports how much of
it rests on RSA and elliptic-curve Diffie-Hellman, both of which Shor's
algorithm breaks.

It is the counterpart to the [CodeQL source-code
analysis](https://github.blog/2023-12-05-addressing-post-quantum-cryptography-with-codeql/)
we published previously. Static analysis tells you what your code *could*
negotiate. Traffic tells you what it *did* negotiate, against real servers,
with real middleboxes in the way, after whatever the deployment turned off.
The two disagree in both directions, and the disagreement is the interesting
part.

## What it tells you

A committed 24-packet fixture, so this is exactly reproducible:

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

One connection, and the finding this tool exists to produce. The client
offered a post-quantum hybrid group. The server refused it with a
HelloRetryRequest and named a classical curve instead, so the traffic that
followed can be decrypted by anyone who records it and waits for a quantum
computer. A reader that saw only the first ClientHello would have reported
"post-quantum key exchange offered" — the opposite of what happened.

Point it at a real capture and you get the same report over thousands of
connections. Across the twelve corpus captures of everyday desktop
application traffic, measured with the parsers installed at the time of
writing: 624 key exchanges performed, 116 of them a post-quantum hybrid
(18.6%), 508 classical, and 61 post-quantum offers refused by the far end.
Every certificate key in the corpus is classical.

[docs/reading-a-report.md](docs/reading-a-report.md) explains the rest of it,
starting with why `15.3%` is quoted *of key exchanges performed* and never on
its own.

## Which of these are you?

Three ways to run this, and they have almost nothing in common. Read the
right-hand column and pick the first row that is true of you.

| | You need | Use it when |
|---|---|---|
| **[Docker](docs/install.md#docker)** | Docker, and nothing else | You want an answer about a capture file and do not want to install anything. |
| **[The offline analyser](docs/install.md#the-offline-analyser)** | Python 3.10+, no root, no database | You have captures. This is the whole tool for most people and it sees more than the live sensor does. |
| **[The live sensor](docs/install.md#the-live-sensor)** | Linux, bcc, kernel headers, root, MongoDB | You want a continuous picture of a network rather than an answer about a file. |

If the live sensor is what you want and `bcc` will not install, that is
[issue #26](docs/troubleshooting.md#bcc-will-not-install-or-will-not-compile-issue-26),
and it is the most common way to get stuck here. The offline analyser needs
none of it and answers the same question about a capture.

### A capture, analysed, with nothing installed

```bash
docker build -f docker/Dockerfile.offline -t cryptomon-offline .

docker run --rm --network none --read-only \
    -v "$PWD:/captures:ro" cryptomon-offline /captures/your-capture.pcap
```

The image runs as a non-root user with a read-only filesystem and no network
at all, and contains no database, no eBPF and no kernel headers.
[`docker/README.md`](docker/README.md) covers the other two images — the API
and the sensor — the compose stack, and the capability list the sensor needs.

### A capture, analysed, with Python

```bash
pip install cryptography
python -m pcapscan your-capture.pcap
```

No root, no eBPF, no interface, no database, on any platform Python runs on.
`cryptography` is the only third-party package it uses, and it is used for
one thing: parsing the X.509 chain. Without it the analyser still runs and
the certificate section of the report is silently empty — see
[docs/troubleshooting.md](docs/troubleshooting.md#the-report-has-no-certificates-in-it).
See [docs/offline-analysis.md](docs/offline-analysis.md) for the output
formats and the pipelines — NDJSON into MongoDB, CycloneDX CBOM, several
captures at once, reading from a pipe.

### The service, the dashboard and the upload page

```bash
export DB_URL="mongodb://127.0.0.1:27017/cryptomon"
export DB_NAME="cryptomon"
python api.py
```

Then `http://127.0.0.1:8000/`. The dashboard is at `/`, the browser upload
page at `/analyse/`, the JSON rollups at `/stats/` and the raw documents at
`/data/`. It binds loopback, and writes are refused, until you say
otherwise. See [docs/service.md](docs/service.md), and
[deploy/README.md](deploy/README.md) before you put it in front of anybody.

### The live sensor

```bash
sudo ./ubuntu-setup.sh      # read it first; see docs/install.md
sudo python3 ./cryptomon.py -i eth0
```


Linux only. [docs/live-sensor.md](docs/live-sensor.md) covers what it can and
cannot see, and [deploy/README.md](deploy/README.md) covers running it as a
service under systemd with nginx in front.

## What it reads

TLS handshakes of every version, on any TCP port for the offline analyser and
on a [configurable list](docs/configuration.md#which-ports-the-sensor-watches)
for the live sensor: the versions and ciphersuites proposed and selected, the
key exchange group, the server name, ALPN, PSK modes, Encrypted ClientHello,
JA4/JA4S fingerprints, plaintext alerts and the direction they came from, and
X.509 certificate chains where the handshake is not encrypted. SSH KEXINIT
algorithm lists, banners, and host key type and size — though there is no SSH
traffic in this project's capture corpus, so that half is checked against
constructed fixtures and real OpenSSH-encoded keys rather than against
captured sessions.

The offline analyser also reads what arrives over **UDP** — 30,530 datagrams,
19% of the corpus, used to be dropped at the framing layer and now reach a
dispatcher — and unwraps **mirrored and tunnelled traffic** (GRE, ERSPAN,
VXLAN, GENEVE, IP-in-IP) before it frames anything, so a capture taken off a
switch's mirror port reports what it carries. The individual UDP protocol
handlers are landing as this is written; see
[docs/offline-analysis.md](docs/offline-analysis.md#mirrored-and-tunnelled-traffic).
Neither applies to the live sensor, whose kernel filter reads TCP and nothing
else.

## What it does not read

Being clear about this is more useful than a feature list.

* **Anything inside a TLS 1.3 encrypted flight.** The certificate in TLS 1.3
  travels under the handshake keys. CryptoMon records `certificates_unreadable`
  for those sessions rather than reporting no certificate, because "not
  readable" and "not sent" are different claims.
* **DTLS.** No support, in either path.
* **Encrypted traffic.** There is no decryption anywhere in this project. It
  reads the parts of a handshake that are, by design, in the clear.
* **The inner name of an accepted ECH connection.** When a server accepts
  Encrypted ClientHello the server name on the wire is a public outer name.
  The record says `ech: offered` or `ech: accepted` so that the hostname
  carries its own caveat.

## Documentation

| | |
|---|---|
| [docs/install.md](docs/install.md) | The three install paths, honestly, including what `ubuntu-setup.sh` actually does |
| [docs/configuration.md](docs/configuration.md) | Every setting, its default, its effect, and when to change it |
| [docs/offline-analysis.md](docs/offline-analysis.md) | `python -m pcapscan`: formats, flags, pipelines |
| [docs/service.md](docs/service.md) | The API, the dashboard, the upload page and `/stats` |
| [docs/live-sensor.md](docs/live-sensor.md) | The eBPF sensor: what it sees and what it costs |
| [docs/reading-a-report.md](docs/reading-a-report.md) | What `X25519MLKEM768`, `hybrid`, `t13d1516h2_…`, `resumed` and `ech: offered` mean |
| [docs/architecture.md](docs/architecture.md) | Why there are two parsing paths, and what each one can see |
| [docs/troubleshooting.md](docs/troubleshooting.md) | The things that go wrong, and what they look like |
| [deploy/README.md](deploy/README.md) | nginx, systemd, subpath mounting, hardening |
| [docker/README.md](docker/README.md) | The three images, capabilities, compose |
| [tests/README.md](tests/README.md) | How the test suite is built and why |

## One number, two denominators

The headline this tool produces is a percentage, and a percentage here is
meaningless without the base it is taken over. Across the project's twelve
capture corpus, 81 key exchanges used a post-quantum hybrid group. That is
**14.4% of the 564 sessions that performed a key exchange**, and **6.4% of
the 1260 TLS sessions**, because a resumed session performs no key exchange
at all and 696 of those 1260 performed none. Both numbers are true, they are
not the same claim, and which one is right depends on the question.

The base has to be named, not assumed, and that is not a stylistic
preference — it is load-bearing. The same run also produces a record for
every cleartext UDP flow it identifies, and on this corpus those outnumber
the TLS sessions: dividing 116 by *that* total gives a smaller percentage
that measures nothing at all, because a DNS lookup was never going to
negotiate a key exchange. Every figure this project prints carries its base
beside it.
[docs/reading-a-report.md](docs/reading-a-report.md) explains why that
matters more than any other idea here.

## Software Bill of Materials

We are firm supporters of the SBOM movement, as it is a key building block in
software security and supply chain risk management. `bom.json` in this
repository is CryptoMon's own SBOM.

Two things about it are worth knowing. It records the PyPI package `bcc`,
which is **not** what the eBPF sensor uses — the sensor uses the
distribution's `python3-bpfcc`, an unrelated package, as
[`docker/README.md`](docker/README.md#what-it-installs-for-the-sbom) records.
And a CBOM produced by this tool from observed traffic
(`python -m pcapscan capture.pcap -f cbom`) is a different document with a
different job: it inventories the cryptography on the *network*, not the
dependencies of *this software*.

![](img/sbom1.png)
![](img/sbom2.png)
![](img/sbom3.png)
![](img/sbom4.png)

## Licence, citation and security

GPL v3 — see [LICENSE](LICENSE). To cite this work, see
[CITATION.cff](CITATION.cff). To report a vulnerability, see
[SECURITY.md](SECURITY.md).
