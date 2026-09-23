# The live sensor

```bash
sudo python3 ./cryptomon.py -i eth0
```

The half of CryptoMon that watches an interface. It loads an eBPF program
into the kernel, has the kernel hand it the packets that look like the start
of a TLS or SSH handshake, parses those in Python, and writes one document
per parsed frame into MongoDB.

Linux only, and it needs root (or the capability set below), bcc, kernel
headers matching the running kernel, and a database. [install.md](install.md)
covers getting those. If you want an answer about a *capture file*, use
[the offline analyser](offline-analysis.md) — it needs none of this and sees
more.

> **Not verified on this machine.** Everything on this page that needs a
> kernel is read from the code, its comments, the project's commit history
> and [`docker/README.md`](../docker/README.md), which records where its own
> measurements were taken. These pages were written on macOS. The two
> failures quoted below with `$` prompts were reproduced here, because both
> happen before any kernel call.

## Flags

```
python3 ./cryptomon.py [-i IFACE] [--pcap FILE] [-tc]
```

| | |
|---|---|
| `-i`, `--interface` | The interface to attach to. |
| `--pcap FILE` | Replay a capture over loopback instead of monitoring. Forces `-i lo`. |
| `-tc`, `--traffic-control` | Attach through traffic control instead of a raw socket. |

**`-i` is effectively required.** Without it the script lists the interfaces
it found and prompts with `input()` for a number. That is fine at a terminal
and fatal under systemd, where there is no terminal and the prompt raises
`EOFError` — the unit then dies on every start with a traceback that says
nothing about a missing interface. `deploy/systemd/sensor.env.example` makes
`CRYPTOMON_IFACE` required for that reason. Note also that the README used to
say the interface defaults to `enp0s1`; it does not. The default lives on the
`CryptoMon` class, and `cryptomon.py` always passes whatever `-i` or the
prompt produced.

### The two attach modes

| | How | Needs |
|---|---|---|
| default (`library`) | `BPF.SOCKET_FILTER` on a raw `AF_PACKET` socket | `CAP_NET_RAW` |
| `-tc` | `BPF.SCHED_CLS` on a `clsact` qdisc, interface set `IFF_PROMISC` | `CAP_NET_ADMIN`, and `python3-pyroute2` |

The comment in the code says most physical Ethernet devices need TC to sniff
properly; the raw-socket mode is the older path and the default. `-tc` also
puts the interface into promiscuous mode and adds a qdisc, and removes its
filter again on a clean shutdown.

Without `pyroute2` the TC mode fails with a message that names the package:

```
Exception: pyroute2 is not available, so load_method='tc' cannot attach to
the interface. Install it from your distribution (`apt-get install
python3-pyroute2`), or use load_method='library' to attach a raw socket
instead.
```

### Capabilities, if you would rather not run it as root

Measured — not read off `capability(7)` — in the project's sensor container:

| | |
|---|---|
| `CAP_BPF` | loading the program and creating the perf-event map |
| `CAP_PERFMON` | `perf_event_open(2)`, the ring buffer that carries frames to userspace |
| `CAP_NET_RAW` | the `AF_PACKET` socket the default mode attaches to |
| `CAP_NET_ADMIN` | `-tc` only: the qdisc, the filter, and `IFF_PROMISC` |

The row worth remembering is `CAP_BPF` + `CAP_NET_RAW` without
`CAP_PERFMON`: the program loads, attaches, and delivers nothing — which
looks exactly like a quiet network. `docker/README.md` has the full table,
including what each missing grant says when it fails.

## What the kernel program does

The filter is C, generated at import from `cryptomon/ports.py` so that
changing the watched ports is an environment variable rather than an edit to
a string literal. It:

* reads every offset from the packet rather than assuming any of them — the
  ethertype decides the family, stacked VLAN tags are stepped over, the IPv4
  header length comes from IHL, and for IPv6 the extension-header chain is
  walked, because IPv6 moved options out of the fixed header and there is no
  length field to read;
* refuses non-initial IPv6 fragments, which carry no transport header;
* is **TCP only**. It previously let UDP and ICMP through to the port checks
  and then read a TCP data offset out of them, which decoded into nothing;
* checks the destination or source port against `TLS_PORTS` or `SSH_PORTS`;
* and forwards the frame only if the TCP payload *starts with* a TLS
  handshake record (`0x16`, major 3, minor 1–4) or an SSH banner.

That last condition is the whole reason the live path sees less than the
offline one. See [architecture.md](architecture.md).

The filter has no test that pytest can reach, because a mistake in it does
not produce a wrong answer — it produces a service that will not start, which
is [issue #26](troubleshooting.md#bcc-will-not-install-or-will-not-compile-issue-26)
exactly. Two tools exist instead, both runnable in a container and both CI
jobs: `tests/tools/check_bpf.py` compiles the program and loads it past the
verifier in both attach modes, and `tests/tools/check_bpf_behaviour.py`
attaches it to loopback and replays the committed framing fixtures. Both read
`bpf.py` straight from its path rather than importing the package, so neither
needs the runtime dependencies.

A malformed `TLS_PORTS` raises at import, before any of this — the traceback
ends:

```console
$ TLS_PORTS=443,https python3 ./cryptomon.py -i eth0
ValueError: TLS_PORTS: 'https' is not a port number
```

and without bcc, the monitor says so in as many words:

```console
$ python3 ./cryptomon.py -i eth0
Exception: bcc is not available, so the live monitor cannot start. It is
Linux-only and comes from your distribution rather than pip: run
ubuntu-setup.sh, or `apt-get install bpfcc-tools python3-bpfcc`. Parsing a
capture offline does not need it.
```

(Both need `DB_URL` and `DB_NAME` set, because `cryptomon.py` imports
`fapi.config`, which validates them first.)

## What it writes

One document per parsed frame, with `ptype` of `client` or `server`, and `ts`
set at insertion rather than from the packet. That is a different shape from
what the offline analyser produces — one document per *session* with `ptype`
of `session` and `ts` from the capture — and both shapes can share a
collection. `/stats/overview`'s `by_ptype` is how a reader tells which one
they are looking at.

Writes are issued through motor without blocking the packet path, and the
future is kept so the result is retrieved. That matters: motor 3.5.1 returns
an already-scheduled future, so the write goes out even when nothing awaits
it — but the result was then discarded, and with it every authentication
failure, network error and duplicate key. Failures are now counted in
`cryptomon.WRITE_STATS` and the first of each kind is printed once.

At most 1000 inserts may be in flight. Past that, new records are **dropped**
and counted as `dropped_backpressure`, because a burst of handshakes must not
be allowed to queue futures without bound. If you are seeing gaps, that
counter is the first thing to look at.

`tag` — the field the dashboard's capture filter uses — comes from the
`data_tag` constructor argument. `cryptomon.py` passes an empty string, so
nothing the shipped command line writes is ever tagged. To tag a run you have
to drive `CryptoMon` as a library, or add the field during a `mongoimport` of
offline output (see [offline-analysis.md](offline-analysis.md#ndjson-and-the-point-of-it)).

There is a TinyDB backend, selected by constructing `CryptoMon(mongodb=False)`
and writing to `cryptomon.json` in the working directory. `cryptomon.py`
always passes `mongodb=True`, so it is reachable from Python and not from the
command line.

## What it cannot see

The live path receives one frame at a time, with no reassembly, so it can
only read a handshake that starts at the beginning of a TCP payload and
finishes inside the same packet. Concretely, across the eleven corpus
captures it reported 411 "client hellos" of which **272 were truncated
records parsed as though they were whole** — not missed, reported, incomplete
and without saying so. Certificates were worse: 15 fragments against 93 whole
chains from the offline path.

It also cannot see:

* **Traffic on ports it is not watching.** 13 of 1369 TLS flows in the corpus
  (0.95%) are on ports the filter does not watch — twelve on 53443, one on
  888. The offline analyser has no port filter and finds them.
* **A segment where a ChangeCipherSpec record sits ahead of the handshake**,
  because the filter tests only the first three bytes of the payload. That is
  a measured 7% of the corpus.
* **The second half of a HelloRetryRequest**, so a post-quantum key exchange
  the server *refused* is indistinguishable from one it accepted.
* **Anything over UDP.** The kernel filter reads IP protocol 6 and nothing
  else, so UDP never reaches userspace on this path. The offline analyser
  does read it.
* **Encapsulated traffic.** A SPAN or ERSPAN feed arriving on a monitored
  interface is IP protocol 47, which the filter refuses, so a mirror port
  produces no events. The offline analyser unwraps it.
* **DTLS**, in either path.

None of this is a defect in the filter. It is what a kernel filter that sees
one packet at a time can do, and it is why the offline analyser exists.

## Running it as a service

`create-service.sh` installs two systemd units — the sensor, which needs
`CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN` and a network interface, and the
API, which needs neither — and starts neither of them, so that you can read
the unit files and put the database password in place first.

```bash
sudo ./create-service.sh --nginx
```

[deploy/README.md](../deploy/README.md) is the reference for
what it installs and why, including the one systemd hardening directive that
is deliberately absent: `SystemCallFilter=~@resources` appears in nearly
every hardening guide and contains `setrlimit`, which `pcapscan.sandbox`
calls on itself to bound an upload. Filtered, every analysis would run with
no memory and no CPU ceiling, reports would still come out correct, and the
only symptom would be that the protection the upload path is built on is
gone.
