# CryptoMon in containers

Three images, because CryptoMon is three things that need three different
amounts of trust from the machine they run on.

| image | what it does | privileges |
|---|---|---|
| `Dockerfile.offline` | reads a capture, prints what cryptography it negotiated | none: non-root, `--read-only`, `--network none` |
| `Dockerfile.api` | the query API and the browser upload UI | non-root, no capabilities, one writable volume |
| `Dockerfile.sensor` | the live eBPF monitor | root, four capabilities, host network |

**The MongoDB password in `compose.yaml` is a placeholder, not a password.**
It is `change-me-this-is-not-a-password`, written out in full so that it
cannot be mistaken for a generated secret. It is adequate for an evaluation
on your own machine, where nothing listens outside `127.0.0.1`, and it is
adequate for nothing else. Before this stack is reachable by anybody but
you: `cp env.example .env`, put a real password in `MONGO_PASSWORD`, and set
`API_KEY`.

---

## Start here: a capture, in one command, with nothing installed

```bash
docker build -f docker/Dockerfile.offline -t cryptomon-offline .

docker run --rm --network none --read-only \
    -v "$PWD:/captures:ro" \
    cryptomon-offline /captures/your-capture.pcap
```

That is the whole of it. No `apt-get`, no bcc, no kernel headers, no
MongoDB, no root, and nothing from `ubuntu-setup.sh`. The image is 164 MB,
of which 150 MB is `python:3.11-slim` itself.

Every flag `python -m pcapscan --help` lists works, because the image *is*
that command:

```bash
# a CycloneDX cryptographic bill of materials
docker run --rm -v "$PWD:/captures:ro" cryptomon-offline \
    /captures/*.pcap -f cbom > cbom.json

# NDJSON in the same document shape the live monitor writes
docker run --rm -v "$PWD:/captures:ro" cryptomon-offline \
    /captures/*.pcapng -f ndjson | mongoimport --collection cryptomon
```

Writing a report back out to the mount needs the container to be you:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/captures" \
    cryptomon-offline /captures/x.pcap -f csv -o /captures/report.csv
```

### What is in the image

`pcapscan/`, `cryptomon/`, and one third-party package: `cryptography`, at
the version `requirements.txt` pins. Nothing else. There is no shell script,
no database driver, no web framework and no capture — the capture is
yours and arrives on a bind mount.

`cryptography` is there although `import pcapscan` does not need it, because
without it `pcapscan.certificates` cannot be imported and the certificate
chain is dropped on the floor — quietly, since carrying the raw DER onwards
is the right behaviour for a chain that was encrypted anyway. Over
`tests/fixtures/streams/tls12_certificate.pcap`, a capture with two RSA-2048
certificates in it, that costs:

```
with cryptography                       without
  Certificate keys                        (the section is absent)
    RSA-2048              2
    quantum-vulnerable    2 of 2
  certificate-key RSA-2048   classical 2  (absent)
  signature sha256WithRSAEncryption    1  (absent)
  signature sha384WithRSAEncryption    1  (absent)
```

A CBOM that omits every certificate key does not read as incomplete, it
reads as an estate with no certificate keys. The 13 MB is worth it. If you
disagree — `--build-arg CERTIFICATES=0` builds the 151 MB standard-library-only
image, and the runtime flag `--no-certificates` asks for the same
degradation per run.

---

## The stack: MongoDB and the API

```bash
cd docker
cp env.example .env          # then edit MONGO_PASSWORD
docker compose up --build
```

Then:

* <http://127.0.0.1:8000/analyse/> — upload a capture, get a report
* <http://127.0.0.1:8000/docs> — the API browser
* <http://127.0.0.1:8000/data/count> — how many session documents are stored

Both published ports bind `127.0.0.1`. MongoDB is published too, on
`127.0.0.1:27017`, because `mongosh` from the host is how this project's own
documentation says to look at the data and because the sensor profile
(below) runs with host networking and cannot resolve a compose service name.
Set `MONGO_PORT=` empty in `.env` if you want neither.

### Exposure

Everything above is safe because nothing listens outside loopback. Three
ways to change that, in increasing order of regret:

* **`API_BIND=0.0.0.0`** publishes the API on every interface of the host.
  On Linux, docker's forwarding rules are applied *before* the host
  firewall's `INPUT` chain, so a firewall you thought was in front of this
  is not. **Set `API_KEY` first.** `READ_ONLY` is true by default so a bare
  exposure leaks reads rather than writes, but `/analyse` will still spend
  your CPU and your disk for whoever finds it.
* **`MONGO_BIND=0.0.0.0`** publishes the database itself, with whatever is
  in `MONGO_PASSWORD`. If that is still the placeholder, you have published
  an open database.
* **`--network host` on the api service** puts the API exactly where PR-10
  found it: bound to every interface with unauthenticated writes available.
  Don't.

`HOST=0.0.0.0` *is* set inside the api image, and that is not the same
mistake. `fapi.config` defaults `HOST` to `127.0.0.1` because on a host that
means "not reachable"; inside a container it means "not reachable even by
`docker run -p`", so the image binds all of the container's interfaces and
the container's network namespace becomes the boundary instead. The boundary
did not go away, it moved out one layer — to the `ports:` line, which binds
loopback.

### If the API exits immediately

```
pydantic_core._pydantic_core.ValidationError: 2 validation errors for Settings
DB_URL   Field required
DB_NAME  Field required
```

Neither has a default, anywhere, on purpose: `fapi.config.DatabaseSettings`
declares them required so that a misconfigured deployment refuses to start
rather than connecting somewhere unintended. `docker compose` sets both.
A bare `docker run` must:

```bash
docker run --rm -p 127.0.0.1:8000:8000 \
    -e DB_URL='mongodb://cryptomon:...@host.docker.internal:27017/?authSource=admin' \
    -e DB_NAME=cryptomon \
    cryptomon-api
```

### Where uploads and reports go

`UPLOAD_DIR=/var/lib/cryptomon/uploads`, a declared volume rather than a
directory in the container's writable layer — so it survives
`--force-recreate` and a report link somebody shared still resolves, and so
that it does not grow the container instead.

A report holds the SNI of every connection in the capture, which is browsing
history. Uploaded captures are deleted the moment they are analysed; reports
are swept after `REPORT_RETENTION_HOURS` (24 by default) whether or not
anybody has looked at them. `docker volume rm cryptomon_api-uploads` throws
away every stored report without touching the monitoring database.

---

## The sensor

```bash
SENSOR_IFACE=eth0 docker compose --profile sensor up
```

Opt-in, and in a profile rather than in the default set, because it needs
host networking and elevated capabilities and the first thing anybody should
be able to do with this project is analyse a capture, which needs neither.

### Does eBPF work on this host at all?

```bash
docker build -f docker/Dockerfile.sensor -t cryptomon-sensor .
docker run --rm --cap-add BPF cryptomon-sensor
```

```
cryptomon-sensor: BCC_KERNEL_SOURCE=/usr/src/linux-headers-6.8.0-142-generic
kernel 6.12.76-linuxkit, headers /usr/src/linux-headers-6.8.0-142-generic
program: 5633 chars, 150 lines
OK    compiles
OK    verifies as SOCKET_FILTER (fd=5)
OK    verifies as SCHED_CLS (fd=5)
```

That is the image's default command. It compiles the kernel filter and puts
it past the verifier in both attach modes, touching no interface and no
database. This is issue #26 made answerable in one command: if it prints
`OK compiles` and two `OK verifies`, the kernel half of CryptoMon works here
and any remaining problem is configuration.

### What the host must provide

* **A Linux kernel with BPF enabled.** A container shares the host's kernel.
  No image can give a kernel eBPF it does not have.
* **Kernel version 5.8 or newer** for `CAP_BPF` and `CAP_PERFMON` to exist
  as separate capabilities. On anything older the only grant available is
  `CAP_SYS_ADMIN`, and that is an argument for a newer kernel rather than
  for `--privileged`.
* **`--ulimit memlock=-1` on kernels before 5.11**, where BPF map memory was
  charged against `RLIMIT_MEMLOCK`. The failure without it is an opaque
  `EPERM` from `bpf(BPF_MAP_CREATE)`.
* **`--network host`** to see the host's interfaces. Without it the sensor
  watches the container's veth pair and reports a very quiet network.

On macOS and Windows "the host" is Docker Desktop's Linux VM. The program
compiles, verifies, attaches and receives frames — in that VM, on that VM's
interfaces. That is enough to check the kernel filter and no use at all for
monitoring your laptop's traffic.

### Capabilities, and why not `--privileged`

`--privileged` is the lazy answer: it grants every capability, drops the
seccomp profile and hands over the host's devices, so the container can load
a kernel module, write to any block device and read any process's memory —
on a machine whose reason for running this software is that somebody cares
what is on the wire. The four it actually needs:

| capability | what needs it |
|---|---|
| `CAP_BPF` | `bpf(2)`: loading the program, creating the perf-event map. Split out of `CAP_SYS_ADMIN` in 5.8. |
| `CAP_PERFMON` | `perf_event_open(2)`, which opens the ring buffer that carries packets to userspace. Also 5.8. |
| `CAP_NET_RAW` | the `AF_PACKET` socket that `load_method="library"` attaches the filter to. Already in docker's default set; named so that `--cap-drop ALL --cap-add …` works. |
| `CAP_NET_ADMIN` | `load_method="tc"` only: the `clsact` qdisc, the ingress filter, and `IFF_PROMISC`. |

**Measured, not guessed** (Docker Desktop's VM: engine 29.6.2, linux/arm64,
kernel 6.12.76-linuxkit, 2026-09). Each grant prevents a different failure,
and the interesting one is the third row — the program loads and attaches
and nothing reaches userspace, which looks exactly like a quiet network:

| granted | what happens |
|---|---|
| nothing added | `could not open bpf map: skb_events, error: Operation not permitted` — before it compiles |
| `BPF` | selftest passes: compiles, verifies as `SOCKET_FILTER` and as `SCHED_CLS`. Not enough to run. |
| `BPF` + `NET_RAW` | `Exception: Could not open perf buffer` |
| `BPF` + `PERFMON` | `Failed to open raw device b'lo': Operation not permitted` |
| `BPF` + `PERFMON` + `NET_RAW`, with `--cap-drop ALL` | every synthetic framing fixture behaves as intended |

That last row is `tests/tools/check_bpf_behaviour.py` — the program attached
to `lo` for real, with all eight framings forwarded or dropped as expected.

**Not verified:** the TC path (`load_method="tc"`, the `-tc` flag) against a
physical NIC. `CAP_NET_ADMIN` is listed from what `pyroute2` asks the kernel
for, not from a run — this was built on a Mac and there is no physical NIC
in reach of it.

`--security-opt no-new-privileges` is set in `compose.yaml` and costs
nothing here.

### The container runs as root, unlike the other two

Deliberately. Docker places `--cap-add` capabilities in the *permitted* set
of the initial process; a non-root uid inherits none of them across `execve`
because docker does not set ambient capabilities. A non-root sensor would be
a container that looks safer and cannot load its program. The mitigation
that is real is the short capability list above, not a `USER` line that
would have to be undone.

### What it installs, for the SBOM

```
apt:  python3  python3-venv  python3-bpfcc  python3-pyroute2
      linux-headers-generic  libcap2-bin
pip:  requirements.txt, unchanged
```

`python3-bpfcc` is the eBPF dependency. It is **not** the PyPI package
`bcc`, which is unrelated and which `bom.json` currently records — that is a
known defect in the SBOM and this image is where the truth about it now
lives.

`python3-pyroute2` is from apt for the same reason bcc is: Linux-only, from
the distribution, and deliberately absent from `requirements.txt` so that
the test suite and the offline tools import on a machine that has neither.

---

## `.dockerignore`

All three images build with the repository root as their context. Measured
over this repository's working tree: without the root `.dockerignore` that
context is **1.86 GB** and takes 16.3 seconds to transfer; with it,
**844 kB** and under a tenth of a second. The difference is `CryptomonData/`
(240 MB of packet captures plus the 240 MB of zips they came out of),
`sandbox/` (13 MB more captures and a 690 MB monitor dump), and 570 MB of
git history.

Two things worth knowing about that number:

* BuildKit is cleverer than the figure suggests. When a Dockerfile's `COPY`
  lines name specific paths, as all three of these do, BuildKit transfers
  only those paths and the full-context cost is never paid. Measured: the
  offline image against an un-ignored 1.86 GB context still transferred only
  1.09 MB. The 1.86 GB is what the classic builder pays, what any
  `COPY . .` pays, and what the first careless line added to any of these
  files would pay.
* Which is why the file is a disclosure control first and a speed
  optimisation second. `COPY . .` copies whatever is lying in the working
  tree, and in this repository that is other people's packet captures and
  MongoDB dumps. A capture's SNI field is browsing history. A layer expires
  never and is pushed to whichever registry somebody points at it.

`**/*.pcap` excludes the committed test fixtures too. No image reads a
capture from inside itself; the offline analyser is given one on a bind
mount, which is also the only way it can be given one that is not in this
repository.

---

## Sizes and build times

Measured on linux/arm64 (Apple silicon, Docker Desktop 29.6.2), cold build
cache but base images already pulled:

| image | size | build | of which is the base image |
|---|---|---|---|
| `cryptomon-offline` | 164 MB | 3.9 s | 150 MB (`python:3.11-slim`) |
| `cryptomon-offline` (`--build-arg CERTIFICATES=0`) | 151 MB | 3.5 s | 150 MB |
| `cryptomon-api` | 254 MB | 14.8 s | 150 MB |
| `cryptomon-sensor` | 598 MB | 43.4 s | 101 MB (`ubuntu:24.04`) |

`docker compose up -d` from nothing — pulling `mongo:7.0`, creating two
volumes and a network, waiting for MongoDB's health check and starting the
API — took 51 seconds.

The sensor is large because `linux-headers-generic` and `python3-bpfcc`
are large, and neither is optional: bcc compiles the program at load time
and needs headers it can parse. That is the price of the image that makes
`ubuntu-setup.sh` unnecessary.

---

## Reproducibility and architecture

Both base images are pinned by digest — `python:3.11-slim` (3.11.16, Debian
trixie) and `ubuntu:24.04`. Both digests are OCI image *indexes* covering
`linux/amd64` and `linux/arm64`, checked with `docker buildx imagetools
inspect` rather than assumed, so the pin fixes the contents without fixing
the architecture.

Nothing in these files is architecture-dependent. They name no architecture,
download no binary by URL and compile no C at build time; every pin in
`requirements.txt` has a manylinux wheel for both architectures at the
version pinned. They were built and run on **linux/arm64** (Apple silicon,
Docker Desktop), so the amd64 path is unexercised rather than unsupported —
`--platform linux/amd64` is the way to find out.

To bump a base image, replace the digest in both stages of the file at once;
a stale build stage against a fresh runtime stage is a mismatch that shows
up as a missing shared library months later.
