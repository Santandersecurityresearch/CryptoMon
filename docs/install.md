# Installing CryptoMon

Three paths, and they are not variations on one install. Each needs a
different set of things from the machine, and the differences are large
enough that picking the wrong one costs an afternoon.

| | Needs | Does not need | Runs on |
|---|---|---|---|
| **Docker** | Docker | anything else | anywhere Docker runs |
| **The offline analyser** | Python 3.10+ | root, eBPF, a kernel, a database, an interface | macOS, Linux, Windows, BSD |
| **The live sensor** | Linux 5.8+, bcc, kernel headers, root, MongoDB | — | Linux only |

The question that decides it is whether you have **a capture file** or **a
network**. A capture file is answered by the first two, and the offline
analyser reads more out of a capture than the live sensor could ever have
seen (see [architecture.md](architecture.md)). A live network — a continuous
series rather than a snapshot — is the only reason to take the third path.

---

## Docker

Nothing to install but Docker itself, and three images to choose from.
[`docker/README.md`](../docker/README.md) is the reference; this is the
thirty-second version.

```bash
# analyse a capture: 164MB, non-root, read-only filesystem, no network
docker build -f docker/Dockerfile.offline -t cryptomon-offline .
docker run --rm --network none --read-only \
    -v "$PWD:/captures:ro" cryptomon-offline /captures/your-capture.pcap

# the API, the upload UI, the dashboard, and a MongoDB beside them
cd docker
cp env.example .env          # then put a real password in MONGO_PASSWORD
docker compose up --build    # http://127.0.0.1:8000/

# does eBPF work on this host at all?
docker build -f docker/Dockerfile.sensor -t cryptomon-sensor .
docker run --rm --cap-add BPF cryptomon-sensor
```

That last command is [issue #26](troubleshooting.md#bcc-will-not-install-or-will-not-compile-issue-26)
made answerable: it compiles the kernel filter and puts it past the verifier
in both attach modes, touching no interface and no database. If it prints
`OK compiles` and two `OK verifies`, the kernel half of CryptoMon works on
this machine and anything still wrong is configuration.

> **Not verified on this machine.** The Docker commands above are quoted from
> `docker/README.md`, which records where and when they were checked. Building
> an image needs the network, and these pages were written with none.

The password that ships in `docker/compose.yaml` is
`change-me-this-is-not-a-password` — a placeholder written out in full so it
cannot be mistaken for a generated secret. Both published ports bind
`127.0.0.1`.

---

## The offline analyser

The path most people want. It reads a capture file, needs no privileges and
touches no database.

```bash
git clone https://github.com/Santandersecurityresearch/CryptoMon.git
cd CryptoMon
pip install cryptography
python -m pcapscan your-capture.pcap
```

Python 3.10 is the floor. `cryptography` is the only third-party package
involved, and it does exactly one job: parsing the X.509 chain out of the
handshake. Everything else — reading pcap and pcapng, reassembling TCP,
walking TLS records, classifying algorithms, writing NDJSON, CSV, JSON and a
CycloneDX CBOM — is the standard library. This was checked by blocking the
import of every other package in `requirements.txt` and running all five
output formats; they all work.

Without `cryptography` the analyser still runs, and the certificate section
of the report is **silently empty** rather than absent. That failure has its
own entry in [troubleshooting.md](troubleshooting.md#the-report-has-no-certificates-in-it)
because an estate with no certificate keys and an estate whose certificates
could not be parsed look identical in the output.

`pip install -r requirements.txt` installs the rest of the project too —
FastAPI, motor, uvicorn, scapy, TinyDB — and is what you want if you also
intend to run the service. It is not needed to analyse a capture.

### A virtual environment, if your Python objects

Recent distributions mark the system Python as externally managed (PEP 668)
and refuse `pip install` into it:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

---

## The live sensor

Linux only, root, and a kernel that will load a BPF program. This is the half
of CryptoMon that watches an interface instead of reading a file.

### What it needs

| | |
|---|---|
| Linux kernel | 5.8 or newer, so `CAP_BPF` and `CAP_PERFMON` exist as their own capabilities. Older kernels can only be given `CAP_SYS_ADMIN`. |
| `bcc` | From the distribution — `bpfcc-tools`, which pulls in `python3-bpfcc`. **Not** the PyPI package called `bcc`, which is something else entirely. |
| Kernel headers | Matching the kernel that is actually running, because bcc compiles the program against them at load time. |
| `pyroute2` | `python3-pyroute2`, and only for the `-tc` traffic-control attach mode. |
| MongoDB | The sensor writes one document per parsed frame and has nowhere else to put them. |
| root | Or the capability set in [`docker/README.md`](../docker/README.md#capabilities-and-why-not---privileged). |

`bcc` and `pyroute2` are deliberately absent from `requirements.txt`. They
are Linux-only and come from the distribution, and keeping them out is what
lets the test suite and the offline tools import on a machine that has
neither.

### `ubuntu-setup.sh`, honestly

The repository ships a 40-line `apt-get` script, and the README has always
said it "will install all the necessary files". Read it before you run it.
It has not aged well, and on Ubuntu 24.04 "Noble Numbat" — the release the
README names — several of its lines fail.

```bash
sudo ./ubuntu-setup.sh
```

What is in it, and what to expect:

* **It has no `set -e` and no root check.** Every line that fails is passed
  over in silence and the script exits 0 regardless. That matters because
  several lines do fail.
* **`linux-tools-5.15.0-41-generic` is pinned to one specific kernel.** That
  is a 5.15 kernel — Ubuntu 22.04's. On 24.04, whose kernel is 6.8, the
  package does not exist and the line fails. Nothing downstream needs it;
  the later `linux-tools-$(uname -r)` line is the one that matters.
* **`llvm-12`, `clang-12` and `clang-format-12` are pinned to an LLVM
  release that 24.04 does not carry.** Where those packages are absent the
  three lines fail, and then the loop below them that strips the `-12` suffix
  runs `which clang-12` on nothing and hands `ln -s` an empty path. Harmless,
  noisy, and confusing to read in the output. Unversioned `clang` and `llvm`
  are installed by the second line of the script regardless.
* **`sudo snap install --devmode bpftrace` carries a `# TODO - find out why
  this doesn't work` beside it.** It has not worked and it does not need to:
  nothing in this repository uses bpftrace. It can be ignored.
* **`apt-get install bpfcc-tools linux-headers-$(uname -r)` has no `-y`**,
  unlike every other line, so it prompts. It is also the line that fails
  inside a container or on a host whose running kernel has no matching
  headers package — the single most common way the sensor fails to start.
  `linux-headers-generic` is what the project's own container images install,
  for exactly that reason.
* **It installs Python packages from `apt`**, not from `requirements.txt`:
  `python3-scapy`, `python3-motor`, `python3-psutil`, `python3-pyroute2`,
  `python3-pymongo`, `python3-fastapi`, `python3-tinydb`. Those are the
  distribution's versions, which are not the versions `requirements.txt`
  pins.
* **It does not install everything the API needs.** `uvicorn`, `jinja2`,
  `python-multipart` and `cryptography` are in `requirements.txt` and are not
  in this script, so `python api.py` will not start after running it alone.
* **It adds MongoDB 7.0 from the `jammy` (22.04) repository** regardless of
  what you are running.
* **The final `python3 -m pip install jc` will be refused** on a PEP 668
  distribution. `jc` is used by one function on the live path
  (`cryptomon.utils.cert_guess`), which prints a message and returns nothing
  when it is missing. The apt line above it usually covers it.

A reasonable reading of all that: run it for the eBPF toolchain, then install
the Python side properly.

```bash
sudo ./ubuntu-setup.sh                          # the apt/eBPF half
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                 # the pinned Python half
```

> **Not verified on this machine.** Everything in this section is read from
> `ubuntu-setup.sh`, the package lists of the releases it names, and the
> project's own commit history. It was not executed: these pages were written
> on macOS, with no network.

### MongoDB

The sensor needs somewhere to write. Create the database and a user for it:

```bash
mongosh
```

```javascript
use cryptomon
db.createCollection('cryptomon')
db.createUser({user: "cryptomonUser", pwd: passwordPrompt(),
               roles: [{ role: "readWrite", db: "cryptomon" }]})
```

Then point CryptoMon at it. The variable names carry no prefix — see
[configuration.md](configuration.md):

```bash
export DB_URL="mongodb://cryptomonUser:<password>@127.0.0.1:27017/cryptomon?retryWrites=true&w=majority"
export DB_NAME="cryptomon"
```

Or, for Atlas or another hosted service:

```bash
export DB_URL="mongodb+srv://<connection-url>/cryptomon?retryWrites=true&w=majority"
export DB_NAME="cryptomon"
```

Worth giving the sensor its own user with write access only. The sensor and
the API have very different exposure, and there is no reason a compromise of
one should hand over the other's credential.

### Running it

```bash
sudo python3 ./cryptomon.py -i eth0    # the sensor
python3 ./api.py                       # the API, in another shell
```

See [live-sensor.md](live-sensor.md) for what it sees, and
[deploy/README.md](../deploy/README.md) for running both as systemd services
behind nginx. `create-service.sh` installs the units and deliberately starts
neither, so that you can read them and put the database password in place
first.

---

## Checking the install

```bash
python -m pcapscan tests/fixtures/streams/tls13_hello_retry.pcap
```

This is a committed 24-packet capture of one real handshake, and it exercises
the whole offline path — reader, reassembler, record walker, TLS parser,
certificate handling and the classification table. It should print one
session, one classical key exchange, and one post-quantum offer that the
server refused.

```bash
python -m pytest -m smoke        # ~5s, no captures, no database, no network
python -m pytest                 # everything, ~12s
```

See [tests/README.md](../tests/README.md) for what the two sets cover and why
they are split.
