# CryptoMon documentation

Start at the repository [README](../README.md) if you have not already — it
routes you to one of three quite different ways of running this.

## Getting it running

* **[install.md](install.md)** — Docker, the offline analyser, or the full
  live sensor. What each one genuinely needs, and what `ubuntu-setup.sh`
  actually does.
* **[configuration.md](configuration.md)** — every setting, its default, its
  effect, and when you would change it. The environment variable names carry
  **no prefix**; that is the first thing on the page.
* **[deploy/README.md](../deploy/README.md)** — nginx, systemd, secrets,
  subpath mounting, hardening. Read this before anybody but you can reach the
  service.
* **[docker/README.md](../docker/README.md)** — the three images, the
  compose stack, and the sensor's capability list.

## Using it

* **[offline-analysis.md](offline-analysis.md)** — `python -m pcapscan`: all
  five output formats, every flag, and the pipelines that make it useful.
* **[service.md](service.md)** — the FastAPI service and its three faces: the
  dashboard at `/`, the upload page at `/analyse/`, and JSON at `/data` and
  `/stats`.
* **[live-sensor.md](live-sensor.md)** — the eBPF sensor: what it sees, what
  it cannot see, and what it costs.

## Understanding it

* **[reading-a-report.md](reading-a-report.md)** — what `X25519MLKEM768`,
  `hybrid`, `t13d1516h2_8daaf6152771_02713d6af862`, `resumption: resumed` and
  `ech: offered` mean, and which of them should worry you. Read the section
  on denominators even if you read nothing else.
* **[architecture.md](architecture.md)** — why there are two parsing paths
  and why the offline one sees several times more.

## When it goes wrong

* **[troubleshooting.md](troubleshooting.md)** — the failures this project
  has actually hit, what each one looks like, and what to do. Including
  issue #26.

## A note on the measurements

Numbers quoted in these pages come from the project's capture corpus:
`CryptomonData/` (eleven captures of common desktop applications on macOS and
Windows 11, December 2024 and November 2024), `sandbox/` (one 13MB capture)
and the trimmed fixtures under `tests/fixtures/`. Where a figure is not
measured, it says so. Where something could not be checked on the machine
these pages were written on — anything needing Linux, root, bcc or a live
interface — it says **not verified on this machine** rather than implying
otherwise.
