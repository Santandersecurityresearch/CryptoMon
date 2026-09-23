#!/bin/bash
#
# Install CryptoMon as two systemd services.
#
# What this replaces, and why it had to be replaced. The previous version of
# this script generated a unit file containing the line
#
#     Environment="DB_URL=mongodb://cryptomonUser:<password>@<uri>:27017/..."
#
# and then ran `systemctl enable --now` on it. Three separate problems:
#
#   1. The placeholder was never substituted, so the service it started could
#      not reach the database, and the first thing every operator did was
#      edit a root-owned unit file by hand.
#   2. Once they did, the password was in /etc/systemd/system/cryptomon
#      .service -- world-readable by default -- and in the output of
#      `systemctl show` and `systemctl cat`, which any user can run.
#   3. One unit ran both the eBPF sensor and the HTTP API, as root, with no
#      hardening whatsoever. The half of the program that accepts uploads
#      from the network had every privilege the half that loads BPF
#      programs needs.
#
# So: two units, neither of which is generated here -- they are files in
# deploy/systemd/ that you can read before you install them -- secrets in a
# 0600 EnvironmentFile that the service account itself cannot open, and no
# `systemctl start` until an operator has filled that file in. A service that
# starts broken and restarts forever teaches everyone to ignore it.
#
# Usage:
#   sudo ./create-service.sh                 install both units
#   sudo ./create-service.sh --api-only      just the HTTP service
#   sudo ./create-service.sh --sensor-only   just the eBPF sensor
#   sudo ./create-service.sh --nginx         also install the nginx config
#   sudo ./create-service.sh --install-dir /srv/cryptomon
#
# Nothing here is started. The last thing it prints is what to do next.

set -euo pipefail

# --------------------------------------------------------------------------
# Where things go
# --------------------------------------------------------------------------
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SOURCE_DIR"
CONFIG_DIR="/etc/cryptomon"
UNIT_DIR="/etc/systemd/system"
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_SNIPPET_DIR="/etc/nginx/cryptomon"
SERVICE_USER="cryptomon"
STATE_DIR="/var/lib/cryptomon"

WANT_API=1
WANT_SENSOR=1
WANT_NGINX=0

while [ $# -gt 0 ]; do
  case "$1" in
    --api-only)     WANT_SENSOR=0 ;;
    --sensor-only)  WANT_API=0 ;;
    --nginx)        WANT_NGINX=1 ;;
    --install-dir)  INSTALL_DIR="${2:?--install-dir needs a path}"; shift ;;
    -h|--help)      sed -n '3,40p' "$0"; exit 0 ;;
    *)              echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "This script installs into /etc and must run as root." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found. These units are for a systemd host." >&2
  exit 1
fi

say()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

# --------------------------------------------------------------------------
# The interpreter the units will call
# --------------------------------------------------------------------------
# A virtualenv in the checkout if there is one, the system python3 otherwise.
# Resolved here rather than left as a guess in the unit, because Type=exec
# turns a wrong path into a clear failure at `systemctl start` and there is
# no reason to make anybody debug that.
if [ -x "$INSTALL_DIR/.venv/bin/python" ]; then
  PYTHON="$INSTALL_DIR/.venv/bin/python"
elif [ -x "$INSTALL_DIR/venv/bin/python" ]; then
  PYTHON="$INSTALL_DIR/venv/bin/python"
else
  PYTHON="$(command -v python3 || true)"
  if [ -z "$PYTHON" ]; then
    echo "No python3 found, and no virtualenv in $INSTALL_DIR." >&2
    exit 1
  fi
  warn "Using the system interpreter $PYTHON."
  warn "A virtualenv in $INSTALL_DIR/.venv would be better: it keeps this"
  warn "service's dependency versions independent of the distribution's."
fi

for required in api.py cryptomon.py deploy/systemd; do
  if [ ! -e "$INSTALL_DIR/$required" ]; then
    echo "$INSTALL_DIR does not look like a CryptoMon checkout" >&2
    echo "(no $required). Pass --install-dir." >&2
    exit 1
  fi
done

# --------------------------------------------------------------------------
# The service account
# --------------------------------------------------------------------------
# Only the API needs one; the sensor runs as root because bcc does. A system
# account with no login shell and no password: it exists to own a uid and a
# directory of reports, not to be logged into.
if [ "$WANT_API" -eq 1 ]; then
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    say "user $SERVICE_USER already exists"
  else
    say "creating system user $SERVICE_USER"
    useradd --system --no-create-home --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  # StateDirectory= in the unit creates and chowns this on every start, so
  # this is only to make the first `ls` before the first start make sense.
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/uploads"
fi

# --------------------------------------------------------------------------
# Environment files
# --------------------------------------------------------------------------
# 0600 root:root. systemd reads these as PID 1 before dropping to User=, so
# the service account does not need to be able to open them -- and something
# that compromises the service gets the environment, not the file.
#
# Never overwritten. An install that silently replaced a filled-in
# credentials file with a template would be the worst possible behaviour for
# a script people run twice.
install -d -m 0750 -o root -g root "$CONFIG_DIR"

install_env() {
  local example="$1" target="$2"
  if [ -e "$target" ]; then
    say "$target exists, leaving it alone"
    NEEDS_EDIT="${NEEDS_EDIT:-}"
  else
    install -m 0600 -o root -g root "$example" "$target"
    say "wrote $target (0600 root:root) -- EDIT IT, it has placeholders"
    NEEDS_EDIT="yes"
  fi
}

# --------------------------------------------------------------------------
# Units
# --------------------------------------------------------------------------
# The shipped unit files hardcode /opt/cryptomon and a venv interpreter,
# because a unit file with an unsubstituted @PLACEHOLDER@ in it is a unit
# file nobody can read and check. If the checkout is somewhere else, the
# paths are rewritten on the way in -- and the substitution is narrow enough
# to be obvious from `systemctl cat`.
install_unit() {
  local name="$1"
  local source="$INSTALL_DIR/deploy/systemd/$name"
  local target="$UNIT_DIR/$name"

  [ -r "$source" ] || { echo "missing $source" >&2; exit 1; }

  sed -e "s#/opt/cryptomon/\.venv/bin/python#${PYTHON//#/\\#}#g" \
      -e "s#/opt/cryptomon#${INSTALL_DIR//#/\\#}#g" \
      "$source" > "$target.new"
  chmod 0644 "$target.new"
  chown root:root "$target.new"
  mv -f "$target.new" "$target"
  say "installed $target"
}

if [ "$WANT_API" -eq 1 ]; then
  install_env "$INSTALL_DIR/deploy/systemd/api.env.example" "$CONFIG_DIR/api.env"
  install_unit cryptomon-api.service
fi

if [ "$WANT_SENSOR" -eq 1 ]; then
  install_env "$INSTALL_DIR/deploy/systemd/sensor.env.example" "$CONFIG_DIR/sensor.env"
  install_unit cryptomon-sensor.service
fi

# --------------------------------------------------------------------------
# nginx, if asked
# --------------------------------------------------------------------------
if [ "$WANT_NGINX" -eq 1 ]; then
  install -d -m 0755 "$NGINX_SNIPPET_DIR"
  install -m 0644 "$INSTALL_DIR/deploy/nginx/proxy-to-cryptomon.conf" \
                  "$NGINX_SNIPPET_DIR/proxy-to-cryptomon.conf"
  install -m 0644 "$INSTALL_DIR/deploy/nginx/security-headers.conf" \
                  "$NGINX_SNIPPET_DIR/security-headers.conf"
  if [ -e "$NGINX_CONF_DIR/cryptomon.conf" ]; then
    say "$NGINX_CONF_DIR/cryptomon.conf exists, leaving it alone"
  else
    install -d -m 0755 "$NGINX_CONF_DIR"
    install -m 0644 "$INSTALL_DIR/deploy/nginx/cryptomon.conf" \
                    "$NGINX_CONF_DIR/cryptomon.conf"
    say "wrote $NGINX_CONF_DIR/cryptomon.conf"
    warn "It will NOT load until you replace server_name and the two"
    warn "ssl_certificate paths -- they are marked REPLACE. Run"
    warn "\`nginx -t\` before \`systemctl reload nginx\`."
  fi
fi

# --------------------------------------------------------------------------
# Check, but do not start
# --------------------------------------------------------------------------
systemctl daemon-reload
say "systemd reloaded"

# Catches a typo in a directive name, which systemd otherwise reports only in
# the journal at the first start -- as a warning, while running the service
# anyway with that line ignored. A hardening directive that is silently
# ignored is worse than one that is absent, because it is in the file.
if command -v systemd-analyze >/dev/null 2>&1; then
  for unit in cryptomon-api cryptomon-sensor; do
    [ -e "$UNIT_DIR/$unit.service" ] || continue
    if systemd-analyze verify "$UNIT_DIR/$unit.service" 2>&1 | grep -q .; then
      warn "systemd-analyze verify had something to say about $unit.service:"
      systemd-analyze verify "$UNIT_DIR/$unit.service" || true
    else
      say "$unit.service verifies clean"
    fi
  done
fi

cat <<NEXT

Installed. Nothing has been started.

Next:

  1. Fill in the credentials. They are placeholders, and the services will
     fail to reach MongoDB until they are real:

       \$EDITOR $CONFIG_DIR/api.env
       \$EDITOR $CONFIG_DIR/sensor.env

     sensor.env needs CRYPTOMON_IFACE set to a real interface -- \`ip -br
     link\` will list them. Without it cryptomon.py tries to prompt, which
     under systemd means EOFError on every start.

  2. If this service is reachable from anywhere but this host, set API_KEY
     in api.env:

       python3 -c "import secrets; print(secrets.token_urlsafe(32))"

  3. Start them:

       systemctl enable --now cryptomon-api
       systemctl enable --now cryptomon-sensor

  4. Check:

       systemctl status cryptomon-api cryptomon-sensor
       journalctl -u cryptomon-api -f
       systemd-analyze security cryptomon-api.service

Note on config-secrets.sh, which is still in this repository: it exports
DB_URL and DB_NAME into an interactive shell, which is a different job from
this one and does not feed these services. A value exported in your shell
does not reach a systemd unit. Use $CONFIG_DIR/api.env for the services and
keep config-secrets.sh for running api.py by hand -- and note that it, and
start_cryptomon.sh, put the password in your shell history and in the
environment of everything you launch from that shell.

NEXT
