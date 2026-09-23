#!/bin/sh
# Point bcc at headers that exist, then run what was asked for.
#
# bcc compiles the eBPF program at load time and looks for the *running*
# kernel's headers under /lib/modules/$(uname -r)/build. Inside a container
# `uname -r` is the host's kernel -- the Docker Desktop VM's on a Mac, the
# node's on a cluster -- and that directory is not there, because what is
# installed in this image is linux-headers-generic, which is the version
# this image's bcc can parse. bcc then fails with "Unable to find kernel
# headers", which is indistinguishable from "eBPF does not work here" and is
# most of what issue #26 feels like from the outside.
#
# tests/tools/check_bpf.py has worked around exactly this since the eBPF
# checks were written. This is that fallback moved to where the service can
# use it too: cryptomon.py calls BPF(text=...) directly and has nowhere to
# put it.
#
# Deliberately not a Python wrapper. This runs as pid 1 and execs, so the
# monitor receives SIGTERM from `docker stop` itself rather than through a
# parent that would have to forward it.
set -eu

if [ -z "${BCC_KERNEL_SOURCE:-}" ]; then
    running="/lib/modules/$(uname -r)/build"
    if [ -d "$running" ]; then
        # A host whose kernel headers are bind-mounted in, which is the one
        # case where compiling against the running kernel is the right thing.
        BCC_KERNEL_SOURCE="$running"
    else
        # Newest linux-headers-*-generic in the image. `sort -V`, because
        # linux-headers-6.8.0-9 sorts after linux-headers-6.8.0-84
        # lexically and that is how you end up compiling against the oldest.
        BCC_KERNEL_SOURCE="$(ls -d /usr/src/linux-headers-*-generic 2>/dev/null \
                             | sort -V | tail -1)"
    fi
fi

if [ -z "${BCC_KERNEL_SOURCE:-}" ] || [ ! -d "$BCC_KERNEL_SOURCE" ]; then
    echo "cryptomon-sensor: no usable kernel headers." >&2
    echo "  This image installs linux-headers-generic; if that package is" >&2
    echo "  gone the image is broken rather than the host. Rebuild it, or" >&2
    echo "  set BCC_KERNEL_SOURCE to a header tree bcc can parse." >&2
    exit 78                                       # EX_CONFIG
fi
export BCC_KERNEL_SOURCE

# Belt and braces for anything that ignores the variable and looks the
# default path up itself. Harmless when the directory is already there.
if [ ! -e "/lib/modules/$(uname -r)/build" ]; then
    mkdir -p "/lib/modules/$(uname -r)" 2>/dev/null || true
    ln -sfn "$BCC_KERNEL_SOURCE" "/lib/modules/$(uname -r)/build" 2>/dev/null || true
fi

case "${1:-selftest}" in
    selftest)
        # The default, and the answer to "does eBPF work on this host at
        # all". Compiles the program and puts it past the verifier in both
        # attach modes without touching an interface or a database, so it
        # needs no MongoDB and no network. If this passes and the monitor
        # still will not start, the problem is not the kernel filter.
        echo "cryptomon-sensor: BCC_KERNEL_SOURCE=$BCC_KERNEL_SOURCE"
        exec python3 /app/tests/tools/check_bpf.py
        ;;
    monitor)
        # The service. Everything after `monitor` is cryptomon.py's own
        # command line: -i <iface>, -tc, --pcap <file>.
        shift
        if [ "$#" -eq 0 ]; then
            # No arguments, so the interface has to come from the
            # environment. compose does it this way rather than with a
            # `${SENSOR_IFACE:?...}` in the command, because compose
            # interpolates every service in the file including the ones no
            # active profile selects -- a required variable there makes a
            # plain `docker compose up`, which does not start this service
            # at all, fail before it starts anything.
            #
            # An explicit refusal rather than a guess at eth0: cryptomon.py
            # prompts on stdin when -i is absent and a container has no
            # stdin to prompt on, and a monitor watching the wrong interface
            # reports a quiet network rather than an error.
            if [ -z "${SENSOR_IFACE:-}" ]; then
                echo "cryptomon-sensor: no interface to watch." >&2
                echo "  Set SENSOR_IFACE, or pass one:" >&2
                echo "    docker run ... cryptomon-sensor monitor -i eth0" >&2
                echo "    SENSOR_IFACE=eth0 docker compose --profile sensor up" >&2
                exit 78                           # EX_CONFIG
            fi
            set -- -i "$SENSOR_IFACE"
        fi
        exec python3 /app/cryptomon.py "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
