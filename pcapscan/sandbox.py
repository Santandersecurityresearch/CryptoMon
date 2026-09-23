"""
Run a capture through the pipeline in a subprocess that cannot outgrow or
outlast its limits.

PR-26 fuzzed the parsers hard and they hold up. This is the layer that
assumes some day one will not. A capture arriving from a browser upload is
chosen entirely by whoever sends it, and there are two failures no amount of
parser hardening removes:

* **Memory.** The reassembler is bounded per flow and per flow table, but a
  capture can contain an unbounded number of *sessions*, and the session
  records are held until the run finishes. A 4GB file of distinct handshakes
  is a legitimate capture and a memory exhaustion at the same time.
* **Time.** Every loop in the parsers is bounded, but "bounded" and "quick"
  are different claims, and the bound is per record rather than per file.

Both are answered the same way: do the work somewhere it can be killed.

    result = analyse_capture('/var/spool/uploads/abc123.pcap')
    if result.ok:
        report = result.document          # the same JSON the CLI writes
    else:
        log(result.reason)                # 'timeout', 'memory', 'cpu', ...

**The limits are set by the child on itself, not by the parent through
`preexec_fn`.** `preexec_fn` runs between fork and exec, where only
async-signal-safe calls are legal, and the CPython docs say plainly that it
is unsafe in the presence of threads. The service that will call this is
FastAPI under uvicorn, which is exactly that. So the worker re-executes as
`python -m pcapscan.sandbox --worker`, applies its own rlimits before it
imports anything that allocates, and gets on with it.

What this is not: a security boundary against arbitrary code execution.
There is no namespace, no seccomp filter and no chroot here. It bounds
resource consumption by a parser that is assumed to be honest but fallible,
which is the threat PR-26 measured. A parser assumed to be *malicious* needs
a container, and that is PR-39's ground.
"""
import json
import os
import subprocess
import sys
from typing import NamedTuple

try:
    import resource
except ImportError:                          # pragma: no cover -- Windows
    resource = None

# Defaults chosen against measurement rather than taste. The whole 253MB
# corpus analyses in 1.7s and 63MB of resident memory (PR-23), so these leave
# roughly two orders of magnitude of headroom and still stop a runaway well
# before it troubles the host.
DEFAULT_ADDRESS_SPACE = 2 * 1024 * 1024 * 1024     # 2 GiB
DEFAULT_CPU_SECONDS = 120
DEFAULT_WALL_SECONDS = 180
DEFAULT_OUTPUT_BYTES = 256 * 1024 * 1024           # 256 MiB of JSON
DEFAULT_MAX_CAPTURE_BYTES = 2 * 1024 * 1024 * 1024

# Wall-clock is deliberately longer than the CPU limit: a process that is
# swapping or waiting on a slow disk has not misbehaved, and killing it on
# CPU time says something truer about it than killing it on elapsed time.
# Both exist because either alone can be evaded by the other.


class Limits(NamedTuple):
    """What the child may consume. Every field is enforced separately."""
    address_space: int = DEFAULT_ADDRESS_SPACE
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    wall_seconds: int = DEFAULT_WALL_SECONDS
    output_bytes: int = DEFAULT_OUTPUT_BYTES
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES


class SandboxResult(NamedTuple):
    """
    What came back. `ok` is the only field worth branching on.

    `reason` names the limit that stopped it, so an operator reading a log
    can tell "this capture is too big for the limits we set" from "this
    capture broke the parser" without reading a traceback.
    """
    ok: bool
    document: dict = None
    reason: str = None
    detail: str = ''
    exit_code: int = None
    elapsed: float = 0.0
    limits: Limits = None

    @property
    def summary(self):
        """The analysis summary, or None. Convenience for the UI."""
        return (self.document or {}).get('summary')

    @property
    def sessions(self):
        return (self.document or {}).get('sessions') or []


# --------------------------------------------------------------------------
# parent side
# --------------------------------------------------------------------------
def analyse_capture(path, limits=None, python=None):
    """
    Analyse one capture in a bounded subprocess. Never raises.

    Returns a SandboxResult. A capture that is refused, that runs out of
    time or memory, or that makes the worker die in any way at all, comes
    back as `ok=False` with a reason -- because the caller is a web request
    handler and an exception there is a 500 for something that is not the
    server's fault.
    """
    import time

    limits = limits or Limits()
    path = os.fspath(path)

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return SandboxResult(False, reason='unreadable', detail=str(exc),
                             limits=limits)
    if size > limits.max_capture_bytes:
        # Refused before a process is even started: there is no point paying
        # for a fork to discover a number we already have.
        return SandboxResult(
            False, reason='too_large',
            detail='{0} bytes exceeds the {1}-byte limit'.format(
                size, limits.max_capture_bytes), limits=limits)

    command = [python or sys.executable, '-m', 'pcapscan.sandbox',
               '--worker', path,
               '--address-space', str(limits.address_space),
               '--cpu-seconds', str(limits.cpu_seconds)]
    # A deliberately small environment, with one thing added back. The
    # package is commonly run from a checkout rather than installed, and
    # `python -m` finds it through the working directory -- which is the
    # caller's, not ours. A service started from anywhere but the app root
    # would get an ImportError reported as a parse failure. Pointing
    # PYTHONPATH at the directory this package lives in makes the child
    # independent of where the parent happens to be standing.
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python_path = os.pathsep.join(
        part for part in (os.environ.get('PYTHONPATH', ''), package_root)
        if part)
    environment = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'PYTHONPATH': python_path,
        'PYTHONHASHSEED': '0',
        'LC_ALL': 'C',
        'HOME': os.environ.get('HOME', '/tmp'),
    }

    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=limits.wall_seconds,
            env=environment,
            # Its own session, so that a timeout kills any grandchildren
            # along with it rather than orphaning them.
            start_new_session=True)
    except subprocess.TimeoutExpired:
        return SandboxResult(
            False, reason='timeout',
            detail='no result within {0}s'.format(limits.wall_seconds),
            elapsed=time.monotonic() - started, limits=limits)
    except OSError as exc:
        return SandboxResult(False, reason='spawn_failed', detail=str(exc),
                             elapsed=time.monotonic() - started, limits=limits)
    elapsed = time.monotonic() - started

    stderr = completed.stderr.decode('utf-8', 'replace')[-4000:]
    if completed.returncode != 0:
        return SandboxResult(False, reason=_reason_for(completed.returncode,
                                                       stderr),
                             detail=stderr.strip(),
                             exit_code=completed.returncode,
                             elapsed=elapsed, limits=limits)
    if len(completed.stdout) > limits.output_bytes:
        return SandboxResult(
            False, reason='output_too_large',
            detail='{0} bytes of output'.format(len(completed.stdout)),
            exit_code=0, elapsed=elapsed, limits=limits)
    try:
        document = json.loads(completed.stdout.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        return SandboxResult(False, reason='bad_output', detail=str(exc),
                             exit_code=0, elapsed=elapsed, limits=limits)
    return SandboxResult(True, document=document, exit_code=0,
                         elapsed=elapsed, limits=limits)


# Signals worth naming. A worker killed by the kernel leaves no traceback, so
# the exit code is the only evidence of what happened to it.
_SIGNAL_REASONS = {
    9: 'killed',            # SIGKILL -- the OOM killer, or our own timeout
    24: 'cpu',              # SIGXCPU -- RLIMIT_CPU soft limit
    11: 'crashed',          # SIGSEGV
    6: 'crashed',           # SIGABRT
}


def _reason_for(code, stderr):
    if code < 0:
        return _SIGNAL_REASONS.get(-code, 'signal_{0}'.format(-code))
    if 'MemoryError' in stderr:
        # RLIMIT_AS makes the allocation fail rather than killing the
        # process, so this is what hitting the memory limit usually looks
        # like from here: a clean Python exception, not a signal.
        return 'memory'
    if 'CaptureError' in stderr:
        return 'not_a_capture'
    return 'failed'


# --------------------------------------------------------------------------
# child side
# --------------------------------------------------------------------------
def apply_limits(address_space, cpu_seconds):
    """
    Bound this process. Returns the names of the limits actually applied.

    Applied by the child to itself rather than through `preexec_fn`, which
    runs between fork and exec where only async-signal-safe calls are legal
    and which CPython documents as unsafe when threads are present -- and the
    caller here is a threaded web server.

    A limit that will not set is reported rather than assumed: macOS honours
    RLIMIT_AS inconsistently across allocators, and silently believing a
    ceiling that is not there is worse than knowing it is missing.
    """
    applied = []
    if resource is None:                     # pragma: no cover -- Windows
        return applied
    for name, attribute, value in (
            ('address_space', 'RLIMIT_AS', address_space),
            ('cpu_seconds', 'RLIMIT_CPU', cpu_seconds)):
        limit = getattr(resource, attribute, None)
        # `not value` would skip a limit of zero, which is a request for no
        # CPU at all rather than a request for no limit. Silently ignoring
        # what a caller explicitly asked for is the wrong failure: it hands
        # back an unbounded process while reporting success.
        if limit is None or value is None or value < 0:
            continue
        try:
            soft, hard = resource.getrlimit(limit)
            ceiling = value if hard == resource.RLIM_INFINITY \
                else min(value, hard)
            resource.setrlimit(limit, (ceiling, hard))
        except (ValueError, OSError):
            continue
        applied.append(name)
    return applied


def _worker(argv):
    """
    The child. Bounds itself, then writes the same JSON the CLI writes.

    Imports of the pipeline happen *after* the limits are in place, so that a
    ceiling low enough to matter applies to the import as well.
    """
    import argparse

    parser = argparse.ArgumentParser(prog='pcapscan.sandbox')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('capture')
    parser.add_argument('--address-space', type=int,
                        default=DEFAULT_ADDRESS_SPACE)
    parser.add_argument('--cpu-seconds', type=int,
                        default=DEFAULT_CPU_SECONDS)
    args = parser.parse_args(argv)

    applied = apply_limits(args.address_space, args.cpu_seconds)

    from cryptomon.analysis import analyse
    from pcapscan.export import write_json
    from pcapscan.reader import Reader
    from pcapscan.sessions import SessionBuilder
    from pcapscan.tunnels import decode_packet

    builder = SessionBuilder()
    with Reader(args.capture) as reader:
        for packet in reader:
            # The same decode the CLI does, and it has to stay that way. This
            # loop was TCP-only for two waves after the CLI stopped being,
            # which meant a capture uploaded through the browser was analysed
            # by a strictly weaker parser than the same file on the command
            # line -- silently, since a report of nothing looks like a
            # capture with nothing in it. An upload is the most
            # attacker-controlled input this project takes and the least
            # likely to be re-run by hand, so it is the last place that
            # should quietly see less.
            decoded = decode_packet(packet.data, packet.linktype,
                                    builder.stats)
            if decoded is None:
                builder.stats['frames_undecodable'] += 1
                continue
            if decoded.frame is None:
                builder.push_datagram(packet.timestamp, decoded.raw,
                                      decoded.datagram)
                continue
            builder.stats['frames'] += 1
            builder.push(packet.timestamp, decoded.raw, decoded.frame,
                         decoded.tunnel is not None
                         and decoded.tunnel.truncated)
        capture_stats = dict(reader.stats)

    records = list(builder.finish())
    summary = analyse(records)

    import io
    buffer = io.StringIO()
    write_json(records, buffer, summary, source=os.path.basename(args.capture))
    document = json.loads(buffer.getvalue())
    document['meta']['sandbox'] = {
        'limits_applied': applied,
        'address_space': args.address_space,
        'cpu_seconds': args.cpu_seconds,
    }
    document['meta']['capture'] = capture_stats
    document['meta']['pipeline'] = dict(builder.stats)
    json.dump(document, sys.stdout)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if '--worker' not in argv:
        print('pcapscan.sandbox is not meant to be run directly; call '
              'analyse_capture() or pass --worker.', file=sys.stderr)
        return 2
    return _worker(argv)


if __name__ == '__main__':
    sys.exit(main())
