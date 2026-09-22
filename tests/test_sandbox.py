"""
Bounded parsing in a subprocess.

Each `analyse_capture()` costs a fork and an interpreter start, so the
subprocess tests are deliberately few and the rest drive the pure functions
directly. Only the fast ones carry the `smoke` mark; the merge gate should
not be paying half a second per limit.

What is checked on Linux and not elsewhere is the memory ceiling. macOS sets
RLIMIT_AS inconsistently -- `apply_limits` reports 2 GiB as not applied while
accepting 1 TiB -- which is exactly why it returns the list of limits it
actually managed to set rather than assuming they took.
"""
import json
import os
import subprocess
import sys

import pytest

from pcapscan.sandbox import (DEFAULT_ADDRESS_SPACE, Limits, SandboxResult,
                              _reason_for, analyse_capture, apply_limits)

from conftest import FIXTURES

CAPTURE = str(FIXTURES / "streams" / "tls12_certificate.pcap")
LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith('linux'),
    reason="RLIMIT_AS is honoured inconsistently outside Linux")


@pytest.fixture(scope='module')
def analysed():
    """One real run, shared -- a fork per assertion is not worth it."""
    return analyse_capture(CAPTURE)


# --------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------
def test_a_capture_comes_back_analysed(analysed):
    assert analysed.ok, analysed.detail
    assert analysed.reason is None
    assert analysed.exit_code == 0
    assert len(analysed.sessions) == 1
    assert analysed.summary['readiness']['sessions'] == 1


def test_the_document_is_what_the_cli_writes(analysed):
    """
    Same shape, so the UI in PR-28 and the `-f json` output are one format.
    Two report renderers would be one too many.
    """
    assert set(analysed.document) >= {'meta', 'sessions', 'summary'}
    assert analysed.document['meta']['tool'] == 'pcapscan'


def test_the_result_says_what_the_child_was_actually_limited_to(analysed):
    """
    Reported rather than assumed. A ceiling that silently failed to apply is
    worse than one that is known to be missing, because only one of the two
    can be acted on.
    """
    sandbox = analysed.document['meta']['sandbox']
    assert isinstance(sandbox['limits_applied'], list)
    assert sandbox['address_space'] == DEFAULT_ADDRESS_SPACE
    assert set(sandbox['limits_applied']) <= {'address_space', 'cpu_seconds'}


def test_the_counters_come_back_too(analysed):
    """The reader and pipeline stats, so a quiet drop is still visible."""
    assert analysed.document['meta']['capture']['packets'] > 0
    assert analysed.document['meta']['pipeline']['sessions_emitted'] == 1


# --------------------------------------------------------------------------
# refusals that cost nothing
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_an_oversized_capture_is_refused_without_forking():
    """
    The size is already known, so paying for a process to discover it would
    be the one case where the sandbox costs more than it saves.
    """
    result = analyse_capture(CAPTURE, Limits(max_capture_bytes=100))
    assert not result.ok
    assert result.reason == 'too_large'
    assert result.exit_code is None          # nothing was ever started


@pytest.mark.smoke
def test_a_missing_file_is_a_result_not_an_exception():
    """
    The caller is a request handler. An exception there is a 500 for
    something that is not the server's fault.
    """
    result = analyse_capture('/nonexistent/nowhere.pcap')
    assert not result.ok
    assert result.reason == 'unreadable'


@pytest.mark.smoke
def test_analyse_capture_never_raises(tmp_path):
    for path in (tmp_path, tmp_path / 'absent', __file__):
        result = analyse_capture(path, Limits(wall_seconds=30))
        assert isinstance(result, SandboxResult)
        assert result.ok is False or result.document is not None


# --------------------------------------------------------------------------
# limits that bite
# --------------------------------------------------------------------------
def test_a_wall_clock_timeout_is_reported_as_one():
    result = analyse_capture(CAPTURE, Limits(wall_seconds=0.001))
    assert not result.ok
    assert result.reason == 'timeout'


def test_a_capture_that_is_not_one_is_named_as_such(tmp_path):
    rubbish = tmp_path / 'notes.pcap'
    rubbish.write_bytes(b'this is not a capture at all')
    result = analyse_capture(rubbish)
    assert not result.ok
    assert result.reason == 'not_a_capture'


def test_output_larger_than_the_cap_is_refused():
    result = analyse_capture(CAPTURE, Limits(output_bytes=10))
    assert not result.ok
    assert result.reason == 'output_too_large'


@LINUX_ONLY
def test_a_memory_ceiling_actually_stops_it():
    """
    Same capture, same code, only the ceiling differs -- and the ceiling
    decides. That is the property worth having.

    What is deliberately *not* asserted is how the child dies. A process
    starved of address space can raise MemoryError, fail an import, or be
    killed outright, and which one happens moves with the interpreter
    version and with whether the bytecode cache is warm: measured at 16MB
    giving MemoryError and 12MB giving a failed import on the same machine
    minutes apart. Pinning the reason would make this a test of CPython's
    allocator rather than of the sandbox.
    """
    tight = analyse_capture(CAPTURE, Limits(address_space=16 * 1024 * 1024))
    assert not tight.ok, 'a 16MB ceiling did not stop the run'
    assert analyse_capture(CAPTURE).ok, 'the default ceiling should not stop it'


@LINUX_ONLY
def test_a_cpu_ceiling_actually_stops_it():
    """Zero CPU seconds means zero, and arrives as SIGXCPU."""
    result = analyse_capture(CAPTURE, Limits(cpu_seconds=0))
    assert not result.ok
    assert result.reason == 'cpu'
    assert result.exit_code == -24


# --------------------------------------------------------------------------
# apply_limits, driven directly
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_apply_limits_reports_only_what_it_set():
    applied = apply_limits(1 << 40, 3600)
    assert set(applied) <= {'address_space', 'cpu_seconds'}


@pytest.mark.smoke
def test_a_limit_of_zero_is_a_limit_not_an_absence():
    """
    `not value` skipped it, so asking for no CPU at all handed back an
    unbounded process while reporting success -- the worst combination
    available: wrong, and quiet about it.
    """
    source = (
        'import sys; sys.path.insert(0, %r)\n'
        'from pcapscan.sandbox import apply_limits\n'
        'apply_limits(1 << 40, 0)\n'
        'x = 0\n'
        'while True:\n'
        '    x += 1\n'
        % os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # In a child, because a zero CPU limit applied here would take the test
    # run with it -- which is also the assertion: if the limit was applied
    # the child cannot survive its own loop, and if it was skipped the loop
    # runs until the timeout. Its death *is* the evidence, so there is
    # nothing to print.
    out = subprocess.run([sys.executable, '-c', source], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode != 0, 'a zero CPU limit was silently ignored'


@pytest.mark.smoke
def test_a_negative_limit_is_ignored_rather_than_applied():
    assert apply_limits(-1, -1) == []


# --------------------------------------------------------------------------
# reading the exit status
# --------------------------------------------------------------------------
@pytest.mark.smoke
@pytest.mark.parametrize("code,stderr,reason", [
    (-9, '', 'killed'),
    (-24, '', 'cpu'),
    (-11, '', 'crashed'),
    (-13, '', 'signal_13'),
    (1, 'MemoryError\n', 'memory'),
    (1, 'pcapscan.reader.CaptureError: unrecognised magic', 'not_a_capture'),
    (1, 'ZeroDivisionError', 'failed'),
])
def test_the_exit_status_is_translated_into_a_reason(code, stderr, reason):
    """
    A worker killed by the kernel leaves no traceback, so the exit code is
    the only evidence of what became of it. An operator reading a log should
    be able to tell "too big for the limits we set" from "broke the parser"
    without one.
    """
    assert _reason_for(code, stderr) == reason


# --------------------------------------------------------------------------
# the module is not a command
# --------------------------------------------------------------------------
@pytest.mark.smoke
def test_running_the_module_without_worker_refuses():
    out = subprocess.run(
        [sys.executable, '-m', 'pcapscan.sandbox'],
        capture_output=True, text=True, timeout=30,
        env=dict(os.environ, PYTHONPATH=os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
    assert out.returncode == 2
    assert 'not meant to be run directly' in out.stderr


def test_the_worker_writes_json_on_stdout_and_nothing_else():
    """
    stdout is the channel the parent parses, so a stray print anywhere in
    the pipeline would corrupt the result rather than merely be noisy.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run(
        [sys.executable, '-m', 'pcapscan.sandbox', '--worker', CAPTURE],
        capture_output=True, timeout=60,
        env=dict(os.environ, PYTHONPATH=root))
    assert out.returncode == 0, out.stderr[-500:]
    assert json.loads(out.stdout)['meta']['tool'] == 'pcapscan'
