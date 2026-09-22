#!/usr/bin/env python3
"""
Compile and load the eBPF program, as a check.

This is the only part of CryptoMon that runs in the kernel, and until now it
was the only part with nothing checking it at all -- the Python suite cannot
reach it, and a mistake here does not produce a wrong answer, it produces a
service that will not start. Issue #26 is exactly that.

Needs Linux, bcc and kernel headers, so it runs in CI and in a container
rather than in pytest:

    docker run --rm --privileged -v "$PWD":/work -w /work <image> \
        python3 tests/tools/check_bpf.py

bpf.py is loaded straight from its path rather than imported as
cryptomon.bpf, so this needs none of the runtime dependencies -- the point is
to test the C, not the package.

That is still true, with one qualification since PR-35 made the watched
ports configurable: bpf.py now imports cryptomon.ports to build the port
comparisons, so the repository root has to be importable even though the
package as a whole is not imported. cryptomon.ports is pure standard library
and pulls in nothing else, so the isolation this file wants is preserved --
but the sys.path entry below is load-bearing, and without it this check dies
with ModuleNotFoundError before it ever reaches the compiler.
"""
import glob
import importlib.util
import os
import pathlib
import platform
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
BPF_SOURCE = REPO_ROOT / "cryptomon" / "bpf.py"

# So that bpf.py's `from cryptomon.ports import ...` resolves. See the note
# in the module docstring about why this does not reintroduce the runtime
# dependencies.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_program_text():
    spec = importlib.util.spec_from_file_location("_cryptomon_bpf", BPF_SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = getattr(module, "bpf_text", None) or getattr(module, "bpf_ipv4_txt")
    if not text or "crypto_monitor" not in text:
        raise SystemExit(f"{BPF_SOURCE}: no crypto_monitor program found")
    return text


def ensure_kernel_headers():
    """
    Point bcc at usable headers.

    bcc compiles against the *running* kernel's headers by default. A
    container, and sometimes a CI runner, has headers for a different version
    installed -- so fall back to whatever is present rather than failing for a
    reason that has nothing to do with the program.
    """
    running = platform.release()
    exact = f"/lib/modules/{running}/build"
    if os.path.isdir(exact) or os.environ.get("BCC_KERNEL_SOURCE"):
        return os.environ.get("BCC_KERNEL_SOURCE", exact)
    candidates = sorted(glob.glob("/usr/src/linux-headers-*-generic"))
    if not candidates:
        candidates = sorted(glob.glob("/usr/src/linux-headers-*"))
    if candidates:
        os.environ["BCC_KERNEL_SOURCE"] = candidates[-1]
        return candidates[-1]
    return None


def main():
    headers = ensure_kernel_headers()
    print(f"kernel {platform.release()}, headers {headers or 'NOT FOUND'}")
    from bcc import BPF

    text = load_program_text()
    print(f"program: {len(text)} chars, {len(text.splitlines())} lines")

    failures = []
    try:
        program = BPF(text=text)
    except Exception as exc:
        print(f"FAIL  compile: {type(exc).__name__}: {exc}")
        return 1
    print("OK    compiles")

    # Both attach modes are offered by CryptoMon.__init__ (load_method
    # 'library' uses a raw socket filter, anything else uses TC), and the
    # verifier judges them separately.
    for mode_name in ("SOCKET_FILTER", "SCHED_CLS"):
        try:
            fn = program.load_func("crypto_monitor", getattr(BPF, mode_name))
            print(f"OK    verifies as {mode_name} (fd={fn.fd})")
        except Exception as exc:
            failures.append(mode_name)
            print(f"FAIL  {mode_name}: {type(exc).__name__}: "
                  f"{str(exc)[:300]}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
