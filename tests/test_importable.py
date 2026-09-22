"""
Acceptance test for the harness itself: this suite must run on a machine with
no bcc, no pyroute2, no MongoDB and no root. If any of those creep back into
import time, everything else here stops being runnable.

# Merge gate: these need no capture fixtures and run in well under a second.
pytestmark = pytest.mark.smoke
"""
import importlib
import types

import pytest


def test_package_imports():
    import cryptomon
    assert cryptomon.__version__


def test_bcc_is_not_imported_at_module_scope():
    import cryptomon
    source = importlib.import_module("cryptomon").__file__
    with open(source) as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")) and not line[:1].isspace():
                assert "bcc" not in stripped, (
                    "bcc imported at module scope; the package stops being "
                    "importable off Linux and this suite cannot run")
                assert "pyroute2" not in stripped


def test_parsers_need_no_instance():
    from cryptomon import CryptoMon
    frame = types.SimpleNamespace(raw=bytes(200), magic=1)
    assert isinstance(CryptoMon.tls_parse_crypto(None, frame), dict)
    frame.magic = 2
    assert isinstance(CryptoMon.ssh_parse_crypto(None, frame), dict)


def test_ciphersuite_table_loads_from_any_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    module = importlib.reload(importlib.import_module("cryptomon.data"))
    assert len(module.TLS_DICT) > 300
    assert module.CIPHERSUITES_CSV.is_file()
