# Tests

Runs with no bcc, no pyroute2, no MongoDB and no root. That is the point: the
parsers touch only `skb_event.raw` and `.magic` and use no attribute of
`self`, so `CryptoMon.tls_parse_crypto(None, skb)` works with no BPF compile
and no socket.

```bash
pip install -r requirements-dev.txt
pytest -m smoke     # merge gate, ~5s, no capture fixtures
pytest              # everything, ~12s
```

## What is here

| Path | What it does |
|---|---|
| `test_codepoints.py` | GREASE (RFC 8701) and the never-raising lookups. **smoke** |
| `test_importable.py` | The package imports without the Linux-only stack. **smoke** |
| `test_storage.py` | Backend dispatch, write failures, backpressure. **smoke** |
| `test_parsers_vs_oracle.py` | Parsers diffed against tshark over real captures |
| `test_framing.py` | VLAN / QinQ / IPv6 framing — `xfail` until the offsets are dynamic |
| `fixtures/*.pcap` | 25 handshake frames per client, trimmed from the corpus |
| `fixtures/synthetic/` | Hand-built framing the corpus does not contain |
| `oracle/*.tsv` | tshark's independent decode of each fixture |

## Two things to understand before changing this

**The oracle uses `tcp.desegment_tcp_streams:FALSE`.** The live path receives
one skb per event and cannot reassemble, so tshark's reassembled view contains
handshakes the parser is structurally unable to read — on the Chrome capture,
97 ClientHellos reassembled against 7 visible in single segments. Holding the
parser to the reassembled view would report the missing-reassembly gap as a
parser bug on roughly 90% of handshakes. `make_fixtures.sh` and
`make_oracle.sh` must keep this setting identical.

**`conftest.forwarded_by_ebpf` mirrors the kernel filter.** `bpf.py` raises a
TLS event only when the TCP payload *starts* with a handshake record
(`0x16`, major 3, minor 1-4). The corpus contains segments carrying a
ChangeCipherSpec record ahead of the handshake; tshark decodes those, the live
path never sees them. Feeding them to the parser tests a path production never
takes. `test_ebpf_gate_shortfall_is_recorded` measures that gap rather than
assuming it.

## Why `pythonpath = .` is in pytest.ini

`python -m pytest` puts the working directory on `sys.path`; the `pytest`
console script does not. Without that line the suite passes locally under
`python -m pytest` and fails in CI with `ModuleNotFoundError: No module named
'cryptomon'` — which is exactly how it first failed. Don't remove it unless
the package gains a real install (`pip install -e .`).

## Regenerating

Needs the corpus (`CryptomonData/`, `sandbox/`), which is gitignored. The
fixtures and oracle are committed, so this is only for adding a capture.

```bash
./tests/tools/make_fixtures.sh    # corpus  -> fixtures/*.pcap
./tests/tools/make_oracle.sh      # fixtures -> oracle/*.tsv
./tests/tools/make_synthetic.py   # hand-built VLAN / QinQ / IPv6
```

Note `tls.handshake.type in {1,2,11}` needs Wireshark 3.6+; the scripts use
the `||` form so they work on 3.4, which is what ships on macOS.
