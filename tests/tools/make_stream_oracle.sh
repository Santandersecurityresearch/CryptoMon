#!/usr/bin/env bash
#
# Regenerate tests/oracle/streams/*.tsv from tests/fixtures/streams/*.pcap,
# with TCP desegmentation ON.
#
#   ./tests/tools/make_stream_oracle.sh
#
# This is the *other* oracle, and the difference from make_oracle.sh is the
# whole point of having two.
#
#   make_oracle.sh          desegmentation OFF -- what a single-packet reader
#                           can see. Judges cryptomon.parsers on the input the
#                           eBPF path actually receives.
#
#   make_stream_oracle.sh   desegmentation ON  -- what is really in the
#                           capture. Judges pcapscan, which reassembles first
#                           and so has no excuse for seeing less.
#
# Holding the offline path to the first oracle would pass whatever it did;
# holding the live path to this one would fail for a reason no parser change
# can fix. Two questions, two oracles.
#
# Both the fixtures and the oracle are committed, so the suite needs neither
# tshark nor the original corpus to run -- only to be regenerated. The
# `oracle` CI job re-runs this and fails if the committed files have drifted.
#
# Numeric code points are canonicalised to 0x%04x before being written.
# Wireshark 3.4 prints ciphersuites in decimal and 4.2 prints them in hex, so
# without this the drift check would fail on every runner whose tshark differs
# from whoever last regenerated the file -- which is a check on Wireshark
# releases, not on us. The decoded values are identical either way; only the
# spelling moved.
#
set -euo pipefail
cd "$(dirname "$0")/../.."

command -v tshark >/dev/null || { echo "tshark not found" >&2; exit 1; }
mkdir -p tests/oracle/streams

FIELDS=(frame.number tls.handshake.type
        tls.handshake.ciphersuite
        tls.handshake.extensions_key_share_group
        tls.handshake.extensions_server_name
        x509ce.dNSName x509sat.printableString)

for pcap in tests/fixtures/streams/*.pcap; do
  name="$(basename "$pcap" .pcap)"
  out="tests/oracle/streams/$name.tsv"
  {
    printf 'frame\ttype\tciphersuites\tkey_share\tsni\tcert_dns\tcert_names\n'
    args=(); for f in "${FIELDS[@]}"; do args+=(-e "$f"); done
    # No -o tcp.desegment_tcp_streams:FALSE here: the default is ON, which is
    # exactly what makes this oracle different from the other one.
    tshark -r "$pcap" -Y 'tls.handshake.type' -T fields \
           -E occurrence=a -E aggregator=, -E separator=/t "${args[@]}" 2>/dev/null
  } | python3 "$(dirname "$0")/canonicalise_oracle.py" ciphersuites key_share \
    > "$out"
  printf '  %-30s %s rows\n' "$(basename "$out")" "$(( $(wc -l < "$out") - 1 ))"
done

echo
echo "tshark: $(tshark -v 2>/dev/null | head -1)"
