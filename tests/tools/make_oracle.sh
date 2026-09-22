#!/usr/bin/env bash
#
# Regenerate tests/oracle/*.tsv from tests/fixtures/*.pcap using tshark as an
# independent decoder. Both the fixtures and the oracle are committed, so the
# suite needs neither tshark nor the original corpus to run -- only to be
# regenerated.
#
#   ./tests/tools/make_oracle.sh
#
# tcp.desegment_tcp_streams:FALSE must match make_fixtures.sh: the oracle has
# to describe what a single-skb reader can see, or every fragmented handshake
# reads as a parser bug rather than as the missing-reassembly gap it is.
#
# TSV rather than -T json: the JSON layout shifts between Wireshark releases,
# and a committed oracle wants to diff cleanly when a fixture is regenerated.
#
set -euo pipefail
cd "$(dirname "$0")/../.."

command -v tshark >/dev/null || { echo "tshark not found" >&2; exit 1; }
mkdir -p tests/oracle

FIELDS=(frame.number tls.handshake.type tls.handshake.version
        tls.handshake.ciphersuite tls.handshake.extensions_supported_group
        tls.handshake.sig_hash_alg tls.handshake.extensions_key_share_group
        tls.handshake.extensions_server_name)

for pcap in tests/fixtures/*.pcap; do
  name="$(basename "$pcap" .pcap)"
  out="tests/oracle/$name.tsv"
  {
    printf 'frame\ttype\tversion\tciphersuites\tgroups\tsigalgs\tkey_share\tsni\n'
    args=(); for f in "${FIELDS[@]}"; do args+=(-e "$f"); done
    tshark -r "$pcap" -o tcp.desegment_tcp_streams:FALSE \
           -Y 'tls.handshake.type' -T fields \
           -E occurrence=a -E aggregator=, -E separator=/t "${args[@]}" 2>/dev/null
  } > "$out"
  printf '  %-24s %s rows\n' "$(basename "$out")" "$(( $(wc -l < "$out") - 1 ))"
done

echo
echo "tshark: $(tshark -v 2>/dev/null | head -1)"
