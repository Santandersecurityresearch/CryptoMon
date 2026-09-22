#!/usr/bin/env bash
#
# Regenerate tests/fixtures/*.pcap from the full capture corpus.
#
# The corpus (CryptomonData/, sandbox/) is gitignored and multi-megabyte; the
# fixtures are a few tens of kilobytes and ARE committed, so the suite runs
# without it. Re-run this only when adding a capture or changing the trim.
#
#   ./tests/tools/make_fixtures.sh
#
# Two things to know about the trim:
#
#  * -o tcp.desegment_tcp_streams:FALSE keeps only what a single-skb reader can
#    see. The live eBPF path gets one skb per event by construction and cannot
#    reassemble, so a fixture built from the reassembled view would hold
#    handshakes the parser is structurally unable to read. Keeping the two
#    views aligned is what makes a failure mean "the parser is wrong" rather
#    than "TCP reassembly is not implemented yet".
#
#  * The set-membership form `tls.handshake.type in {1,2,11}` needs Wireshark
#    3.6+. The || form below works on 3.4, which is what ships on macOS.
#
set -euo pipefail
cd "$(dirname "$0")/../.."

FILTER='tls.handshake.type==1 || tls.handshake.type==2 || tls.handshake.type==11'
MAX_FRAMES=25
OUT=tests/fixtures

command -v tshark >/dev/null || { echo "tshark not found" >&2; exit 1; }

trim() {   # trim <source pcap> <fixture name>
  local src="$1" name="$2"
  [ -f "$src" ] || { echo "  skip   $name (no $src)"; return; }
  # Filter first, then truncate. tshark's -c is a *read* limit, not a match
  # limit, so combining it with -Y silently yields "matches among the first N
  # packets of the file" -- which for these captures is almost nothing.
  local tmp
  tmp="$(mktemp -t cryptomon-fixture)"
  tshark -r "$src" -o tcp.desegment_tcp_streams:FALSE -Y "$FILTER" \
         -w "$tmp" 2>/dev/null
  editcap -r "$tmp" "$OUT/$name.pcap" "1-$MAX_FRAMES" 2>/dev/null
  rm -f "$tmp"
  printf '  wrote  %-22s %6s bytes  %s frames\n' "$name.pcap" \
    "$(wc -c < "$OUT/$name.pcap" | tr -d ' ')" \
    "$(tshark -r "$OUT/$name.pcap" 2>/dev/null | wc -l | tr -d ' ')"
}

MAC=CryptomonData/UC_1-Common_Apps-Mac_PCAPs
WIN=CryptomonData/UC_1-Common_Apps-Windows_11_PCAPs

trim "$MAC/2024-12-11_UC1_Chrome_Mac.pcap"        chrome_mac
trim "$MAC/2024-12-11_UC1_Edge_Mac.pcap"          edge_mac
trim "$MAC/2024-12-11_UC1_Firefox_Mac.pcap"       firefox_mac
trim "$MAC/2024-12-11_UC1_Safari_Mac.pcap"        safari_mac
trim "$MAC/2024-12-11_UC1_Teams_Chrome_Mac.pcap"  teams_chrome_mac
trim "$WIN/2024-11-05_UC1_Win11_Edge.pcap"        edge_win11
trim "$WIN/2024-11-05_UC1_Win11_Outlook.pcap"     outlook_win11
trim "$WIN/2024-11-05_UC1_Win11_Teams.pcap"       teams_win11
trim "sandbox/A007653A_00001_20230626092541.pcap" pcapng_sample

echo
echo "Now regenerate the oracle:  ./tests/tools/make_oracle.sh"
