#!/usr/bin/env bash
#
# Extract whole TCP conversations from the capture corpus, for the tests that
# exercise reassembly.
#
#   ./tests/tools/make_stream_fixtures.sh
#
# Why these are separate from tests/fixtures/*.pcap, and why they had to exist:
#
# make_fixtures.sh builds its fixtures by filtering with
# `tcp.desegment_tcp_streams:FALSE` and keeping only the frames that survive.
# That is the right corpus for judging the single-frame parser -- it contains
# exactly what the kernel filter can forward -- but it is useless for judging
# reassembly, because every frame in it is already self-contained. Run the
# reassembler over those fixtures and it finds precisely what the single-frame
# path found, which proves nothing whatsoever.
#
# These fixtures are whole conversations instead: every frame of one TCP
# stream, SYN to close, in order. Each was chosen because it contains
# something a single frame cannot hold.
#
# All three are conversations with badssl.com and one Microsoft CDN endpoint
# -- deliberate test traffic to public endpoints, not somebody's browsing.
#
set -euo pipefail
cd "$(dirname "$0")/../.."

OUT=tests/fixtures/streams
MAC=CryptomonData/UC_1-Common_Apps-Mac_PCAPs

command -v tshark >/dev/null || { echo "tshark not found" >&2; exit 1; }
mkdir -p "$OUT"

# grab <source pcap> <tcp.stream index> <fixture name> <frame limit>
grab() {
  local src="$1" stream="$2" name="$3" limit="$4"
  [ -f "$src" ] || { echo "  skip   $name (no $src)"; return; }
  local tmp
  tmp="$(mktemp -t cryptomon-stream)"
  tshark -r "$src" -Y "tcp.stream==$stream" -w "$tmp" 2>/dev/null
  editcap -r "$tmp" "$OUT/$name.pcap" "1-$limit" 2>/dev/null
  rm -f "$tmp"
  printf '  wrote  %-26s %6s bytes  %s frames\n' "$name.pcap" \
    "$(wc -c < "$OUT/$name.pcap" | tr -d ' ')" \
    "$(tshark -r "$OUT/$name.pcap" 2>/dev/null | wc -l | tr -d ' ')"
}

# TLS 1.2, sha384.badssl.com. The ClientHello spans two segments (1238 + 660)
# and the certificate chain spans three, so the single-frame path sees a
# truncated hello and no certificate at all. Also carries a plaintext Alert.
grab "$MAC/2024-12-11_UC1_Firefox_Mac.pcap" 48 tls12_certificate 20

# TLS 1.2, badssl.com. Same shape, but the certificate is spread over six
# segments -- the case that needs the message walk, not just the record walk.
grab "$MAC/2024-12-11_UC1_Firefox_Mac.pcap" 26 tls12_split_certificate 16

# TLS 1.3 HelloRetryRequest, cdn.bizible.com. The server refuses the client's
# offered group and asks for another, so there are two ClientHellos and two
# ServerHellos on the connection -- with a middlebox-compatibility
# ChangeCipherSpec between them in each direction (RFC 8446 D.4). Reading that
# CCS as "everything after this is encrypted", which is correct for TLS 1.2,
# loses the second hello of every such exchange.
grab "$MAC/2024-12-11_UC1_Chrome_Mac.pcap" 96 tls13_hello_retry 24

echo
echo "These are committed. Regenerate only when adding a case."
