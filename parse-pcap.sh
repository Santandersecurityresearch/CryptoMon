#! /bin/bash

trap 'kill $(jobs -p) 2>/dev/null' EXIT

python3 ./cryptomon.py -i lo &
python3 ./cryptomon.py --pcap $1 -i lo
exit