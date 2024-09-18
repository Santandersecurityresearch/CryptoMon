#!/usr/bin/python

"""
cryptomon.py  Find TLS traffic and extract cryptographic data/settings,
    then submit the information to a MongoDB database for 
    retrieval and analysis.

Licensed under the Apache License, Version 2.0 (the "License")
Author: Mark Carney (mark[.]carney[@]gruposantander[.]com)
"""

__author__ = "Mark Carney"
__copyright__ = "Copyright 2024, Mark Carney"
__credits__ = ["Mark Carney", "Daniel Cuthbert"]
__license__ = "GLP 3.0"
__version__ = "1.0.0"
__maintainer__ = "Mark Carney"
__email__ = "mark.carney@gruposantander.com"
__status__ = "MVP"

import asyncio
import argparse
import psutil
import sys
from fapi.config import settings
from scapy.all import rdpcap, sendp

from cryptomon import CryptoMon

def list_interfaces():
    interfaces = psutil.net_if_addrs().keys()
    return list(interfaces)


def parse_argz():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", 
                        help="Interface to hook with eBPF module.")
    parser.add_argument("--pcap", 
                        help="PCAP file to be replayed on loopback.")
    args = parser.parse_args()

    if not args.interface:
        interfaces = list_interfaces()
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}: {iface}")
        choice = int(input("Select an interface by number: ")) - 1
        args.interface = interfaces[choice]

    if args.pcap:
        print("[i] Setting interface to loopback (lo) to parse PCAPs...")
        args.interface = "lo"
    return args


def rerun_pcap(pcap_file="test.pcap"):
    packets = rdpcap(pcap_file)
    iface = "lo"
    print(f"[i] Replaying packets from {str(pcap_file)}...")
    ctr = 0
    for packet in packets:
        if ctr % 10 == 0:
            print(f"[{int(100*ctr/len(packets))}%] {ctr} of {len(packets)}", end='\r')
        try:
            sendp(packet, iface=iface, verbose=False)
        except Exception as e:
            print(f"Error happened when sending packet...: {str(e)}")
        ctr += 1
    sys.exit(0)

if __name__ == "__main__":
    task_list = []
    args = parse_argz()
    if args.pcap:
        rerun_pcap(args.pcap)
        sys.exit(0)
    cm = CryptoMon(iface=args.interface,
                   mongodb=True,
                   settings=settings,
                   pcap_file=args.pcap,
                   data_tag="")
    loop = asyncio.get_event_loop()
    loop.create_task(cm.run_async())
    loop.run_forever()
    # alternatively, run...
    # cm.run()
