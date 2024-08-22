#!/usr/bin/python

"""
cryptomon.py  Find TLS traffic and extract cryptographic data/settings,
    then submit the information to a MongoDB database for 
    retrieval and analysis.

Licensed under the Apache License, Version 2.0 (the "License")
Author: Mark Carney (mark[.]carney[@]gruposantander[.]com)
"""

__author__ = "Mark Carney & Daniel Cuthbert"
__copyright__ = "Copyright 2024, Mark Carney. Daniel Cuthbert"
__credits__ = ["Mark Carney"]
__license__ = "GLP 3.0"
__version__ = "1.1.0"
__maintainer__ = "Mark Carney"
__email__ = "mark.carney@gruposantander.com"
__status__ = "Demonstration"

import asyncio
import argparse
import psutil
from fapi.config import settings

from cryptomon import CryptoMon


banner = r"""
 _______  _______           _______ _________ _______  _______  _______  _       
(  ____ \(  ____ )|\     /|(  ____ )\__   __/(  ___  )(       )(  ___  )( (    /|
| (    \/| (    )|( \   / )| (    )|   ) (   | (   ) || () () || (   ) ||  \  ( |
| |      | (____)| \ (_) / | (____)|   | |   | |   | || || || || |   | ||   \ | |
| |      |     __)  \   /  |  _____)   | |   | |   | || |(_)| || |   | || (\ \) |
| |      | (\ (      ) (   | (         | |   | |   | || |   | || |   | || | \   |
| (____/\| ) \ \__   | |   | )         | |   | (___) || )   ( || (___) || )  \  |
(_______/|/   \__/   \_/   |/          )_(   (_______)|/     \|(_______)|/    )_)
                                                                                 
   ,     ,
  (\____/)    sniff...
   (_oo_)     
     (O)
   __||__   \)
 []/______\[]
 / \______/ \
/    /__\    
\   /____\   

"""

def list_interfaces():
    interfaces = psutil.net_if_addrs().keys()
    return list(interfaces)


def parse_argz():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", 
                        help="Interface to hook with eBPF module.")
    parser.add_argument("--ipv6", action="store_true",
                        help="Enable IPv6 support.")
    args = parser.parse_args()

    if not args.interface:
        interfaces = list_interfaces()
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}: {iface}")
        choice = int(input("Select an interface by number: ")) - 1
        args.interface = interfaces[choice]

    return args


if __name__ == "__main__":

    print(banner)
    task_list = []
    args = parse_argz()
    cm = CryptoMon(iface=args.interface,
                   mongodb=True,
                   settings=settings,
                   data_tag="")
    loop = asyncio.get_event_loop()
    loop.create_task(cm.run_async())
    loop.run_forever()
    # alternatively, run...
    # cm.run()
