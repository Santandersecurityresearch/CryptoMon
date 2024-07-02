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
__credits__ = ["Mark Carney"]
__license__ = "Apache 2.0"
__version__ = "1.0.0"
__maintainer__ = "Mark Carney"
__email__ = "mark.carney@gruposantander.com"
__status__ = "Demonstration"

import asyncio
import argparse

from fapi.config import settings
from cryptomon.bpf import bpf_ipv4_tls_txt, bpf_ipv4_ssh_txt

from cryptomon import CryptoMon

MOD_LOOKUP = {'ipv4_tls': (bpf_ipv4_tls_txt, "tls_parser"),
              'ipv4_ssh': (bpf_ipv4_ssh_txt, "ssh_parser")}

def parse_argz():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", 
                        default="enp0s1",
                        help="Interface to hook with eBPF module.",)
    parser.add_argument('-m', '--modules', nargs='+',
                        help='Set BPF modules. Choose from: \
                            ipv4_tls, ipv4_ssh, ipv6_tls',
                        default="ipv4_tls",)
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    task_list = []
    args = parse_argz()
    for i in args.modules:
        if i not in MOD_LOOKUP.keys():
            raise Exception("Invalid module!")
        a, b = MOD_LOOKUP[i]
        task_list.append(CryptoMon(iface=args.interface,
                                   mongodb=True,
                                   settings=settings,
                                   bpf_code=a,  # set bpf code block
                                   pparser=b))  # set packet parser
    loop = asyncio.get_event_loop()
    for t in task_list:
        loop.create_task(t.run_async())
    loop.run_forever()
