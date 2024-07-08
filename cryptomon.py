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
__license__ = "GLP 3.0"
__version__ = "1.0.0"
__maintainer__ = "Mark Carney"
__email__ = "mark.carney@gruposantander.com"
__status__ = "Demonstration"

import asyncio
import argparse

from fapi.config import settings

from cryptomon import CryptoMon


def parse_argz():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", 
                        default="enp0s1",
                        help="Interface to hook with eBPF module.",)
    args = parser.parse_args()
    return args


if __name__ == "__main__":
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
