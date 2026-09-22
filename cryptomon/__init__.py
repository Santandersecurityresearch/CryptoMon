"""
Cryptomon - a library that uses eBPF to monitor network traffic from 
    user space, with a view to catching and analysing TLS 'hello'
    packets from clients and servers, live.
"""

__author__ = "Mark Carney"
__copyright__ = "Copyright 2024, Mark Carney"
__credits__ = ["Mark Carney"]
__license__ = "GLP 3.0"
__version__ = "1.0.0"
__maintainer__ = "Mark Carney"
__email__ = "mark.carney@gruposantander.com"
__status__ = "Demonstration"

from cryptomon.bpf import bpf_ipv4_txt
from cryptomon.parsers import parse_ssh, parse_tls

import collections
import datetime as dt
import sys

import ctypes as ct
import asyncio

# bcc and pyroute2 are Linux-only and are supplied by the distribution
# (bpfcc-tools / python3-pyroute2, see ubuntu-setup.sh), not by pip. They are
# imported lazily in CryptoMon.__init__ so that everything else in this
# package -- in particular the packet parsers -- can be imported and tested on
# a machine that has neither, which is what CI and non-Linux development need.
#
# motor, fastapi and tinydb are now lazy for the same reason, one layer up.
# They are only ever used by a live CryptoMon instance, but importing them
# here meant `import cryptomon.analysis` -- and therefore `python -m pcapscan`
# and the sandbox worker -- pulled in fastapi, motor, pymongo, starlette and
# tinydb: 564 modules and a quarter of a second to parse a file that needs
# none of them. pcapscan's own docstring claims it imports no database
# driver; until this moved, that was not true.

# Per-run write counters, so that silent data loss becomes visible. Module
# scope mirrors the parse counters and keeps them readable from anywhere.
WRITE_STATS = collections.Counter()

# How many inserts may be in flight before new records are dropped. A burst of
# handshakes must not be allowed to queue futures without bound.
DEFAULT_MAX_PENDING = 1000

IP4_HDR_LEN = 20


class CryptoMon(object):
    def __init__(self, iface="enp0s1", fapiapp="",
                 mongodb=False, settings="",
                 bpf_code=bpf_ipv4_txt, pcap_file="",
                 data_tag="", load_method="library",
                 max_pending=DEFAULT_MAX_PENDING):
        """
        `fapiapp` is a FastAPI application or falsy. It used to be annotated
        `FastAPI` while defaulting to `""`, which is not a FastAPI and was
        the only reason this module imported fastapi at all.
        """
        if not settings:
            raise Exception("No settings provided... Aborting.")
        self.data_tag = data_tag if data_tag else ""
        try:
            from bcc import BPF
        except ImportError as exc:
            raise Exception(
                "bcc is not available, so the live monitor cannot start. It is "
                "Linux-only and comes from your distribution rather than pip: "
                "run ubuntu-setup.sh, or `apt-get install bpfcc-tools "
                "python3-bpfcc`. Parsing a capture offline does not need it."
            ) from exc
        self.b = BPF(text=bpf_code)
        self.unload_tc_device = False
        if load_method == "library":  # don't use Traffic Control to manage devices
            # old code
            self.fn = self.b.load_func("crypto_monitor", BPF.SOCKET_FILTER)
            BPF.attach_raw_socket(self.fn, iface)
        else:
            self.unload_tc_device = True
            # new code! 
            # most physical ethernet devices need TC to properly sniff.
            self.fn = self.b.load_func("crypto_monitor", BPF.SCHED_CLS)
            try:
                from pyroute2 import IPRoute
            except ImportError as exc:
                raise Exception(
                    "pyroute2 is not available, so load_method='tc' cannot "
                    "attach to the interface. Install it from your "
                    "distribution (`apt-get install python3-pyroute2`), or use "
                    "load_method='library' to attach a raw socket instead."
                ) from exc
            self.ipr = IPRoute()
            self.if_name = self.ipr.link_lookup(ifname=iface)[0]
            self.ipr.link('set', index=self.if_name, state='up')
            self.ipr.link('set', index=self.if_name, flags=['IFF_PROMISC'])  # set PROMISC mode...
            try:
                self.ipr.tc("add", "clsact", self.if_name)  # add qdisc clsact.
            except Exception:
                print("[i] 'add clsact' failed on interface, but may work fine...")
            # NB - the TC documentation doesn't say much about clsact yet.
            # The best ref is still: https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1f211a1b929c804100e138c5d3d656992cfd5622
            self.ipr.tc("add-filter", "bpf", self.if_name, ":1", fd=self.fn.fd,
                        name=self.fn.name, parent="ffff:fff2", # parent can be :fff2 for ingress or :fff3 for egress. 
                        classid=1, direct_action=True)
        self.b["skb_events"].open_perf_buffer(self.get_ebpf_data)
        # Dispatch on an explicit backend name. The previous code set
        # self.mongodb = False as its "no mongo" sentinel and then tested
        # `self.mongodb is not None`, which is True for False -- so the Mongo
        # branch was taken with a bool in hand and raised TypeError, and the
        # TinyDB branch was unreachable.
        self.max_pending = max_pending
        self._pending = set()
        self._warned_writes = set()
        self.mongodb_client = None
        self.mongodb = None
        self.tinydb = None
        self.fapi_app = None
        self.fapi_on = bool(fapiapp)
        if fapiapp:
            self.fapi_app = fapiapp
            self.backend = 'fapi'
        elif mongodb:
            from motor.motor_asyncio import AsyncIOMotorClient
            self.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
            self.mongodb = self.mongodb_client[settings.DB_NAME]
            self.backend = 'mongodb'
        else:
            from tinydb import TinyDB
            self.tinydb = TinyDB("cryptomon.json")
            self.backend = 'tinydb'
        
    def get_ebpf_data(self, cpu, data, size):
        class SkbEvent(ct.Structure):
            _fields_ = [("magic", ct.c_uint64),
                        ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))]
        # packet structure is:
        # 14 bytes - Ethernet header, 
        # 20 bytes - IPv4 header
        # 20-40 bytes - TCP header;
        skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
        match skb_event.magic:
            case 1:
                data = self.tls_parse_crypto(skb_event)
            case 2:
                data = self.ssh_parse_crypto(skb_event)
            case _:
                data = skb_event
        if not data:
            return
        self.handle_data(data)
        
    def handle_data(self, data_object):
        # add tag
        if self.data_tag:
            data_object['tag'] = self.data_tag
        # add timestamp
        data_object['ts'] = dt.datetime.now().timestamp()
        if self.backend == 'fapi':
            self._insert_mongo(self.fapi_app.mongodb["cryptomon"], data_object)
        elif self.backend == 'mongodb':
            self._insert_mongo(self.mongodb["cryptomon"], data_object)
        else:
            try:
                self.tinydb.insert(data_object)
            except Exception as exc:
                WRITE_STATS['failed'] += 1
                self._note_write_error(exc)
            else:
                WRITE_STATS['inserted'] += 1

    def _insert_mongo(self, collection, data_object):
        """
        Issue an insert and keep hold of its future so the result is retrieved.

        motor 3.5.1 returns an already-scheduled Future rather than a
        coroutine, so the write does go out even when nothing awaits it -- but
        the result was then discarded, and with it every auth failure, network
        error, validation error and duplicate key. Retrieving it from a
        done-callback keeps the packet path non-blocking while making failures
        countable.
        """
        if len(self._pending) >= self.max_pending:
            WRITE_STATS['dropped_backpressure'] += 1
            return
        try:
            future = collection.insert_one(data_object)
        except RuntimeError as exc:
            # motor needs a running event loop to schedule the write. This is
            # what makes the synchronous run() path unusable with MongoDB.
            WRITE_STATS['failed'] += 1
            self._note_write_error(exc)
            return
        self._pending.add(future)
        future.add_done_callback(self._insert_done)

    def _insert_done(self, future):
        self._pending.discard(future)
        try:
            future.result()
        except Exception as exc:
            WRITE_STATS['failed'] += 1
            self._note_write_error(exc)
        else:
            WRITE_STATS['inserted'] += 1

    def _note_write_error(self, exc):
        """Count every failure; print the first of each kind, once."""
        name = type(exc).__name__
        WRITE_STATS['failed_' + name] += 1
        if name not in self._warned_writes:
            self._warned_writes.add(name)
            print("[!] {0} write failed ({1}: {2}). Further occurrences are "
                  "counted in cryptomon.WRITE_STATS.".format(
                      self.backend, name, exc), file=sys.stderr)

    def close(self):
        """Release the interface and the storage client. Safe to call twice."""
        if self.unload_tc_device:
            try:
                self.ipr.tc("del-filter", "bpf", self.if_name)
            except Exception:
                WRITE_STATS['tc_cleanup_failed'] += 1
            self.unload_tc_device = False
        if self.mongodb_client is not None:
            self.mongodb_client.close()
            self.mongodb_client = None
        if self.tinydb is not None:
            self.tinydb.close()
            self.tinydb = None

    def run(self):
        """
        Synchronous poll loop.

        The MongoDB backends need a running event loop for motor to schedule
        writes, so pair those with run_async(); this path suits the TinyDB
        backend. Previously the cleanup sat in a `finally` *inside* the loop,
        so the TC filter was deleted on every poll, and KeyboardInterrupt only
        `pass`ed -- leaving Ctrl-C unable to stop the loop at all.
        """
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    async def run_async(self):
        try:
            while True:
                await asyncio.sleep(1)
                self.b.perf_buffer_poll()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            self.close()

    def tls_parse_crypto(self, skb_event):
        """
        Adapter: unwrap the eBPF SkbEvent and delegate.

        The parsing itself lives in cryptomon.parsers.tls as a pure function,
        so it can be driven from a capture file as easily as from the perf
        buffer. Signature unchanged.
        """
        return parse_tls(skb_event.raw, skb_event.magic)

    def ssh_parse_crypto(self, skb_event):
        """Adapter: unwrap the eBPF SkbEvent and delegate. See tls_parse_crypto."""
        return parse_ssh(skb_event.raw, skb_event.magic)
