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
from cryptomon.data import TLS_DICT, TLS_GROUPS_DICT, SSH_SECTIONS
from cryptomon.utils import lst2int, lst2str, parse_sigalgs, get_tls_version
from cryptomon.utils import decimal_to_human, cert_guess
from cryptomon.utils import PARSE_STATS, is_grease
from cryptomon.utils import describe_codepoint, describe_codepoints
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI
from tinydb import TinyDB

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

# Per-run write counters, so that silent data loss becomes visible. Module
# scope mirrors the parse counters and keeps them readable from anywhere.
WRITE_STATS = collections.Counter()

# How many inserts may be in flight before new records are dropped. A burst of
# handshakes must not be allowed to queue futures without bound.
DEFAULT_MAX_PENDING = 1000

ETH_HDR_LEN = 14
IP4_HDR_LEN = 20
TCP_HDR_LEN = 20


class CryptoMon(object):
    def __init__(self, iface="enp0s1", fapiapp: FastAPI = "",
                 mongodb=False, settings="",
                 bpf_code=bpf_ipv4_txt, pcap_file="",
                 data_tag="", load_method="library",
                 max_pending=DEFAULT_MAX_PENDING):
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
            self.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
            self.mongodb = self.mongodb_client[settings.DB_NAME]
            self.backend = 'mongodb'
        else:
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
        data = {}
        ETH_HDR_LEN = 14
        IP4_HDR_LEN = 20
        TCP_HDR_LEN = 20

        net_packet_len = ETH_HDR_LEN + IP4_HDR_LEN
        tcp_hdr_len = ((skb_event.raw[net_packet_len+12:net_packet_len+13][0] >> 4) * 4) # get tcp header len
        tls_offset = net_packet_len + tcp_hdr_len
        srcdst = skb_event.magic
        sess_id_len = skb_event.raw[tls_offset+43]
        supported_groups = []
        supported_sigalgs = []
        supported_tls_versions = []
        src = lst2int(skb_event.raw[26:30])
        dst = lst2int(skb_event.raw[30:34])
        data['eth'] = {}
        data['eth']['src'] = {}
        data['eth']['dst'] = {}
        data['eth']['src']['ipv4'] = decimal_to_human(str(src))
        data['eth']['dst']['ipv4'] = decimal_to_human(str(dst))
        data['eth']['src']['port'] = lst2int(skb_event.raw[net_packet_len:net_packet_len+2])
        data['eth']['dst']['port'] = lst2int(skb_event.raw[net_packet_len+2:net_packet_len+4])
        data['tls'] = {}
        data['tls']['tls_versions'] = get_tls_version(skb_event.raw[tls_offset + 9: tls_offset + 11])
        tls_len = lst2int(skb_event.raw[tls_offset + 3: tls_offset + 5])
        # the 44 in the next line is the various declarations of TLS type plus a 32-byte random value.
        offset = tls_offset + 44 + sess_id_len
        if skb_event.raw[tls_offset + 5] == 2:  # server helo
            data['ptype'] = 'server'
            negotiated_suite = tuple(skb_event.raw[offset:offset+2])
            data['tls']['ciphersuite'] = describe_codepoint(
                TLS_DICT, negotiated_suite, 'unknown_ciphersuite')
            ext_offset = offset + 5  # SKIP negotiated suite (2 bytes), TLS section length (2 bytes) and compression method (1 byte)
            ext_section_len = ext_offset + lst2int(skb_event.raw[offset+3:offset+5])
            while ext_offset < ext_section_len:
                ext_type = lst2int(skb_event.raw[ext_offset:ext_offset+2])
                ext_len = lst2int(skb_event.raw[ext_offset+2:ext_offset+4])
                if ext_type == 51:  # key section
                    kex_group = tuple(skb_event.raw[ext_offset+4:ext_offset+6])
                    data['tls']['kex_group'] = describe_codepoint(
                        TLS_GROUPS_DICT, kex_group, 'unknown_group')
                if ext_type == 43:  # supported TLS versions
                    vers_offset = ext_offset + 2
                    # Two byte length for server HELO... (1 for client HELO)
                    vers_ext_len = lst2int(skb_event.raw[vers_offset:vers_offset+2])
                    vers_offset += 2
                    for i in range(0, vers_ext_len, 2):
                        supported_tls_versions.append(skb_event.raw[vers_offset+i:vers_offset+i+2])
                    data['tls']['tls_versions'] = [get_tls_version(x) for x in supported_tls_versions]
                ext_offset += ext_len + 4
        if skb_event.raw[tls_offset + 5] == 1:  # client helo
            data['ptype'] = 'client'
            len_ciphersuite_list = lst2int(skb_event.raw[offset:offset+2])
            csuite_offset = offset + 2
            proposed_suites = skb_event.raw[csuite_offset:csuite_offset + len_ciphersuite_list]
            ciphersuites = list(zip(proposed_suites[::2], proposed_suites[1::2]))
            data['tls']['ciphersuites'] = describe_codepoints(
                TLS_DICT, ciphersuites, 'unknown_ciphersuite')
            ext_offset = csuite_offset + len_ciphersuite_list
            ext_offset = ext_offset + 1 + lst2int(skb_event.raw[ext_offset:ext_offset+1])  # compression method len, 1 byte
            ext_offset += 2  # extension length bytes
            while ext_offset < tls_len-1:
                ext_type = lst2int(skb_event.raw[ext_offset:ext_offset+2])
                ext_len = lst2int(skb_event.raw[ext_offset+2:ext_offset+4])
                if ext_type == 22:  # EtM is enabled
                    data['tls']['EtM'] = True
                else:
                    data['tls']['EtM'] = False
                if ext_type == 43:  # supported TLS versions
                    vers_offset = ext_offset + 4
                    vers_ext_len = skb_event.raw[vers_offset:vers_offset+1][0]  # just one byte...
                    vers_offset += 1
                    for i in range(0, vers_ext_len, 2):
                        supported_tls_versions.append(skb_event.raw[vers_offset+i:vers_offset+i+2])
                    data['tls']['tls_versions'] = [get_tls_version(x) for x in supported_tls_versions]
                if ext_type == 0:  # check if '0000' indicating server_name TLS parameter
                    name_offset = ext_offset + 7 # shift 7 bytes to find length of hostname
                    len_hostname = lst2int(skb_event.raw[name_offset:name_offset+2]) # get length of hostname
                    name_offset += 2  # skip over the length bytes we just enumerated
                    data['tls']['hostname'] = lst2str(skb_event.raw[name_offset:name_offset+len_hostname])
                if ext_type == 10:  # supported ECC groups
                    group_offset = ext_offset + 4
                    group_list_len = lst2int(skb_event.raw[group_offset:group_offset + 2])
                    group_offset += 2
                    for i in range(0, group_list_len, 2):
                        supported_groups.append(tuple(skb_event.raw[group_offset+i:group_offset+i+2]))
                    data['tls']['groups'] = describe_codepoints(
                        TLS_GROUPS_DICT, supported_groups, 'unknown_group')
                if ext_type == 13: # supported Signature Algorithms
                    sigalg_offset = ext_offset + 4
                    sigalt_list_len = lst2int(skb_event.raw[sigalg_offset:sigalg_offset + 2])
                    sigalg_offset += 2
                    for i in range(0, sigalt_list_len, 2):
                        supported_sigalgs.append(tuple(skb_event.raw[sigalg_offset+i:sigalg_offset+i+2]))
                    data['tls']['sigalgs'] = parse_sigalgs(supported_sigalgs)
                if ext_type == 51: # key share extension
                    # The client offers a *list* of key shares, and Chrome and
                    # Edge put a GREASE entry first (RFC 8701). Taking entry
                    # zero therefore recorded the padding as the negotiated
                    # group on every Chromium ClientHello; walk to the first
                    # real group instead.
                    shares_len = lst2int(skb_event.raw[ext_offset+4:ext_offset+6])
                    share_offset = ext_offset + 6
                    share_end = share_offset + shares_len
                    kex_group = None
                    while share_offset + 4 <= share_end:
                        group = tuple(skb_event.raw[share_offset:share_offset+2])
                        key_len = lst2int(skb_event.raw[share_offset+2:share_offset+4])
                        if not is_grease(group):
                            kex_group = group
                            break
                        PARSE_STATS['grease_filtered'] += 1
                        share_offset += 4 + key_len
                    if kex_group is not None:
                        data['tls']['kex_group'] = describe_codepoint(
                            TLS_GROUPS_DICT, kex_group, 'unknown_group')
                ext_offset += ext_len + 4
        # next, attempt to get a cert if present...
        if "ptype" not in data.keys():
            # this means that it wasn't a hello packet, so drop
            return {}
        cert = {}
        try:
            cert = cert_guess(skb_event.raw)
        except Exception:
            # Counted, not printed: this runs per packet at line rate, so the
            # counter is the surface. Read it with cryptomon.utils.PARSE_STATS.
            PARSE_STATS['cert_error'] += 1
        if cert:
            data['tls']['certificate'] = cert
        return data
    
    def ssh_parse_crypto(self, skb_event):
        data = {}
        ETH_HDR_LEN = 14
        IP4_HDR_LEN = 20
        # TCP_HDR_LEN = 20

        net_packet_len = ETH_HDR_LEN + IP4_HDR_LEN
        src_prt = lst2int(skb_event.raw[net_packet_len:net_packet_len+2])
        # dst_prt = lst2int(skb_event.raw[net_packet_len+2:net_packet_len+4])
        data['ptype'] = "server" if src_prt == 22 else "client"
        full_packet_len = lst2int(skb_event.raw[16:18])
        tcp_hdr_len = ((skb_event.raw[net_packet_len+12:net_packet_len+13][0] >> 4) * 4) # get tcp header len
        ssh_offset = net_packet_len + tcp_hdr_len
        src = lst2int(skb_event.raw[26:30])
        dst = lst2int(skb_event.raw[30:34])
        data['eth'] = {}
        data['eth']['src'] = {}
        data['eth']['dst'] = {}
        data['eth']['src']['ipv4'] = decimal_to_human(str(src))
        data['eth']['dst']['ipv4'] = decimal_to_human(str(dst))
        data['eth']['src']['port'] = lst2int(skb_event.raw[net_packet_len:net_packet_len+2])
        data['eth']['dst']['port'] = lst2int(skb_event.raw[net_packet_len+2:net_packet_len+4])
        data['ssh'] = {}
        # ssh_section_len = lst2int(skb_event.raw[ssh_offset:ssh_offset+4])
        ssh_offset = ssh_offset + 6 + 16  # 6 bytes for packet length, padding length,
                                          # and message code then 16 bytes for SSH cookie

        for sec in SSH_SECTIONS:
            if not (ssh_offset < full_packet_len):
                break
            sec_len = lst2int(skb_event.raw[ssh_offset:ssh_offset+4])
            ssh_offset += 4
            str_block = skb_event.raw[ssh_offset:ssh_offset+sec_len]  # get the block of text
            str_raw = "".join([chr(x) for x in str_block])
            data['ssh'][sec] = str_raw.split(',')  # split on commas
            ssh_offset += sec_len
        return data
