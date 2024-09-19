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
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI
from tinydb import TinyDB

import datetime as dt

from bcc import BPF
import ctypes as ct
import asyncio

ETH_HDR_LEN = 14
IP4_HDR_LEN = 20
TCP_HDR_LEN = 20


class CryptoMon(object):
    def __init__(self, iface="enp0s1", fapiapp: FastAPI = "",
                 mongodb=False, settings="",
                 bpf_code=bpf_ipv4_txt, pcap_file="",
                 data_tag=""):
        if not settings:
            raise Exception("No settings provided... Aborting.")
        self.data_tag = data_tag if data_tag else ""
        self.b = BPF(text=bpf_code)
        self.fn = self.b.load_func("crypto_monitor", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(self.fn, iface)
        self.b["skb_events"].open_perf_buffer(self.get_ebpf_data)
        self.fapi_on = False
        if fapiapp:
            self.fapi_on = True
            self.fapi_app = fapiapp
        if mongodb:
            self.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
            self.mongodb = self.mongodb_client[settings.DB_NAME]
        else:
            self.mongodb = False
        if not fapiapp and not mongodb:
            self.tinydb = TinyDB("cryptomon.json")
        
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
        if self.fapi_on:
            self.fapi_app.mongodb["cryptomon"].insert_one(data_object)
        elif self.mongodb is not None:
            self.mongodb["cryptomon"].insert_one(data_object)
        else:
            self.tinydb.insert(data_object)
            # print(data_object)
            # print("================================")

    def run(self):
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                self.mongodb_client.close()
                pass

    async def run_async(self):
        while True:
            await asyncio.sleep(1)
            self.b.perf_buffer_poll()
        
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
            data['tls']['ciphersuite'] = TLS_DICT[negotiated_suite]
            ext_offset = offset + 5  # SKIP negotiated suite (2 bytes), TLS section length (3 bytes)
            ext_section_len = ext_offset + lst2int(skb_event.raw[offset+3:offset+5])
            while ext_offset < ext_section_len:
                ext_type = lst2int(skb_event.raw[ext_offset:ext_offset+2])
                ext_len = lst2int(skb_event.raw[ext_offset+2:ext_offset+4])
                if ext_type == 51:  # key section
                    kex_group = tuple(skb_event.raw[ext_offset+4:ext_offset+6])
                    data['tls']['kex_group'] = TLS_GROUPS_DICT[kex_group]
                if ext_type == 43:  # supported TLS versions
                    vers_offset = ext_offset + 2
                    # Two byte length for server HELO... (1 for client HELO)
                    vers_ext_len = lst2int(skb_event.raw[vers_offset:vers_offset+2])
                    vers_offset += 2
                    for i in range(0, vers_ext_len, 2):
                        supported_tls_versions.append(skb_event.raw[vers_offset+i:vers_offset+i+2])
                    data['tls']['tls_versions'] = [get_tls_version(x) for x in supported_tls_versions]
                ext_offset = ext_len + 4
        if skb_event.raw[tls_offset + 5] == 1:  # client helo
            data['ptype'] = 'client'
            len_ciphersuite_list = lst2int(skb_event.raw[offset:offset+2])
            csuite_offset = offset + 2
            proposed_suites = skb_event.raw[csuite_offset:csuite_offset + len_ciphersuite_list]
            ciphersuites = list(zip(proposed_suites[::2], proposed_suites[1::2]))
            data['tls']['ciphersuites'] = [TLS_DICT.get(x, 'Reserved') for x in ciphersuites]
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
                    data['tls']['groups'] = [TLS_GROUPS_DICT.get(x, 'Reserved') for x in supported_groups]
                if ext_type == 13: # supported Signature Algorithms
                    sigalg_offset = ext_offset + 4
                    sigalt_list_len = lst2int(skb_event.raw[sigalg_offset:sigalg_offset + 2])
                    sigalg_offset += 2
                    for i in range(0, sigalt_list_len, 2):
                        supported_sigalgs.append(tuple(skb_event.raw[sigalg_offset+i:sigalg_offset+i+2]))
                    data['tls']['sigalgs'] = parse_sigalgs(supported_sigalgs)
                if ext_type == 51: # key share extension
                    kex_group = tuple(skb_event.raw[ext_offset+6:ext_offset+8])
                    data['tls']['kex_group'] = TLS_GROUPS_DICT.get(kex_group, 'Reserved')
                ext_offset += ext_len + 4
        # next, attempt to get a cert if present...
        if "ptype" not in data.keys():
            # this means that it wasn't a hello packet, so drop
            return {}
        cert = {}
        try:
            cert = cert_guess(skb_event.raw)
        except:
            pass
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
