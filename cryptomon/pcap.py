from cryptomon import CryptoMon
import ctypes as ct
from scapy.all import *
load_layer('tls')


def parse_pcap(pcap_file_path: str, cmon_instance: CryptoMon):
    print("[i] Loading PCAP...")
    p = rdpcap(pcap_file_path)
    print("[i] Locating TLS Client HELO packets...")
    tls_client_helo_list = []
    for packet in p:
        if TLS in packet:
            if type(packet[TLS].msg[0]) == scapy.layers.tls.handshake.TLSClientHello:
                tls_client_helo_list.append(packet)
    print("[i] Parsing Data...")
    for helo in tls_client_helo_list:
        raw_data = bytes(helo)
        size = len(raw_data)
        
        class SkbEvent(ct.Structure):
            _fields_ = [("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))]
        sk_object = ct.cast(raw_data, ct.POINTER(SkbEvent)).contents
        data = cmon_instance.tls_parse_crypto(sk_object)
        cmon_instance.handle_data(data)
    print("[i] DONE!")
    return 0
