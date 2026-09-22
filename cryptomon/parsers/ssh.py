"""
SSH KEXINIT parsing.

Pure functions: bytes in, dict out. Moved verbatim from
CryptoMon.ssh_parse_crypto; only the skb unwrapping and the header walk changed.
"""
from cryptomon.data import SSH_SECTIONS
from cryptomon.parsers.framing import decode_ipv4_tcp
from cryptomon.utils import PARSE_STATS, lst2int


def parse_ssh(raw, magic=2):
    """Parse one SSH KEXINIT frame into its algorithm lists."""
    data = {}
    frame = decode_ipv4_tcp(raw)
    if frame is None:
        PARSE_STATS['unsupported_framing'] += 1
        return {}
    ssh_offset = frame.payload_offset
    src_prt = frame.endpoints['src']['port']
    data['ptype'] = "server" if src_prt == 22 else "client"
    # The IPv4 total length field, which moves with a VLAN tag; it used to be
    # read from the fixed offset 16.
    full_packet_len = frame.ip_total_len
    data['eth'] = frame.endpoints
    data['ssh'] = {}
    # ssh_section_len = lst2int(raw[ssh_offset:ssh_offset+4])
    ssh_offset = ssh_offset + 6 + 16  # 6 bytes for packet length, padding length,
                                      # and message code then 16 bytes for SSH cookie

    for sec in SSH_SECTIONS:
        if not (ssh_offset < full_packet_len):
            break
        sec_len = lst2int(raw[ssh_offset:ssh_offset+4])
        ssh_offset += 4
        str_block = raw[ssh_offset:ssh_offset+sec_len]  # get the block of text
        str_raw = "".join([chr(x) for x in str_block])
        data['ssh'][sec] = str_raw.split(',')  # split on commas
        ssh_offset += sec_len
    return data
