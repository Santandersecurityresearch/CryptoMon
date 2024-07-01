bpf_txt = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_PERF_OUTPUT(skb_events);

struct eth_hdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    unsigned short  h_proto;
};

int crypto_monitor(struct __sk_buff *skb)
{
    u64 magic = 0xfaceb00c;
    u8 *cursor = 0;
    u32 saddr, daddr;
    unsigned short sport, dport;
    long prts = 0;
    long one = 1;
    u64 pass_value = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
    if (ip->ver != 4)
        return 0;
    if (ip->nextp != IP_TCP)
    {
        if (ip -> nextp != IP_UDP)
        {
            if (ip -> nextp != IP_ICMP)
                return 0;
        }
    }

    saddr = ip -> src;
    daddr = ip -> dst;
    sport = tcp -> src_port;
    dport = tcp -> dst_port;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    if (dport != 0x1BB && sport != 0x1BB){ //filter for port 443, SSL
        return -1; // return -1 to keep packet, return 0 to drop packet.
    }

    u32  tcp_header_length = 0;
    u32  ip_header_length = 0;
    u32  payload_offset = 0;
    u32  payload_length = 0;

    // IP header length is ip->hlen times 4
    ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

    // similarly for TCP header len
    tcp_header_length = tcp->offset << 2;

    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    payload_length = ip->tlen - ip_header_length - tcp_header_length;

    // we are only interested in packets that are
    // client- or server-side TLS HELLO packets
    unsigned short hello_check = load_byte(skb, payload_offset);
    if (hello_check != 0x16){
    // TLS 'helo' data is heralded by a value of '22'.
        return -1;
    }

    skb_events.perf_submit_skb(skb, skb->len, &pass_value, sizeof(pass_value));

    return TC_ACT_OK;
}"""
