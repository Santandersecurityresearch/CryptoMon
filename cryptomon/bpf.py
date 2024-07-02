bpf_txt = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>


// here are our protocol constrants
#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_PERF_OUTPUT(skb_events);

// this is our ethernet header
struct eth_hdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    unsigned short  h_proto;
};

// this is the main program that monitors all crypto handshakes
// when each packet is received, it will be processed by this function
int crypto_monitor(struct __sk_buff *skb)
{
    u64 magic = 0xfaceb00c; // our magic number
    u8 *cursor = 0; 
    unsigned short sport, dport; // source and destination port
    long prts = 0;
    long one = 1;
    u64 pass_value = 0;

    struct eth_hdr *ethernet = cursor_advance(cursor, sizeof(*ethernet)); 
    struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    u32 saddr[4], daddr[4];

    // check which ip version we have ipb4 or ipv6
    if (ip6->ver != 4 && ip6->ver != 6)
        return 0;

    // check what the protocol is (TCP, UDP, ICMP)    
    if (ip6->nextp != IP_TCP && ip6->nextp != IP_UDP && ip6->nextp != IP_ICMP)
        return 0;

        
    // if this is ipv4 then process it    
    if (ip6->ver == 4) {
        struct ip_t *ip = (struct ip_t *)ip6;
        saddr[0] = ip->src;
        daddr[0] = ip->dst;
    } else { // if this is ipv6 then process it
        bpf_probe_read(&saddr, sizeof(saddr), ip6->src);
        bpf_probe_read(&daddr, sizeof(daddr), ip6->dst);
    }

    // extract the source and destination ports
    sport = tcp->src_port;
    dport = tcp->dst_port;

    
    // here's where we filter for the ports we are interested in 
    if (dport != 0x1BB && sport != 0x1BB || // port 443
        dport != 3389 && sport != 3389 || // port 3389 (RDP)
        dport != 8080 && sport != 8080 || // port 8080
        dport != 8443 && sport != 8443)   // port 8443
    {
        return -1; // return -1 to keep packet, return 0 to drop packet.
    }

    // calculate the length of the headers
    u32 tcp_header_length = tcp->offset << 2;
    u32 ip_header_length = (ip6->ver == 4) ? ((struct ip_t *)ip6)->hlen << 2 : sizeof(*ip6);

    // here we look for the TLS 'hello' message
    u32 payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    u32 payload_length = (ip6->ver == 4) ? ((struct ip_t *)ip6)->tlen - ip_header_length - tcp_header_length : ip6->plen - tcp_header_length;

    unsigned short hello_check = load_byte(skb, payload_offset);
    if (hello_check != 0x16) {
        // TLS 'hello' data is heralded by a value of '22'.
        return -1;
    }

    // once we found the bits we want, submit them to the user space
    skb_events.perf_submit_skb(skb, skb->len, &saddr, sizeof(saddr));
    skb_events.perf_submit_skb(skb, skb->len, &daddr, sizeof(daddr));

    return TC_ACT_OK;
}
"""
