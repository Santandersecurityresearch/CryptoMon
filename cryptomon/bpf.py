bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// transport protocols
#define IP_TCP 6

// link layer
#define ETH_HLEN      14
#define ETH_P_IP      0x0800
#define ETH_P_IPV6    0x86DD
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_QINQ1   0x9100
#define ETH_P_QINQ2   0x9200
#define MAX_VLAN_TAGS 2

// IPv6 moved options out of the fixed header into a chain, so the transport
// header is only found by walking it. The walk must be bounded for the
// verifier, and a chain longer than this is hostile rather than real.
#define IP6_HDR_LEN   40
#define IP6_HOPOPTS   0
#define IP6_ROUTING   43
#define IP6_FRAGMENT  44
#define IP6_NONEXT    59
#define IP6_DSTOPTS   60
#define IP6_MOBILITY  135
#define MAX_IP6_EXT   4

BPF_PERF_OUTPUT(skb_events);

// Monitors crypto handshakes. Every offset below is computed from the packet
// rather than assumed, so VLAN-tagged frames, IPv4 options and IPv6 all reach
// the same port and handshake checks.
//
// Note the packet bytes themselves are what userspace parses: pass_value only
// carries which parser to use (1 = TLS, 2 = SSH), and perf_submit_skb hands
// over the whole frame.
int crypto_monitor(struct __sk_buff *skb)
{
    u64 pass_value = 0;
    u32 nh_off = ETH_HLEN;
    u16 ethertype = load_half(skb, 12);

    // --- link layer: step over any stacked VLAN tags --------------------
    #pragma unroll
    for (int i = 0; i < MAX_VLAN_TAGS; i++) {
        if (ethertype == ETH_P_8021Q  || ethertype == ETH_P_8021AD ||
            ethertype == ETH_P_QINQ1  || ethertype == ETH_P_QINQ2) {
            ethertype = load_half(skb, nh_off + 2);
            nh_off += 4;
        }
    }

    u32 proto  = 0;
    u32 th_off = 0;

    // --- network layer ---------------------------------------------------
    if (ethertype == ETH_P_IP) {
        u8  vhl = load_byte(skb, nh_off);
        u32 ihl = (vhl & 0x0f) << 2;
        if ((vhl >> 4) != 4 || ihl < 20)
            return TC_ACT_OK;
        proto  = load_byte(skb, nh_off + 9);
        th_off = nh_off + ihl;
    } else if (ethertype == ETH_P_IPV6) {
        proto  = load_byte(skb, nh_off + 6);
        th_off = nh_off + IP6_HDR_LEN;

        #pragma unroll
        for (int i = 0; i < MAX_IP6_EXT; i++) {
            if (proto == IP6_HOPOPTS || proto == IP6_ROUTING ||
                proto == IP6_DSTOPTS || proto == IP6_MOBILITY) {
                u8  next = load_byte(skb, th_off);
                u32 elen = (((u32)load_byte(skb, th_off + 1)) + 1) << 3;
                proto   = next;
                th_off += elen;
            } else if (proto == IP6_FRAGMENT) {
                // A non-initial fragment carries no transport header, so
                // anything read at th_off would be payload wearing a hat.
                if ((load_half(skb, th_off + 2) >> 3) != 0)
                    return TC_ACT_OK;
                proto   = load_byte(skb, th_off);
                th_off += 8;
            }
        }
    } else {
        return TC_ACT_OK;
    }

    // Only TCP. The previous program also let UDP and ICMP through to the
    // port checks below, then read a TCP data offset out of them -- the
    // userspace parsers refuse anything but TCP anyway, so those events were
    // decoded into nothing. QUIC needs its own path, not this one.
    if (proto != IP_TCP)
        return TC_ACT_OK;

    // --- transport layer ---------------------------------------------------
    u16 sport = load_half(skb, th_off);
    u16 dport = load_half(skb, th_off + 2);
    u32 tcp_header_length = (load_byte(skb, th_off + 12) >> 4) << 2;
    u32 payload_offset = th_off + tcp_header_length;

    // here's where we filter for the ports we are interested in
    if (dport == 443   || sport == 443   || // port 443  for TLS
        dport == 990   || sport == 990   || // port 990 for FTPS
        dport == 3389  || sport == 3389  || // port 3389 (RDP TLS)
        dport == 8080  || sport == 8080  || // port 8080 for TLS
        dport == 8443  || sport == 8443)    // port 8443 for TLS
    {
        // we are only interested in packets that are
        // client- or server-side TLS HELLO packets
        unsigned short hello_check = load_byte(skb, payload_offset);
        unsigned short hello_tls_1 = load_byte(skb, payload_offset+1);
        unsigned short hello_tls_2 = load_byte(skb, payload_offset+2);
        if (hello_check == 0x16 && hello_tls_1 == 3 &&
            (hello_tls_2 == 1 || hello_tls_2 == 2 ||
             hello_tls_2 == 3 || hello_tls_2 == 4 )){
            // TLS 'helo' data is heralded by a value of '22'.
            pass_value = 1;
            skb_events.perf_submit_skb(skb, skb->len,
                                       &pass_value, sizeof(pass_value));
            return -1;  // return -1 to keep packet, return 0 to drop packet.
        }
        return -1;
    }

    if (dport == 22 || sport == 22)
    {
        // client- or server-side SSH KEX Init packets
        unsigned short kex_init_check = load_byte(skb, payload_offset+5);
        if (kex_init_check == 0x14){
            // SSH KEX data is heralded by a value of '20'.
            pass_value = 2;
            skb_events.perf_submit_skb(skb, skb->len,
                                       &pass_value, sizeof(pass_value));
            return -1;
        }
        return -1;
    }
    return TC_ACT_OK;
}"""

# The program handles IPv4 and IPv6; the old name is kept so that anything
# importing it, including a pinned release, keeps working.
bpf_ipv4_txt = bpf_text
