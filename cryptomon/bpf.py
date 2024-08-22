# Santander Cyber Security Research (CSR)
# Copyright © 2024 Mark Carney
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Santander IDA Punycode generator for PoseidonVersion: 1.1


bpf_ipv4_txt = """
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

// define a structure for the IPv6 header

struct ipv6_t {
    unsigned char src[16];
    unsigned char dst[16];
    unsigned char next_header; //what header follows the IPv6 header
    unsigned char hop_limit; //max number of hops
    unsigned char vtc_flow; //the first 32 bits of the IPv6 header, which includes the version, traffic class, and flow label fields
    unsigned short payload_len; //payload length
};


// this now has logic to handle both ipv4 and iupv6 packets
int crypto_monitor(struct __sk_buff *skb)
{
    u64 magic = 0xfaceb00c; // our magic number
    u8 *cursor = 0;
    u32 saddr = 0, daddr = 0; // IPv4 source and destination addresses
    unsigned char saddr6[16] = {0}; // IPv6 source address
    unsigned char daddr6[16] = {0}; // IPv6 destination address
    unsigned short sport, dport;
    long prts = 0;
    long one = 1;
    u64 pass_value = 0;

    struct eth_hdr *ethernet = cursor_advance(cursor, sizeof(*ethernet));

     // IPv4 section
    if (ethernet->h_proto == bpf_htons(ETH_P_IP)) { // IPv4
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

        if (ip->ver != 4)
            return 0;
        if (ip->nextp != IP_TCP && ip->nextp != IP_UDP && ip->nextp != IP_ICMP)
            return 0;

        saddr = ip->src;
        daddr = ip->dst;

        // IPv6 section
    } else if (ethernet->h_proto == bpf_htons(ETH_P_IPV6)) { // IPv6
        struct ipv6_t *ipv6 = cursor_advance(cursor, sizeof(*ipv6));
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

        if (ipv6->next_header != IP_TCP && ipv6->next_header != IP_UDP && ipv6->next_header != IP_ICMP)
            return 0;

        bpf_probe_read(&saddr6, sizeof(saddr6), ipv6->src);
        bpf_probe_read(&daddr6, sizeof(daddr6), ipv6->dst);

    } else {
        return 0; // Not an IPv4 or IPv6 packet
    }

    // extract the source and destination ports
    sport = tcp->src_port;
    dport = tcp->dst_port;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

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
            bpf_trace_printk("TLS HELLO packet: saddr=%x, daddr=%x, sport=%d, dport=%d\\n",
                             saddr, daddr, sport, dport);
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
            bpf_trace_printk("SSH KEX Init packet: saddr=%x, daddr=%x, sport=%d, dport=%d\\n",
                             saddr, daddr, sport, dport);
            return -1;
        }
        return -1;
    }
    return TC_ACT_OK;
}"""
