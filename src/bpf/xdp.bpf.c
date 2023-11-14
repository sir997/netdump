#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

union ipaddr
{
    u32 ipv4;
    u32 ipv6[4];
};

struct event
{
    u16 eth_proto;
    u16 h_proto;
    u32 length;
    u64 timestamp;
    union ipaddr saddr;
    union ipaddr daddr;
};

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    void *data = (void *)(u64)ctx->data;
    void *data_end = (void *)(u64)ctx->data_end;

    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    struct iphdr *ip;
    struct ipv6hdr *ipv6;

    // union ipaddr saddr;
    // union ipaddr daddr;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return XDP_PASS;

    switch (bpf_ntohs(eth->h_proto))
    {
    case ETH_P_IP:
        ip = eth + sizeof(*eth);
        if (ip + sizeof(*ip) > data_end)
            break;

        e->saddr.ipv4 = bpf_ntohs(ip->saddr);
        e->daddr.ipv4 = bpf_ntohs(ip->daddr);
        break;
    case ETH_P_IPV6:
        ipv6 = eth + sizeof(*eth);
        if (ipv6 + sizeof(*ipv6) > data_end)
            break;

        for (int i = 0; i < 4; i++)
        {
            e->saddr.ipv6[i] = bpf_ntohl(ipv6->saddr.in6_u.u6_addr32[i]);
            e->daddr.ipv6[i] = bpf_ntohl(ipv6->daddr.in6_u.u6_addr32[i]);
        }
        break;
    default:
        // return XDP_PASS;
        break;
    }

    // e->saddr = saddr;
    // e->daddr = daddr;

    e->eth_proto = bpf_ntohs(eth->h_proto);
    e->timestamp = bpf_ktime_get_ns();
    e->length = data_end - data;
    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}