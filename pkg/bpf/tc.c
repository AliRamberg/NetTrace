#include "common.h"
#include "input.h"

#define QUERY_MISS 0
#define QUERY_HIT 1

#define ETH_ADDR_ZERO "\x00\x00\x00\x00\x00\x00"
#define IP_ADDR_ZERO "\x00\x00\x00\x00"

int static __always_inline handle_input(struct query **query)
{
    __u32 key = 0;
    *query = bpf_map_lookup_elem(&queries, &key);
    if (!*query)
        return 1;

    return 0;
}

int static __always_inline eth_proto_0(struct query *query)
{
    if (!query)
        return 1;
    BPF_PRINTK_DEBUG("query proto: %d", query->eth.h_proto);

    return 0;
}

int static __always_inline handle_eth(struct ethhdr *eth, struct query *query)
{
    if (!query)
        return QUERY_HIT;

    if (__builtin_memcmp(query->eth.h_dest, ETH_ADDR_ZERO, ETH_ALEN) &&
        __builtin_memcmp(query->eth.h_dest, eth->h_dest, ETH_ALEN))
        return QUERY_MISS;

    if (__builtin_memcmp(query->eth.h_source, ETH_ADDR_ZERO, ETH_ALEN) &&
        __builtin_memcmp(query->eth.h_source, eth->h_source, ETH_ALEN))
        return QUERY_MISS;

    if (query->eth.h_proto && eth->h_proto != query->eth.h_proto)
        return QUERY_MISS;

    return QUERY_HIT;
}

int static __always_inline handle_ip(struct iphdr *ip, struct query *query)
{
    if (!query)
        return QUERY_HIT;

    if (__builtin_memcmp(&query->ip.daddr, IP_ADDR_ZERO, sizeof(__u32)) &&
        __builtin_memcmp(&query->ip.daddr, &ip->daddr, sizeof(__u32)))
        return QUERY_MISS;

    if (__builtin_memcmp(&query->ip.saddr, IP_ADDR_ZERO, sizeof(__u32)) &&
        __builtin_memcmp(&query->ip.saddr, &ip->saddr, sizeof(__u32)))
        return QUERY_MISS;

    if (ip->protocol != query->ip.protocol)
        return QUERY_MISS;

    return QUERY_HIT;
}

int static __always_inline handle_tcp(struct tcphdr *tcp, struct query *query)
{
    if (!query)
        return QUERY_HIT;

    if (query->tcp.dest && tcp->dest != query->tcp.dest)
        return QUERY_MISS;

    if (query->tcp.source && tcp->source != query->tcp.source)
        return QUERY_MISS;

    return QUERY_HIT;
}

int static __always_inline handle_udp(struct udphdr *udp, struct query *query)
{
    if (!query)
        return QUERY_HIT;

    if (query->udp.dest && udp->dest != query->udp.dest)
        return QUERY_MISS;

    if (query->udp.source && udp->source != query->udp.source)
        return QUERY_MISS;

    return QUERY_HIT;
}

struct query query = {0};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1024 KB ~ 700 TCP packets
} events SEC(".maps");

SEC("classifier")
const int traffic_tracer(struct __sk_buff *skb)
{
    int ret;
    struct query *q = &query;
    struct event *e;

    if (handle_input(&q))
    {
        BPF_PRINTK_DEBUG("failed to load query");
        return TC_ACT_OK;
    }

    // Data link layer
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0 || !handle_eth(&eth, q))
        return TC_ACT_OK;

    if (q && q->eth.h_proto == 0)
    {
        // Not an IP packet, so we let the userspace handle it
        goto send_event;
    }

    // Network layer
    if (eth.h_proto != bpf_htons(ETH_P_IP))
    {
        // Not an IP packet, so we let the userspace handle it
        goto send_event;
    }

    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0 || !handle_ip(&ip, q))
        return TC_ACT_OK;

    // Transport layer
    // currently support only tcp and udp packets.
    // otherwise, we let the userspace handle it
    if (ip.protocol == IPPROTO_UDP)
    {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &udp, sizeof(udp)) < 0 || !handle_udp(&udp, q))
            return TC_ACT_OK;
    }
    else if (ip.protocol == IPPROTO_TCP)
    {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &tcp, sizeof(tcp)) < 0 || !handle_tcp(&tcp, q))
            return TC_ACT_OK;
    }

send_event:
    if (!(e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0)))
    {
        BPF_PRINTK_WARN("ringbuf reserve failed, size %d", sizeof(*e));
        return TC_ACT_OK;
    }
    BPF_PRINTK_INFO("ringbuf reserved e: %p, %d bytes", (unsigned long long)e,
                    sizeof(*e));

    e->timestamp = bpf_ktime_get_ns();
    int max_len = sizeof(e->data);
    int len = skb->len;
    if (len > max_len)
        len = max_len; // Cap 'len' to 'max_len'

    if (len > 0) 
    {
        int ret = bpf_skb_load_bytes(skb, 0, e->data, len);
        if (ret < 0)
        {
            BPF_PRINTK_ERROR("failed to load skb data: %d", ret);
        }
    }

    BPF_PRINTK_INFO("event submit: timestamp: %lld, size %d", e->timestamp,
                    sizeof(*e));
    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
