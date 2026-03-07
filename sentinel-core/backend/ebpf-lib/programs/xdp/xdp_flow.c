// SPDX-License-Identifier: GPL-2.0
// SENTINEL XDP flow monitor -- packet inspection, per-flow accounting, blocklist enforcement

#include "../common/types.h"

/* ── Maps ─────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  /* IPv4 address */
    __type(value, struct blocklist_value);
} ip_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  /* 1 MiB */
} flow_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_counter SEC(".maps");

/* Export threshold: emit a flow event after this many packets per flow */
#define FLOW_EXPORT_INTERVAL 64

/* ── Helpers ──────────────────────────────────────────────────────── */

static __always_inline int parse_ethhdr(void *data, void *data_end,
                                        struct ethhdr **eth)
{
    *eth = data;
    if ((void *)(*eth + 1) > data_end)
        return -1;
    return bpf_ntohs((*eth)->h_proto);
}

static __always_inline int parse_iphdr(void *data, void *data_end,
                                       struct iphdr **ip, void *l3_start)
{
    *ip = l3_start;
    if ((void *)(*ip + 1) > data_end)
        return -1;
    if ((*ip)->ihl < 5)
        return -1;
    return (*ip)->protocol;
}

static __always_inline void extract_ports(void *l4_start, void *data_end,
                                          __u8 proto, __u16 *sport, __u16 *dport,
                                          __u32 *tcp_flags)
{
    *sport = 0;
    *dport = 0;
    *tcp_flags = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_start;
        if ((void *)(tcp + 1) <= data_end) {
            *sport = bpf_ntohs(tcp->source);
            *dport = bpf_ntohs(tcp->dest);
            /* Pack flags: SYN=0x02, RST=0x04, FIN=0x01, ACK=0x10, PSH=0x08 */
            __u8 flags = 0;
            if (tcp->syn) flags |= 0x02;
            if (tcp->rst) flags |= 0x04;
            if (tcp->fin) flags |= 0x01;
            if (tcp->ack) flags |= 0x10;
            if (tcp->psh) flags |= 0x08;
            *tcp_flags = flags;
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_start;
        if ((void *)(udp + 1) <= data_end) {
            *sport = bpf_ntohs(udp->source);
            *dport = bpf_ntohs(udp->dest);
        }
    }
}

static __always_inline void emit_flow_event(struct flow_key *key,
                                            struct flow_value *val)
{
    struct network_flow_event *evt;
    evt = bpf_ringbuf_reserve(&flow_events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->event_type = SENTINEL_EVENT_NETWORK_FLOW;
    evt->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(&evt->key, key, sizeof(*key));
    __builtin_memcpy(&evt->value, val, sizeof(*val));

    bpf_ringbuf_submit(evt, 0);
}

/* ── XDP entry point ─────────────────────────────────────────────── */

SEC("xdp")
int sentinel_xdp_flow(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Count packets */
    __u32 idx = 0;
    __u64 *counter = bpf_map_lookup_elem(&pkt_counter, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    /* Parse Ethernet */
    struct ethhdr *eth;
    int proto = parse_ethhdr(data, data_end, &eth);
    if (proto != ETH_P_IP)
        return XDP_PASS;

    /* Parse IP */
    struct iphdr *ip;
    void *l3_start = (void *)(eth + 1);
    int l4_proto = parse_iphdr(data, data_end, &ip, l3_start);
    if (l4_proto < 0)
        return XDP_PASS;

    /* Check blocklist */
    __u32 src_ip = ip->saddr;
    struct blocklist_value *blocked = bpf_map_lookup_elem(&ip_blocklist, &src_ip);
    if (blocked) {
        __u64 pkt_len = data_end - data;
        __sync_fetch_and_add(&blocked->blocked_packets, 1);
        __sync_fetch_and_add(&blocked->blocked_bytes, pkt_len);
        return XDP_DROP;
    }

    /* Extract L4 ports and flags */
    void *l4_start = (void *)ip + (ip->ihl * 4);
    __u16 sport, dport;
    __u32 tcp_flags;
    extract_ports(l4_start, data_end, l4_proto, &sport, &dport, &tcp_flags);

    /* Build flow key */
    struct flow_key fk = {
        .src_ip   = src_ip,
        .dst_ip   = ip->daddr,
        .src_port = sport,
        .dst_port = dport,
        .protocol = l4_proto,
    };

    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = bpf_ntohs(ip->tot_len);

    /* Update flow table */
    struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &fk);
    if (fv) {
        __sync_fetch_and_add(&fv->packets, 1);
        __sync_fetch_and_add(&fv->bytes, pkt_len);
        fv->last_seen_ns = now;
        fv->tcp_flags |= tcp_flags;
        if (tcp_flags & 0x02) __sync_fetch_and_add(&fv->syn_count, 1);
        if (tcp_flags & 0x04) __sync_fetch_and_add(&fv->rst_count, 1);
        if (tcp_flags & 0x01) __sync_fetch_and_add(&fv->fin_count, 1);

        if (fv->packets % FLOW_EXPORT_INTERVAL == 0)
            emit_flow_event(&fk, fv);
    } else {
        struct flow_value new_fv = {
            .packets       = 1,
            .bytes         = pkt_len,
            .first_seen_ns = now,
            .last_seen_ns  = now,
            .tcp_flags     = tcp_flags,
            .syn_count     = (tcp_flags & 0x02) ? 1 : 0,
            .rst_count     = (tcp_flags & 0x04) ? 1 : 0,
            .fin_count     = (tcp_flags & 0x01) ? 1 : 0,
        };
        bpf_map_update_elem(&flow_table, &fk, &new_fv, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
