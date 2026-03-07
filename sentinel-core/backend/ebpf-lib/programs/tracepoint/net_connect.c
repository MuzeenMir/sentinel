// SPDX-License-Identifier: GPL-2.0
// SENTINEL network connect monitor
// Hooks tcp_v4_connect to capture outbound connections per process.

#include "../common/types.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  /* 256 KiB */
} connect_events SEC(".maps");

/* Track in-flight connects so we can get the destination from return probe */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);  /* pid_tgid */
    __type(value, struct sock *);
} connect_ctx SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int sentinel_tcp_v4_connect_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_ctx, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int sentinel_tcp_v4_connect_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    if (ret != 0 && ret != -115)  /* -EINPROGRESS is okay */
        goto cleanup;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&connect_ctx, &pid_tgid);
    if (!skp)
        return 0;

    struct sock *sk = *skp;

    struct net_connect_event *evt;
    evt = bpf_ringbuf_reserve(&connect_events, sizeof(*evt), 0);
    if (!evt)
        goto cleanup;

    evt->event_type = SENTINEL_EVENT_NET_CONNECT;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid_tgid >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->protocol = IPPROTO_TCP;

    BPF_CORE_READ_INTO(&evt->dst_ip, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt->dst_port, sk, __sk_common.skc_dport);
    evt->dst_port = bpf_ntohs(evt->dst_port);

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);

cleanup:
    bpf_map_delete_elem(&connect_ctx, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
