// Minimal XDP program for SENTINEL
//
// This program currently counts packets and passes them up the stack.
// In production you can extend it to perform early drops or steering
// into AF_XDP queues.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_cnt SEC(".maps");

SEC("xdp")
int xdp_sentinel_prog(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&packet_cnt, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    // For now, do not drop traffic; just pass it upwards.
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

