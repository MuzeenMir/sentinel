// SPDX-License-Identifier: GPL-2.0
// SENTINEL privilege escalation and module load monitor.
// Detects setuid calls and kernel module loading.

#include "../common/types.h"

/* ── Ring buffers ─────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17);  /* 128 KiB */
} priv_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17);  /* 128 KiB */
} module_events SEC(".maps");

/* ── setuid tracepoint ───────────────────────────────────────────── */

struct trace_event_raw_sys_enter_setuid {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    long           uid;
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int sentinel_setuid(struct trace_event_raw_sys_enter_setuid *ctx)
{
    struct priv_escalation_event *evt;
    evt = bpf_ringbuf_reserve(&priv_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->event_type = SENTINEL_EVENT_PRIV_ESCALATION;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->target_uid = (__u32)ctx->uid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ── module load tracepoint ──────────────────────────────────────── */

struct trace_event_raw_module_load {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    unsigned int   taints;
    int            __data_loc_name;
};

SEC("tracepoint/module/module_load")
int sentinel_module_load(struct trace_event_raw_module_load *ctx)
{
    struct module_load_event *evt;
    evt = bpf_ringbuf_reserve(&module_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->event_type = SENTINEL_EVENT_MODULE_LOAD;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    unsigned short name_off = ctx->__data_loc_name & 0xFFFF;
    bpf_probe_read_str(evt->name, sizeof(evt->name),
                       (void *)ctx + name_off);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
