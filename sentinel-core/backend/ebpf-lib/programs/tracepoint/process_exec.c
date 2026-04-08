// SPDX-License-Identifier: GPL-2.0
// SENTINEL process execution monitor
// Attaches to sched_process_exec to capture every new process.

#include "../common/types.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  /* 256 KiB */
} exec_events SEC(".maps");

/* Tracepoint context for sched/sched_process_exec */
struct trace_event_raw_sched_process_exec {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __data_loc_filename;
    pid_t          pid;
    pid_t          old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int sentinel_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_exec_event *evt;
    evt = bpf_ringbuf_reserve(&exec_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->event_type = SENTINEL_EVENT_PROCESS_EXEC;
    evt->timestamp_ns = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->pid  = bpf_get_current_pid_tgid() >> 32;
    evt->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->gid  = bpf_get_current_uid_gid() >> 32;

    /* Read parent PID */
    struct task_struct *parent;
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    BPF_CORE_READ_INTO(&evt->ppid, parent, tgid);

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Read filename from tracepoint data */
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(evt->filename, sizeof(evt->filename),
                       (void *)ctx + fname_off);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
