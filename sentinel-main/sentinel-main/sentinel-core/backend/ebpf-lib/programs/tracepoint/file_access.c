// SPDX-License-Identifier: GPL-2.0
// SENTINEL file access monitor
// Hooks sys_enter_openat to detect access to sensitive files.

#include "../common/types.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  /* 256 KiB */
} file_events SEC(".maps");

/* Monitored paths: user-space populates this map with paths to watch.
 * Key is a hash of the path; value indicates active monitoring. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct monitored_path);
} monitored_paths SEC(".maps");

/* Tracepoint context for syscalls/sys_enter_openat */
struct trace_event_raw_sys_enter_openat {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    long           dfd;
    const char    *filename;
    long           flags;
    long           mode;
};

/* djb2 hash for path comparison in BPF */
static __always_inline __u64 hash_path(const char *path, int len)
{
    __u64 hash = 5381;
    for (int i = 0; i < len && i < MAX_PATH_LEN; i++) {
        char c = path[i];
        if (c == 0)
            break;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sentinel_file_access(struct trace_event_raw_sys_enter_openat *ctx)
{
    char path_buf[MAX_PATH_LEN] = {};
    int ret = bpf_probe_read_user_str(path_buf, sizeof(path_buf), ctx->filename);
    if (ret <= 0)
        return 0;

    __u64 path_hash = hash_path(path_buf, ret);
    struct monitored_path *mp = bpf_map_lookup_elem(&monitored_paths, &path_hash);
    if (!mp || !mp->active)
        return 0;

    struct file_access_event *evt;
    evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->event_type = SENTINEL_EVENT_FILE_ACCESS;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid   = bpf_get_current_pid_tgid() >> 32;
    evt->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->flags = (__u32)ctx->flags;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->path, path_buf, MAX_PATH_LEN);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
