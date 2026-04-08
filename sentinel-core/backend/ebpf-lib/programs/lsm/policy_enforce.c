// SPDX-License-Identifier: GPL-2.0
// SENTINEL LSM-based runtime policy enforcement.
// Requires kernel 5.7+ with BPF_LSM enabled (CONFIG_BPF_LSM=y).
//
// Enforces policies by consulting BPF maps populated by the hardening-service
// and DRL engine. All decisions are logged to a ring buffer for audit.

#include "../common/types.h"

/* ── Maps ─────────────────────────────────────────────────────────── */

/* Ports restricted to specific process names.
 * Key: port number. Value: allowed comm (first match). */
struct port_policy {
    char allowed_comm[MAX_COMM_LEN];
    __u8 active;
    __u8 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);  /* port */
    __type(value, struct port_policy);
} port_bind_policy SEC(".maps");

/* Blocked module names. Key: hash of module name. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);  /* 1 = blocked */
} blocked_modules SEC(".maps");

/* Immutable paths: deny writes. Key: path hash. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  /* path hash */
    __type(value, __u8);  /* 1 = immutable */
} immutable_paths SEC(".maps");

/* Policy enforcement audit log */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  /* 256 KiB */
} policy_events SEC(".maps");

/* Global enforcement toggle: 0 = audit-only, 1 = enforce */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforcement_mode SEC(".maps");

/* ── Helpers ──────────────────────────────────────────────────────── */

static __always_inline int is_enforcing(void)
{
    __u32 idx = 0;
    __u32 *mode = bpf_map_lookup_elem(&enforcement_mode, &idx);
    return mode && *mode == 1;
}

static __always_inline void log_decision(__u32 pid, __u32 uid,
                                         __u32 action, __u32 rule_id,
                                         const char *detail, int detail_len)
{
    struct policy_decision_event *evt;
    evt = bpf_ringbuf_reserve(&policy_events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->event_type = SENTINEL_EVENT_POLICY_DECISION;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->uid = uid;
    evt->action = action;
    evt->rule_id = rule_id;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    if (detail && detail_len > 0)
        bpf_probe_read_kernel_str(evt->detail, sizeof(evt->detail), detail);

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline __u64 hash_str(const char *s, int len)
{
    __u64 hash = 5381;
    for (int i = 0; i < len && i < 64; i++) {
        char c = s[i];
        if (c == 0)
            break;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* ── LSM hooks ────────────────────────────────────────────────────── */

SEC("lsm/socket_bind")
int BPF_PROG(sentinel_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    if (address->sa_family != AF_INET && address->sa_family != AF_INET6)
        return 0;

    __u16 port;
    if (address->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        BPF_CORE_READ_INTO(&port, sin, sin_port);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        BPF_CORE_READ_INTO(&port, sin6, sin6_port);
    }
    port = bpf_ntohs(port);

    struct port_policy *pp = bpf_map_lookup_elem(&port_bind_policy, &port);
    if (!pp || !pp->active)
        return 0;

    char current_comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(current_comm, sizeof(current_comm));

    int match = 1;
    for (int i = 0; i < MAX_COMM_LEN; i++) {
        if (pp->allowed_comm[i] != current_comm[i]) {
            match = 0;
            break;
        }
        if (pp->allowed_comm[i] == 0)
            break;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (!match) {
        log_decision(pid, uid, POLICY_DENY, 1, "bind_port_denied", 18);
        if (is_enforcing())
            return -EACCES;
    }

    return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(sentinel_module_request, char *kmod_name, int ret)
{
    if (ret != 0)
        return ret;

    char mod_name[64] = {};
    bpf_probe_read_kernel_str(mod_name, sizeof(mod_name), kmod_name);

    __u64 mod_hash = hash_str(mod_name, 64);
    __u8 *blocked = bpf_map_lookup_elem(&blocked_modules, &mod_hash);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (blocked && *blocked) {
        log_decision(pid, uid, POLICY_DENY, 2, "module_load_denied", 20);
        if (is_enforcing())
            return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
