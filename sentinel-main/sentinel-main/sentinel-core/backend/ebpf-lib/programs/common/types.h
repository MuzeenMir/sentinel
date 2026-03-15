/* SPDX-License-Identifier: GPL-2.0 */
/* SENTINEL eBPF common types shared across all programs */

#ifndef __SENTINEL_TYPES_H
#define __SENTINEL_TYPES_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* ── Event types ──────────────────────────────────────────────────── */

enum sentinel_event_type {
    SENTINEL_EVENT_NETWORK_FLOW   = 1,
    SENTINEL_EVENT_PROCESS_EXEC   = 2,
    SENTINEL_EVENT_FILE_ACCESS    = 3,
    SENTINEL_EVENT_NET_CONNECT    = 4,
    SENTINEL_EVENT_PRIV_ESCALATION = 5,
    SENTINEL_EVENT_MODULE_LOAD    = 6,
    SENTINEL_EVENT_POLICY_DECISION = 7,
    SENTINEL_EVENT_PTRACE_ATTACH  = 8,
};

/* ── Network flow record (XDP) ───────────────────────────────────── */

#define FLOW_KEY_SIZE 13  /* 4+4+2+2+1 */

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
} __attribute__((packed));

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 tcp_flags;       /* OR of all flags seen */
    __u32 syn_count;
    __u32 rst_count;
    __u32 fin_count;
};

struct network_flow_event {
    __u32 event_type;      /* SENTINEL_EVENT_NETWORK_FLOW */
    __u64 timestamp_ns;
    struct flow_key key;
    struct flow_value value;
};

/* ── Process exec event (tracepoint) ─────────────────────────────── */

#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN     16

struct process_exec_event {
    __u32 event_type;      /* SENTINEL_EVENT_PROCESS_EXEC */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[MAX_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
};

/* ── File access event (tracepoint) ──────────────────────────────── */

#define MAX_PATH_LEN 256

struct file_access_event {
    __u32 event_type;      /* SENTINEL_EVENT_FILE_ACCESS */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 flags;           /* open flags */
    char  comm[MAX_COMM_LEN];
    char  path[MAX_PATH_LEN];
};

/* ── Network connect event (kprobe) ──────────────────────────────── */

struct net_connect_event {
    __u32 event_type;      /* SENTINEL_EVENT_NET_CONNECT */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad;
    char  comm[MAX_COMM_LEN];
};

/* ── Privilege escalation event ──────────────────────────────────── */

struct priv_escalation_event {
    __u32 event_type;      /* SENTINEL_EVENT_PRIV_ESCALATION */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 target_uid;
    char  comm[MAX_COMM_LEN];
};

/* ── Module load event ───────────────────────────────────────────── */

#define MAX_MODULE_NAME 64

struct module_load_event {
    __u32 event_type;      /* SENTINEL_EVENT_MODULE_LOAD */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char  name[MAX_MODULE_NAME];
};

/* ── Policy decision event (LSM) ─────────────────────────────────── */

enum policy_action {
    POLICY_ALLOW = 0,
    POLICY_DENY  = 1,
    POLICY_LOG   = 2,
};

struct policy_decision_event {
    __u32 event_type;      /* SENTINEL_EVENT_POLICY_DECISION */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 action;          /* enum policy_action */
    __u32 rule_id;
    char  comm[MAX_COMM_LEN];
    char  detail[128];
};

/* ── Blocklist entry for XDP ─────────────────────────────────────── */

struct blocklist_value {
    __u64 blocked_packets;
    __u64 blocked_bytes;
    __u64 added_ns;
    __u32 reason;          /* 0=manual, 1=drl, 2=ai */
};

/* ── Monitored path entry for HIDS ───────────────────────────────── */

struct monitored_path {
    __u8 active;
    __u8 _pad[3];
};

#endif /* __SENTINEL_TYPES_H */
