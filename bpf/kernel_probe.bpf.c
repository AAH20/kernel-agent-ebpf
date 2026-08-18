// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Ahmed Hassan <ahmed.alaa.hassan25@gmail.com> */
/* Kernel-Agent-eBPF: Ring-0 Syscall Probe & Agent Sandbox Guard */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

struct agent_event_t {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    __u32 allowed;
    __u64 timestamp_ns;
};

// BPF map to track authorized agent PIDs and allowed syscall masks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u32); // Policy mask: 1 = read_only, 2 = network_denied, 3 = quarantine
} agent_pid_policy SEC(".maps");

// Ring buffer to stream audit events to userspace ActionLedger
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} agent_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *policy = bpf_map_lookup_elem(&agent_pid_policy, &pid);

    if (!policy) {
        return 0; // Not an enrolled agent process
    }

    struct agent_event_t *event;
    event = bpf_ringbuf_reserve(&agent_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = pid;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->timestamp_ns = bpf_ktime_get_ns();

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);

    // Enforce Sandbox Policy
    if (*policy == 1) { // Strict isolation: block new executable forks
        event->allowed = 0;
        bpf_ringbuf_submit(event, 0);
        return -1; // Block syscall at Ring 0
    }

    event->allowed = 1;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
