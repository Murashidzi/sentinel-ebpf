#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "headers.h"

/* Define the BPF ring buffer map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB buffer */
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int  trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct sentinel_event *e;
    struct task_struct *task;
    struct task_struct *real_parent;

    /* Reserve space in the ring buffer */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; /* Drop event if buffer is full */
    }

    /* 1. Capture basic tracepoint metadata */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->timestamp_ns = bpf_ktime_get_ns();

    /* 2. Capture process name and arguments */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Safely read the filename from user-space memory */
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[0]);

    /* 3. CO-RE: Walk the task_struct to get parent info */
    task = (struct task_struct *)bpf_get_current_task();
    real_parent = BPF_CORE_READ(task, real_parent);

    e->ppid = BPF_CORE_READ(real_parent, tgid);
    BPF_CORE_READ_STR_INTO(&e->parent_comm, real_parent, comm);

    /* Submit the event to user-space */
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
