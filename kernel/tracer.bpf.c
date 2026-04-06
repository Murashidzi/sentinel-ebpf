#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "headers.h"

/*
 * Force BTF emission for sentinel_event.
 * bpf2go reads BTF debug info from the compiled object to generate
 * Go type bindings. The compiler only emits BTF for types that appear
 * in the object — using the struct via bpf_ringbuf_reserve (which
 * takes a size argument, not the type itself) is not enough.
 * This volatile reference forces the compiler to include the full
 * type definition in the BTF section.
 */
struct sentinel_event _sentinel_event_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct sentinel_event *e;
    struct task_struct *task;
    struct task_struct *real_parent;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[0]);

    task = (struct task_struct *)bpf_get_current_task();
    real_parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(real_parent, tgid);
    BPF_CORE_READ_STR_INTO(&e->parent_comm, real_parent, comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
