#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "headers.h"

/*
 * Force BTF emission for sentinel_event.
 * bpf2go reads BTF debug info from the compiled object to generate
 * Go type bindings. This variable forces the compiler to include
 * the full type definition in the BTF section.
 */
struct sentinel_event _sentinel_event_unused __attribute__((unused));

/* BPF ring buffer map — 256KB, zero-copy kernel-to-user delivery */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Helper: populate common fields present in every event.
 * Called by all six tracepoint handlers before syscall-specific fields.
 */
static __always_inline void fill_common(struct sentinel_event *e,
                                        __u32 syscall_type)
{
    struct task_struct *task;
    struct task_struct *parent;

    e->syscall_type  = syscall_type;
    e->pid           = bpf_get_current_pid_tgid() >> 32;
    e->uid           = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->cgroup_id     = bpf_get_current_cgroup_id();
    e->timestamp_ns  = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* CO-RE parent walk: traverse task_struct to get parent info */
    task   = (struct task_struct *)bpf_get_current_task();
    parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    BPF_CORE_READ_STR_INTO(&e->parent_comm, parent, comm);
}

/* ── Tracepoint 1: execve ─────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct sentinel_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, SYSCALL_EXECVE);


    /* filename is args[0]: pointer to string in user memory */
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint 2: openat ─────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct sentinel_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, SYSCALL_OPENAT);


    /*
     * openat(dirfd, pathname, flags)
     * args[1] is pathname: pointer to string in user memory.
     * Used to detect: /etc/shadow reads, /proc/1/ns/ (container escape),
     * Kubernetes service account token reads (/var/run/secrets/...)
     */
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint 3: connect ────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sentinel_event *e;
    struct sockaddr_in sa;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, SYSCALL_CONNECT);


    /*
     * connect(sockfd, addr, addrlen)
     * args[1] is a pointer to sockaddr in user memory.
     * We read the full sockaddr_in struct, then check sa_family.
     * AF_INET = 2 for IPv4. Only populate dest_ip/dest_port for IPv4.
     */
    if (bpf_probe_read_user(&sa, sizeof(sa),
                            (const void *)ctx->args[1]) == 0) {
        if (sa.sin_family == 2) { /* AF_INET */
            e->dest_ip   = sa.sin_addr.s_addr; /* network byte order */
            e->dest_port = sa.sin_port;         /* network byte order */
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint 4: setuid ─────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct sentinel_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, SYSCALL_SETUID);


    /*
     * setuid(uid)
     * args[0] is the new UID directly — no pointer dereference.
     * Detection: setuid(0) from a non-root container process is
     * privilege escalation. The Go rule engine checks:
     * e.UID != 0 && e.NewUID == 0
     */
    e->new_uid = (__u32)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint 5: clone ──────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx)
{
    struct sentinel_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, SYSCALL_CLONE);


    /*
     * clone(flags, ...)
     * args[0] is the clone flags bitmask — no pointer dereference.
     *
     * Namespace escape flags to watch for:
     * CLONE_NEWPID   = 0x20000000 — new PID namespace
     * CLONE_NEWNET   = 0x40000000 — new network namespace
     * CLONE_NEWNS    = 0x00020000 — new mount namespace
     * CLONE_NEWUSER  = 0x10000000 — new user namespace (highest risk)
     *
     * The Go rule engine checks clone_flags against these masks.
     * A container creating a new user namespace is attempting
     * privilege escalation via user namespace mapping.
     */
    e->clone_flags = (__u64)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Tracepoint 6: ptrace ─────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct sentinel_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, SYSCALL_PTRACE);


    /*
     * ptrace(request, pid, addr, data)
     * args[0] is the request type — no pointer dereference.
     *
     * PTRACE_ATTACH = 16: attaching to another process.
     * Detection: any ptrace from inside a container is suspicious.
     * Legitimate debuggers do not run in production containers.
     * We reuse new_uid to carry the ptrace request type since
     * setuid and ptrace never fire together in the same event.
     */
    e->new_uid = (__u32)ctx->args[0]; /* ptrace request type */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
