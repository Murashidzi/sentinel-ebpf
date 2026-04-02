#ifndef HEADERS_H
#define HEADERS_H

/*
 * headers.h — Shared event struct for sentinel-ebpf
 *
 * This struct is the data contract between the eBPF kernel program
 * and the Go user-space daemon. Both sides must agree on the exact
 * layout of bytes written to and read from the BPF ring buffer.
 *
 * Design decisions:
 * - All fields use explicit-width types (u32, u64) to guarantee
 *   identical layout on every kernel and architecture.
 * - 64-bit fields are grouped first to avoid compiler padding.
 * - Strings are fixed-size arrays — no pointers, which are
 *   meaningless across the kernel/user-space boundary.
 * - Field sizes match Linux kernel constants:
 *   TASK_COMM_LEN = 16, PATH_MAX practical limit = 256 for eBPF.
 */

/*
 * sentinel_event — one syscall event captured at the kernel boundary.
 *
 * Written by: kernel/tracer.bpf.c (eBPF program, runs in kernel)
 * Read by:    daemon/loader.go    (Go program, runs in user space)
 */
struct sentinel_event {

    /* --- 64-bit fields first (8 bytes each, no padding needed) --- */

    __u64 cgroup_id;      /* cgroup ID of the process — maps to container ID.
                           * The Go enricher reads /sys/fs/cgroup/ to convert
                           * this number into a human-readable container ID. */

    __u64 timestamp_ns;   /* Kernel monotonic timestamp in nanoseconds.
                           * Used for temporal correlation — detecting events
                           * that occur within a defined window of each other,
                           * e.g. connect() followed by execve() within 2s. */

    /* --- 32-bit fields next (4 bytes each) --- */

    __u32 pid;            /* Process ID in the host PID namespace.
                           * Containers have their own PID namespace, but
                           * the host sees all PIDs globally. This is the
                           * host-side PID. */

    __u32 ppid;           /* Parent process ID.
                           * Powers parent-child relationship tracking.
                           * When nginx spawns bash, the bash event has
                           * nginx's PID as ppid. This is the field that
                           * makes unusual_parent_spawn detection possible. */

    __u32 uid;            /* User ID of the process at time of syscall.
                           * Combined with setuid tracing, detects privilege
                           * escalation: uid=1000 calling setuid(0). */

    __u32 pad;            /* Explicit padding to align the struct to 8 bytes.
                           * Without this, the compiler inserts invisible
                           * padding anyway — making it explicit documents
                           * the intent and keeps the layout predictable. */

    /* --- Fixed-size string arrays (inline, no pointers) --- */

    char comm[16];        /* Name of the process that triggered the syscall.
                           * Matches TASK_COMM_LEN in the Linux kernel.
                           * Examples: "nginx", "bash", "python3", "nc". */

    char parent_comm[16]; /* Name of the parent process.
                           * Together with ppid, this powers context-aware
                           * detection: parent_comm="nginx", comm="bash"
                           * is the web shell pattern. */

    char filename[256];   /* Full path of the binary being executed.
                           * Only populated for execve events.
                           * Examples: "/bin/bash", "/usr/bin/nmap".
                           * 256 bytes covers all practical eBPF path lengths. */
};

#endif /* HEADERS_H */
