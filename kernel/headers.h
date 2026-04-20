#ifndef HEADERS_H
#define HEADERS_H

/*
 * headers.h - Shared event struct for sentinel-ebpf
 *
 * Single universal struct for all six tracepoints.
 * Fields unused by a given tracepoint are zeroed.
*
* Design rationale: a universal struct allows the Go daemon to
* deserialize all events through a single binary.Read call and
 * process them through a single channel. This is the bifurcated
 * stream design that eliminates instrumentation as a confounding
 * variable in the three-model comparison.
 *
 * Written by: kernel/tracer.bpf.c
 * Read by:    daemon/main.go via bpf2go generated bindings
 */

#ifndef __BPF_HELPERS_H
typedef unsigned long long __u64;
typedef unsigned int       __u32;
typedef unsigned short     __u16;
typedef unsigned char      __u8;
#endif

/*
 * Syscall type indentifiers -tells the Go daemon which tracepoint
 * produced this event so the feature extractor can route it correctly.
 */
#define SYSCALL_EXECVE   1
#define SYSCALL_OPENAT   2
#define SYSCALL_CONNECT  3
#define SYSCALL_SETUID   4
#define SYSCALL_CLONE    5
#define SYSCALL_PTRACE   6

struct sentinel_event {
    /* --- 64-bit fields first (8 bytes each) --- */

    __u64 cgroup_id;    /* cgroup ID maps to container ID in Go enricher */
    __u64 timestamp_ns; /* kernel monotonic clock is nanoseconds */
    __u64 clone_flags;  /* clone(2) flags - namespace escape detection
                         * populated only for SYSCALL_CLONE events */

    /* --- 32-bit fields (4 bytes each) --- */

    __u32 pid;         /* host PID namespace process ID */
    __u32 ppid;        /* parent PID - parent-child lineage tracking */
    __u32 uid;         /* user ID at time of syscall */
    __u32 new_uid;     /* target UID for setuid(2)  - privilege escalation
                        * populated only for SYSCALL_SETUID events */
    __u32 dest_ip;     /* destination IPv4 address in network byte order
                        * populated only for SYSCALL_CONNECT events */
    __u32 syscall_type; /* which tracepoint fired - use SYSCALL_* constants */

    /* --- 16-bit fields (2 bytes each) --- */

    __u16 dest_port;    /* destination port in network byte order
    * populated only for SYSCALL_CONNECT events */

    /* --- explicit padding to align to 8-byte boundary --- */

    __u16 pad1;
    __u32 pad2;

    /* --- fixed-size string arrays --- */

    char comm[16]; /* process name - TASK_COMM_LEN = 16 */
    char parent_comm[16]; /* parent process name - parent-child detection */
    char filename[256];   /* binary path for execve, file path for openat
                           * populated for SYSCALL_EXECVE and  SYSCALL_OPENAT */
};

#endif /* HEADERS_H */
