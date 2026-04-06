#ifndef HEADERS_H
#define HEADERS_H

/*
 * headers.h - Shared event struct for sentinel-ebpf
 *
 * When included by tracer.bpf.c, vmlinux.h has already defined __u64
 * and __u32. When parsed by bpf2go for Go type generation, vmlinux.h
 * is not processed, so we define the types here unconditionally.
 * The __attribute__((unused)) suppresses redefinition warnings.
 */
#ifndef __BPF_HELPERS_H
typedef unsigned long long __u64;
typedef unsigned int       __u32;
typedef unsigned char      __u8;
#endif

struct sentinel_event {
    __u64 cgroup_id;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 pad;
    char  comm[16];
    char  parent_comm[16];
    char  filename[256];
};

#endif /* HEADERS_H */
