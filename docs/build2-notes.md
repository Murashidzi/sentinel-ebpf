# Build 2 Planning Notes

## Target: May 2026

## What Build 2 adds over Build 1
- Five additional tracepoints: openat, connect, setuid, clone, ptrace
feature_extractor.go: nine-feature vector per container per window
Rule engine: five deterministic detection rules (Strategy pattern)
Three-class behaviour simulation: Class 1 Normal, Class 2 Suspicious, Class 3 Advanced-like
ContainerBaseline: rolling window means and std devs per container

Nine features
Rate-based (6): execve_rate, network_connect_rate, file_open_rate, process_spawn_rate, privileged_syscall_count, ptrace_count

Context-aware (3): unusual_parent_spawn, shell_spawn_after_connect, process_depth_anomaly

## Five detection rules
R1: PRIVILEGE_ESCALATION - setuid(0) from non-root container process
R2: REVERSE_SHELL - execve(/bin/sh) within 500ms of connect(external_ip)
R3: CONTAINER_ESCAPE - openat(/proc/1/ns/*) from inside container
R4: PORT_SCAN - 50+ connect() events in 10s from one container
R5: RECON_TOOL - execve of nmap, masscan, netcat, nc
