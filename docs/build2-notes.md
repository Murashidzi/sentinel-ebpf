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
## April 10 2026
COS720 Practical 2 submitted. COS760 proposal submitted.

## April 12 2026
COS720 semester test 15 April at 14:30. Chapters 14-19 and AI-driven cybersecurity notes reviewed.
Mandela Rhodes recommendation deadline: 13 April 10:00 — reminders sent to all three recommenders.

## April 13 2026
Mandela Rhodes recommendation deadline today at 10:00.
COS720 semester test tomorrow 15 April at 14:30.
Final exam consolidation — Chapters 14-19 and AI-driven cybersecurity notes complete.

## April 15 2026
COS720 semester test written. BUILD 2 implementation begins.
Next: all 6 tracepoints, 9-feature extractor, rule engine.

## Planned additions beyond core BUILD 2 (BUILD 3 or future work)

### sys_enter_mount - Container Escape Detection
Triggers when a process attempts to mount a filesystem.
A container should never mount new filesystems.
Unauthorized mount = high-confidence container escape signal.
Document as future work in Chapter 6 if not implemented by BUILD 3.

### sched:sched_process_exit - Short-lived Process Detection
Triggers when a process terminates.
Correlate with execve entry events by PID to compute process lifetime.
Processes that live under 1 second are a known malware pattern.
Adds complexity to feature extractor - requires PID lifecycle tracking.
Target: implement in BUILD 3 alongside the full feature pipeline.
