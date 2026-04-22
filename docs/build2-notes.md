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

## Reviewer challenge - dataset validity (add to chapter 6 discussion)

A likely reviewer objection: "Why should we trust that your Class 3 simulations represent real attacks?"

Argument for self-generated telemetry being methodologically superior:

1. The core research variable is REPRESENTATION, not attack coverage.
The experiment asks: given identical telemetry, does LSTM outperform IF and AE? A public dataset cannot provide identical telemetry across all three models because public datasets were not collected via eBPF tracepoints with ppid/parent_comm fields. Switching to a public dataset would introduce instrumentation as a confounding vulnerable which is precisely what the bifurcated stream design eliminates.

2. External datasets introduce instrumentation confounds. ADFA-LD was collected on different kernel versions, different container runtimes, and without parent-process lineage. Using it alongside eBPF telemetry would mean the models are not being compared on the same data - defeating the controlled comparison.

3. The three-class taxonomy is explicitly labelled as behavioural patterns, not attacks. Class 3 is "advanced-like behaviour" not confirmed malware." This is methodologically precise and legally unambiguous. The argument is: we train on normal, and measure deviation. The nature of the deviation (Class 2 or Class 3) tests the model's sensitivity to increasingly subtle anomalies. Whether those exact patterns appear in ADFA-LD is irrelevant to the representational comparison.

4. Reproducibility. Self-generated telemetry means the dataset can be fully released with the paper. Every reviewer can reproduce the exact collection conditions using the open-source sentinel-eBPF codebase. ADFA-LD and DARPA cannot offer this for eBPF-specific features.

Cite: the bifurcated stream design (section 4.5) as the key methodological justification. Any difference in detection performance is attributable to represantation alone because the telemetry source is identical for all three models. No public dataset can make that guarantee.

Add this argument explicitly to Chapter 5 (Evaluation) under "Threates to Validity" and defend it in Chapter 6 (Discussion).

## April 20 2026
Research proposal updated and submitted to Mr Makura.
COS760 double-dip removed from plan — LSTM is COS700 only.
Bill Mulligan outreach: commented on Tetragon issue tracker.

## April 20 2026
BUILD 2 progress: all 6 tracepoints active and verified.
headers.h expanded to 344 bytes universal struct.
tracer.bpf.c: fill_common() helper + 6 tracepoint handlers.
main.go: attaches all 6 tracepoints, switch on SyscallType.
README updated. LinkedIn post published.
Next: Enricher goroutine (issue #15).

## April 21 2026
Resuming BUILD 2. Next: Enricher goroutine (issue #15).
Enricher maps cgroup_id to container_id by reading /sys/fs/cgroup/.

##Observer effect - kernel-side PID filter (stretch goal)
The daemon's own openat calls during cgroup refresh appear in output.
Fix: pass daemon PID to kernel via BPF_MAP_TYPE_ARRAY at load time.
Filter in each tracepoint handler before bpf_ringbuf_submit.
This eliminates the event before ring buffer write - zero CPU cost.
Implement after core BUILD 2  feautures are complete.
## April 22 2026
Enricher complete and verified. Issue #15 closed.
SENTINEL_PID incomplete filter removed from tracer.bpf.c
Next: feature_extractor.go - nine-feature vector per container per window.
