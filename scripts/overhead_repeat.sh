#!/bin/bash
# B7 (comments 3.31, 4.30, 5.32): repeated overhead + kernel-side eBPF cost.
#  B7a: RUNS runs of scripts/measure_overhead.sh DUR on the current daemon build.
#  B7b: one more run with kernel.bpf_stats_enabled=1; run_cnt and run_time_ns of
#       the daemon's eBPF programs are read from bpftool before and after the
#       daemon's measurement window. The sysctl is reset to 0 on exit.
# Usage: bash scripts/overhead_repeat.sh [DUR=120] [RUNS=5]   (about 25 to 30 minutes)
set -u
cd "$(dirname "$(readlink -f "$0")")/.." || exit 1
DUR=${1:-120}; RUNS=${2:-5}; NCPU=$(nproc)
LOG=evaluation/overhead; mkdir -p "$LOG"
command -v bpftool >/dev/null || { echo "bpftool not found. Install: sudo apt install linux-tools-common linux-tools-$(uname -r)"; exit 1; }
command -v mpstat >/dev/null && command -v pidstat >/dev/null || { echo "sysstat missing: sudo apt install sysstat"; exit 1; }
sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo sysctl -q -w kernel.bpf_stats_enabled=0' EXIT
echo "daemon binary: $(stat -c '%y' daemon/sentinel)   commit: $(git rev-parse --short HEAD)"
echo "cores: $NCPU   window: ${DUR}s   runs: $RUNS"

echo ""; echo "=== B7a: $RUNS repeated runs of measure_overhead.sh $DUR ==="
for r in $(seq 1 "$RUNS"); do
  echo ""; echo "--- run $r of $RUNS ---"
  bash scripts/measure_overhead.sh "$DUR" | tee "$LOG/run_$r.txt"
done
python3 - "$LOG" "$RUNS" << 'PY'
import re, sys, statistics as st
log, runs = sys.argv[1], int(sys.argv[2])
rows = []
for r in range(1, runs + 1):
    t = open(f"{log}/run_{r}.txt").read()
    core = float(re.search(r"one core\):\s*([0-9.]+)%", t).group(1))
    sysv = float(re.search(r"core system\):\s*([0-9.]+)%", t).group(1))
    b = re.search(r"baseline system busy:\s*([0-9.]+)%", t)
    rows.append((core, sysv, float(b.group(1)) if b else float("nan")))
print("\n=== B7a SUMMARY ===")
print(f"{'run':>4}{'daemon, % of one CPU':>24}{'daemon, % of system':>22}{'baseline busy %':>18}")
for i, (c, s, b) in enumerate(rows, 1):
    print(f"{i:>4}{c:>24.2f}{s:>22.3f}{b:>18.2f}")
for name, k in [("% of one CPU", 0), ("% of system", 1)]:
    v = [r[k] for r in rows]
    print(f"  {name:13s} mean {st.mean(v):.3f}  SD {st.stdev(v) if len(v) > 1 else 0.0:.3f}  min {min(v):.3f}  max {max(v):.3f}")
PY

echo ""; echo "=== B7b: instrumented run, kernel.bpf_stats_enabled=1 ==="
sudo bpftool prog show --json > "$LOG/bpf_pre.json"
sudo sysctl -w kernel.bpf_stats_enabled=1
(
  until pgrep -x sentinel >/dev/null; do sleep 0.5; done
  sleep 5                                    # aligns with the start of pidstat's window
  date +%s.%N > "$LOG/bpf_t0.txt"; sudo bpftool prog show --json > "$LOG/bpf_before.json"
  sleep $((DUR - 3))                         # finishes before the daemon is stopped
  date +%s.%N > "$LOG/bpf_t1.txt"; sudo bpftool prog show --json > "$LOG/bpf_after.json"
) &
POLL=$!
bash scripts/measure_overhead.sh "$DUR" | tee "$LOG/run_instrumented.txt"
wait $POLL
sudo sysctl -w kernel.bpf_stats_enabled=0
python3 - "$LOG" "$NCPU" "$DUR" << 'PY'
import json, sys
log, ncpu, dur = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
pre = {p["id"] for p in json.load(open(f"{log}/bpf_pre.json"))}
bef = {p["id"]: p for p in json.load(open(f"{log}/bpf_before.json"))}
aft = {p["id"]: p for p in json.load(open(f"{log}/bpf_after.json"))}
t0 = float(open(f"{log}/bpf_t0.txt").read()); t1 = float(open(f"{log}/bpf_t1.txt").read())
new = sorted(i for i in aft if i not in pre and i in bef)
ours = [i for i in new if aft[i].get("type") == "tracepoint" and aft[i].get("name", "").startswith("trace_")]
other = [f"{i}:{aft[i].get('name', '?')}({aft[i].get('type', '?')})" for i in new if i not in ours]
if other:
    print("excluded, loaded meanwhile by other software (e.g. Docker device-cgroup programs): " + ", ".join(other))
print("\n=== B7b SUMMARY: the daemon's eBPF programs (trace_* tracepoints) ===")
print(f"{'id':>6}  {'name':16s}{'type':14s}{'run_cnt before':>16s}{'run_cnt after':>15s}{'run_time_ns before':>20s}{'run_time_ns after':>19s}")
tot_cnt = tot_ns = 0
for i in ours:
    b, a = bef[i], aft[i]
    dc = a.get("run_cnt", 0) - b.get("run_cnt", 0); dn = a.get("run_time_ns", 0) - b.get("run_time_ns", 0)
    tot_cnt += dc; tot_ns += dn
    print(f"{i:>6}  {a.get('name','?'):16s}{a.get('type','?'):14s}{b.get('run_cnt',0):>16}{a.get('run_cnt',0):>15}{b.get('run_time_ns',0):>20}{a.get('run_time_ns',0):>19}")
el = t1 - t0
print(f"\nmeasured interval between snapshots: {el:.1f} s")
print(f"programs: {len(ours)}   total runs in interval: {tot_cnt}   total run_time_ns in interval: {tot_ns}")
if tot_cnt:
    print(f"mean cost per program run: {tot_ns / tot_cnt:.0f} ns")
print(f"kernel-side cost, % of system, measured interval: {100 * tot_ns / (el * 1e9 * ncpu):.4f}%")
print(f"kernel-side cost, % of system, work-order formula run_time_ns / ({dur}e9 x {ncpu}): {100 * tot_ns / (dur * 1e9 * ncpu):.4f}%")
print("note: enabling bpf_stats itself adds timing overhead to every program run.")
PY
echo ""; echo "kernel.bpf_stats_enabled is now: $(sysctl -n kernel.bpf_stats_enabled)"
