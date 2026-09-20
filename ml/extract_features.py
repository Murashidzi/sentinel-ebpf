#!/usr/bin/env python3
"""
Feature extraction for sentinel-eBPF BUILD 3.
Reads captured NDJSON events (three classes), filters to the target
container per file, and emits TWO representations from the IDENTICAL
event stream:
  X_aggregated : nine per-window features (matches feature_extractor.go)
  X_sequence   : ordered syscall-type IDs, window N=20
Labels: 0=normal, 1=suspicious, 2=advanced
"""
import json, glob, os
from collections import Counter, defaultdict
import numpy as np

SEQ_LEN = 20          # sequence window (parameterized for later sweep)
WINDOW = 20           # events per aggregated feature window
DATA = os.path.expanduser("~/Projects/sentinel-ebpf/evaluation/datasets")
OUT  = os.path.expanduser("~/Projects/sentinel-ebpf/ml")

SYS_ID = {"execve":1,"openat":2,"connect":3,"setuid":4,"clone":5,"ptrace":6}
SHELLS = {"sh","bash","dash","zsh","ash"}

def load_events(class_dir):
    """Load events, keep only the dominant (target) container per file."""
    evs = []
    for f in glob.glob(os.path.join(DATA, class_dir, "*.jsonl")):
        rows = []
        with open(f) as fh:
            for line in fh:
                line=line.strip()
                if not line: continue
                try: rows.append(json.loads(line))
                except: continue
        if not rows: continue
        # dominant container = the workload we drove
        cids = Counter(r.get("container_id","") for r in rows
                       if r.get("container_id","") not in ("","host"))
        if not cids: continue
        target = cids.most_common(1)[0][0]
        evs += [r for r in rows if r.get("container_id")==target]
    # order by timestamp so sequences are truly temporal
    evs.sort(key=lambda r: r.get("timestamp_ns",0))
    return evs

def aggregate(win):
    """Nine features over a window of events (matches the Go extractor)."""
    n = len(win)
    span = max((win[-1]["timestamp_ns"]-win[0]["timestamp_ns"])/1e9, 1e-6)
    c = Counter(e["syscall_type"] for e in win)
    execve_rate      = c.get("execve",0)/span
    connect_rate     = c.get("connect",0)/span
    fileopen_rate    = c.get("openat",0)/span
    spawn_rate       = c.get("clone",0)/span
    priv_count       = sum(1 for e in win
                           if e["syscall_type"]=="setuid" and e.get("new_uid",1)==0)
    ptrace_count     = c.get("ptrace",0)
    # unusual parent spawn: execve whose parent_comm is a shell
    unusual_parent   = sum(1 for e in win
                           if e["syscall_type"]=="execve"
                           and e.get("parent_comm","") in SHELLS)
    # shell spawn after connect: a connect followed within window by shell execve
    shell_after_conn = 0
    seen_conn=False
    for e in win:
        if e["syscall_type"]=="connect": seen_conn=True
        if seen_conn and e["syscall_type"]=="execve" \
           and e.get("comm","") in SHELLS:
            shell_after_conn+=1
    # process depth anomaly: distinct ppids (proxy for chain depth)
    depth = len(set(e.get("ppid",0) for e in win))
    return [execve_rate,connect_rate,fileopen_rate,spawn_rate,
            priv_count,ptrace_count,unusual_parent,shell_after_conn,depth]

def build(evs):
    """Non-overlapping windows -> aggregated vectors and syscall-ID sequences."""
    agg, seq = [], []
    for i in range(0, len(evs)-WINDOW+1, WINDOW):
        win = evs[i:i+WINDOW]
        agg.append(aggregate(win))
        ids = [SYS_ID.get(e["syscall_type"],0) for e in win[:SEQ_LEN]]
        ids += [0]*(SEQ_LEN-len(ids))     # pad
        seq.append(ids)
    return np.array(agg,dtype=np.float32), np.array(seq,dtype=np.int64)

classes = [("normal",0),("suspicious",1),("advanced",2)]
Xa,Xs,y = [],[],[]
for name,label in classes:
    evs = load_events(name)
    a,s = build(evs)
    print(f"{name:11s}: {len(evs):7d} events -> {len(a):5d} windows")
    Xa.append(a); Xs.append(s); y.append(np.full(len(a),label))

Xa=np.vstack(Xa); Xs=np.vstack(Xs); y=np.concatenate(y)
np.save(f"{OUT}/X_aggregated.npy",Xa)
np.save(f"{OUT}/X_sequence.npy",Xs)
np.save(f"{OUT}/y.npy",y)
print(f"\nsaved: X_aggregated {Xa.shape}, X_sequence {Xs.shape}, y {y.shape}")
print("class balance:", dict(Counter(y.tolist())))
