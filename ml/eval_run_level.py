#!/usr/bin/env python3
"""
Run-level split evaluation for sentinel-eBPF.

The main protocol splits normal windows by window, so windows from one
capture run appear in train, calibration and test. A sequence model can
exploit within-run familiarity more than an aggregated model, which could
bias the comparison toward the LSTM. This script removes that risk: whole
capture runs are assigned to train, calibration or test, so no test window
shares a run with any training window.

Assignment (6 normal runs: 3 worker, 3 shell; 3 suspicious; 3 advanced):
  train:       worker run 1, shell run 1   (model fit, normal only)
  calibration: worker run 2, shell run 2   (threshold)
  test normal: worker run 3, shell run 3   (FPR)
  test attack: suspicious run 3, advanced run 3  (unseen runs)
All four models are retrained from scratch on the run-level train set and
scored identically. Bootstrap CIs use B=2000, seed 42.
"""
import json, glob, os
from collections import Counter
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

np.random.seed(42); torch.manual_seed(42)
DATA = os.path.expanduser("~/Projects/sentinel-ebpf/evaluation/datasets")
SEQ_LEN = 20; WINDOW = 20
SYS_ID = {"execve":1,"openat":2,"connect":3,"setuid":4,"clone":5,"ptrace":6}
SHELLS = {"sh","bash","dash","zsh","ash"}

def load_file(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            try: rows.append(json.loads(line))
            except: continue
    if not rows: return []
    cids = Counter(r.get("container_id","") for r in rows
                   if r.get("container_id","") not in ("","host"))
    if not cids: return []
    target = cids.most_common(1)[0][0]
    evs = [r for r in rows if r.get("container_id")==target]
    evs.sort(key=lambda r: r.get("timestamp_ns",0))
    return evs

def aggregate(win):
    span = max((win[-1]["timestamp_ns"]-win[0]["timestamp_ns"])/1e9, 1e-6)
    c = Counter(e["syscall_type"] for e in win)
    priv = sum(1 for e in win if e["syscall_type"]=="setuid" and e.get("new_uid",1)==0)
    unusual = sum(1 for e in win if e["syscall_type"]=="execve"
                  and e.get("parent_comm","") in SHELLS)
    shell_after = 0; seen_conn = False
    for e in win:
        if e["syscall_type"]=="connect": seen_conn=True
        if seen_conn and e["syscall_type"]=="execve" and e.get("comm","") in SHELLS:
            shell_after += 1
    depth = len(set(e.get("ppid",0) for e in win))
    return [c.get("execve",0)/span, c.get("connect",0)/span, c.get("openat",0)/span,
            c.get("clone",0)/span, priv, c.get("ptrace",0), unusual, shell_after, depth]

def build_file(evs):
    agg, seq, seqlin = [], [], []
    for i in range(0, len(evs)-WINDOW+1, WINDOW):
        win = evs[i:i+WINDOW]
        agg.append(aggregate(win))
        ids = [SYS_ID.get(e["syscall_type"],0) for e in win[:SEQ_LEN]]
        ids += [0]*(SEQ_LEN-len(ids))
        seq.append(ids)
        seen=set(); enr=[]
        for e in win[:SEQ_LEN]:
            ppid=e.get("ppid",0)
            enr.append([SYS_ID.get(e["syscall_type"],0),
                        1 if e.get("parent_comm","") in SHELLS else 0,
                        1 if ppid not in seen else 0])
            seen.add(ppid)
        while len(enr)<SEQ_LEN: enr.append([0,0,0])
        seqlin.append(enr)
    return (np.array(agg,dtype=np.float32), np.array(seq,dtype=np.int64),
            np.array(seqlin,dtype=np.int64))

def files(cls, pattern):
    return sorted(glob.glob(os.path.join(DATA, cls, pattern)))

# Map runs to roles. Sorted order is chronological by timestamp in filename.
norm_worker = files("normal", "normal_worker_*.jsonl")
norm_shell  = files("normal", "normal_shell_*.jsonl")
susp = files("suspicious", "*.jsonl")
adv  = files("advanced", "*.jsonl")
assert len(norm_worker)>=3 and len(norm_shell)>=3 and len(susp)>=3 and len(adv)>=3, "need 3 runs each"

train_files = [norm_worker[0], norm_shell[0]]
cal_files   = [norm_worker[1], norm_shell[1]]
testN_files = [norm_worker[2], norm_shell[2]]
testA_susp  = [susp[2]]
testA_adv   = [adv[2]]

def collect(file_list):
    A,S,L = [],[],[]
    for f in file_list:
        a,s,l = build_file(load_file(f))
        if len(a): A.append(a); S.append(s); L.append(l)
    return np.vstack(A), np.vstack(S), np.vstack(L)

Atr,Str,Ltr = collect(train_files)
Aca,Sca,Lca = collect(cal_files)
AtN,StN,LtN = collect(testN_files)
AtS,StS,LtS = collect(testA_susp)
AtA,StA,LtA = collect(testA_adv)

print("=== RUN-LEVEL SPLIT ===")
print(f"  train (worker1+shell1):   {len(Atr)} normal windows")
print(f"  calibration (w2+shell2):  {len(Aca)} normal windows")
print(f"  test normal (w3+shell3):  {len(AtN)} windows")
print(f"  test suspicious (run3):   {len(AtS)} windows")
print(f"  test advanced (run3):     {len(AtA)} windows")

# Evaluation set: test normal + test attacks
Aev = np.vstack([AtN, AtS, AtA])
Sev = np.vstack([StN, StS, StA])
Lev = np.vstack([LtN, LtS, LtA])
yev = np.concatenate([np.zeros(len(AtN)), np.ones(len(AtS)), np.full(len(AtA),2)]).astype(int)
truth = (yev>0).astype(int)
nN, nS, nA = len(AtN), len(AtS), len(AtA)

# --- Isolation Forest ---
sc = StandardScaler().fit(Atr)
iff = IsolationForest(n_estimators=100, random_state=42).fit(sc.transform(Atr))
if_ev = -iff.score_samples(sc.transform(Aev))
if_ca = -iff.score_samples(sc.transform(Aca))

# --- Autoencoder ---
class AE(nn.Module):
    def __init__(s,d):
        super().__init__()
        s.e=nn.Sequential(nn.Linear(d,16),nn.ReLU(),nn.Linear(16,4),nn.ReLU())
        s.d=nn.Sequential(nn.Linear(4,16),nn.ReLU(),nn.Linear(16,d))
    def forward(s,x): return s.d(s.e(x))
sc2 = StandardScaler().fit(Atr)
Xtr = torch.tensor(sc2.transform(Atr))
ae = AE(9); opt=torch.optim.Adam(ae.parameters(),lr=1e-3); lf=nn.MSELoss()
ae.train()
for _ in range(200):
    opt.zero_grad(); loss=lf(ae(Xtr),Xtr); loss.backward(); opt.step()
ae.eval()
with torch.no_grad():
    ae_ev=((ae(torch.tensor(sc2.transform(Aev)))-torch.tensor(sc2.transform(Aev)))**2).mean(1).numpy()
    ae_ca=((ae(torch.tensor(sc2.transform(Aca)))-torch.tensor(sc2.transform(Aca)))**2).mean(1).numpy()

# --- LSTM (plain) and LSTM+Lineage ---
VOCAB=7
class SeqLSTM(nn.Module):
    def __init__(s,extra=0):
        super().__init__()
        s.emb=nn.Embedding(VOCAB,16); s.lstm=nn.LSTM(16+extra,32,batch_first=True)
        s.out=nn.Linear(32,VOCAB); s.extra=extra
    def forward(s,x):
        if s.extra:
            tok=x[:,:,0]; lin=x[:,:,1:].float()
            e=torch.cat([s.emb(tok),lin],2)
            h,_=s.lstm(e); return s.out(h), tok
        else:
            h,_=s.lstm(s.emb(x)); return s.out(h), x
lf2=nn.CrossEntropyLoss(reduction='none')
def seqloss(logits,tok):
    p=logits[:,:-1,:].reshape(-1,VOCAB); t=tok[:,1:].reshape(-1)
    return lf2(p,t).reshape(tok.size(0),-1).mean(1)

def train_lstm(Xtrain, extra):
    m=SeqLSTM(extra); o=torch.optim.Adam(m.parameters(),lr=5e-3)
    Xt=torch.tensor(Xtrain); m.train(); B=64
    for _ in range(60):
        perm=torch.randperm(len(Xt))
        for i in range(0,len(Xt),B):
            b=Xt[perm[i:i+B]]; o.zero_grad()
            lg,tok=m(b); loss=seqloss(lg,tok).mean(); loss.backward(); o.step()
    m.eval(); return m

def lstm_scores(m, X):
    with torch.no_grad():
        lg,tok=m(torch.tensor(X)); return seqloss(lg,tok).numpy()

lm = train_lstm(Str, 0)
lstm_ev = lstm_scores(lm, Sev); lstm_ca = lstm_scores(lm, Sca)
lml = train_lstm(Ltr, 2)
lin_ev = lstm_scores(lml, Lev); lin_ca = lstm_scores(lml, Lca)

scores = {"IsolationForest":(if_ev,if_ca),"Autoencoder":(ae_ev,ae_ca),
          "LSTM":(lstm_ev,lstm_ca),"LSTM+Lineage":(lin_ev,lin_ca)}

print("\n=== RUN-LEVEL RESULTS ===")
print(f"  {'model':16s}{'AUC':>7s}{'recall':>8s}{'FPR':>7s}{'adv_det':>9s}")
aucs={}
for n,(ev,ca) in scores.items():
    auc=roc_auc_score(truth,ev); aucs[n]=auc
    thr=np.percentile(ca,95); pred=ev>thr
    rec=pred[truth==1].mean(); fpr=pred[yev==0].mean(); advd=pred[yev==2].mean()
    print(f"  {n:16s}{auc:7.3f}{rec:8.3f}{fpr:7.3f}{advd:9.3f}")

# Bootstrap CIs on AUC differences
B=2000; boot=np.random.RandomState(42)
idxN=np.arange(nN); idxS=np.arange(nN,nN+nS); idxA=np.arange(nN+nS,nN+nS+nA)
store={n:[] for n in scores}
for _ in range(B):
    bn=boot.choice(idxN,nN,replace=True); bs=boot.choice(idxS,nS,replace=True)
    ba=boot.choice(idxA,nA,replace=True); bi=np.concatenate([bn,bs,ba])
    tr=(yev[bi]>0).astype(int)
    for n,(ev,ca) in scores.items():
        store[n].append(roc_auc_score(tr,ev[bi]))
print("\n=== BOOTSTRAP AUC CIs (B=2000) ===")
for n in scores:
    lo,hi=np.percentile(store[n],2.5),np.percentile(store[n],97.5)
    print(f"  {n:16s} {aucs[n]:.3f}  95% CI [{lo:.3f}, {hi:.3f}]")
print("\n=== KEY DIFFERENCES ===")
for a,b in [("LSTM","Autoencoder"),("LSTM","IsolationForest"),
            ("LSTM+Lineage","LSTM"),("Autoencoder","IsolationForest")]:
    d=np.array(store[a])-np.array(store[b])
    lo,hi=np.percentile(d,2.5),np.percentile(d,97.5)
    v="excludes 0" if (lo>0 or hi<0) else "includes 0"
    print(f"  {a} - {b}: mean {d.mean():+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}]  {v}")
