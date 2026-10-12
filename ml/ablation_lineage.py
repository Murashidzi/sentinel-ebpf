#!/usr/bin/env python3
"""
RQ3 lineage ablation for sentinel-eBPF.

Retrains the two aggregated-representation models (Isolation Forest and
Autoencoder) with and without the two lineage-derived features, under the
identical leakage-free protocol used by results_table.py:
  - normal split 70/15/15 (train / threshold calibration / FPR test, seed 42)
  - every metric on unseen data only (normal test + suspicious + advanced)
  - paired, class-stratified bootstrap, B=2000, seed 42

Lineage-derived features (from parent process information):
  column 6  unusual_parent   execve whose parent command is a shell
  column 8  depth            distinct parent PIDs in the window

Model code is copied from train_isolation_forest.py and train_autoencoder.py.
Step 1 retrains both models on all nine features and checks that the
saved locked scores are reproduced. If they are, the ablation differs from
the locked results only by the dropped columns.

This is the lineage ablation planned for RQ3, and it also tests whether the
aggregated models' advantage over the LSTM depends on lineage information
the token sequence never receives. Reported whichever way it falls.
"""
import os
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
RNG = 42
FEATURES = ["execve_rate", "connect_rate", "fileopen_rate", "spawn_rate", "priv_count",
            "ptrace_count", "unusual_parent", "shell_after_conn", "depth"]
LINEAGE = [6, 8]
FULL = list(range(9))
NO_LINEAGE = [i for i in FULL if i not in LINEAGE]

Xa = np.load(f"{ML}/X_aggregated.npy").astype(np.float32)
Xs = np.load(f"{ML}/X_sequence.npy")
y = np.load(f"{ML}/y.npy")
saved = {"IsolationForest": np.load(f"{ML}/if_scores.npy"),
         "Autoencoder":     np.load(f"{ML}/ae_scores.npy"),
         "LSTM":            np.load(f"{ML}/lstm_scores.npy")}

norm_idx = np.where(y == 0)[0]
norm_train, norm_hold = train_test_split(norm_idx, test_size=0.3, random_state=RNG)
norm_cal, norm_test = train_test_split(norm_hold, test_size=0.5, random_state=RNG)
susp_idx = np.where(y == 1)[0]
adv_idx = np.where(y == 2)[0]
eval_idx = np.concatenate([norm_test, susp_idx, adv_idx])
yev = y[eval_idx]
truth = (yev > 0).astype(int)

# --- model code, copied from the training scripts --------------------------
def if_scores(cols):
    X = Xa[:, cols]
    scaler = StandardScaler().fit(X[norm_train])
    clf = IsolationForest(n_estimators=100, contamination='auto', random_state=RNG)
    clf.fit(scaler.transform(X[norm_train]))
    return -clf.score_samples(scaler.transform(X))

class AE(nn.Module):
    def __init__(self, d):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(d, 16), nn.ReLU(), nn.Linear(16, 4), nn.ReLU())
        self.dec = nn.Sequential(nn.Linear(4, 16), nn.ReLU(), nn.Linear(16, d))
    def forward(self, x):
        return self.dec(self.enc(x))

def ae_scores(cols):
    X = Xa[:, cols]
    torch.manual_seed(RNG); np.random.seed(RNG)
    scaler = StandardScaler().fit(X[norm_train])
    Xtr = torch.tensor(scaler.transform(X[norm_train]))
    model = AE(X.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()
    model.train()
    for epoch in range(200):
        opt.zero_grad()
        out = model(Xtr)
        loss = loss_fn(out, Xtr)
        loss.backward(); opt.step()
    model.eval()
    with torch.no_grad():
        Xall = torch.tensor(scaler.transform(X))
        return ((model(Xall) - Xall) ** 2).mean(dim=1).numpy()

def pair_auc(s, neg_idx, pos_idx):
    yy = np.concatenate([np.zeros(len(neg_idx)), np.ones(len(pos_idx))])
    return roc_auc_score(yy, np.concatenate([s[neg_idx], s[pos_idx]]))

# --- Step 1: reproduce the locked scores ------------------------------------
print("=== STEP 1: reproduction check (all nine features) ===")
runs = {}
runs["IF full"] = if_scores(FULL)
runs["AE full"] = ae_scores(FULL)
ok = True
for name, key in [("IF full", "IsolationForest"), ("AE full", "Autoencoder")]:
    diff = np.abs(runs[name] - saved[key]).max()
    a_new = roc_auc_score(truth, runs[name][eval_idx])
    a_old = roc_auc_score(truth, saved[key][eval_idx])
    match = diff < 1e-4 and round(a_new, 3) == round(a_old, 3)
    ok = ok and match
    print(f"  {name}: max |score diff| {diff:.2e}   AUC retrained {a_new:.3f}  locked {a_old:.3f}   "
          f"{'REPRODUCED' if match else 'NOT REPRODUCED'}")
if not ok:
    print("\n  STOP: retraining does not reproduce the locked scores.")
    print("  The ablation would not be comparable to the locked results. Report this before going further.")
    raise SystemExit(1)

# --- Step 2: ablation -------------------------------------------------------
print("\n=== STEP 2: retrain without lineage features ===")
print(f"  dropped: {', '.join(FEATURES[i] for i in LINEAGE)}")
runs["IF no-lineage"] = if_scores(NO_LINEAGE)
runs["AE no-lineage"] = ae_scores(NO_LINEAGE)
runs["LSTM"] = saved["LSTM"]

order = ["IF full", "IF no-lineage", "AE full", "AE no-lineage", "LSTM"]
print(f"\n  {'model':15s}{'AUC':>7s}{'norm vs susp':>14s}{'norm vs adv':>13s}{'susp vs adv':>13s}")
for n in order:
    s = runs[n]
    print(f"  {n:15s}{roc_auc_score(truth, s[eval_idx]):7.3f}"
          f"{pair_auc(s, norm_test, susp_idx):14.3f}"
          f"{pair_auc(s, norm_test, adv_idx):13.3f}"
          f"{pair_auc(s, susp_idx, adv_idx):13.3f}")

# --- Step 3: paired bootstrap -----------------------------------------------
B = 2000
boot = np.random.RandomState(RNG)
overall = {n: [] for n in order}
advnorm = {n: [] for n in order}
for _ in range(B):
    nt = boot.choice(norm_test, len(norm_test), replace=True)
    su = boot.choice(susp_idx, len(susp_idx), replace=True)
    ad = boot.choice(adv_idx, len(adv_idx), replace=True)
    idx = np.concatenate([nt, su, ad])
    tr = (y[idx] > 0).astype(int)
    for n in order:
        overall[n].append(roc_auc_score(tr, runs[n][idx]))
        advnorm[n].append(pair_auc(runs[n], nt, ad))

def report(title, comps):
    print(f"\n=== {title} (paired bootstrap, B={B}) ===")
    for metric, store in [("overall AUC", overall), ("normal vs advanced AUC", advnorm)]:
        for a, b in comps:
            d = np.asarray(store[a]) - np.asarray(store[b])
            lo, hi = np.percentile(d, 2.5), np.percentile(d, 97.5)
            v = "excludes 0 -> real difference" if (lo > 0 or hi < 0) else "includes 0 -> not distinguishable"
            print(f"  {metric:23s} {a} - {b}: mean {d.mean():+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}]  {v}")

report("RQ3: contribution of lineage", [("IF full", "IF no-lineage"), ("AE full", "AE no-lineage")])
report("Confound check: aggregated without lineage vs LSTM", [("IF no-lineage", "LSTM"), ("AE no-lineage", "LSTM")])

# --- Step 4: descriptive, window time span per class ------------------------
print("\n=== DESCRIPTIVE: time span of a 20-event window, per class ===")
n_open = (Xs == 2).sum(axis=1)
rate = Xa[:, 2].astype(np.float64)
span_ms = np.where(rate > 0, n_open / np.where(rate > 0, rate, 1) * 1000, np.nan)
for lbl, cname in [(0, "normal"), (1, "suspicious"), (2, "advanced")]:
    v = span_ms[y == lbl]; v = v[np.isfinite(v)]
    print(f"  {cname:11s}: median {np.median(v):8.2f} ms   IQR [{np.percentile(v, 25):.2f}, {np.percentile(v, 75):.2f}] ms")
