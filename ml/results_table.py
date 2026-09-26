#!/usr/bin/env python3
"""Generate the full per-class and per-model results table for Chapter 5,
from saved anomaly scores. Recomputes calibrated thresholds the same way
the training scripts did: 95th percentile of training-normal score."""
import numpy as np, os
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

ML = os.path.expanduser("~/Projects/sentinel-ebpf/ml")
y = np.load(f"{ML}/y.npy")
scores = {
    "IsolationForest": np.load(f"{ML}/if_scores.npy"),
    "Autoencoder":     np.load(f"{ML}/ae_scores.npy"),
    "LSTM":            np.load(f"{ML}/lstm_scores.npy"),
}
rng = 42
norm_idx = np.where(y==0)[0]
norm_train, norm_test = train_test_split(norm_idx, test_size=0.3, random_state=rng)

print("=== DATASET COMPOSITION ===")
for lbl,name in [(0,"normal"),(1,"suspicious"),(2,"advanced")]:
    print(f"  {name:11s}: {int((y==lbl).sum())} windows")
print(f"  total: {len(y)}")

for mname, s in scores.items():
    # calibrated threshold: 95th percentile of TRAIN-normal score
    thr = np.percentile(s[norm_train], 95)
    pred = (s > thr).astype(int)
    truth = (y > 0).astype(int)

    print(f"\n=== {mname} (threshold=95th pct train-normal) ===")
    print(f"  overall AUC:       {roc_auc_score(truth, s):.3f}")
    print(f"  overall precision: {precision_score(truth, pred):.3f}")
    print(f"  overall recall:    {recall_score(truth, pred):.3f}")
    print(f"  overall F1:        {f1_score(truth, pred):.3f}")
    # FPR = fraction of normal flagged
    fpr = pred[y==0].mean()
    print(f"  FPR (normal flagged): {fpr:.3f}")
    # per-class detection rate (recall within each attack class)
    for lbl,name in [(1,"suspicious"),(2,"advanced")]:
        det = pred[y==lbl].mean()
        print(f"  {name} detection rate: {det:.3f}")
    # per-class mean score, z-normalised, for separation reporting
    z = (s - s.mean())/(s.std()+1e-9)
    for lbl,name in [(0,"normal"),(1,"suspicious"),(2,"advanced")]:
        print(f"  {name} mean z-score: {z[y==lbl].mean():+.3f}")

print("\n=== SYSCALL PROPORTION PER CLASS (openat dominance) ===")
Xs = np.load(f"{ML}/X_sequence.npy")
for lbl,name in [(0,"normal"),(1,"suspicious"),(2,"advanced")]:
    seq = Xs[y==lbl].flatten()
    seq = seq[seq>0]  # drop padding
    openat = (seq==2).sum()/len(seq)
    print(f"  {name:11s}: openat {openat*100:.1f}% of tokens")
