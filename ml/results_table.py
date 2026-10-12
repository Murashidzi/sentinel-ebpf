#!/usr/bin/env python3
"""
Single source of truth for every number reported in Chapter 5.

Leakage-free evaluation protocol:
  - Normal windows are split 70/30 with the same seed the training scripts
    used, so norm_train is exactly the data each model was fit on.
  - The 30% held-out normal is split again 50/50:
      norm_cal  -> sets the threshold (95th percentile of its scores)
      norm_test -> measures the false positive rate
  - Suspicious and advanced windows were never seen in training.
  - Every metric is computed on unseen data only:
      norm_test + suspicious + advanced.
  - Precision and F1 are reported at a stated 1:1 prevalence,
    precision = TPR / (TPR + FPR), so they do not depend on how many
    attack windows were captured relative to normal test windows.
"""
import numpy as np, os
from scipy import stats
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
RNG = 42
y = np.load(f"{ML}/y.npy")
scores = {
    "IsolationForest": np.load(f"{ML}/if_scores.npy"),
    "Autoencoder":     np.load(f"{ML}/ae_scores.npy"),
    "LSTM":            np.load(f"{ML}/lstm_scores.npy"),
}

norm_idx = np.where(y == 0)[0]
norm_train, norm_hold = train_test_split(norm_idx, test_size=0.3, random_state=RNG)
norm_cal, norm_test = train_test_split(norm_hold, test_size=0.5, random_state=RNG)
susp_idx = np.where(y == 1)[0]
adv_idx = np.where(y == 2)[0]
eval_idx = np.concatenate([norm_test, susp_idx, adv_idx])
yev = y[eval_idx]
truth = (yev > 0).astype(int)

print("=== EVALUATION PROTOCOL ===")
print(f"  normal train (model fit):       {len(norm_train)}")
print(f"  normal calibration (threshold): {len(norm_cal)}")
print(f"  normal test (FPR):              {len(norm_test)}")
print(f"  suspicious (unseen):            {len(susp_idx)}")
print(f"  advanced (unseen):              {len(adv_idx)}")
print(f"  evaluation set total:           {len(eval_idx)}")

z_eval = {}
for name, s in scores.items():
    thr = np.percentile(s[norm_cal], 95)
    se = s[eval_idx]
    pred = (se > thr).astype(int)
    tpr = pred[truth == 1].mean()
    fpr = pred[yev == 0].mean()
    prec = tpr / (tpr + fpr) if (tpr + fpr) > 0 else 0.0
    f1 = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0
    print(f"\n=== {name} ===")
    print(f"  AUC:                       {roc_auc_score(truth, se):.3f}")
    print(f"  recall (all attacks):      {tpr:.3f}")
    print(f"  FPR (normal test flagged): {fpr:.3f}")
    print(f"  precision (1:1 prevalence): {prec:.3f}")
    print(f"  F1 (1:1 prevalence):        {f1:.3f}")
    print(f"  suspicious detection rate: {pred[yev == 1].mean():.3f}")
    print(f"  advanced detection rate:   {pred[yev == 2].mean():.3f}")
    z = (se - se.mean()) / (se.std() + 1e-9)
    z_eval[name] = z
    for lbl, cname in [(0, "normal"), (1, "suspicious"), (2, "advanced")]:
        print(f"  {cname} mean z-score:      {z[yev == lbl].mean():+.3f}")

print("\n=== PRE-SPECIFIED TESTS, SUPERSEDED (ANOVA/KW assume independent samples; all three models score the same windows, so the paired bootstrap below is the valid test) ===")
atk = yev > 0
groups = [z_eval[n][atk] for n in scores]
F, p = stats.f_oneway(*groups)
allv = np.concatenate(groups); grand = allv.mean()
eta2 = sum(len(g) * (g.mean() - grand) ** 2 for g in groups) / ((allv - grand) ** 2).sum()
H, pk = stats.kruskal(*groups)
print(f"  ANOVA:          F = {F:.3f}   p = {p:.4g}   eta^2 = {eta2:.4f}")
print(f"  Kruskal-Wallis: H = {H:.3f}   p = {pk:.4g}")

print("\n=== SYSCALL COMPOSITION PER CLASS (all windows of each class) ===")
Xs = np.load(f"{ML}/X_sequence.npy")
names = {1: "execve", 2: "openat", 3: "connect", 4: "setuid", 5: "clone", 6: "ptrace"}
for lbl, cname in [(0, "normal"), (1, "suspicious"), (2, "advanced")]:
    seq = Xs[y == lbl].flatten(); seq = seq[seq > 0]
    parts = "  ".join(f"{names[t]} {100 * (seq == t).mean():.1f}%" for t in range(1, 7))
    print(f"  {cname:11s}: {parts}")

# ---------------------------------------------------------------------------
# PER-CLASS AUC (threshold-free, removes the operating-point confound)
# ---------------------------------------------------------------------------
print("\n=== PER-CLASS AUC (threshold-free) ===")
print(f"  {'model':16s}{'norm vs susp':>14s}{'norm vs adv':>13s}{'susp vs adv':>13s}")
def pair_auc(s, neg_idx, pos_idx):
    yy = np.concatenate([np.zeros(len(neg_idx)), np.ones(len(pos_idx))])
    return roc_auc_score(yy, np.concatenate([s[neg_idx], s[pos_idx]]))
for name, s in scores.items():
    print(f"  {name:16s}"
          f"{pair_auc(s, norm_test, susp_idx):14.3f}"
          f"{pair_auc(s, norm_test, adv_idx):13.3f}"
          f"{pair_auc(s, susp_idx, adv_idx):13.3f}")

# ---------------------------------------------------------------------------
# PAIRED BOOTSTRAP: 95% CIs for each AUC and for pairwise AUC differences.
# All three models are scored on the SAME resample each iteration, so the
# comparison is paired. Resampling is stratified by class to keep the
# evaluation composition fixed. B=2000, seed 42, deterministic.
# ---------------------------------------------------------------------------
B = 2000
boot = np.random.RandomState(RNG)
model_names = list(scores)
overall = {n: [] for n in model_names}
advnorm = {n: [] for n in model_names}
for _ in range(B):
    nt = boot.choice(norm_test, len(norm_test), replace=True)
    su = boot.choice(susp_idx, len(susp_idx), replace=True)
    ad = boot.choice(adv_idx, len(adv_idx), replace=True)
    idx = np.concatenate([nt, su, ad])
    tr = (y[idx] > 0).astype(int)
    for n in model_names:
        overall[n].append(roc_auc_score(tr, scores[n][idx]))
        advnorm[n].append(pair_auc(scores[n], nt, ad))

def ci(a):
    a = np.asarray(a)
    return np.percentile(a, 2.5), np.percentile(a, 97.5)

for label, store in [("overall AUC", overall), ("normal vs advanced AUC", advnorm)]:
    print(f"\n=== PAIRED BOOTSTRAP, {label} (B={B}) ===")
    for n in model_names:
        lo, hi = ci(store[n])
        print(f"  {n:16s} 95% CI [{lo:.3f}, {hi:.3f}]")
    pairs = [("Autoencoder", "IsolationForest"), ("Autoencoder", "LSTM"),
             ("IsolationForest", "LSTM")]
    for a, b in pairs:
        d = np.asarray(store[a]) - np.asarray(store[b])
        lo, hi = ci(d)
        verdict = "excludes 0 -> real difference" if (lo > 0 or hi < 0) else "includes 0 -> not distinguishable"
        print(f"  {a} - {b}: mean {d.mean():+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}]  {verdict}")
