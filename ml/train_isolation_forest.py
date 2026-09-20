#!/usr/bin/env python3
"""
Isolation Forest baseline for sentinel-eBPF.
Tabular model on the nine aggregated features. Trained on NORMAL only
(unsupervised), scores all classes. Role: the aggregated/tabular floor
against which the sequence model is measured.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             roc_auc_score, classification_report)
import os

ML = os.path.expanduser("~/Projects/sentinel-ebpf/ml")
Xa = np.load(f"{ML}/X_aggregated.npy")
y  = np.load(f"{ML}/y.npy")   # 0=normal 1=suspicious 2=advanced
rng = 42

# split normal into train (fit) and test; attack classes are eval-only
norm_idx = np.where(y==0)[0]
susp_idx = np.where(y==1)[0]
adv_idx  = np.where(y==2)[0]

norm_train, norm_test = train_test_split(norm_idx, test_size=0.3, random_state=rng)

# scaler fit on training normal only (no leakage)
scaler = StandardScaler().fit(Xa[norm_train])
Xtr = scaler.transform(Xa[norm_train])

# balanced eval set: equal normal-test, suspicious, advanced
k = min(len(norm_test), len(susp_idx), len(adv_idx))
rs = np.random.RandomState(rng)
eval_idx = np.concatenate([
    rs.choice(norm_test, k, replace=False),
    rs.choice(susp_idx,  k, replace=False),
    rs.choice(adv_idx,   k, replace=False),
])
Xev = scaler.transform(Xa[eval_idx])
yev = y[eval_idx]
# binary truth: 1 = anomaly (suspicious or advanced), 0 = normal
truth = (yev>0).astype(int)

clf = IsolationForest(n_estimators=100, contamination='auto', random_state=rng)
clf.fit(Xtr)

# IsolationForest: -1 anomaly, 1 inlier -> map to 1=anomaly,0=normal
pred = (clf.predict(Xev)==-1).astype(int)
score = -clf.score_samples(Xev)   # higher = more anomalous

print("=== Isolation Forest (tabular baseline) ===")
print(f"train normal windows: {len(norm_train)}")
print(f"eval per class: {k}  (normal/suspicious/advanced)")
print(f"precision: {precision_score(truth,pred):.3f}")
print(f"recall:    {recall_score(truth,pred):.3f}")
print(f"f1:        {f1_score(truth,pred):.3f}")
print(f"roc_auc:   {roc_auc_score(truth,score):.3f}")
print()
# per-class detection rate (how often each class is flagged anomalous)
for label,name in [(0,"normal"),(1,"suspicious"),(2,"advanced")]:
    m = yev==label
    rate = pred[m].mean() if m.sum() else 0
    print(f"  {name:11s}: flagged anomalous {rate*100:5.1f}%  (n={m.sum()})")

np.save(f"{ML}/if_scores.npy", -clf.score_samples(scaler.transform(Xa)))
print("\nsaved anomaly scores for all windows: if_scores.npy")
