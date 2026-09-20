#!/usr/bin/env python3
"""
Autoencoder for sentinel-eBPF.
Neural model on the nine aggregated features (same input as the
Isolation Forest, for a clean neural-vs-nonneural comparison).
Trained on NORMAL only; reconstruction error = anomaly score.
"""
import numpy as np, os, torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             roc_auc_score)

torch.manual_seed(42); np.random.seed(42)
ML = os.path.expanduser("~/Projects/sentinel-ebpf/ml")
Xa = np.load(f"{ML}/X_aggregated.npy").astype(np.float32)
y  = np.load(f"{ML}/y.npy")
rng = 42

norm_idx = np.where(y==0)[0]; susp_idx=np.where(y==1)[0]; adv_idx=np.where(y==2)[0]
norm_train, norm_test = train_test_split(norm_idx, test_size=0.3, random_state=rng)

scaler = StandardScaler().fit(Xa[norm_train])
Xtr = torch.tensor(scaler.transform(Xa[norm_train]))

D = Xa.shape[1]
class AE(nn.Module):
    def __init__(self,d):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(d,16), nn.ReLU(), nn.Linear(16,4), nn.ReLU())
        self.dec = nn.Sequential(nn.Linear(4,16), nn.ReLU(), nn.Linear(16,d))
    def forward(self,x): return self.dec(self.enc(x))

model = AE(D)
opt = torch.optim.Adam(model.parameters(), lr=1e-3)
loss_fn = nn.MSELoss()

model.train()
for epoch in range(200):
    opt.zero_grad()
    out = model(Xtr)
    loss = loss_fn(out, Xtr)
    loss.backward(); opt.step()
    if (epoch+1)%50==0:
        print(f"  epoch {epoch+1:3d}  train recon loss {loss.item():.4f}")

# balanced eval set (same recipe as the IF baseline)
k = min(len(norm_test), len(susp_idx), len(adv_idx))
rs = np.random.RandomState(rng)
eval_idx = np.concatenate([
    rs.choice(norm_test, k, replace=False),
    rs.choice(susp_idx,  k, replace=False),
    rs.choice(adv_idx,   k, replace=False)])
Xev = torch.tensor(scaler.transform(Xa[eval_idx]))
yev = y[eval_idx]
truth = (yev>0).astype(int)

model.eval()
with torch.no_grad():
    rec = ((model(Xev)-Xev)**2).mean(dim=1).numpy()   # per-sample recon error

# threshold: 95th percentile of TRAIN normal recon error (calibrated on normal)
with torch.no_grad():
    tr_err = ((model(Xtr)-Xtr)**2).mean(dim=1).numpy()
thr = np.percentile(tr_err, 95)
pred = (rec>thr).astype(int)

print("\n=== Autoencoder (neural, aggregated features) ===")
print(f"train normal windows: {len(norm_train)}")
print(f"eval per class: {k}")
print(f"precision: {precision_score(truth,pred):.3f}")
print(f"recall:    {recall_score(truth,pred):.3f}")
print(f"f1:        {f1_score(truth,pred):.3f}")
print(f"roc_auc:   {roc_auc_score(truth,rec):.3f}")
print()
for label,name in [(0,"normal"),(1,"suspicious"),(2,"advanced")]:
    m = yev==label
    print(f"  {name:11s}: flagged anomalous {pred[m].mean()*100:5.1f}%  (n={m.sum()})")

# save scores for all windows (for cross-model comparison + ANOVA)
with torch.no_grad():
    allsc = ((model(torch.tensor(scaler.transform(Xa)))-torch.tensor(scaler.transform(Xa)))**2).mean(dim=1).numpy()
np.save(f"{ML}/ae_scores.npy", allsc)
print("\nsaved ae_scores.npy")
