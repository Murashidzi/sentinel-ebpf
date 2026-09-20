#!/usr/bin/env python3
"""
LSTM sequence model for sentinel-eBPF.
Consumes ordered syscall-type sequences (N=20), NOT aggregated features.
Trained on NORMAL only as a next-syscall predictor. Anomaly score =
mean per-step prediction loss over the window: sequences that don't
follow learned normal ordering score high. This is the sequence-aware
model the study's primary hypothesis is built to test.
"""
import numpy as np, os, torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             roc_auc_score)

torch.manual_seed(42); np.random.seed(42)
ML = os.path.expanduser("~/Projects/sentinel-ebpf/ml")
Xs = np.load(f"{ML}/X_sequence.npy").astype(np.int64)   # (N,20) token IDs 0..6
y  = np.load(f"{ML}/y.npy")
rng = 42
VOCAB = 7   # 0=pad, 1..6 syscall types
SEQ = Xs.shape[1]

norm_idx=np.where(y==0)[0]; susp_idx=np.where(y==1)[0]; adv_idx=np.where(y==2)[0]
norm_train, norm_test = train_test_split(norm_idx, test_size=0.3, random_state=rng)
Xtr = torch.tensor(Xs[norm_train])

class SeqLSTM(nn.Module):
    def __init__(self, vocab, emb=16, hid=32):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb)
        self.lstm = nn.LSTM(emb, hid, batch_first=True)
        self.out = nn.Linear(hid, vocab)
    def forward(self, x):
        e = self.emb(x)
        h,_ = self.lstm(e)
        return self.out(h)   # logits per timestep

model = SeqLSTM(VOCAB)
opt = torch.optim.Adam(model.parameters(), lr=5e-3)
loss_fn = nn.CrossEntropyLoss(reduction='none')

def seq_loss(logits, x):
    # predict token t+1 from tokens up to t
    pred = logits[:, :-1, :].reshape(-1, VOCAB)
    tgt  = x[:, 1:].reshape(-1)
    l = loss_fn(pred, tgt).reshape(x.size(0), -1)
    return l.mean(dim=1)   # per-sequence mean loss

model.train()
B = 64
for epoch in range(60):
    perm = torch.randperm(len(Xtr))
    tot = 0
    for i in range(0, len(Xtr), B):
        b = Xtr[perm[i:i+B]]
        opt.zero_grad()
        logits = model(b)
        loss = seq_loss(logits, b).mean()
        loss.backward(); opt.step()
        tot += loss.item()*len(b)
    if (epoch+1)%15==0:
        print(f"  epoch {epoch+1:3d}  train next-syscall loss {tot/len(Xtr):.4f}")

# balanced eval set (same recipe as IF and AE)
k = min(len(norm_test), len(susp_idx), len(adv_idx))
rs = np.random.RandomState(rng)
eval_idx = np.concatenate([
    rs.choice(norm_test, k, replace=False),
    rs.choice(susp_idx,  k, replace=False),
    rs.choice(adv_idx,   k, replace=False)])
Xev = torch.tensor(Xs[eval_idx]); yev = y[eval_idx]
truth = (yev>0).astype(int)

model.eval()
with torch.no_grad():
    scores = seq_loss(model(Xev), Xev).numpy()
    tr_scores = seq_loss(model(Xtr), Xtr).numpy()
thr = np.percentile(tr_scores, 95)     # calibrated on training normal
pred = (scores>thr).astype(int)

print("\n=== LSTM (sequence-aware, ordered syscalls) ===")
print(f"train normal windows: {len(norm_train)}")
print(f"eval per class: {k}")
print(f"precision: {precision_score(truth,pred):.3f}")
print(f"recall:    {recall_score(truth,pred):.3f}")
print(f"f1:        {f1_score(truth,pred):.3f}")
print(f"roc_auc:   {roc_auc_score(truth,scores):.3f}")
print()
for label,name in [(0,"normal"),(1,"suspicious"),(2,"advanced")]:
    m = yev==label
    print(f"  {name:11s}: flagged anomalous {pred[m].mean()*100:5.1f}%  (n={m.sum()})")

with torch.no_grad():
    allsc = seq_loss(model(torch.tensor(Xs)), torch.tensor(Xs)).numpy()
np.save(f"{ML}/lstm_scores.npy", allsc)
print("\nsaved lstm_scores.npy")
