#!/usr/bin/env python3
"""
LSTM with per-event lineage information for sentinel-eBPF.
Same architecture and training procedure as train_lstm.py, but each
timestep carries three channels instead of one:
  ch0: syscall type ID (embedded, same as plain LSTM)
  ch1: parent_is_shell (binary, per-event equivalent of unusual_parent)
  ch2: new_parent (binary, 1 if ppid not seen earlier in window)
This gives the sequence model the same lineage information the aggregated
models summarise into their two features. Anomaly score is unchanged:
mean per-step next-syscall prediction loss.
"""
import numpy as np, os, torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             roc_auc_score)

torch.manual_seed(42); np.random.seed(42)
ML = os.path.expanduser("~/Projects/sentinel-ebpf/ml")
Xl = np.load(f"{ML}/X_seq_lineage.npy").astype(np.int64)  # (N, 20, 3)
y  = np.load(f"{ML}/y.npy")
rng = 42
VOCAB = 7   # 0=pad, 1..6 syscall types
SEQ = Xl.shape[1]

norm_idx = np.where(y == 0)[0]
susp_idx = np.where(y == 1)[0]
adv_idx  = np.where(y == 2)[0]
norm_train, norm_test = train_test_split(norm_idx, test_size=0.3, random_state=rng)
Xtr = torch.tensor(Xl[norm_train])

class SeqLSTMLineage(nn.Module):
    def __init__(self, vocab, emb=16, hid=32):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb)
        # ch0 is embedded (dim=emb), ch1 and ch2 are concatenated raw
        self.lstm = nn.LSTM(emb + 2, hid, batch_first=True)
        self.out = nn.Linear(hid, vocab)

    def forward(self, x):
        # x shape: (batch, seq_len, 3)
        token_ids = x[:, :, 0]          # (batch, seq_len)
        lineage = x[:, :, 1:].float()   # (batch, seq_len, 2)
        e = self.emb(token_ids)          # (batch, seq_len, emb)
        combined = torch.cat([e, lineage], dim=2)  # (batch, seq_len, emb+2)
        h, _ = self.lstm(combined)
        return self.out(h)               # logits per timestep

model = SeqLSTMLineage(VOCAB)
opt = torch.optim.Adam(model.parameters(), lr=5e-3)
loss_fn = nn.CrossEntropyLoss(reduction='none')

def seq_loss(logits, x):
    # predict token t+1 from tokens up to t (same target as plain LSTM)
    token_ids = x[:, :, 0] if x.dim() == 3 else x
    pred = logits[:, :-1, :].reshape(-1, VOCAB)
    tgt  = token_ids[:, 1:].reshape(-1)
    l = loss_fn(pred, tgt).reshape(x.size(0), -1)
    return l.mean(dim=1)

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
        tot += loss.item() * len(b)
    if (epoch + 1) % 15 == 0:
        print(f"  epoch {epoch+1:3d}  train next-syscall loss {tot/len(Xtr):.4f}")

# balanced eval set (same recipe as all other training scripts)
k = min(len(norm_test), len(susp_idx), len(adv_idx))
rs = np.random.RandomState(rng)
eval_idx = np.concatenate([
    rs.choice(norm_test, k, replace=False),
    rs.choice(susp_idx,  k, replace=False),
    rs.choice(adv_idx,   k, replace=False)])
Xev = torch.tensor(Xl[eval_idx]); yev = y[eval_idx]
truth = (yev > 0).astype(int)

model.eval()
with torch.no_grad():
    scores = seq_loss(model(Xev), Xev).numpy()
    tr_scores = seq_loss(model(Xtr), Xtr).numpy()
thr = np.percentile(tr_scores, 95)
pred = (scores > thr).astype(int)

print("\n=== LSTM+Lineage (sequence with per-event lineage) ===")
print(f"train normal windows: {len(norm_train)}")
print(f"eval per class: {k}")
print(f"precision: {precision_score(truth, pred):.3f}")
print(f"recall:    {recall_score(truth, pred):.3f}")
print(f"f1:        {f1_score(truth, pred):.3f}")
print(f"roc_auc:   {roc_auc_score(truth, scores):.3f}")
print()
for label, name in [(0, "normal"), (1, "suspicious"), (2, "advanced")]:
    m = yev == label
    print(f"  {name:11s}: flagged anomalous {pred[m].mean()*100:5.1f}%  (n={m.sum()})")

# score ALL windows for results_table.py
with torch.no_grad():
    allsc = seq_loss(model(torch.tensor(Xl)), torch.tensor(Xl)).numpy()
np.save(f"{ML}/lstm_lin_scores.npy", allsc)
print("\nsaved lstm_lin_scores.npy")
