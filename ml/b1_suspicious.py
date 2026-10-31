#!/usr/bin/env python3
"""
B1 supplement: suspicious-class detection at each model's calibrated threshold,
run-level split, with paired class-stratified bootstrap intervals (B = 2000,
seed 42, the same resampling as revision3_analyses.py B1). Reads the saved
run-level scores only; nothing is retrained and nothing locked is written.
"""
import os
import numpy as np
ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
R = np.load(os.path.join(ML, "run_level_scores.npz"))
yev = R["yev"]; RNG, B = 42, 2000
KEY = {"IsolationForest": "IF", "Autoencoder": "AE", "LSTM": "LSTM", "LSTM+Lineage": "LSTM_LIN"}
EV = {n: R[f"ev_{k}"] for n, k in KEY.items()}
THR = {n: float(np.percentile(R[f"cal_{k}"], 95)) for n, k in KEY.items()}
susp = lambda ev, thr, yv: (ev[yv == 1] > thr).mean()

rs = np.random.RandomState(RNG)
boot = {n: [] for n in KEY}
for _ in range(B):
    bi = np.concatenate([rs.choice(np.where(yev == c)[0], (yev == c).sum(), replace=True) for c in (0, 1, 2)])
    for n in KEY:
        boot[n].append(susp(EV[n][bi], THR[n], yev[bi]))
ci = lambda v: (np.mean(v), np.percentile(v, 2.5), np.percentile(v, 97.5))
print("=== B1 supplement: suspicious-class detection at the calibrated threshold (run-level) ===")
print(f"  suspicious test windows: {(yev == 1).sum()}")
for n in KEY:
    m, lo, hi = ci(boot[n])
    print(f"  {n:16s} point {susp(EV[n], THR[n], yev):.3f}  boot mean {m:.3f}  95% interval [{lo:.3f}, {hi:.3f}]")
print("  Paired differences:")
for a, b in [("LSTM", "Autoencoder"), ("LSTM", "IsolationForest"), ("LSTM+Lineage", "LSTM")]:
    d = np.asarray(boot[a]) - np.asarray(boot[b]); m, lo, hi = ci(d)
    v = "excludes 0" if (lo > 0 or hi < 0) else "includes 0"
    print(f"    {a} - {b}: mean {m:+.3f}  95% interval [{lo:+.3f}, {hi:+.3f}]  {v}")
