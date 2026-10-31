#!/usr/bin/env python3
"""
Revision 3 analyses for sentinel-eBPF (additions only).

Re-executes ml/eval_run_level.py in-process, with its score-file write
disabled, so the four run-level models used here are exactly the locked
ones. Step 0 checks the reproduction and stops on any mismatch. Nothing
locked is changed: no locked script is edited and no locked file is written.

  B1 (5.8)   threshold metrics with paired, class-stratified bootstrap intervals
  B2 (5.13)  class-pair AUCs with intervals; normal-vs-suspicious differences
  B3 (5.7)   TPR at common false-positive rates of 1%, 5% and 10%
  B4 (5.18)  moving-block bootstrap within each test run (blocks of 25 and 100)
  B5 (5.25)  (a) permutation importance for IF and AE  (b) LSTM order-shuffle test
  B6 (3.19)  IF and AE retrained on count features instead of rates
  B8 (5.6)   held-out benign workload: train and calibrate on original-normal only

All on the run-level split. Seed 42 and B = 2000 throughout. Thresholds are
held fixed inside every bootstrap. Results also go to ml/revision3_results.json.
"""
import os, sys, io, json, math, runpy, contextlib
from collections import Counter
import numpy as np
from scipy.stats import rankdata
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, roc_curve

ROOT = os.environ.get("SENTINEL_ROOT", os.path.expanduser("~/Projects/sentinel-ebpf"))
ML = os.path.join(ROOT, "ml")
RNG, B = 42, 2000
LOCKED = {"IsolationForest": 0.638, "Autoencoder": 0.642, "LSTM": 0.670, "LSTM+Lineage": 0.678}
MODELS = list(LOCKED)
KEY = {"IsolationForest": "IF", "Autoencoder": "AE", "LSTM": "LSTM", "LSTM+Lineage": "LSTM_LIN"}
FEATURES = ["execve_rate", "connect_rate", "fileopen_rate", "spawn_rate", "priv_count",
            "ptrace_count", "unusual_parent", "shell_after_conn", "depth"]
SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
RESULTS = {"seed": RNG, "B": B}

def section(t):
    print(f"\n{'=' * 78}\n{t}\n{'=' * 78}")

def f3(x):
    return float(round(float(x), 6))

# ============================================================================
# STEP 0: rebuild the locked run-level models and verify the reproduction
# ============================================================================
section("STEP 0  Reproduce the locked run-level models (re-executes ml/eval_run_level.py)")
saved = np.load(os.path.join(ML, "run_level_scores.npz"))
_savez = np.savez
np.savez = lambda *a, **k: None                      # never overwrite the locked score file
try:
    with contextlib.redirect_stdout(io.StringIO()):
        g = runpy.run_path(os.path.join(ML, "eval_run_level.py"), run_name="__main__")
finally:
    np.savez = _savez

yev = g["yev"]; truth = (yev > 0).astype(int)
nN, nS, nA = g["nN"], g["nS"], g["nA"]
EV = {n: g["scores"][n][0] for n in MODELS}
CA = {n: g["scores"][n][1] for n in MODELS}
THR = {n: float(np.percentile(CA[n], 95)) for n in MODELS}
ok = True
RESULTS["step0"] = {}
print(f"  test windows: normal {nN}, suspicious {nS}, advanced-like {nA}")
for n in MODELS:
    diff = float(np.abs(EV[n] - saved[f"ev_{KEY[n]}"]).max())
    auc = roc_auc_score(truth, EV[n])
    match = diff < 1e-6 and round(auc, 3) == LOCKED[n]
    ok = ok and match
    RESULTS["step0"][n] = {"auc": f3(auc), "max_score_diff_vs_locked": diff, "reproduced": bool(match)}
    print(f"  {n:16s} AUC {auc:.3f} (locked {LOCKED[n]:.3f})  max |score diff| {diff:.2e}  "
          f"{'REPRODUCED' if match else 'NOT REPRODUCED'}")
if not ok:
    print("\n  STOP: the run-level models do not reproduce the locked results. Nothing else was run.")
    sys.exit(1)

# >>> MODEL ADAPTERS (torch code mirrors ml/eval_run_level.py exactly)
torch = g["torch"]; nn = g["nn"]

def score_if_locked(A):
    return -g["iff"].score_samples(g["sc"].transform(A))

def score_ae_locked(A):
    with torch.no_grad():
        X = torch.tensor(g["sc2"].transform(A))
        return ((g["ae"](X) - X) ** 2).mean(1).numpy()

def score_lstm_locked(S):
    return g["lstm_scores"](g["lm"], S)

def fit_if(Xtr):
    sc = StandardScaler().fit(Xtr)
    m = IsolationForest(n_estimators=100, random_state=RNG).fit(sc.transform(Xtr))
    return lambda A: -m.score_samples(sc.transform(A))

def fit_ae(Xtr):
    torch.manual_seed(RNG)
    sc = StandardScaler().fit(Xtr)
    T = torch.tensor(sc.transform(Xtr))
    m = g["AE"](Xtr.shape[1]); opt = torch.optim.Adam(m.parameters(), lr=1e-3); lf = nn.MSELoss()
    m.train()
    for _ in range(200):
        opt.zero_grad(); loss = lf(m(T), T); loss.backward(); opt.step()
    m.eval()
    def s(A):
        with torch.no_grad():
            X = torch.tensor(sc.transform(A))
            return ((m(X) - X) ** 2).mean(1).numpy()
    return s

def fit_lstm(S, extra):
    torch.manual_seed(RNG)
    m = g["train_lstm"](S, extra)
    return lambda X: g["lstm_scores"](m, X)
# <<< MODEL ADAPTERS

# ---------------------------------------------------------------- helpers
def auc_fast(neg, pos):
    """Mann-Whitney AUC with average ranks for ties; equals roc_auc_score."""
    r = rankdata(np.concatenate([neg, pos]))
    n1, n0 = len(pos), len(neg)
    return (r[n0:].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)

def pair_auc(s, yv, a, b):
    return auc_fast(s[yv == a], s[yv == b])

def overall_auc(s, yv):
    return auc_fast(s[yv == 0], s[yv > 0])

def op_metrics(ev, thr, yv):
    pred = ev > thr
    tpr = pred[yv > 0].mean(); fpr = pred[yv == 0].mean()
    p = tpr / (tpr + fpr) if tpr + fpr > 0 else 0.0
    f1 = 2 * p * tpr / (p + tpr) if p + tpr > 0 else 0.0
    return {"recall": tpr, "FPR": fpr, "precision_1to1": p, "F1_1to1": f1, "adv_detection": pred[yv == 2].mean()}

def strat_draw(rs, yv):
    return np.concatenate([rs.choice(np.where(yv == c)[0], (yv == c).sum(), replace=True) for c in (0, 1, 2)])

def ci(v):
    v = np.asarray(v)
    return f3(v.mean()), f3(np.percentile(v, 2.5)), f3(np.percentile(v, 97.5))

def verdict(lo, hi):
    return "excludes 0" if (lo > 0 or hi < 0) else "includes 0"

for n in MODELS:                                     # self-check: fast AUC equals sklearn to float precision
    dd = abs(overall_auc(EV[n], yev) - roc_auc_score(truth, EV[n]))
    print(f"  self-check {n:16s} rank AUC vs sklearn |difference| {dd:.1e}")
    assert dd < 1e-6, "rank-based AUC disagrees with sklearn beyond float rounding"

# ============================================================================
# B1 + B2: one paired, class-stratified bootstrap (thresholds fixed)
# ============================================================================
rs = np.random.RandomState(RNG)
boot = {n: {k: [] for k in ["recall", "FPR", "precision_1to1", "F1_1to1", "adv_detection",
                            "AUC", "N-S", "N-A", "S-A"]} for n in MODELS}
for _ in range(B):
    bi = strat_draw(rs, yev); yb = yev[bi]
    for n in MODELS:
        eb = EV[n][bi]
        for k, v in op_metrics(eb, THR[n], yb).items():
            boot[n][k].append(v)
        boot[n]["AUC"].append(overall_auc(eb, yb))
        boot[n]["N-S"].append(pair_auc(eb, yb, 0, 1))
        boot[n]["N-A"].append(pair_auc(eb, yb, 0, 2))
        boot[n]["S-A"].append(pair_auc(eb, yb, 1, 2))

section("B1 (comment 5.8)  Threshold metrics, run-level, thresholds fixed, paired class-stratified bootstrap")
print(f"  {'model':16s}{'metric':16s}{'point':>8s}{'boot mean':>11s}{'95% interval':>22s}")
RESULTS["B1"] = {}
for n in MODELS:
    pm = op_metrics(EV[n], THR[n], yev); RESULTS["B1"][n] = {}
    for k in ["recall", "FPR", "precision_1to1", "F1_1to1", "adv_detection"]:
        m, lo, hi = ci(boot[n][k])
        RESULTS["B1"][n][k] = {"point": f3(pm[k]), "mean": m, "lo": lo, "hi": hi}
        print(f"  {n:16s}{k:16s}{pm[k]:8.3f}{m:11.3f}      [{lo:.3f}, {hi:.3f}]")

section("B2 (comment 5.13)  Class-pair AUCs with 95% intervals, run-level")
print(f"  {'model':16s}{'pair':30s}{'point':>8s}{'95% interval':>22s}")
RESULTS["B2"] = {"auc": {}, "diff_normal_vs_suspicious": {}}
pairs = {"N-S": ("normal vs suspicious", 0, 1), "N-A": ("normal vs advanced-like", 0, 2),
         "S-A": ("suspicious vs advanced-like", 1, 2)}
for n in MODELS:
    RESULTS["B2"]["auc"][n] = {}
    for k, (lab, a, b) in pairs.items():
        pt = pair_auc(EV[n], yev, a, b); m, lo, hi = ci(boot[n][k])
        RESULTS["B2"]["auc"][n][lab] = {"point": f3(pt), "lo": lo, "hi": hi}
        print(f"  {n:16s}{lab:30s}{pt:8.3f}      [{lo:.3f}, {hi:.3f}]")
print("\n  Paired differences, normal vs suspicious AUC:")
for a, b in [("LSTM", "Autoencoder"), ("LSTM", "IsolationForest"), ("LSTM+Lineage", "LSTM")]:
    d = np.asarray(boot[a]["N-S"]) - np.asarray(boot[b]["N-S"]); m, lo, hi = ci(d)
    RESULTS["B2"]["diff_normal_vs_suspicious"][f"{a} - {b}"] = {"mean": m, "lo": lo, "hi": hi}
    print(f"    {a} - {b}: mean {m:+.3f}  95% interval [{lo:+.3f}, {hi:+.3f}]  {verdict(lo, hi)}")

# ============================================================================
# B3: TPR at common false-positive rates, read from the ROC curve
# ============================================================================
section("B3 (comment 5.7)  TPR at common false-positive rates, run-level")
print("  TPR = highest true-positive rate on the ROC curve with FPR <= target.")
print("  The operating point is chosen on the test normal windows, so this is a")
print("  comparison at equal FPR, not a deployable threshold.")
print(f"  {'model':16s}{'FPR 1%':>9s}{'FPR 5%':>9s}{'FPR 10%':>9s}")
RESULTS["B3"] = {}
for n in MODELS:
    fpr, tpr, _ = roc_curve(truth, EV[n])
    row = {f"{int(t * 100)}%": f3(tpr[np.where(fpr <= t)[0][-1]]) for t in (0.01, 0.05, 0.10)}
    RESULTS["B3"][n] = row
    print(f"  {n:16s}{row['1%']:9.3f}{row['5%']:9.3f}{row['10%']:9.3f}")

# ============================================================================
# B4: moving-block bootstrap within each test run
# ============================================================================
section("B4 (comment 5.18)  Moving-block bootstrap within each test run, run-level")
n_w3 = len(g["build_file"](g["load_file"](g["norm_worker"][2]))[0])
strata = [np.arange(0, n_w3), np.arange(n_w3, nN),
          np.arange(nN, nN + nS), np.arange(nN + nS, nN + nS + nA)]
names = ["worker run 3", "shell-heavy run 3", "suspicious run 3", "advanced-like run 3"]
print("  strata (windows kept in time order): " +
      ", ".join(f"{nm} {len(s)}" for nm, s in zip(names, strata)))
assert sum(len(s) for s in strata) == len(yev) and n_w3 < nN
comps = [("LSTM", "Autoencoder"), ("LSTM", "IsolationForest"), ("LSTM+Lineage", "LSTM")]

def mbb_index(rs, s, L):
    n = len(s); L = min(L, n); k = math.ceil(n / L)
    starts = rs.randint(0, n - L + 1, size=k)
    return s[np.concatenate([np.arange(st, st + L) for st in starts])[:n]]

RESULTS["B4"] = {}
iid = {}
for a, b in comps:
    for k in ("AUC", "N-A"):
        d = np.asarray(boot[a][k]) - np.asarray(boot[b][k]); m, lo, hi = ci(d)
        iid[(a, b, k)] = (m, lo, hi)
for L in (25, 100):
    rsb = np.random.RandomState(RNG)
    store = {n: {"AUC": [], "N-A": []} for n in MODELS}
    for _ in range(B):
        bi = np.concatenate([mbb_index(rsb, s, L) for s in strata]); yb = yev[bi]
        for n in MODELS:
            eb = EV[n][bi]
            store[n]["AUC"].append(overall_auc(eb, yb)); store[n]["N-A"].append(pair_auc(eb, yb, 0, 2))
    RESULTS["B4"][f"block_{L}"] = {}
    print(f"\n  Block length {L} windows:")
    print(f"  {'difference':30s}{'measure':8s}{'block interval':>22s}{'iid interval':>22s}{'width ratio':>12s}")
    for a, b in comps:
        for k in ("AUC", "N-A"):
            d = np.asarray(store[a][k]) - np.asarray(store[b][k]); m, lo, hi = ci(d)
            _, ilo, ihi = iid[(a, b, k)]
            ratio = (hi - lo) / (ihi - ilo) if ihi > ilo else float('nan')
            RESULTS["B4"][f"block_{L}"][f"{a} - {b} | {k}"] = {
                "mean": m, "lo": lo, "hi": hi, "iid_lo": ilo, "iid_hi": ihi, "width_ratio": f3(ratio)}
            print(f"  {a + ' - ' + b:30s}{k:8s}  [{lo:+.3f}, {hi:+.3f}]    [{ilo:+.3f}, {ihi:+.3f}]{ratio:12.2f}  {verdict(lo, hi)}")
print("\n  iid interval = the ordinary window bootstrap (B1/B2 draws). Ratio > 1 means the")
print("  block bootstrap, which keeps neighbouring windows together, gives a wider interval.")

# ============================================================================
# B5: permutation importance and the order-shuffle test
# ============================================================================
section("B5a (comment 5.25)  Permutation importance, IF and AE, drop in normal-vs-advanced AUC")
Aev = g["Aev"]; Sev = g["Sev"]
RESULTS["B5a"] = {}
for n, scorer in [("IsolationForest", score_if_locked), ("Autoencoder", score_ae_locked)]:
    base = pair_auc(scorer(Aev), yev, 0, 2)
    assert abs(base - pair_auc(EV[n], yev, 0, 2)) < 1e-6, "locked scorer mismatch"
    rsp = np.random.RandomState(RNG); RESULTS["B5a"][n] = {"base_N-A": f3(base)}
    print(f"  {n}: baseline normal-vs-advanced AUC {base:.3f} (scaler and model fixed, 30 repeats)")
    for j, fname in enumerate(FEATURES):
        drops = []
        for _ in range(30):
            Ap = Aev.copy(); Ap[:, j] = Ap[rsp.permutation(len(Ap)), j]
            drops.append(base - pair_auc(scorer(Ap), yev, 0, 2))
        RESULTS["B5a"][n][fname] = {"mean_drop": f3(np.mean(drops)), "sd": f3(np.std(drops, ddof=1))}
        print(f"    {fname:18s} drop {np.mean(drops):+.4f}  SD {np.std(drops, ddof=1):.4f}")

section("B5b (comment 5.25)  Order-shuffle test, plain LSTM (already-trained model)")
base_all = overall_auc(EV["LSTM"], yev); base_na = pair_auc(EV["LSTM"], yev, 0, 2)
assert abs(base_all - overall_auc(score_lstm_locked(Sev), yev)) < 1e-6, "locked LSTM scorer mismatch"
gen = np.random.default_rng(RNG); sh_all, sh_na = [], []
for _ in range(10):
    s = score_lstm_locked(gen.permuted(Sev, axis=1))
    sh_all.append(overall_auc(s, yev)); sh_na.append(pair_auc(s, yev, 0, 2))
RESULTS["B5b"] = {"unshuffled": {"AUC": f3(base_all), "N-A": f3(base_na)},
                  "shuffled": {"AUC_mean": f3(np.mean(sh_all)), "AUC_sd": f3(np.std(sh_all, ddof=1)),
                               "N-A_mean": f3(np.mean(sh_na)), "N-A_sd": f3(np.std(sh_na, ddof=1))}}
print("  Tokens shuffled inside each test window: same calls, order destroyed. 10 repeats.")
print(f"  overall AUC            unshuffled {base_all:.3f}   shuffled {np.mean(sh_all):.3f} (SD {np.std(sh_all, ddof=1):.3f})")
print(f"  normal vs advanced-like unshuffled {base_na:.3f}   shuffled {np.mean(sh_na):.3f} (SD {np.std(sh_na, ddof=1):.3f})")

# ============================================================================
# B6: count features in place of the four rates
# ============================================================================
section("B6 (comment 3.19)  IF and AE retrained on count features, run-level")
def counts_vec(win):
    c = Counter(e["syscall_type"] for e in win)
    priv = sum(1 for e in win if e["syscall_type"] == "setuid" and e.get("new_uid", 1) == 0)
    unusual = sum(1 for e in win if e["syscall_type"] == "execve" and e.get("parent_comm", "") in SHELLS)
    sac = 0; seen = False
    for e in win:
        if e["syscall_type"] == "connect": seen = True
        if seen and e["syscall_type"] == "execve" and e.get("comm", "") in SHELLS: sac += 1
    depth = len(set(e.get("ppid", 0) for e in win))
    return [c.get("execve", 0), c.get("connect", 0), c.get("openat", 0), c.get("clone", 0),
            priv, c.get("ptrace", 0), unusual, sac, depth]

def counts_of(files):
    rows = []
    for f in files:
        evs = g["load_file"](f)
        rows += [counts_vec(evs[i:i + 20]) for i in range(0, len(evs) - 20 + 1, 20)]
    return np.array(rows, dtype=np.float32)

nw, ns, su, ad = g["norm_worker"], g["norm_shell"], g["susp"], g["adv"]
Ctr = counts_of([nw[0], ns[0]]); Cca = counts_of([nw[1], ns[1]])
Cev = np.vstack([counts_of([nw[2], ns[2]]), counts_of([su[2]]), counts_of([ad[2]])])
assert len(Ctr) == len(g["Atr"]) and len(Cca) == len(g["Aca"]) and len(Cev) == len(Aev)
assert np.allclose(Cev[:, 4:], Aev[:, 4:]), "count windows do not match the rate windows"
print(f"  windows: train {len(Ctr)}, calibration {len(Cca)}, test {len(Cev)} (identical windows; "
      f"the five shared features match the rate data exactly)")
s_if = fit_if(Ctr); s_ae = fit_ae(Ctr)
CNT = {"IF (counts)": (s_if(Cev), s_if(Cca)), "AE (counts)": (s_ae(Cev), s_ae(Cca))}
allm = {**{n: (EV[n], THR[n]) for n in MODELS},
        **{k: (v[0], float(np.percentile(v[1], 95))) for k, v in CNT.items()}}
rs6 = np.random.RandomState(RNG); b6 = {n: {"AUC": [], "N-A": [], "recall": [], "FPR": []} for n in allm}
for _ in range(B):
    bi = strat_draw(rs6, yev); yb = yev[bi]
    for n, (ev, thr) in allm.items():
        eb = ev[bi]; om = op_metrics(eb, thr, yb)
        b6[n]["AUC"].append(overall_auc(eb, yb)); b6[n]["N-A"].append(pair_auc(eb, yb, 0, 2))
        b6[n]["recall"].append(om["recall"]); b6[n]["FPR"].append(om["FPR"])
RESULTS["B6"] = {"models": {}, "differences": {}}
print(f"  {'model':16s}{'AUC':>7s}{'interval':>18s}{'N-A AUC':>9s}{'interval':>18s}{'recall':>8s}{'FPR':>7s}")
for n in ["IF (counts)", "AE (counts)", "IsolationForest", "Autoencoder", "LSTM", "LSTM+Lineage"]:
    ev, thr = allm[n]; om = op_metrics(ev, thr, yev)
    a = overall_auc(ev, yev); na = pair_auc(ev, yev, 0, 2)
    _, alo, ahi = ci(b6[n]["AUC"]); _, nlo, nhi = ci(b6[n]["N-A"])
    _, rlo, rhi = ci(b6[n]["recall"]); _, flo, fhi = ci(b6[n]["FPR"])
    RESULTS["B6"]["models"][n] = {"AUC": f3(a), "AUC_lo": alo, "AUC_hi": ahi, "N-A": f3(na), "N-A_lo": nlo,
                                  "N-A_hi": nhi, "recall": f3(om["recall"]), "recall_lo": rlo, "recall_hi": rhi,
                                  "FPR": f3(om["FPR"]), "FPR_lo": flo, "FPR_hi": fhi}
    print(f"  {n:16s}{a:7.3f}  [{alo:.3f}, {ahi:.3f}]{na:9.3f}  [{nlo:.3f}, {nhi:.3f}]{om['recall']:8.3f}{om['FPR']:7.3f}")
print("\n  Paired differences:")
for a_, b_ in [("IF (counts)", "IsolationForest"), ("AE (counts)", "Autoencoder"),
               ("LSTM", "IF (counts)"), ("LSTM", "AE (counts)")]:
    for k in ("AUC", "N-A"):
        d = np.asarray(b6[a_][k]) - np.asarray(b6[b_][k]); m, lo, hi = ci(d)
        RESULTS["B6"]["differences"][f"{a_} - {b_} | {k}"] = {"mean": m, "lo": lo, "hi": hi}
        print(f"    {k:4s} {a_} - {b_}: mean {m:+.3f}  95% interval [{lo:+.3f}, {hi:+.3f}]  {verdict(lo, hi)}")

# ============================================================================
# B8: held-out benign workload
# ============================================================================
section("B8 (comment 5.6)  Held-out benign workload: trained and calibrated on original-normal only")
print("  train: original-normal run 1   calibration: original-normal run 2")
print("  never seen: all three shell-heavy runs. Attack run: advanced-like run 3.")
bf = g["build_file"]; lf_ = g["load_file"]
def build(files):
    A, S, L = [], [], []
    for f in files:
        a, s, l = bf(lf_(f))
        if len(a): A.append(a); S.append(s); L.append(l)
    return np.vstack(A), np.vstack(S), np.vstack(L)
Tr = build([nw[0]]); Ca = build([nw[1]]); Ad = build([ad[2]]); N3 = build([nw[2]])
SH = [build([f]) for f in ns]
fitted = {"IsolationForest": (fit_if(Tr[0]), 0), "Autoencoder": (fit_ae(Tr[0]), 0),
          "LSTM": (fit_lstm(Tr[1], 0), 1), "LSTM+Lineage": (fit_lstm(Tr[2], 2), 2)}
RESULTS["B8"] = {"windows": {"train": len(Tr[0]), "calibration": len(Ca[0]),
                             "shell_heavy_runs": [len(s[0]) for s in SH], "advanced_run3": len(Ad[0]),
                             "original_normal_run3": len(N3[0])}, "models": {}}
print(f"  windows: train {len(Tr[0])}, calibration {len(Ca[0])}, shell-heavy runs "
      f"{[len(s[0]) for s in SH]}, original-normal run 3 {len(N3[0])}, advanced-like run 3 {len(Ad[0])}")
print(f"\n  {'model':16s}{'FPR sh1':>8s}{'FPR sh2':>8s}{'FPR sh3':>8s}{'FPR all':>9s}"
      f"{'AUC shell vs adv':>18s}{'AUC orig3 vs adv':>18s}")
for n, (scorer, r) in fitted.items():
    thr = float(np.percentile(scorer(Ca[r]), 95))
    shs = [scorer(s[r]) for s in SH]; fprs = [float((x > thr).mean()) for x in shs]
    allsh = np.concatenate(shs); fpr_all = float((allsh > thr).mean())
    adv_s = scorer(Ad[r]); orig_s = scorer(N3[r])
    auc_sh = auc_fast(allsh, adv_s); auc_or = auc_fast(orig_s, adv_s)
    RESULTS["B8"]["models"][n] = {"FPR_shell_runs": [f3(x) for x in fprs], "FPR_shell_all": f3(fpr_all),
                                  "AUC_shell_vs_adv3": f3(auc_sh), "AUC_orig3_vs_adv3": f3(auc_or)}
    print(f"  {n:16s}" + "".join(f"{x:8.3f}" for x in fprs) + f"{fpr_all:9.3f}{auc_sh:18.3f}{auc_or:18.3f}")
print("\n  Threshold: 95th percentile of calibration (original-normal run 2) scores, so the")
print("  expected FPR on familiar normal behaviour is about 0.05.")

with open(os.path.join(ML, "revision3_results.json"), "w") as fh:
    json.dump(RESULTS, fh, indent=2)
section("Done. Results written to ml/revision3_results.json")
