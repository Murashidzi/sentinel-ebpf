#!/usr/bin/env python3
"""
Chapter 5 figures for the revised sentinel-eBPF dissertation.

  fig5_1_composition   system call composition per class (window data)
  fig5_2_roc           ROC curves, RUN-LEVEL split, four models, operating points
  fig5_3_perclass_auc  per-class AUC, WINDOW-LEVEL split, four models

Inputs (all produced by committed scripts, no number typed by hand):
  y.npy, X_sequence.npy                       extract_features.py
  if/ae/lstm/lstm_lin_scores.npy              the four training scripts
  run_level_scores.npz                        eval_run_level.py
Every plotted value is printed so it can be checked against
results_table.py and eval_run_level.py. Figures are 6.0 inches wide,
all text is at least 8 pt, and each model has one colour plus a marker,
line style and hatch so the figures survive greyscale printing.
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.text import Text
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, roc_curve

ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
OUT = os.environ.get("FIG_DIR", os.path.join(ML, "figures"))
os.makedirs(OUT, exist_ok=True)
RNG = 42
WIDTH = 6.0
MIN_PT = 8

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 9,
    "xtick.labelsize": 8, "ytick.labelsize": 8, "legend.fontsize": 8,
    "axes.linewidth": 0.8, "lines.linewidth": 1.4, "hatch.linewidth": 0.6,
    "savefig.pad_inches": 0.0,
})

# One identity per model, used in every figure (Okabe-Ito colours).
MODELS = ["IsolationForest", "Autoencoder", "LSTM", "LSTM+Lineage"]
KEY = {"IsolationForest": "IF", "Autoencoder": "AE", "LSTM": "LSTM", "LSTM+Lineage": "LSTM_LIN"}
STYLE = {
    "IsolationForest": dict(label="Isolation Forest", color="#E69F00", hatch="///", ls="--", marker="s"),
    "Autoencoder":     dict(label="Autoencoder",      color="#0072B2", hatch="...", ls="-",  marker="o"),
    "LSTM":            dict(label="LSTM",             color="#009E73", hatch="xxx", ls=":",  marker="^"),
    "LSTM+Lineage":    dict(label="LSTM+Lineage",     color="#CC79A7", hatch="---", ls="-.", marker="D"),
}
CLASSES = [(0, "Normal"), (1, "Suspicious"), (2, "Advanced-like")]
CLASS_FILL = {0: "#FFFFFF", 1: "#9E9E9E", 2: "#303030"}

def check_and_save(fig, name):
    fig.canvas.draw()
    sizes = [t.get_fontsize() for t in fig.findobj(Text) if t.get_text().strip()]
    smallest = min(sizes) if sizes else 0
    wd, ht = fig.get_size_inches()
    fig.savefig(os.path.join(OUT, name + ".pdf"))
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=300)
    plt.close(fig)
    flag = "OK" if smallest >= MIN_PT else f"WARNING text below {MIN_PT} pt"
    print(f"  saved {name}: {wd:.2f} x {ht:.2f} in, smallest text {smallest:.1f} pt  {flag}")

y = np.load(f"{ML}/y.npy")
Xs = np.load(f"{ML}/X_sequence.npy")

# ---------------------------------------------------------------------------
# Figure 5.1: system call composition per class
# ---------------------------------------------------------------------------
print("\n=== Figure 5.1 values (percent of tokens per class) ===")
SYS = {1: "execve", 2: "openat", 3: "connect", 4: "setuid", 5: "clone", 6: "ptrace"}
comp = {}
for lbl, cname in CLASSES:
    seq = Xs[y == lbl].flatten(); seq = seq[seq > 0]
    comp[lbl] = {t: 100 * (seq == t).mean() for t in SYS}
    print(f"  {cname:13s}: " + "  ".join(f"{SYS[t]} {comp[lbl][t]:.1f}%" for t in SYS))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(WIDTH, 3.2), gridspec_kw={"width_ratios": [1, 1.7]}, layout="constrained")
xs = np.arange(3)
op = [comp[l][2] for l, _ in CLASSES]
ax1.bar(xs, op, width=0.6, color="#D9D9D9", edgecolor="black", linewidth=0.6, label="openat")
ax1.bar(xs, [100 - v for v in op], bottom=op, width=0.6, color="#404040",
        edgecolor="black", linewidth=0.6, label="all other calls")
for i, v in enumerate(op):
    ax1.text(i, v / 2, f"openat\n{v:.1f}%", ha="center", va="center", fontsize=8)
    ax1.text(i, v + (100 - v) / 2, f"other\n{100 - v:.1f}%", ha="center", va="center",
             fontsize=8, color="white")
ax1.set_xticks(xs, ["Normal", "Suspicious", "Advanced-\nlike"])
ax1.set_ylabel("Share of tokens (%)"); ax1.set_ylim(0, 100)
ax1.set_title("(a) openat against all other calls")

minor = [1, 3, 4, 5, 6]; w = 0.27
top = max(comp[l][t] for l, _ in CLASSES for t in minor)
for k, (lbl, cname) in enumerate(CLASSES):
    vals = [comp[lbl][t] for t in minor]
    bx = np.arange(len(minor)) + (k - 1) * w
    ax2.bar(bx, vals, width=w, color=CLASS_FILL[lbl], edgecolor="black", linewidth=0.6, label=cname)
    for xx, v in zip(bx, vals):
        ax2.text(xx, v + top * 0.02, f"{v:.1f}", ha="center", va="bottom", fontsize=8, rotation=90)
ax2.set_xticks(np.arange(len(minor)), [SYS[t] for t in minor])
ax2.set_ylabel("Share of tokens (%)"); ax2.set_ylim(0, top * 1.45)
ax2.set_title("(b) Calls other than openat")
from matplotlib.patches import Patch
fig.legend(handles=[Patch(facecolor=CLASS_FILL[l], edgecolor="black", label=c) for l, c in CLASSES],
           title="Panel (b) classes", title_fontsize=8,
           loc="outside lower center", ncol=3, frameon=False, columnspacing=1.5, handlelength=1.4)
check_and_save(fig, "fig5_1_composition")

# ---------------------------------------------------------------------------
# Figure 5.2: ROC curves, run-level split, with calibrated operating points
# ---------------------------------------------------------------------------
print("\n=== Figure 5.2 values (run-level split, unseen runs) ===")
R = np.load(f"{ML}/run_level_scores.npz")
yev = R["yev"]; truth = (yev > 0).astype(int)
print(f"  test windows: normal {int(R['n_test_normal'])}, suspicious {int(R['n_test_susp'])}, "
      f"advanced-like {int(R['n_test_adv'])}")
fig, (axa, axb) = plt.subplots(1, 2, figsize=(WIDTH, 3.6), layout="constrained")
handles = [Line2D([0], [0], color="#999999", lw=0.8, label="Chance")]
for ax in (axa, axb):
    ax.plot([0, 1], [0, 1], color="#999999", lw=0.8)
for n in MODELS:
    st = STYLE[n]; ev = R[f"ev_{KEY[n]}"]; ca = R[f"cal_{KEY[n]}"]
    fpr_c, tpr_c, _ = roc_curve(truth, ev)
    auc = roc_auc_score(truth, ev)
    thr = np.percentile(ca, 95); pred = ev > thr
    op_fpr = pred[yev == 0].mean(); op_tpr = pred[truth == 1].mean()
    for ax in (axa, axb):
        ax.plot(fpr_c, tpr_c, color=st["color"], ls=st["ls"])
        ax.plot(op_fpr, op_tpr, marker=st["marker"], color=st["color"], markeredgecolor="black",
                markersize=6, ls="none", zorder=5)
    handles.append(Line2D([0], [0], color=st["color"], ls=st["ls"], marker=st["marker"],
                          markeredgecolor="black", label=f"{st['label']} (AUC {auc:.3f})"))
    print(f"  {n:16s} AUC {auc:.3f}   operating point FPR {op_fpr:.3f}  recall {op_tpr:.3f}")
axa.set_xlim(0, 1); axa.set_ylim(0, 1); axa.set_aspect("equal")
axa.set_title("(a) Full range")
axb.set_xlim(0, 0.2); axb.set_ylim(0, 1)
axb.set_title("(b) False positive rate 0 to 0.2")
for ax in (axa, axb):
    ax.set_xlabel("False positive rate")
axa.set_ylabel("True positive rate")
fig.legend(handles=handles, loc="outside lower center", ncol=3, frameon=False)
check_and_save(fig, "fig5_2_roc")

# ---------------------------------------------------------------------------
# Figure 5.3: per-class AUC, window-level split (same split as results_table.py)
# ---------------------------------------------------------------------------
print("\n=== Figure 5.3 values (window-level split, per-class AUC) ===")
scores = {n: np.load(f"{ML}/{f}") for n, f in [
    ("IsolationForest", "if_scores.npy"), ("Autoencoder", "ae_scores.npy"),
    ("LSTM", "lstm_scores.npy"), ("LSTM+Lineage", "lstm_lin_scores.npy")]}
norm_idx = np.where(y == 0)[0]
_, norm_hold = train_test_split(norm_idx, test_size=0.3, random_state=RNG)
_, norm_test = train_test_split(norm_hold, test_size=0.5, random_state=RNG)
susp_idx = np.where(y == 1)[0]; adv_idx = np.where(y == 2)[0]
def pair_auc(s, neg, pos):
    yy = np.concatenate([np.zeros(len(neg)), np.ones(len(pos))])
    return roc_auc_score(yy, np.concatenate([s[neg], s[pos]]))
pairs = [("Normal vs\nsuspicious", norm_test, susp_idx),
         ("Normal vs\nadvanced-like", norm_test, adv_idx),
         ("Suspicious vs\nadvanced-like", susp_idx, adv_idx)]
fig, ax = plt.subplots(figsize=(WIDTH, 3.4), layout="constrained")
w = 0.2
for k, n in enumerate(MODELS):
    st = STYLE[n]
    vals = [pair_auc(scores[n], a, b) for _, a, b in pairs]
    bx = np.arange(3) + (k - 1.5) * w
    ax.bar(bx, vals, width=w, color=st["color"], hatch=st["hatch"], edgecolor="black",
           linewidth=0.6, label=st["label"])
    for xx, v in zip(bx, vals):
        ax.text(xx, v + 0.015, f"{v:.3f}", ha="center", va="bottom", fontsize=8, rotation=90)
    print(f"  {n:16s} " + "  ".join(f"{p.replace(chr(10), ' ')} {v:.3f}"
                                    for (p, _, _), v in zip(pairs, vals)))
ax.axhline(0.5, color="#666666", lw=0.8, ls="--", label="Chance (0.5)")
ax.set_xticks(np.arange(3), [p for p, _, _ in pairs])
ax.set_ylabel("AUC"); ax.set_ylim(0, 1.1)
fig.legend(loc="outside lower center", ncol=5, frameon=False, columnspacing=1.0, handlelength=1.6)
check_and_save(fig, "fig5_3_perclass_auc")
print(f"\nAll figures written to {OUT}")
