#!/usr/bin/env python3
"""
Chapter 5 figures for sentinel-eBPF.

Uses the same saved scores, the same normal split (seed 42), the same
threshold rule, and the same bootstrap loop as results_table.py. Every
plotted value is printed so it can be checked against results_table.py.
No number in any figure is typed by hand.

Outputs (PDF for the document, PNG at 300 dpi for preview):
  fig5_1_composition    system call composition per class
  fig5_2_roc            ROC curves with calibrated operating points
  fig5_3_perclass_auc   per-class AUC, threshold-free
  fig5_4_bootstrap      paired bootstrap AUC differences, 95% CIs
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, roc_curve

ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
OUT = os.environ.get("FIG_DIR", os.path.join(ML, "figures"))
os.makedirs(OUT, exist_ok=True)
RNG = 42

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 9, "axes.labelsize": 9, "xtick.labelsize": 8,
    "ytick.labelsize": 8, "legend.fontsize": 8,
    "axes.linewidth": 0.8, "lines.linewidth": 1.4,
    "hatch.linewidth": 0.6,
    "savefig.bbox": "tight", "savefig.pad_inches": 0.03,
})

# One identity per model across every figure: Okabe-Ito colours
# (colour-blind safe) plus hatch, line style, and marker for greyscale.
MODELS = ["IsolationForest", "Autoencoder", "LSTM"]
STYLE = {
    "IsolationForest": dict(label="Isolation Forest", short="IF", color="#E69F00", hatch="///", ls="--", marker="s"),
    "Autoencoder":     dict(label="Autoencoder",      short="AE", color="#0072B2", hatch="...", ls="-",  marker="o"),
    "LSTM":            dict(label="LSTM",             short="LSTM", color="#009E73", hatch="xxx", ls=":",  marker="^"),
}

y = np.load(f"{ML}/y.npy")
scores = {
    "IsolationForest": np.load(f"{ML}/if_scores.npy"),
    "Autoencoder":     np.load(f"{ML}/ae_scores.npy"),
    "LSTM":            np.load(f"{ML}/lstm_scores.npy"),
}
Xs = np.load(f"{ML}/X_sequence.npy")

# Identical split to results_table.py
norm_idx = np.where(y == 0)[0]
norm_train, norm_hold = train_test_split(norm_idx, test_size=0.3, random_state=RNG)
norm_cal, norm_test = train_test_split(norm_hold, test_size=0.5, random_state=RNG)
susp_idx = np.where(y == 1)[0]
adv_idx = np.where(y == 2)[0]
eval_idx = np.concatenate([norm_test, susp_idx, adv_idx])
yev = y[eval_idx]
truth = (yev > 0).astype(int)

def pair_auc(s, neg_idx, pos_idx):
    yy = np.concatenate([np.zeros(len(neg_idx)), np.ones(len(pos_idx))])
    return roc_auc_score(yy, np.concatenate([s[neg_idx], s[pos_idx]]))

def save(fig, name):
    fig.savefig(os.path.join(OUT, name + ".pdf"))
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=300)
    plt.close(fig)
    print(f"  saved {name}.pdf and {name}.png")

CLASSES = [(0, "Normal"), (1, "Suspicious"), (2, "Advanced")]
CLASS_FILL = {0: "#FFFFFF", 1: "#9E9E9E", 2: "#303030"}

# ---------------------------------------------------------------------------
# Figure 5.1: system call composition per class
# ---------------------------------------------------------------------------
print("\n=== Figure 5.1 values (percent of tokens per class) ===")
SYS = {1: "execve", 2: "openat", 3: "connect", 4: "setuid", 5: "clone", 6: "ptrace"}
comp = {}
for lbl, cname in CLASSES:
    seq = Xs[y == lbl].flatten(); seq = seq[seq > 0]
    comp[lbl] = {t: 100 * (seq == t).mean() for t in SYS}
    print(f"  {cname:11s}: " + "  ".join(f"{SYS[t]} {comp[lbl][t]:.1f}%" for t in SYS))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.3, 2.7),
                               gridspec_kw={"width_ratios": [1, 1.6]})
xs = np.arange(len(CLASSES))
op = [comp[l][2] for l, _ in CLASSES]
other = [100 - v for v in op]
ax1.bar(xs, op, width=0.6, color="#D9D9D9", edgecolor="black", linewidth=0.6, label="openat")
ax1.bar(xs, other, bottom=op, width=0.6, color="#404040", edgecolor="black", linewidth=0.6, label="all other calls")
for i, v in enumerate(op):
    ax1.text(i, v / 2, f"{v:.1f}%", ha="center", va="center", fontsize=8)
ax1.set_xticks(xs, [c for _, c in CLASSES])
ax1.set_ylabel("Share of system call tokens (%)")
ax1.set_ylim(0, 100)
ax1.set_title("(a) openat against all other calls", fontsize=9)
ax1.legend(loc="lower center", bbox_to_anchor=(0.5, -0.42), ncol=2, frameon=False)

minor = [1, 3, 4, 5, 6]
w = 0.26
for k, (lbl, cname) in enumerate(CLASSES):
    vals = [comp[lbl][t] for t in minor]
    bx = np.arange(len(minor)) + (k - 1) * w
    ax2.bar(bx, vals, width=w, color=CLASS_FILL[lbl], edgecolor="black",
            linewidth=0.6, label=cname)
    for xx, v in zip(bx, vals):
        ax2.text(xx, v + 0.15, f"{v:.1f}", ha="center", va="bottom", fontsize=6, rotation=90)
ax2.set_xticks(np.arange(len(minor)), [SYS[t] for t in minor])
ax2.set_ylabel("Share of system call tokens (%)")
ax2.set_title("(b) Calls other than openat", fontsize=9)
ax2.legend(loc="lower center", bbox_to_anchor=(0.5, -0.42), ncol=3, frameon=False)
ax2.set_ylim(0, max(max(comp[l][t] for t in minor) for l, _ in CLASSES) * 1.35 + 0.5)
fig.tight_layout()
save(fig, "fig5_1_composition")

# ---------------------------------------------------------------------------
# Figure 5.2: ROC curves with calibrated operating points
# ---------------------------------------------------------------------------
print("\n=== Figure 5.2 values (evaluation set, unseen data only) ===")
from matplotlib.lines import Line2D
fig, (axa, axb) = plt.subplots(1, 2, figsize=(6.3, 3.2))
handles = [Line2D([0], [0], color="#999999", lw=0.8, label="Chance")]
for ax in (axa, axb):
    ax.plot([0, 1], [0, 1], color="#999999", lw=0.8, ls="-")
for n in MODELS:
    st = STYLE[n]
    se = scores[n][eval_idx]
    fpr_c, tpr_c, _ = roc_curve(truth, se)
    auc = roc_auc_score(truth, se)
    thr = np.percentile(scores[n][norm_cal], 95)
    pred = se > thr
    op_fpr = pred[yev == 0].mean()
    op_tpr = pred[truth == 1].mean()
    for ax in (axa, axb):
        ax.plot(fpr_c, tpr_c, color=st["color"], ls=st["ls"])
        ax.plot(op_fpr, op_tpr, marker=st["marker"], color=st["color"],
                markeredgecolor="black", markersize=6, ls="none", zorder=5)
    handles.append(Line2D([0], [0], color=st["color"], ls=st["ls"], marker=st["marker"],
                          markeredgecolor="black", label=f"{st['label']} (AUC {auc:.3f})"))
    print(f"  {n:16s} AUC {auc:.3f}   operating point FPR {op_fpr:.3f}  TPR {op_tpr:.3f}")
axa.set_xlim(0, 1); axa.set_ylim(0, 1); axa.set_aspect("equal")
axa.set_title("(a) Full range", fontsize=9)
axb.set_xlim(0, 0.2); axb.set_ylim(0, 1)
axb.set_title("(b) False positive rate 0 to 0.2", fontsize=9)
for ax in (axa, axb):
    ax.set_xlabel("False positive rate")
axa.set_ylabel("True positive rate")
fig.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, -0.1), ncol=2, frameon=False)
fig.tight_layout(rect=(0, 0.08, 1, 1))
save(fig, "fig5_2_roc")

# ---------------------------------------------------------------------------
# Figure 5.3: per-class AUC, threshold-free
# ---------------------------------------------------------------------------
print("\n=== Figure 5.3 values (per-class AUC) ===")
pairs = [("Normal vs\nsuspicious", norm_test, susp_idx),
         ("Normal vs\nadvanced", norm_test, adv_idx),
         ("Suspicious vs\nadvanced", susp_idx, adv_idx)]
fig, ax = plt.subplots(figsize=(5.2, 2.9))
w = 0.26
for k, n in enumerate(MODELS):
    st = STYLE[n]
    vals = [pair_auc(scores[n], a, b) for _, a, b in pairs]
    xs = np.arange(len(pairs)) + (k - 1) * w
    ax.bar(xs, vals, width=w, color=st["color"], hatch=st["hatch"],
           edgecolor="black", linewidth=0.6, label=st["label"])
    for xx, v in zip(xs, vals):
        ax.text(xx, v + 0.015, f"{v:.3f}", ha="center", va="bottom", fontsize=6.5, rotation=90)
    print(f"  {n:16s} " + "  ".join(f"{p.replace(chr(10), ' ')} {v:.3f}" for (p, _, _), v in zip(pairs, vals)))
ax.axhline(0.5, color="#666666", lw=0.8, ls="--", label="Chance (0.5)")
ax.set_xticks(np.arange(len(pairs)), [p for p, _, _ in pairs])
ax.set_ylabel("AUC")
ax.set_ylim(0, 1.08)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=4, frameon=False)
save(fig, "fig5_3_perclass_auc")

# ---------------------------------------------------------------------------
# Figure 5.4: paired bootstrap AUC differences (identical loop to results_table.py)
# ---------------------------------------------------------------------------
print("\n=== Figure 5.4 values (paired bootstrap, B=2000, seed 42) ===")
B = 2000
boot = np.random.RandomState(RNG)
overall = {n: [] for n in MODELS}
advnorm = {n: [] for n in MODELS}
for _ in range(B):
    nt = boot.choice(norm_test, len(norm_test), replace=True)
    su = boot.choice(susp_idx, len(susp_idx), replace=True)
    ad = boot.choice(adv_idx, len(adv_idx), replace=True)
    idx = np.concatenate([nt, su, ad])
    tr = (y[idx] > 0).astype(int)
    for n in MODELS:
        overall[n].append(roc_auc_score(tr, scores[n][idx]))
        advnorm[n].append(pair_auc(scores[n], nt, ad))

comparisons = [("Autoencoder", "IsolationForest"), ("Autoencoder", "LSTM"),
               ("IsolationForest", "LSTM")]
rows = []
for metric, store in [("Overall AUC", overall), ("Normal vs advanced AUC", advnorm)]:
    for a, b in comparisons:
        d = np.asarray(store[a]) - np.asarray(store[b])
        lo, hi = np.percentile(d, 2.5), np.percentile(d, 97.5)
        rows.append((metric, f"{STYLE[a]['short']} \u2212 {STYLE[b]['short']}", d.mean(), lo, hi))
        print(f"  {metric:24s} {STYLE[a]['short']:>4s} - {STYLE[b]['short']:<4s} mean {d.mean():+.3f}  95% CI [{lo:+.3f}, {hi:+.3f}]")

fig, ax = plt.subplots(figsize=(4.8, 2.8))
ypos = [5, 4, 3, 1.5, 0.5, -0.5]
for yy, (metric, lab, m, lo, hi) in zip(ypos, rows):
    sig = lo > 0 or hi < 0
    ax.plot([lo, hi], [yy, yy], color="black", lw=1.1)
    ax.plot(m, yy, marker="o", markersize=5, color="black" if sig else "white",
            markeredgecolor="black", ls="none")
ax.axvline(0, color="#666666", lw=0.8, ls="--")
ax.set_yticks(ypos, [r[1] for r in rows])
ax.text(1.02, 4, "Overall AUC", transform=ax.get_yaxis_transform(), va="center", fontsize=8)
ax.text(1.02, 0.5, "Normal vs\nadvanced AUC", transform=ax.get_yaxis_transform(), va="center", fontsize=8)
ax.axhline(2.25, color="#BBBBBB", lw=0.6)
ax.set_xlabel("Difference in AUC (95% bootstrap CI)")
ax.set_ylim(-1.2, 5.7)
from matplotlib.lines import Line2D
key = [Line2D([0], [0], marker="o", color="black", markerfacecolor="black", ls="-", label="Interval excludes 0"),
       Line2D([0], [0], marker="o", color="black", markerfacecolor="white", ls="-", label="Interval includes 0")]
ax.legend(handles=key, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2, frameon=False)
save(fig, "fig5_4_bootstrap")

print(f"\nAll figures written to {OUT}")
