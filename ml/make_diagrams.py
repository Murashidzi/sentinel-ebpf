#!/usr/bin/env python3
"""
Figures 3.1 and 3.2 for sentinel-eBPF, drawn with explicit coordinates so
the layout is fixed and fits a 6.35 inch text width at true font size.

Same fonts and line weights as make_figures.py. Figure 3.2 reads its
window counts from y.npy using the same seed-42 split as results_table.py,
so no count in either figure is typed by hand.

Outputs (PDF for the document, PNG at 300 dpi for preview):
  fig3_1_architecture   as-built architecture, online and offline paths
  fig3_2_design         experimental design and data split
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from sklearn.model_selection import train_test_split

ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
OUT = os.environ.get("FIG_DIR", os.path.join(ML, "figures"))
os.makedirs(OUT, exist_ok=True)
RNG = 42

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 7.5,
    "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})
INK = "#333333"
FS = 7.5          # box text
FS_TITLE = 8.5    # stage titles

def canvas(w, h):
    fig = plt.figure(figsize=(w, h))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, w); ax.set_ylim(h, 0); ax.axis("off")
    return fig, ax

class Box:
    def __init__(self, ax, x, y, w, h, text, dashed=False, fill="white", fs=FS):
        self.x, self.y, self.w, self.h = x, y, w, h
        ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                     boxstyle="round,pad=0,rounding_size=0.06",
                     facecolor=fill, edgecolor=INK, linewidth=0.8,
                     linestyle=(0, (3, 2)) if dashed else "-", zorder=3))
        ax.text(x, y, text, ha="center", va="center", fontsize=fs,
                linespacing=1.15, zorder=4)
    def top(self):    return (self.x, self.y - self.h / 2)
    def bottom(self): return (self.x, self.y + self.h / 2)
    def left(self):   return (self.x - self.w / 2, self.y)
    def right(self):  return (self.x + self.w / 2, self.y)

def stage(ax, x0, y0, x1, y1, title, fill):
    ax.add_patch(FancyBboxPatch((x0, y0), x1 - x0, y1 - y0,
                 boxstyle="round,pad=0,rounding_size=0.04",
                 facecolor=fill, edgecolor="#888888", linewidth=0.8, zorder=1))
    ax.text(x0 + 0.08, y0 + 0.07, title, ha="left", va="top",
            fontsize=FS_TITLE, zorder=2)

def arrow(ax, p, q, dashed=False, label=None, label_dx=0.06, label_dy=0.0):
    ax.annotate("", xy=q, xytext=p, zorder=2,
                arrowprops=dict(arrowstyle="-|>", color=INK, lw=0.8,
                                mutation_scale=7, shrinkA=0, shrinkB=0,
                                linestyle=(0, (3, 2)) if dashed else "-"))
    if label:
        mx, my = (p[0] + q[0]) / 2, (p[1] + q[1]) / 2
        ax.text(mx + label_dx, my + label_dy, label, ha="left", va="center",
                fontsize=FS - 0.5, style="italic", zorder=4)

def save(fig, name):
    fig.savefig(os.path.join(OUT, name + ".pdf"))
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=300)
    plt.close(fig)
    print(f"  saved {name}.pdf and {name}.png")

# ---------------------------------------------------------------------------
# Figure 3.1: as-built architecture
# ---------------------------------------------------------------------------
W, H = 6.35, 7.25
fig, ax = canvas(W, H)

stage(ax, 0.04, 0.04, W - 0.04, 0.95, "Kernel space: eBPF programs (CO-RE)", "#E9E9E9")
ky, kh, kw = 0.58, 0.50, 1.42
kx = [0.83, 2.41, 3.99, 5.57]
tp = Box(ax, kx[0], ky, kw, kh, "Six tracepoints\nexecve, openat, connect,\nsetuid, clone, ptrace")
sf = Box(ax, kx[1], ky, kw, kh, "Self-event filter\ndrops the daemon's\nown PID")
fc = Box(ax, kx[2], ky, kw, kh, "fill_common()\nzeroes the 344-byte event;\nrecords process and parent")
rb = Box(ax, kx[3], ky, kw, kh, "BPF ring buffer\n256 KB, ordered")
arrow(ax, tp.right(), sf.left()); arrow(ax, sf.right(), fc.left()); arrow(ax, fc.right(), rb.left())

stage(ax, 0.04, 1.12, W - 0.04, 3.90, "User space: sentinel daemon (Go), online", "#F5F5F5")
bg = Box(ax, 1.75, 1.66, 1.85, 0.36, "Background refresh, every 5 s\ncgroup v2 hierarchy walk")
rd = Box(ax, 4.60, 1.66, 1.50, 0.36, "Ring buffer reader\nzero-copy decode")
en = Box(ax, 3.17, 2.30, 1.95, 0.62, "Container enrichment\n1. in-memory cgroup map\n2. /proc/<pid>/cgroup on a miss\n3. otherwise \"host\"")
re_ = Box(ax, 1.05, 3.02, 1.50, 0.36, "Rule engine\n5 deterministic rules")
ev = Box(ax, 3.17, 3.02, 1.85, 0.36, "NDJSON event output\n-emit-events (capture mode)")
fe = Box(ax, 5.25, 3.02, 1.85, 0.36, "Online feature extractor\n10 s windows, Welford baseline")
al = Box(ax, 1.05, 3.58, 1.75, 0.36, "Alerts with evidence\nincl. parent comm and ppid")
fw = Box(ax, 5.25, 3.58, 1.55, 0.36, "Online model inference\n(future work)", dashed=True)
arrow(ax, rb.bottom(), rd.top())
arrow(ax, rd.bottom(), (en.x + 0.45, en.top()[1]))
arrow(ax, bg.bottom(), (en.x - 0.45, en.top()[1]), dashed=True)
arrow(ax, (en.x - 0.55, en.bottom()[1]), re_.top())
arrow(ax, en.bottom(), ev.top())
arrow(ax, (en.x + 0.55, en.bottom()[1]), fe.top())
arrow(ax, re_.bottom(), al.top())
arrow(ax, fe.bottom(), fw.top(), dashed=True)

stage(ax, 0.04, 4.12, W - 0.04, H - 0.04, "Offline evaluation (Python)", "#FFFFFF")
ds = Box(ax, 3.17, 4.62, 1.95, 0.36, "Three-class dataset\nnormal, suspicious, advanced")
fx = Box(ax, 3.17, 5.18, 2.05, 0.36, "extract_features.py\nnon-overlapping 20-event windows")
ag = Box(ax, 2.00, 5.78, 1.85, 0.36, "Aggregated vector\n9 features, 2 lineage-derived")
sq = Box(ax, 4.40, 5.78, 1.95, 0.36, "Token sequence\n20 syscall types, no lineage")
mif = Box(ax, 1.30, 6.33, 1.15, 0.28, "Isolation Forest")
mae = Box(ax, 2.70, 6.33, 1.15, 0.28, "Autoencoder")
mls = Box(ax, 4.40, 6.33, 0.95, 0.28, "LSTM")
rt = Box(ax, 3.17, 6.88, 2.35, 0.36, "results_table.py\nleakage-free metrics, paired bootstrap")
arrow(ax, ev.bottom(), ds.top(), label="capture runs")
arrow(ax, ds.bottom(), fx.top())
arrow(ax, (fx.x - 0.45, fx.bottom()[1]), ag.top())
arrow(ax, (fx.x + 0.45, fx.bottom()[1]), sq.top())
arrow(ax, (ag.x - 0.35, ag.bottom()[1]), mif.top())
arrow(ax, (ag.x + 0.35, ag.bottom()[1]), mae.top())
arrow(ax, sq.bottom(), mls.top())
arrow(ax, mif.bottom(), (rt.x - 0.7, rt.top()[1]))
arrow(ax, mae.bottom(), (rt.x - 0.25, rt.top()[1]))
arrow(ax, mls.bottom(), (rt.x + 0.7, rt.top()[1]))
save(fig, "fig3_1_architecture")

# ---------------------------------------------------------------------------
# Figure 3.2: experimental design and data split (counts from y.npy)
# ---------------------------------------------------------------------------
y = np.load(f"{ML}/y.npy")
norm_idx = np.where(y == 0)[0]
norm_train, norm_hold = train_test_split(norm_idx, test_size=0.3, random_state=RNG)
norm_cal, norm_test = train_test_split(norm_hold, test_size=0.5, random_state=RNG)
n_all, n_norm = len(y), len(norm_idx)
n_susp, n_adv = int((y == 1).sum()), int((y == 2).sum())
n_tr, n_cal, n_te = len(norm_train), len(norm_cal), len(norm_test)
n_eval = n_te + n_susp + n_adv
print(f"\n=== Figure 3.2 counts (from y.npy) ===\n  total {n_all}  normal {n_norm}  suspicious {n_susp}  advanced {n_adv}")
print(f"  train {n_tr}  calibration {n_cal}  test {n_te}  evaluation set {n_eval}")

W2, H2 = 6.35, 5.55
fig, ax = canvas(W2, H2)
dsb = Box(ax, 3.17, 0.28, 2.30, 0.36, f"Captured dataset\n{n_all} windows of 20 events")
nb = Box(ax, 1.55, 0.92, 1.30, 0.36, f"Normal\n{n_norm} windows")
sb = Box(ax, 3.95, 0.92, 1.30, 0.36, f"Suspicious\n{n_susp} windows")
ab = Box(ax, 5.35, 0.92, 1.30, 0.36, f"Advanced\n{n_adv} windows")
trb = Box(ax, 0.55, 1.62, 0.95, 0.42, f"Train\n{n_tr}\nfit models")
cab = Box(ax, 1.55, 1.62, 0.95, 0.42, f"Calibration\n{n_cal}\nset thresholds")
teb = Box(ax, 2.55, 1.62, 0.95, 0.42, f"Test\n{n_te}\nmeasure FPR")
evb = Box(ax, 4.65, 2.20, 2.10, 0.42, f"Evaluation set: {n_eval} unseen windows\ntest normal, suspicious, advanced\n(none used in training)")
arrow(ax, (dsb.x - 0.75, dsb.bottom()[1]), nb.top())
arrow(ax, (dsb.x + 0.55, dsb.bottom()[1]), sb.top())
arrow(ax, (dsb.x + 1.0, dsb.bottom()[1]), ab.top())
arrow(ax, (nb.x - 0.45, nb.bottom()[1]), trb.top())
arrow(ax, nb.bottom(), cab.top())
arrow(ax, (nb.x + 0.45, nb.bottom()[1]), teb.top())
arrow(ax, teb.right(), (evb.left()[0], evb.y - 0.05))
arrow(ax, sb.bottom(), (evb.x - 0.30, evb.top()[1]))
arrow(ax, ab.bottom(), (evb.x + 0.55, evb.top()[1]))

stage(ax, 0.04, 2.70, W2 - 0.04, 4.22, "Two representations of every window, three unsupervised models", "#F5F5F5")
agb = Box(ax, 1.55, 3.18, 2.05, 0.36, "Aggregated vector\n9 features, 2 lineage-derived")
sqb = Box(ax, 4.65, 3.18, 2.05, 0.36, "Ordered token sequence\n20 syscall types")
ifb = Box(ax, 0.95, 3.82, 1.10, 0.28, "Isolation Forest")
aeb = Box(ax, 2.20, 3.82, 1.10, 0.28, "Autoencoder")
lsb = Box(ax, 4.65, 3.82, 0.95, 0.28, "LSTM")
arrow(ax, (agb.x - 0.45, agb.bottom()[1]), ifb.top())
arrow(ax, (agb.x + 0.45, agb.bottom()[1]), aeb.top())
arrow(ax, sqb.bottom(), lsb.top())
arrow(ax, trb.bottom(), (trb.x, 2.70), label="fit", label_dx=0.05)
arrow(ax, cab.bottom(), (cab.x, 2.70), label="score", label_dx=0.05)
arrow(ax, evb.bottom(), (evb.x, 2.70), label="score", label_dx=0.05)

thb = Box(ax, 1.55, 4.62, 2.05, 0.36, "Thresholds\n95th percentile of calibration scores")
scb = Box(ax, 4.65, 4.62, 2.05, 0.36, "Anomaly scores\non the evaluation set")
mb = Box(ax, 3.10, 5.27, 2.70, 0.40, "AUC, per-class AUC, operating point\npaired bootstrap (B = 2000)")
arrow(ax, (thb.x, 4.22), thb.top())
arrow(ax, (scb.x, 4.22), scb.top())
arrow(ax, thb.bottom(), (mb.x - 0.6, mb.top()[1]))
arrow(ax, scb.bottom(), (mb.x + 0.6, mb.top()[1]))
save(fig, "fig3_2_design")
print(f"\nAll diagrams written to {OUT}")
