#!/usr/bin/env python3
"""
Figures 3.1 and 3.2 for the revised sentinel-eBPF dissertation, drawn with
explicit coordinates at 6.0 inches wide, all text at least 8 pt.

  fig3_1_architecture  as-built architecture: kernel band with the drop
                       counter, online daemon with the host-attribution
                       counter and health reporter, offline band with three
                       representations and four models
  fig3_2_design        the 2x2 representation-by-lineage design and the
                       run-level split, with counts read from
                       run_level_scores.npz (no count typed by hand)
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
from matplotlib.text import Text

ML = os.environ.get("ML_DIR", os.path.expanduser("~/Projects/sentinel-ebpf/ml"))
OUT = os.environ.get("FIG_DIR", os.path.join(ML, "figures"))
os.makedirs(OUT, exist_ok=True)
MIN_PT = 8
plt.rcParams.update({"font.family": "serif",
                     "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
                     "savefig.pad_inches": 0.0})
INK = "#333333"; FS = 8; FS_TITLE = 9
MODEL_COLOR = {"IF": "#E69F00", "AE": "#0072B2", "LSTM": "#009E73", "LSTM+Lineage": "#CC79A7"}
BOXES = []

def canvas(w, h):
    fig = plt.figure(figsize=(w, h))
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, w); ax.set_ylim(h, 0); ax.axis("off")
    return fig, ax

class Box:
    def __init__(self, ax, x, y, w, h, text, dashed=False, fill="white", edge=INK, lw=0.8, fs=FS, tc="black"):
        self.x, self.y, self.w, self.h = x, y, w, h
        p = FancyBboxPatch((x - w/2, y - h/2), w, h, boxstyle="round,pad=0,rounding_size=0.05",
                           facecolor=fill, edgecolor=edge, linewidth=lw,
                           linestyle=(0, (3, 2)) if dashed else "-", zorder=3)
        ax.add_patch(p)
        t = ax.text(x, y, text, ha="center", va="center", fontsize=fs, linespacing=1.12, zorder=4, color=tc)
        BOXES.append((t, p))
    def top(self, dx=0):    return (self.x + dx, self.y - self.h/2)
    def bottom(self, dx=0): return (self.x + dx, self.y + self.h/2)
    def left(self, dy=0):   return (self.x - self.w/2, self.y + dy)
    def right(self, dy=0):  return (self.x + self.w/2, self.y + dy)

def stage(ax, x0, y0, x1, y1, title, fill):
    ax.add_patch(FancyBboxPatch((x0, y0), x1-x0, y1-y0, boxstyle="round,pad=0,rounding_size=0.04",
                 facecolor=fill, edgecolor="#888888", linewidth=0.8, zorder=1))
    ax.text(x0 + 0.08, y0 + 0.06, title, ha="left", va="top", fontsize=FS_TITLE, zorder=2)

def arrow(ax, p, q, dashed=False, label=None, dx=0.05, dy=0.0, ha="left"):
    ax.annotate("", xy=q, xytext=p, zorder=2,
                arrowprops=dict(arrowstyle="-|>", color=INK, lw=0.8, mutation_scale=7, shrinkA=0, shrinkB=0,
                                linestyle=(0, (3, 2)) if dashed else "-"))
    if label:
        ax.text((p[0]+q[0])/2 + dx, (p[1]+q[1])/2 + dy, label, ha=ha, va="center",
                fontsize=FS, style="italic", zorder=4)

def check_and_save(fig, name):
    fig.canvas.draw(); r = fig.canvas.get_renderer()
    overflow = 0
    for t, p in BOXES:
        tb, pb = t.get_window_extent(r), p.get_window_extent(r)
        if tb.width > pb.width - 2 or tb.height > pb.height - 2:
            overflow += 1; print(f"    WARNING text overflows box: {t.get_text()[:40]!r}")
    BOXES.clear()
    sizes = [t.get_fontsize() for t in fig.findobj(Text) if t.get_text().strip()]
    wd, ht = fig.get_size_inches()
    fig.savefig(os.path.join(OUT, name + ".pdf")); fig.savefig(os.path.join(OUT, name + ".png"), dpi=300)
    plt.close(fig)
    ok = "OK" if min(sizes) >= MIN_PT and overflow == 0 else "CHECK"
    print(f"  saved {name}: {wd:.2f} x {ht:.2f} in, smallest text {min(sizes):.1f} pt, overflows {overflow}  {ok}")

# ---------------------------------------------------------------------------
# Figure 3.1: as-built architecture
# ---------------------------------------------------------------------------
W, H = 6.0, 8.05
fig, ax = canvas(W, H)
stage(ax, 0.03, 0.03, W-0.03, 1.62, "Kernel space: eBPF programs (CO-RE)", "#E9E9E9")
kw, kh, ky = 1.33, 0.64, 0.62
tp = Box(ax, 0.76, ky, kw, kh, "Six tracepoints\nexecve, openat,\nconnect, setuid,\nclone, ptrace")
sf = Box(ax, 2.20, ky, kw, kh, "Self-event filter\ndrops the\ndaemon's own PID")
fc = Box(ax, 3.64, ky, kw, kh, "fill_common()\nzeroes the event,\nrecords process\nand parent")
rb = Box(ax, 5.08, ky, kw, kh, "BPF ring buffer\n256 KB, ordered")
arrow(ax, tp.right(), sf.left()); arrow(ax, sf.right(), fc.left()); arrow(ax, fc.right(), rb.left())
dc = Box(ax, 3.64, 1.27, 2.05, 0.42, "Drop counter (BPF array map)\n+1 on each failed reserve", dashed=True)
arrow(ax, rb.bottom(-0.45), dc.right(-0.05), dashed=True, label="buffer full", dx=0.06, dy=-0.04)

stage(ax, 0.03, 1.80, W-0.03, 4.78, "User space: sentinel daemon (Go), online", "#F5F5F5")
bg = Box(ax, 1.12, 2.30, 2.05, 0.42, "Background refresh, every 5 s\ncgroup v2 hierarchy walk")
hr = Box(ax, 3.20, 2.30, 1.85, 0.42, "Health reporter, every 10 s\n[DROP] and [ENRICH] counts", dashed=True)
rd = Box(ax, 5.10, 2.30, 1.55, 0.42, "Ring buffer reader\nzero-copy decode")
en = Box(ax, 3.20, 3.08, 2.45, 0.66, "Container enrichment\n1. in-memory cgroup map\n2. /proc/<pid>/cgroup on a miss\n3. otherwise \"host\" (counted)")
re_ = Box(ax, 0.92, 3.80, 1.55, 0.42, "Rule engine\n5 deterministic rules")
ev = Box(ax, 3.20, 3.80, 1.90, 0.42, "NDJSON event output\n-emit-events (capture)")
fe = Box(ax, 5.15, 3.80, 1.55, 0.42, "Online feature\nextractor, 10 s windows")
al = Box(ax, 0.92, 4.42, 1.65, 0.42, "Alerts with evidence\nparent comm and ppid")
fw = Box(ax, 5.15, 4.42, 1.55, 0.42, "Online model inference\n(future work)", dashed=True)
arrow(ax, rb.bottom(0.15), rd.top(0.13))
arrow(ax, dc.bottom(-0.44), hr.top(), dashed=True, label="drop count", dx=0.06, dy=0.15)
arrow(ax, rd.bottom(), en.right(-0.18))
arrow(ax, bg.bottom(), en.left(-0.18), dashed=True)
arrow(ax, en.top(), hr.bottom(), dashed=True, label="host count", dx=0.05)
arrow(ax, en.bottom(-0.85), re_.top()); arrow(ax, en.bottom(), ev.top()); arrow(ax, en.bottom(0.85), fe.top())
arrow(ax, re_.bottom(), al.top()); arrow(ax, fe.bottom(), fw.top(), dashed=True)

stage(ax, 0.03, 4.98, W-0.03, H-0.03, "Offline evaluation (Python)", "#FFFFFF")
ds = Box(ax, 3.20, 5.45, 3.30, 0.42, "Three-class dataset, 12 capture runs\nnormal (worker, shell-heavy), suspicious, advanced-like")
fx = Box(ax, 3.20, 6.05, 2.40, 0.42, "extract_features.py\nnon-overlapping 20-event windows")
ag = Box(ax, 1.15, 6.68, 2.05, 0.42, "Aggregated vector\n9 features, 2 lineage-derived")
sq = Box(ax, 3.20, 6.68, 1.75, 0.42, "Token sequence\nsyscall type only")
sl = Box(ax, 5.05, 6.68, 1.75, 0.42, "Lineage sequence\n3 channels per event")
mh = 0.34; my = 7.26
mif = Box(ax, 0.62, my, 1.02, mh, "Isolation Forest", edge=MODEL_COLOR["IF"], lw=1.6)
mae = Box(ax, 1.70, my, 1.02, mh, "Autoencoder", edge=MODEL_COLOR["AE"], lw=1.6)
mls = Box(ax, 3.20, my, 0.90, mh, "LSTM", edge=MODEL_COLOR["LSTM"], lw=1.6)
mll = Box(ax, 5.05, my, 1.30, mh, "LSTM+Lineage", edge=MODEL_COLOR["LSTM+Lineage"], lw=1.6)
rt = Box(ax, 3.20, 7.76, 3.30, 0.42, "results_table.py (window split), eval_run_level.py\n(run-level split): metrics and paired bootstrap")
arrow(ax, ev.bottom(), ds.top(), label="capture runs", dx=0.06)
arrow(ax, ds.bottom(), fx.top())
arrow(ax, fx.bottom(-0.9), ag.top(0.3)); arrow(ax, fx.bottom(), sq.top()); arrow(ax, fx.bottom(0.9), sl.top(-0.3))
arrow(ax, ag.bottom(-0.45), mif.top()); arrow(ax, ag.bottom(0.45), mae.top())
arrow(ax, sq.bottom(), mls.top()); arrow(ax, sl.bottom(), mll.top())
for m, dx in [(mif, -1.2), (mae, -0.55), (mls, 0.0), (mll, 0.9)]:
    arrow(ax, m.bottom(), rt.top(dx))
check_and_save(fig, "fig3_1_architecture")

# ---------------------------------------------------------------------------
# Figure 3.2: 2x2 design and run-level split (counts from run_level_scores.npz)
# ---------------------------------------------------------------------------
R = np.load(f"{ML}/run_level_scores.npz")
n_tr, n_ca = int(R["n_train"]), int(R["n_cal"])
n_tn, n_ts, n_ta = int(R["n_test_normal"]), int(R["n_test_susp"]), int(R["n_test_adv"])
print(f"\n=== Figure 3.2 counts (from run_level_scores.npz) ===\n  train {n_tr}  calibration {n_ca}  "
      f"test normal {n_tn}  test suspicious {n_ts}  test advanced-like {n_ta}")

W2, H2 = 6.0, 5.45
fig, ax = canvas(W2, H2)
ax.text(0.05, 0.10, "(a) Representation by lineage: four models", fontsize=FS_TITLE, va="top")
cx = [1.20, 3.15, 5.00]; cw = [1.85, 1.75, 1.75]
ry = [0.55, 1.07, 1.71]; rh = [0.34, 0.56, 0.56]
Box(ax, cx[1], ry[0], cw[1], rh[0], "Without lineage", fill="#E9E9E9")
Box(ax, cx[2], ry[0], cw[2], rh[0], "With lineage", fill="#E9E9E9")
Box(ax, cx[0], ry[1], cw[0], rh[1], "Aggregated\n9-feature vector", fill="#E9E9E9")
Box(ax, cx[0], ry[2], cw[0], rh[2], "Sequence\n20 events, in order", fill="#E9E9E9")
Box(ax, cx[1], ry[1], cw[1], rh[1], "IF, AE\n7 features (ablation)", dashed=True)
Box(ax, cx[2], ry[1], cw[2], rh[1], "IF, AE\nall 9 features")
Box(ax, cx[1], ry[2], cw[1], rh[2], "LSTM\nsyscall type", edge=MODEL_COLOR["LSTM"], lw=1.6)
Box(ax, cx[2], ry[2], cw[2], rh[2], "LSTM+Lineage\n+ parent-is-shell,\n+ new-parent",
    edge=MODEL_COLOR["LSTM+Lineage"], lw=1.6)

ax.text(0.05, 2.30, "(b) Run-level split: each capture run is assigned to one role", fontsize=FS_TITLE, va="top")
ROLE = {"train": ("#FFFFFF", "///", "Train (fit models)"),
        "cal": ("#D9D9D9", "", "Calibration (threshold)"),
        "test": ("#404040", "", "Test (all metrics)"),
        "unused": ("#FFFFFF", "", "Not used")}
rows = [("Normal, worker", ["train", "cal", "test"]),
        ("Normal, shell-heavy", ["train", "cal", "test"]),
        ("Suspicious", ["unused", "unused", "test"]),
        ("Advanced-like", ["unused", "unused", "test"])]
gx0, gw, gap, gh, gy0 = 1.55, 1.35, 0.10, 0.34, 2.95
colx = [gx0 + j*(gw+gap) for j in range(3)]
for j, r in enumerate(["Run 1", "Run 2", "Run 3"]):
    ax.text(colx[j] + gw/2, gy0 - 0.32, r, ha="center", va="center", fontsize=FS)
for i, (name, roles) in enumerate(rows):
    yy = gy0 + i*(gh+0.08)
    ax.text(gx0 - 0.12, yy, name, ha="right", va="center", fontsize=FS)
    for j, role in enumerate(roles):
        fill, hatch, _ = ROLE[role]
        ax.add_patch(Rectangle((colx[j], yy - gh/2), gw, gh, facecolor=fill, edgecolor=INK, linewidth=0.8,
                               hatch=hatch, linestyle=(0, (3, 2)) if role == "unused" else "-", zorder=3))
cy = gy0 + 3*(gh+0.08) + gh/2 + 0.10
ax.text(colx[0] + gw/2, cy, f"train:\n{n_tr} normal windows", ha="center", va="top", fontsize=FS)
ax.text(colx[1] + gw/2, cy, f"calibration:\n{n_ca} normal windows", ha="center", va="top", fontsize=FS)
ax.text(colx[2] + gw/2, cy, f"test: {n_tn} normal,\n{n_ts} suspicious,\n{n_ta} advanced-like",
        ha="center", va="top", fontsize=FS)
ly = 5.22
lxs = [0.10, 1.55, 3.20, 4.70]
for k, role in enumerate(["train", "cal", "test", "unused"]):
    fill, hatch, lab = ROLE[role]
    x = lxs[k]
    ax.add_patch(Rectangle((x, ly - 0.09), 0.28, 0.18, facecolor=fill, edgecolor=INK, linewidth=0.8,
                           hatch=hatch, linestyle=(0, (3, 2)) if role == "unused" else "-"))
    ax.text(x + 0.34, ly, lab, ha="left", va="center", fontsize=FS)
check_and_save(fig, "fig3_2_design")
print(f"\nAll diagrams written to {OUT}")
