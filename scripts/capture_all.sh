#!/bin/bash
set -e
cd ~/Projects/sentinel-ebpf
DUR=${1:-180}
echo "=== FULL RECAPTURE: 12 runs, ${DUR}s each ==="
echo "started: $(date)"

for RUN in 1 2 3; do
  echo ""
  echo ">>> normal (original) run $RUN of 3"
  bash scripts/capture_normal.sh $DUR
  echo ""
  echo ">>> normal (shell-heavy) run $RUN of 3"
  bash scripts/capture_normal_shell.sh $DUR
  echo ""
  echo ">>> suspicious run $RUN of 3"
  bash scripts/capture_suspicious.sh $DUR
  echo ""
  echo ">>> advanced run $RUN of 3"
  bash scripts/capture_advanced.sh $DUR
done

echo ""
echo "=== RECAPTURE COMPLETE ==="
echo "finished: $(date)"
echo ""
echo "--- files per class ---"
for c in normal suspicious advanced; do
  echo "$c: $(ls evaluation/datasets/$c/*.jsonl 2>/dev/null | wc -l) files"
  for f in evaluation/datasets/$c/*.jsonl; do
    echo "  $(basename $f): $(wc -l < $f) lines"
  done
done
