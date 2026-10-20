#!/bin/bash
set -e
cd ~/Projects/sentinel-ebpf
DUR=${1:-360}
TS=$(date +%s)
sudo pkill -9 -x sentinel 2>/dev/null || true
docker rm -f ns_worker 2>/dev/null || true
sleep 1
docker run -d --name ns_worker python:3.12-slim sleep infinity >/dev/null
sleep 3
# Install common shell tools inside the container
docker exec ns_worker sh -c 'apt-get update -qq && apt-get install -y -qq procps findutils coreutils > /dev/null 2>&1' || true
WID=$(docker inspect ns_worker --format '{{.Id}}')
echo "worker: ${WID:0:12}"
OUT="evaluation/datasets/normal/normal_shell_${TS}.jsonl"
sudo daemon/sentinel -emit-events 2>/dev/null | grep --line-buffered -v '"comm":"sentinel"' > "$OUT" &
sleep 3
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  # Benign CI-style workload: many short-lived shell commands, subshells,
  # pipes, file processing. Creates process chains and diverse parents
  # that resemble attack patterns but are entirely legitimate.
  docker exec ns_worker sh -c '
    # Build-style: compile-like sequence with temp files
    for i in $(seq 1 5); do
      sh -c "echo building module $i > /tmp/build_$i.log"
      sh -c "cat /tmp/build_$i.log | grep -c module > /dev/null"
      sh -c "wc -l /tmp/build_$i.log > /dev/null"
    done
    # CI test runner: nested shells, subprocesses
    sh -c "sh -c \"echo test_passed\" > /tmp/test_result.txt"
    sh -c "cat /tmp/test_result.txt | tr a-z A-Z > /tmp/test_upper.txt"
    # Log rotation style
    for f in /tmp/build_*.log; do
      sh -c "cat $f >> /tmp/all_builds.log" 2>/dev/null
    done
    sh -c "tail -20 /tmp/all_builds.log > /tmp/recent.log" 2>/dev/null
    # Health checks: process listing, disk, network config
    sh -c "ps aux > /tmp/procs.txt" 2>/dev/null
    sh -c "df -h > /tmp/disk.txt" 2>/dev/null
    sh -c "cat /etc/resolv.conf > /dev/null" 2>/dev/null
    # Cleanup
    rm -f /tmp/build_*.log /tmp/test_*.txt /tmp/all_builds.log /tmp/recent.log /tmp/procs.txt /tmp/disk.txt
  ' 2>/dev/null || true
  sleep 2
done
sudo pkill -x sentinel 2>/dev/null || true
sleep 2
N=$(grep -c "\"container_id\":\"$WID\"" "$OUT" || true)
echo "worker real-container events: $N"
echo "--- top comms ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"comm":"[^"]*"' | sort | uniq -c | sort -rn | head -10
echo "--- syscall types ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"syscall_type":"[^"]*"' | sort | uniq -c | sort -rn
docker rm -f ns_worker >/dev/null
echo "saved: $OUT"
