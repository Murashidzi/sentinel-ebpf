#!/bin/bash
set -e
cd ~/Projects/sentinel-ebpf
DUR=${1:-360}
TS=$(date +%s)
sudo pkill -9 -x sentinel 2>/dev/null || true
docker rm -f n_worker n_backend 2>/dev/null || true
sleep 1
docker run -d --name n_backend httpd >/dev/null
sleep 3
BACKEND_IP=$(docker inspect n_backend --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "backend at $BACKEND_IP"
docker run -d --name n_worker python:3.12-slim sleep infinity >/dev/null
sleep 3
WID=$(docker inspect n_worker --format '{{.Id}}')
echo "worker: ${WID:0:12}"
OUT="evaluation/datasets/normal/normal_worker_${TS}.jsonl"
sudo daemon/sentinel 2>/dev/null | grep --line-buffered -v '"comm":"sentinel"' > "$OUT" &
sleep 3
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  docker exec n_worker sh -c 'for i in $(seq 1 5); do cat /etc/hostname >/dev/null; ls -la /usr/lib >/dev/null; head -c 100 /dev/urandom | base64 >/tmp/w_$i.txt; wc -l /tmp/w_$i.txt >/dev/null; done; for i in $(seq 1 10); do echo job$i >/tmp/j_$i.log; cat /tmp/j_$i.log >/dev/null; done; for i in $(seq 1 5); do python3 -c "import urllib.request,os; urllib.request.urlopen(\"http://'"$BACKEND_IP"':80/\",timeout=2).read()" 2>/dev/null; done; rm -f /tmp/w_*.txt /tmp/j_*.log' 2>/dev/null || true
done
sudo pkill -x sentinel 2>/dev/null || true
sleep 2
N=$(grep -c "\"container_id\":\"$WID\"" "$OUT" || true)
echo "worker real-container events: $N"
echo "--- top comms ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"comm":"[^"]*"' | sort | uniq -c | sort -rn | head -10
echo "--- syscall types ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"syscall_type":"[^"]*"' | sort | uniq -c | sort -rn
docker rm -f n_worker n_backend >/dev/null
echo "saved: $OUT"
