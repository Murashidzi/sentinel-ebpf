#!/bin/bash
set -e
cd ~/Projects/sentinel-ebpf
DUR=${1:-360}
TS=$(date +%s)
sudo pkill -9 -x sentinel 2>/dev/null || true
docker rm -f s_worker s_backend 2>/dev/null || true
sleep 1
docker run -d --name s_backend httpd >/dev/null
sleep 3
BACKEND_IP=$(docker inspect s_backend --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "backend at $BACKEND_IP"
docker run -d --name s_worker python:3.12-slim sleep infinity >/dev/null
sleep 3
WID=$(docker inspect s_worker --format '{{.Id}}')
echo "worker: ${WID:0:12}"
OUT="evaluation/datasets/suspicious/suspicious_worker_${TS}.jsonl"
sudo daemon/sentinel -emit-events 2>/dev/null | grep --line-buffered -v '"comm":"sentinel"' > "$OUT" &
sleep 3
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  docker exec s_worker sh -c 'cat /etc/shadow >/dev/null 2>&1; cat /etc/passwd >/dev/null 2>&1; cat /proc/self/environ >/dev/null 2>&1; ls -la /root >/dev/null 2>&1; ls -la /root/.ssh >/dev/null 2>&1; cat /root/.ssh/id_rsa >/dev/null 2>&1; find /etc /root /home -name "*.key" >/dev/null 2>&1; find /usr/bin /bin -perm -4000 >/dev/null 2>&1; cat /proc/1/environ >/dev/null 2>&1; id >/dev/null 2>&1; whoami >/dev/null 2>&1; env >/dev/null 2>&1; cat /etc/hosts >/dev/null 2>&1; ps aux >/dev/null 2>&1' 2>/dev/null || true
done
sudo pkill -x sentinel 2>/dev/null || true
sleep 2
N=$(grep -c "\"container_id\":\"$WID\"" "$OUT" || true)
echo "worker real-container events: $N"
echo "--- top comms ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"comm":"[^"]*"' | sort | uniq -c | sort -rn | head -10
echo "--- syscall types ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"syscall_type":"[^"]*"' | sort | uniq -c | sort -rn
docker rm -f s_worker s_backend >/dev/null
echo "saved: $OUT"
