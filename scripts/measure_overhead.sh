#!/bin/bash
set -e
cd ~/Projects/sentinel-ebpf
DUR=${1:-120}
NCPU=$(nproc)
echo "cores: $NCPU   measurement window: ${DUR}s per pass"

cleanup() {
  sudo pkill -9 -x sentinel 2>/dev/null || true
  docker rm -f ovh_worker ovh_backend 2>/dev/null || true
}
cleanup
sleep 1

start_workload() {
  docker run -d --name ovh_backend httpd >/dev/null
  sleep 3
  BIP=$(docker inspect ovh_backend --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  docker run -d --name ovh_worker python:3.12-slim sleep infinity >/dev/null
  sleep 3
  ( END=$((SECONDS+DUR+20))
    while [ $SECONDS -lt $END ]; do
      docker exec ovh_worker sh -c 'for i in $(seq 1 5); do cat /etc/hostname >/dev/null; ls -la /usr/lib >/dev/null; head -c 100 /dev/urandom | base64 >/tmp/w.txt; done; for i in $(seq 1 10); do echo j >/tmp/j.log; cat /tmp/j.log >/dev/null; done' 2>/dev/null || true
    done ) &
  WLPID=$!
}

echo ""
echo "=== PASS 1: baseline (workload only, no daemon) ==="
start_workload
sleep 5
# system-wide %idle -> %busy, averaged over DUR one-second samples
BASE_BUSY=$(mpstat 1 $DUR | awk '/Average:/ && $2=="all" {print 100-$NF}')
echo "baseline system CPU busy: ${BASE_BUSY}%"
kill $WLPID 2>/dev/null || true
cleanup
sleep 2

echo ""
echo "=== PASS 2: instrumented (workload + daemon) ==="
start_workload
sudo daemon/sentinel >/dev/null 2>&1 &
sleep 5
SENTPID=$(pgrep -x sentinel | head -1)
echo "daemon pid: $SENTPID"
# daemon's own CPU: pidstat mean %CPU over DUR samples (as % of ONE core)
DAEMON_CPU=$(sudo pidstat -p $SENTPID 1 $DUR | awk '/Average:/ {print $8}')
INST_BUSY=$(mpstat 1 3 | awk '/Average:/ && $2=="all" {print 100-$NF}')
sudo pkill -x sentinel 2>/dev/null || true
kill $WLPID 2>/dev/null || true
cleanup

echo ""
echo "=== RESULTS ==="
echo "daemon own CPU (% of one core):        ${DAEMON_CPU}%"
# normalise daemon CPU to whole-system percentage
DAEMON_SYS=$(echo "scale=3; $DAEMON_CPU / $NCPU" | bc)
echo "daemon own CPU (% of ${NCPU}-core system): ${DAEMON_SYS}%"
echo "baseline system busy:                  ${BASE_BUSY}%"
echo "primary overhead figure = daemon own CPU as system %: ${DAEMON_SYS}%"
echo "target: < 2%"
