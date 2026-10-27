#!/bin/bash
# 60-second terminal demo for the README, recorded with asciinema.
# Starts the daemon showing alerts only, triggers a container-escape
# pattern and a port scan inside a deliberately privileged test
# container, then cleans up. Record it as root so no password prompt
# can appear: sudo asciinema rec -c "bash scripts/demo.sh" docs/demo.cast
cd "$(dirname "$(readlink -f "$0")")/.." || exit 1
say() { printf '\n\033[1;36m# %s\033[0m\n' "$1"; sleep 1.5; }
run() { printf '\033[1;32m$\033[0m %s\n' "$1"; sleep 1; }
sudo pkill -9 -x sentinel 2>/dev/null
docker rm -f demo >/dev/null 2>&1

say "sentinel-eBPF: eBPF tracepoints watching container system calls"
run "docker run -d --privileged --pid=host --name demo python:3.12-slim sleep infinity"
docker run -d --privileged --pid=host --name demo python:3.12-slim sleep infinity >/dev/null
run "sudo ./daemon/sentinel    # attach six tracepoints, print alerts"
sudo ./daemon/sentinel 2>&1 | grep --line-buffered "ALERT" \
  | sed -u -E 's/([0-9a-f]{12})[0-9a-f]{52}/\1/g; s/^(\[ALERT\] [A-Z]+ \| [A-Z_]+ \| [0-9a-f]{12}) \| .* \| (evidence=.*)$/\1\n    \2/' &
sleep 4

say "1. Escape pattern: open the host PID namespace handle"
run "docker exec demo sh -c 'cat /proc/1/ns/pid'    # repeated for 4 s"
docker exec demo sh -c 'for i in 1 2 3 4 5 6 7 8; do cat /proc/1/ns/pid >/dev/null 2>&1; sleep 0.5; done'
sleep 2
say "Each alert names the parent process: the shell that ran cat"
sleep 2

say "2. Port scan: 100 connection attempts from the container"
run "docker exec demo python3 -c '<connect to ports 1 to 100>'"
docker exec demo python3 -c "
import socket
for p in range(1, 101):
    try:
        s = socket.socket(); s.settimeout(0.05); s.connect(('172.17.0.1', p)); s.close()
    except Exception:
        pass
"
sleep 3
say "Detected live, with process lineage as evidence."
sudo pkill -x sentinel 2>/dev/null
docker rm -f demo >/dev/null 2>&1
sleep 1
