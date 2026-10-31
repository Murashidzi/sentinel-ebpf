#!/bin/bash
# B9 (comment 4.5): tracepoint coverage test.
# Runs the daemon with -emit-events, triggers each of the six system calls
# inside a fresh container five times, then asserts that each syscall type
# appears in events attributed to that container. Prints PASS or FAIL per type.
set -u
cd "$(dirname "$(readlink -f "$0")")/.." || exit 1
OUT=/tmp/tp_events.jsonl; ERR=/tmp/tp_events.stderr
sudo -v || exit 1
sudo pkill -9 -x sentinel 2>/dev/null; docker rm -f tp_test >/dev/null 2>&1
docker run -d --name tp_test python:3.12-slim sleep infinity >/dev/null
CID=$(docker inspect -f '{{.Id}}' tp_test)
echo "test container: ${CID:0:12}   daemon commit: $(git rev-parse --short HEAD)"
sleep 2
sudo ./daemon/sentinel -emit-events > "$OUT" 2> "$ERR" &
sleep 4                                   # let the daemon load and map the container
for i in 1 2 3 4 5; do
  docker exec tp_test sh -c '
    /bin/true
    cat /etc/hostname > /dev/null
    python3 -c "import socket; s=socket.socket(); s.settimeout(0.2); s.connect_ex((\"127.0.0.1\", 9))"
    python3 -c "import os; os.setuid(0)"
    python3 -c "import os; pid=os.fork(); os._exit(0) if pid == 0 else os.waitpid(pid, 0)"
    python3 -c "import ctypes; print(ctypes.CDLL(None).ptrace(0, 0, 0, 0))"
  ' 2>&1 | tail -1 | sed "s/^/  round $i: ptrace() returned /"
  sleep 1
done
sleep 2
sudo pkill -x sentinel; sleep 1
docker rm -f tp_test >/dev/null
python3 - "$OUT" "$CID" "$ERR" << 'PY'
import json, sys
out, cid, err = sys.argv[1], sys.argv[2], sys.argv[3]
mine, host = {}, {}
for line in open(out, errors="replace"):
    if not line.startswith("{"): continue
    try: e = json.loads(line)
    except Exception: continue
    t = e.get("syscall_type", "?")
    if e.get("container_id") == cid: mine[t] = mine.get(t, 0) + 1
    elif e.get("container_id") == "host" and e.get("comm") in ("true", "cat", "python3", "sh"):
        host[t] = host.get(t, 0) + 1
print("\n=== B9: tracepoint coverage (events attributed to the test container) ===")
fails = 0
for t, trig in [("execve", "/bin/true"), ("openat", "cat"), ("connect", "Python socket connect"),
                ("setuid", "os.setuid(0)"), ("clone", "os.fork()"), ("ptrace", "ctypes ptrace(0,0,0,0)")]:
    n = mine.get(t, 0); ok = n > 0; fails += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {t:8s} {n:6d} events   trigger: {trig}"
          + ("" if ok else f"   (host-attributed events of this type from trigger commands: {host.get(t, 0)})"))
print(f"\n  {6 - fails} of 6 tracepoints PASS")
drops = [l.strip() for l in open(err, errors="replace") if "[DROP]" in l]
print(f"  [DROP] warnings during the test: {len(drops)}")
PY
