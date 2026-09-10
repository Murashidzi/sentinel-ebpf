# Evaluation datasets

Datasets are generated, not stored. Raw syscall captures (*.jsonl) are
gitignored; regenerate them with the capture scripts in ../scripts/.

- scripts/capture_normal.sh [seconds]  -> evaluation/datasets/normal/
  Legitimate multi-process microservice workload: a worker container
  spawning subprocesses, reading/writing files, and making outbound
  connections to an internal backend. Captures execve, openat, connect,
  clone, setuid activity representative of normal container behaviour.

Three behavioural classes: normal, suspicious, advanced (see Chapter 3.5).
Sentinel's own events are filtered at capture time; only events tagged
with the target container ID are retained during feature extraction.
