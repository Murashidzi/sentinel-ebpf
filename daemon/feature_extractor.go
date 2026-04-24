package main

import (
	"math"
	"strings"
	"sync"
	"time"
)

// FeatureVector is the nine-feature representation of container behaviour
// for one sliding window. Fed to the rule engine and ML inference server.
type FeatureVector struct {
	ContainerID       string
	WindowStart       time.Time
	BaselineStabilised bool

	// Rate-based features (events per second)
	ExecveRate           float64 // execve events / window duration
	NetworkConnectRate   float64 // connect events / window duration
	FileOpenRate         float64 // openat events / window duration
	ProcessSpawnRate     float64 // clone events / window duration
	PrivilegedSyscallCount float64 // setuid(0) events — raw count
	PtraceCount          float64 // ptrace events — raw count

	// Context-aware features — security domain knowledge
	UnusualParentSpawn    float64 // web server spawning shell binary
	ShellSpawnAfterConnect float64 // connect() then execve(shell) within 2s
	ProcessDepthAnomaly   float64 // process chain depth vs baseline (z-score)
}

// WindowEvent is a single event stored in the sliding window log.
// Only fields needed for feature computation are kept.
type WindowEvent struct {
	Timestamp   time.Time
	SyscallType uint32
	Comm        string
	ParentComm  string
	Filename    string
	DestIP      uint32
	NewUID      uint32
	CloneFlags  uint64
	PID         uint32
	Depth       int // process chain depth at time of event
}

// welfardState tracks running mean and variance using Welford's algorithm.
// Memory: O(1) regardless of how many windows have been processed.
// Numerical stability: works with deviations from running mean,
// avoiding catastrophic cancellation in naive variance computation.
type welfordState struct {
	n    float64 // count of observations
	mean float64 // running mean
	m2   float64 // sum of squared deviations from mean (for variance)
}

// update incorporates a new observation into the running statistics.
// O(1) time and space.
func (w *welfordState) update(x float64) {
	w.n++
	delta := x - w.mean
	w.mean += delta / w.n
	delta2 := x - w.mean
	w.m2 += delta * delta2
}

// stddev returns the sample standard deviation.
// Returns 1.0 if fewer than 2 observations to avoid division by zero.
func (w *welfordState) stddev() float64 {
	if w.n < 2 {
		return 1.0
	}
	return math.Sqrt(w.m2 / (w.n - 1))
}

// ContainerBaseline tracks per-container rolling statistics for each feature.
// Each container has its own baseline — not global — because containers
// have fundamentally different normal behaviour profiles.
type ContainerBaseline struct {
	features    [9]welfordState
	windowCount int
	stabilised  bool // true after stabilisationWindows complete windows
}

const stabilisationWindows = 12 // 12 x 5s = 60 seconds of history

func (b *ContainerBaseline) update(fv [9]float64) {
	for i, v := range fv {
		b.features[i].update(v)
	}
	b.windowCount++
	if b.windowCount >= stabilisationWindows {
		b.stabilised = true
	}
}

// zScore returns how many standard deviations the value is from the mean.
// Used for process_depth_anomaly. Returns 0 if baseline not stabilised.
func (b *ContainerBaseline) zScore(featureIdx int, value float64) float64 {
	if !b.stabilised {
		return 0
	}
	std := b.features[featureIdx].stddev()
	if std == 0 {
		return 0
	}
	return (value - b.features[featureIdx].mean) / std
}

// containerWindow maintains the sliding event log and baseline for one container.
type containerWindow struct {
	containerID    string
	events         []WindowEvent
	baseline       ContainerBaseline
	windowDuration time.Duration
	lastDepthMean  float64 // cached for process depth computation
}

func newContainerWindow(containerID string) *containerWindow {
	return &containerWindow{
		containerID:    containerID,
		events:         make([]WindowEvent, 0, 256),
		windowDuration: 5 * time.Second,
	}
}

// addEvent appends a new event and evicts events outside the window.
func (cw *containerWindow) addEvent(e WindowEvent) {
	cw.events = append(cw.events, e)
	cw.evict()
}

// evict removes events older than windowDuration from the front of the log.
// The log is time-ordered so we scan from the front until we find a
// recent enough event, then slice off the stale prefix.
func (cw *containerWindow) evict() {
	cutoff := time.Now().Add(-cw.windowDuration)
	i := 0
	for i < len(cw.events) && cw.events[i].Timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		cw.events = cw.events[i:]
	}
}

// compute calculates the nine-feature vector from the current window state.
func (cw *containerWindow) compute() [9]float64 {
	var fv [9]float64
	duration := cw.windowDuration.Seconds()

	var execveCount, connectCount, openatCount, cloneCount float64
	var privilegedCount, ptraceCount float64
	var unusualParentSpawn, shellAfterConnect float64
	var totalDepth float64
	var depthCount float64

	// Web server process names that should not spawn shells.
	webServers := map[string]bool{
		"nginx": true, "node": true, "python": true, "python3": true,
		"java": true, "php": true, "ruby": true, "gunicorn": true,
	}

	// Shell binary paths that indicate a shell was spawned.
	shellBinaries := map[string]bool{
		"/bin/bash": true, "/bin/sh": true,
		"/usr/bin/bash": true, "/usr/bin/sh": true,
		"/bin/dash": true,
	}

	// Recent connect events indexed by container for shell_spawn_after_connect.
	// Key: container ID, Value: most recent connect timestamp.
	lastConnect := time.Time{}

	for _, ev := range cw.events {
		switch ev.SyscallType {
		case SyscallExecve:
			execveCount++

			// unusual_parent_spawn: web server spawning a shell.
			if webServers[ev.ParentComm] && shellBinaries[ev.Filename] {
				unusualParentSpawn++
			}

			// shell_spawn_after_connect: shell spawned within 2s of connect.
			if shellBinaries[ev.Filename] && !lastConnect.IsZero() {
				if ev.Timestamp.Sub(lastConnect) <= 2*time.Second {
					shellAfterConnect++
				}
			}

			// process depth tracking for process_depth_anomaly.
			if ev.Depth > 0 {
				totalDepth += float64(ev.Depth)
				depthCount++
			}

		case SyscallOpenat:
			openatCount++

		case SyscallConnect:
			connectCount++
			// Record timestamp for shell_spawn_after_connect correlation.
			if ev.Timestamp.After(lastConnect) {
				lastConnect = ev.Timestamp
			}

		case SyscallSetuid:
			// privileged_syscall_count: only setuid(0) counts.
			if ev.NewUID == 0 {
				privilegedCount++
			}

		case SyscallClone:
			cloneCount++

		case SyscallPtrace:
			ptraceCount++
		}
	}

	fv[0] = execveCount / duration
	fv[1] = connectCount / duration
	fv[2] = openatCount / duration
	fv[3] = cloneCount / duration
	fv[4] = privilegedCount
	fv[5] = ptraceCount
	fv[6] = unusualParentSpawn
	fv[7] = shellAfterConnect

	// process_depth_anomaly: z-score of mean depth vs baseline.
	// Feature index 8 in baseline corresponds to mean process depth.
	if depthCount > 0 {
		meanDepth := totalDepth / depthCount
		fv[8] = cw.baseline.zScore(8, meanDepth)
	}

	return fv
}

// featureExtractor manages per-container windows and emits feature vectors.
type featureExtractor struct {
	mu       sync.Mutex
	windows  map[string]*containerWindow
	ticker   *time.Ticker
	interval time.Duration
}

func newFeatureExtractor() *featureExtractor {
	return &featureExtractor{
		windows:  make(map[string]*containerWindow),
		interval: 5 * time.Second,
	}
}

// processEvent routes an enriched event to the correct container window.
func (fe *featureExtractor) processEvent(ev EnrichedEvent) {
	fe.mu.Lock()
	cw, ok := fe.windows[ev.ContainerID]
	if !ok {
		cw = newContainerWindow(ev.ContainerID)
		fe.windows[ev.ContainerID] = cw
	}
	fe.mu.Unlock()

	we := WindowEvent{
		Timestamp:   time.Unix(0, int64(ev.TimestampNs)),
		SyscallType: ev.SyscallType,
		Comm:        nullTerminated(ev.Comm[:]),
		ParentComm:  nullTerminated(ev.ParentComm[:]),
		Filename:    strings.TrimRight(nullTerminated(ev.Filename[:]), "\x00"),
		DestIP:      ev.DestIP,
		NewUID:      ev.NewUID,
		CloneFlags:  ev.CloneFlags,
		PID:         ev.PID,
	}

	fe.mu.Lock()
	cw.addEvent(we)
	fe.mu.Unlock()
}

// runComputeLoop fires every interval, computes feature vectors for all
// active containers, updates their baselines, and sends vectors to outCh.
func (fe *featureExtractor) runComputeLoop(
	outCh chan<- FeatureVector,
	done <-chan struct{},
) {
	fe.ticker = time.NewTicker(fe.interval)
	defer fe.ticker.Stop()

	for {
		select {
		case <-fe.ticker.C:
			// Snapshot container IDs under lock before iterating.
			// This prevents a data race where processEvent adds a new
			// container to fe.windows while we are ranging over it.
			fe.mu.Lock()
			ids := make([]string, 0, len(fe.windows))
			for id := range fe.windows {
				ids = append(ids, id)
			}
			fe.mu.Unlock()

			for _, id := range ids {
				fe.mu.Lock()
				cw, ok := fe.windows[id]
				if !ok {
					fe.mu.Unlock()
					continue
				}
				fv := cw.compute()
				cw.baseline.update(fv)
				stabilised := cw.baseline.stabilised
				containerID := cw.containerID
				fe.mu.Unlock()

				outCh <- FeatureVector{
					ContainerID:            containerID,
					WindowStart:            time.Now(),
					BaselineStabilised:     stabilised,
					ExecveRate:             fv[0],
					NetworkConnectRate:     fv[1],
					FileOpenRate:           fv[2],
					ProcessSpawnRate:       fv[3],
					PrivilegedSyscallCount: fv[4],
					PtraceCount:            fv[5],
					UnusualParentSpawn:     fv[6],
					ShellSpawnAfterConnect: fv[7],
					ProcessDepthAnomaly:    fv[8],
				}
			}

		case <-done:
			return
		}
	}
}
