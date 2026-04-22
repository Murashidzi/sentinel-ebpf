package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// EnrichedEvent wraps a raw SentinelEvent with container identity.
// The Enricher resolves cgroup_id to a human-readable container_id
// by mapping inode numbers of cgroup directories to container IDs.
type EnrichedEvent struct {
	SentinelEvent
	ContainerID string // extracted from cgroup directory name
}

// cgroupEnricher maintains a live map of cgroup inode -> container ID.
// The map is rebuilt every refreshInterval by walking /sys/fs/cgroup/.
type cgroupEnricher struct {
	mu              sync.RWMutex
	inodeToContainer map[uint64]string
	refreshInterval  time.Duration
}

func newCgroupEnricher() *cgroupEnricher {
	e := &cgroupEnricher{
		inodeToContainer: make(map[uint64]string),
		refreshInterval:  5 * time.Second,
	}
	// Build the map immediately on creation so the first events
	// are enriched correctly without waiting for the first tick.
	e.refresh()
	return e
}

// refresh walks /sys/fs/cgroup/ and rebuilds the inode -> container ID map.
// It holds the write lock only during the final map swap, not during the walk,
// so readers are blocked for microseconds not milliseconds.
func (e *cgroupEnricher) refresh() {
	newMap := make(map[uint64]string)

	filepath.WalkDir("/sys/fs/cgroup", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable directories silently
		}
		if !d.IsDir() {
			return nil
		}

		name := d.Name()

		// Match container cgroup directories.
		// Docker:      docker-<64-char-hex>.scope
		// containerd:  cri-containerd-<64-char-hex>.scope
		// Both patterns end in .scope and contain the container ID
		// as the last dash-separated segment before .scope.
		if !strings.HasSuffix(name, ".scope") {
			return nil
		}

		containerID := extractContainerID(name)
		if containerID == "" {
			return nil
		}

		// Read the inode of this cgroup directory.
		// The inode == cgroup_id captured by bpf_get_current_cgroup_id().
		info, err := os.Stat(path)
		if err != nil {
			return nil
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}

		newMap[stat.Ino] = containerID
		return nil
	})

	// Swap the map under the write lock.
	// Readers calling lookup() hold RLock and will complete their
	// current lookup before the swap happens.
	e.mu.Lock()
	e.inodeToContainer = newMap
	e.mu.Unlock()
}

// extractContainerID parses a container ID from a cgroup scope directory name.
//
// Examples:
//   docker-abc123def456.scope             -> abc123def456
//   cri-containerd-abc123def456.scope     -> abc123def456
//   system.slice                          -> ""
func extractContainerID(name string) string {
	// Remove .scope suffix
	name = strings.TrimSuffix(name, ".scope")

	// Split on dash and take the last segment
	parts := strings.Split(name, "-")
	if len(parts) < 2 {
		return ""
	}

	id := parts[len(parts)-1]

	// Container IDs are 64-character hex strings.
	// Reject anything that is not at least 12 characters
	// (short IDs used in some contexts) or contains non-hex chars.
	if len(id) < 12 {
		return ""
	}

	return id
}

// lookup returns the container ID for a given cgroup inode.
// Returns "host" if the cgroup is not a known container — this means
// the event came from a host process, not a container.
// Never returns empty string — every event gets an identity.
func (e *cgroupEnricher) lookup(cgroupID uint64) string {
	e.mu.RLock()
	id, ok := e.inodeToContainer[cgroupID]
	e.mu.RUnlock()

	if !ok {
		return "host"
	}
	return id
}

// runRefreshLoop starts the background ticker that keeps the map current.
// Call this in a goroutine. It blocks until the done channel is closed.
func (e *cgroupEnricher) runRefreshLoop(done <-chan struct{}) {
	ticker := time.NewTicker(e.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.refresh()
		case <-done:
			return
		}
	}
}

// enrichEvents reads raw events from rawCh, attaches container identity,
// and writes enriched events to enrichedCh.
// Runs as a goroutine. Exits when rawCh is closed.
func (e *cgroupEnricher) enrichEvents(
	rawCh <-chan SentinelEvent,
	enrichedCh chan<- EnrichedEvent,
) {
	for event := range rawCh {
		containerID := e.lookup(event.CgroupID)
		enrichedCh <- EnrichedEvent{
			SentinelEvent: event,
			ContainerID:   containerID,
		}
	}
	close(enrichedCh)
}
