package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
        "fmt"
)

// EnrichedEvent wraps a raw SentinelEvent with container identity.
type EnrichedEvent struct {
	SentinelEvent
	ContainerID string
}

// cgroupEnricher maintains a live map of cgroup inode -> container ID.
type cgroupEnricher struct {
	mu               sync.RWMutex
	inodeToContainer map[uint64]string
	refreshInterval  time.Duration
}

func newCgroupEnricher() *cgroupEnricher {
	e := &cgroupEnricher{
		inodeToContainer: make(map[uint64]string),
		refreshInterval:  5 * time.Second,
	}
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
			return nil
		}
		if !d.IsDir() {
			return nil
		}

		name := d.Name()

		if !strings.HasSuffix(name, ".scope") {
			return nil
		}

		containerID := extractContainerID(name)
		if containerID == "" {
			return nil
		}

		// Map the scope directory inode itself.
		info, err := os.Stat(path)
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		newMap[stat.Ino] = containerID

		// Recursively map all descendant cgroup directories.
		// On nested container setups (Kubernetes-in-Docker), processes
		// run in cgroups several levels deep under the scope root.
		// Without recursive mapping, container process events appear as "host".
		filepath.WalkDir(path, func(childPath string, cd os.DirEntry, cerr error) error {
			if cerr != nil || childPath == path {
				return nil
			}
			if !cd.IsDir() {
				return nil
			}
			childInfo, err := os.Stat(childPath)
			if err != nil {
				return nil
			}
			childStat, ok := childInfo.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			newMap[childStat.Ino] = containerID
			return nil
		})

		return nil
	})

	e.mu.Lock()
	e.inodeToContainer = newMap
	e.mu.Unlock()
}

// extractContainerID parses a container ID from a cgroup scope directory name.
func extractContainerID(name string) string {
	name = strings.TrimSuffix(name, ".scope")
	parts := strings.Split(name, "-")
	if len(parts) < 2 {
		return ""
	}
	id := parts[len(parts)-1]
	if len(id) < 12 {
		return ""
	}
	return id
}


// lookupByPID reads the container ID directly from /proc/<pid>/cgroup.
// This is more reliable than inode mapping for short-lived containers
// because the cgroup path is available immediately when the process exists.
func lookupByPID(pid uint32) string {
        data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	for _, part := range strings.Split(line, "\n") {
		if !strings.HasPrefix(part, "0::") {
			continue
		}
		path := strings.TrimPrefix(part, "0::")
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if strings.HasSuffix(seg, ".scope") {
				id := extractContainerID(seg)
				if id != "" {
					return id
				}
			}
		}
	}
	return ""
}



// lookup returns the container ID for a given cgroup inode.
// Used as fallback when PID-based lookup fails (process already exited).
func (e *cgroupEnricher) lookup(cgroupID uint64) string {
	e.mu.RLock()
	id, ok := e.inodeToContainer[cgroupID]
	e.mu.RUnlock()


	if ok {
		return id
	}


	for i := 0; i < 5; i++ {
		time.Sleep(20 * time.Millisecond)
		e.refresh()
		e.mu.RLock()
		id, ok = e.inodeToContainer[cgroupID]
		e.mu.RUnlock()
		if ok {
			return id
		}
	}


	return "host"
}

// runRefreshLoop starts the background ticker that keeps the map current.
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

// enrichEvents reads raw events, attaches container identity, writes enriched events.
func (e *cgroupEnricher) enrichEvents(
	rawCh <-chan SentinelEvent,
	enrichedCh chan<- EnrichedEvent,
) {
	for event := range rawCh {
		containerID := lookupByPID(event.PID)
		if containerID == "" {
			containerID = e.lookup(event.CgroupID)
		}
		enrichedCh <- EnrichedEvent{
			SentinelEvent: event,
			ContainerID:   containerID,
		}
	}
	close(enrichedCh)
}
