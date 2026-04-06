package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// SentinelEvent mirrors sentinel_event in kernel/headers.h.
// Field order and sizes must match exactly — binary.Read
// interprets raw ring buffer bytes using this layout.
// Total size: 320 bytes
type SentinelEvent struct {
	CgroupID    uint64    // __u64 cgroup_id      offset 0
	TimestampNs uint64    // __u64 timestamp_ns   offset 8
	PID         uint32    // __u32 pid            offset 16
	PPID        uint32    // __u32 ppid           offset 20
	UID         uint32    // __u32 uid            offset 24
	Pad         uint32    // __u32 pad            offset 28
	Comm        [16]byte  // char  comm[16]       offset 32
	ParentComm  [16]byte  // char  parent_comm[16] offset 48
	Filename    [256]byte // char  filename[256]  offset 64
}

// EventJSON is the JSON output format.
type EventJSON struct {
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	UID         uint32 `json:"uid"`
	CgroupID    uint64 `json:"cgroup_id"`
	TimestampNs uint64 `json:"timestamp_ns"`
	Comm        string `json:"comm"`
	ParentComm  string `json:"parent_comm"`
	Filename    string `json:"filename"`
}

// nullTerminated extracts a Go string from a null-terminated C byte array.
func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve",
		objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}

	// Handle shutdown via context — do NOT defer rd.Close() here.
	// We close rd exactly once in the signal handler below.
	// Deferring a second close causes "file already closed" error loops.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		fmt.Fprintf(os.Stderr, "\nsentinel-ebpf: shutting down.\n")
		rd.Close()
	}()

	fmt.Fprintf(os.Stderr,
		"sentinel-ebpf: tracing sys_enter_execve. Press Ctrl+C to stop.\n\n")

	for {
		record, err := rd.Read()
		if err != nil {
			// ringbuf.ErrClosed is the expected shutdown signal.
			// errors.Is handles both direct and wrapped versions.
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Read error: %v", err)
			continue
		}

		var event SentinelEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.NativeEndian,
			&event,
		); err != nil {
			log.Printf("Deserialise error: %v", err)
			continue
		}

		out := EventJSON{
			PID:         event.PID,
			PPID:        event.PPID,
			UID:         event.UID,
			CgroupID:    event.CgroupID,
			TimestampNs: event.TimestampNs,
			Comm:        nullTerminated(event.Comm[:]),
			ParentComm:  nullTerminated(event.ParentComm[:]),
			Filename:    nullTerminated(event.Filename[:]),
		}

		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("JSON error: %v", err)
			continue
		}
		fmt.Println(string(data))
	}
}
