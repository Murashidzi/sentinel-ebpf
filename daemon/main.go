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

// Syscall type constants — match SYSCALL_* defines in kernel/headers.h
const (
	SyscallExecve  = 1
	SyscallOpenat  = 2
	SyscallConnect = 3
	SyscallSetuid  = 4
	SyscallClone   = 5
	SyscallPtrace  = 6
)

// SentinelEvent mirrors sentinel_event in kernel/headers.h.
// Total size: 344 bytes. Field order and types must match exactly.
//
// Offset map:
//   cgroup_id     uint64   offset 0
//   timestamp_ns  uint64   offset 8
//   clone_flags   uint64   offset 16
//   pid           uint32   offset 24
//   ppid          uint32   offset 28
//   uid           uint32   offset 32
//   new_uid       uint32   offset 36
//   dest_ip       uint32   offset 40
//   syscall_type  uint32   offset 44
//   dest_port     uint16   offset 48
//   pad1          uint16   offset 50
//   pad2          uint32   offset 52
//   comm          [16]byte offset 56
//   parent_comm   [16]byte offset 72
//   filename      [256]byte offset 88
//   total: 344 bytes
type SentinelEvent struct {
	CgroupID    uint64    // __u64 cgroup_id
	TimestampNs uint64    // __u64 timestamp_ns
	CloneFlags  uint64    // __u64 clone_flags
	PID         uint32    // __u32 pid
	PPID        uint32    // __u32 ppid
	UID         uint32    // __u32 uid
	NewUID      uint32    // __u32 new_uid (also ptrace request type)
	DestIP      uint32    // __u32 dest_ip
	SyscallType uint32    // __u32 syscall_type
	DestPort    uint16    // __u16 dest_port
	Pad1        uint16    // __u16 pad1
	Pad2        uint32    // __u32 pad2
	Comm        [16]byte  // char comm[16]
	ParentComm  [16]byte  // char parent_comm[16]
	Filename    [256]byte // char filename[256]
}

// EventJSON is the JSON output format.
type EventJSON struct {
        ContainerID string `json:"container_id"`
	SyscallType string `json:"syscall_type"`
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	UID         uint32 `json:"uid"`
	CgroupID    uint64 `json:"cgroup_id"`
	TimestampNs uint64 `json:"timestamp_ns"`
	Comm        string `json:"comm"`
	ParentComm  string `json:"parent_comm"`
	Filename    string `json:"filename,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestPort    uint16 `json:"dest_port,omitempty"`
	NewUID      uint32 `json:"new_uid,omitempty"`
	CloneFlags  uint64 `json:"clone_flags,omitempty"`
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

// syscallName converts a syscall type constant to a human-readable string.
func syscallName(t uint32) string {
	switch t {
	case SyscallExecve:
		return "execve"
	case SyscallOpenat:
		return "openat"
	case SyscallConnect:
		return "connect"
	case SyscallSetuid:
		return "setuid"
	case SyscallClone:
		return "clone"
	case SyscallPtrace:
		return "ptrace"
	default:
		return "unknown"
	}
}

// formatIP converts a uint32 IPv4 address (network byte order) to dotted decimal.
func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load compiled eBPF object into the kernel.
	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach all six tracepoints.
	// Each attachment activates one syscall hook in the kernel.
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach execve tracepoint: %v", err)
	}
	defer tpExecve.Close()

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("Failed to attach openat tracepoint: %v", err)
	}
	defer tpOpenat.Close()

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		log.Fatalf("Failed to attach connect tracepoint: %v", err)
	}
	defer tpConnect.Close()

	tpSetuid, err := link.Tracepoint("syscalls", "sys_enter_setuid", objs.TraceSetuid, nil)
	if err != nil {
		log.Fatalf("Failed to attach setuid tracepoint: %v", err)
	}
	defer tpSetuid.Close()

	tpClone, err := link.Tracepoint("syscalls", "sys_enter_clone", objs.TraceClone, nil)
	if err != nil {
		log.Fatalf("Failed to attach clone tracepoint: %v", err)
	}
	defer tpClone.Close()

	tpPtrace, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.TracePtrace, nil)
	if err != nil {
		log.Fatalf("Failed to attach ptrace tracepoint: %v", err)
	}
	defer tpPtrace.Close()

	// Open ring buffer reader.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}

	// Graceful shutdown on Ctrl+C or SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

        // done channel signals backhround goroutines to exit.
        done := make(chan struct{})

	go func() {
		<-ctx.Done()
		fmt.Fprintf(os.Stderr, "\nsentinel-ebpf: shutting down.\n")
		rd.Close()
                close(done)
	}()

        // Channels connecting the pipeline stages.
        // Buffer sizes prevent fast producers from blocking slow consumers
        // under brief load spikes without dropping events.
        rawCh := make(chan SentinelEvent, 4096)
        enrichedCh := make(chan EnrichedEvent, 4096)

        // Start the Enricher.
        // refresh() is called once at creation to build the initial map,
        // then runRefreshLoop keeps it current every 5 seconds.
        enricher := newCgroupEnricher()
        go enricher.runRefreshLoop(done)
        go enricher.enrichEvents(rawCh, enrichedCh)

        // Ring buffer reader goroutine.
        // Reads raw bytes from kernel, deserialises into SentinelEvent,
        // forwards to rawCh for enrichment.
        go func() {
            defer close(rawCh)
            for {
                record, err := rd.Read()
                if err != nil {
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
                rawCh <- event
                }
            }()

	fmt.Fprintf(os.Stderr,
		"sentinel-ebpf: tracing 6 syscalls. Press Ctrl+C to stop.\n\n")

        // Event loop: reads enriched events and prints JSON.
        // container_id is now populated for every event.
	for enriched := range enrichedCh {
		out := EventJSON{
                        ContainerID: enriched.ContainerID,
			SyscallType: syscallName(enriched.SyscallType),
			PID:         enriched.PID,
			PPID:        enriched.PPID,
			UID:         enriched.UID,
			CgroupID:    enriched.CgroupID,
			TimestampNs: enriched.TimestampNs,
			Comm:        nullTerminated(enriched.Comm[:]),
			ParentComm:  nullTerminated(enriched.ParentComm[:]),
		}

		// Populate syscall-specific fields.
		switch enriched.SyscallType {
		case SyscallExecve, SyscallOpenat:
			out.Filename = nullTerminated(enriched.Filename[:])
		case SyscallConnect:
			if enriched.DestIP != 0 {
				out.DestIP = formatIP(enriched.DestIP)
				out.DestPort = enriched.DestPort
			}
		case SyscallSetuid:
			out.NewUID = enriched.NewUID
		case SyscallClone:
			out.CloneFlags = enriched.CloneFlags
		case SyscallPtrace:
			out.NewUID = enriched.NewUID // ptrace request type
		}

		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("JSON error: %v", err)
			continue
		}
		fmt.Println(string(data))
	}
}
