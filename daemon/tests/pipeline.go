package main

import "fmt"

// Event represents a single syscall event from the kernel
// This mirrors the struct we will define in kernel/headers.h
type Event struct {
    PID uint32
    Comm string
}

// producer simulates the ring buffer reader goroutine
// In production this will read from the BPF ring buffer
func producer(ch chan<- Event) {
    events:= []Event{
        {PID: 1001, Comm: "nginx"},
        {PID: 1002, Comm: "bash"},
        {PID: 1003, Comm: "curl"},
        {PID: 1004, Comm: "python3"},
        {PID: 1005, Comm: "nc"},
    }
    for _, e := range events {
        ch <- e
    }
    close(ch)
}

// consumer simulates the enricher goroutine
// In production this will map cgroup_id to container_id
func consumer(ch <-chan Event) {
    for e := range ch {
        fmt.Printf("EVENT - PID: %-6d COMM: %s\n", e.PID, e.Comm)
    }
}

func main() {
    // Buffered channel with capacity 10
    // Prevents producer from blocking if consumer is briefly slow
    ch := make(chan Event, 10)

    // Launch producer as a goroutine
    go producer(ch)

    // Consumer runs in main goroutine
    // Blocks until channel is closed by producer
    consumer(ch)

    fmt.Println("Pipeline complete - zero dropped events")
}
