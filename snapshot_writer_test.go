package main

import (
	"testing"
	"time"
)

func TestSnapshotQueuesRejectWhenFullWithoutBlocking(t *testing.T) {
	storage := &Storage{
		processQueue: make(chan []ProcessSnapshot, 1),
		dockerQueue:  make(chan []DockerContainerSnapshot, 1),
		processLast:  make(map[string]time.Time),
		dockerLast:   make(map[string]time.Time),
	}
	now := time.Now()

	if !storage.EnqueueProcessSnapshots([]ProcessSnapshot{{HostID: "host-1", Timestamp: now}}) {
		t.Fatal("first process batch should be queued")
	}
	if storage.EnqueueProcessSnapshots([]ProcessSnapshot{{HostID: "host-2", Timestamp: now}}) {
		t.Fatal("process batch should be rejected when queue is full")
	}
	if !storage.EnqueueDockerSnapshots([]DockerContainerSnapshot{{HostID: "host-1", Timestamp: now}}) {
		t.Fatal("first docker batch should be queued")
	}
	if storage.EnqueueDockerSnapshots([]DockerContainerSnapshot{{HostID: "host-2", Timestamp: now}}) {
		t.Fatal("docker batch should be rejected when queue is full")
	}
}

func TestSnapshotHistorySamplingLimitsWritesPerHost(t *testing.T) {
	storage := &Storage{
		processQueue: make(chan []ProcessSnapshot, 2),
		dockerQueue:  make(chan []DockerContainerSnapshot, 2),
		processLast:  make(map[string]time.Time),
		dockerLast:   make(map[string]time.Time),
	}
	now := time.Now()
	storage.EnqueueProcessSnapshots([]ProcessSnapshot{{HostID: "host-1", Timestamp: now}})
	storage.EnqueueProcessSnapshots([]ProcessSnapshot{{HostID: "host-1", Timestamp: now.Add(10 * time.Second)}})
	if got := len(storage.processQueue); got != 1 {
		t.Fatalf("process queue length = %d, want 1 sampled batch", got)
	}
	storage.EnqueueProcessSnapshots([]ProcessSnapshot{{HostID: "host-1", Timestamp: now.Add(processHistoryInterval)}})
	if got := len(storage.processQueue); got != 2 {
		t.Fatalf("process queue length = %d, want 2 sampled batches", got)
	}
}
