package main

import (
	"testing"
	"time"
)

func TestDockerSnapshotCutoffUsesThirtyDayDefault(t *testing.T) {
	oldRetention := dockerSnapshotRetentionDays
	t.Cleanup(func() { dockerSnapshotRetentionDays = oldRetention })
	dockerSnapshotRetentionDays = 30

	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	if got := dockerSnapshotCutoff(now); !got.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", got, want)
	}
}

func TestDockerSnapshotContainerKey(t *testing.T) {
	snapshot := DockerContainerSnapshot{
		HostID:      "host-1",
		ContainerID: "abcdef1234567890",
		Name:        "api",
	}

	if got := snapshot.ContainerKey(); got != "host-1:abcdef123456" {
		t.Fatalf("ContainerKey() = %q, want %q", got, "host-1:abcdef123456")
	}
}
