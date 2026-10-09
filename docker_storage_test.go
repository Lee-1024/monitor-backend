package main

import (
	"strings"
	"testing"
)

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

func TestDockerContainerTotalUsesLatestDistinctIDs(t *testing.T) {
	ids := []dockerLatestContainerID{
		{MaxID: 10},
		{MaxID: 12},
	}

	if got := dockerContainerTotalFromLatestIDs(ids); got != 2 {
		t.Fatalf("dockerContainerTotalFromLatestIDs() = %d, want 2", got)
	}
}

func TestDockerSnapshotCleanupUsesTimestampCutoff(t *testing.T) {
	got := cleanupBatchDeleteSQL("docker_container_snapshots", "timestamp")
	if !strings.Contains(got, "timestamp < ?") {
		t.Fatalf("cleanup SQL = %q, want timestamp cutoff", got)
	}
}
