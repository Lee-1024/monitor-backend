package main

import (
	"strings"
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

func TestDockerSnapshotRetentionCanBeConfigured(t *testing.T) {
	oldRetention := dockerSnapshotRetentionDays
	t.Cleanup(func() { dockerSnapshotRetentionDays = oldRetention })

	SetDockerSnapshotRetentionDays(14)

	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)

	if got := dockerSnapshotCutoff(now); !got.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", got, want)
	}
}

func TestRetentionConfigDefaultsDockerSnapshotsToThirtyDays(t *testing.T) {
	cfg := RetentionConfig{}

	if got := cfg.EffectiveDockerSnapshotDays(); got != 30 {
		t.Fatalf("EffectiveDockerSnapshotDays() = %d, want 30", got)
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

func TestDockerContainerTotalUsesLatestDistinctIDs(t *testing.T) {
	ids := []dockerLatestContainerID{
		{MaxID: 10},
		{MaxID: 12},
	}

	if got := dockerContainerTotalFromLatestIDs(ids); got != 2 {
		t.Fatalf("dockerContainerTotalFromLatestIDs() = %d, want 2", got)
	}
}

func TestDockerSnapshotCleanupUsesBatches(t *testing.T) {
	if dockerSnapshotCleanupBatchSize <= 0 {
		t.Fatalf("dockerSnapshotCleanupBatchSize = %d, want positive", dockerSnapshotCleanupBatchSize)
	}

	if got := cleanupBatchDeleteSQL("docker_container_snapshots"); got == "" {
		t.Fatal("cleanupBatchDeleteSQL returned empty SQL")
	} else if !strings.Contains(got, "LIMIT ?") {
		t.Fatalf("cleanup SQL = %q, want LIMIT placeholder", got)
	} else if !strings.Contains(got, "docker_container_snapshots") {
		t.Fatalf("cleanup SQL = %q, want docker_container_snapshots table", got)
	}
}
