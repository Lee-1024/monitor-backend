package main

import (
	"testing"
	"time"
)

func TestProcessSnapshotCutoffUsesThirtyDayDefault(t *testing.T) {
	oldRetention := processSnapshotRetentionDays
	t.Cleanup(func() { processSnapshotRetentionDays = oldRetention })
	processSnapshotRetentionDays = 30

	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	if got := processSnapshotCutoff(now); !got.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", got, want)
	}
}
