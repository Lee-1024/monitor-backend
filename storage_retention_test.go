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

func TestProcessSnapshotRetentionCanBeConfigured(t *testing.T) {
	oldRetention := processSnapshotRetentionDays
	t.Cleanup(func() { processSnapshotRetentionDays = oldRetention })

	SetProcessSnapshotRetentionDays(14)

	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	if got := processSnapshotCutoff(now); !got.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", got, want)
	}
}

func TestRetentionConfigDefaultsProcessSnapshotsToThirtyDays(t *testing.T) {
	cfg := RetentionConfig{}

	if got := cfg.EffectiveProcessSnapshotDays(); got != 30 {
		t.Fatalf("EffectiveProcessSnapshotDays() = %d, want 30", got)
	}
}

func TestRetentionConfigKeepsExplicitProcessSnapshotDays(t *testing.T) {
	cfg := RetentionConfig{ProcessSnapshotDays: 14}

	if got := cfg.EffectiveProcessSnapshotDays(); got != 14 {
		t.Fatalf("EffectiveProcessSnapshotDays() = %d, want 14", got)
	}
}
