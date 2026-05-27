package main

import (
	"testing"
	"time"
)

func TestServiceStatusCutoffUsesThirtyDayDefault(t *testing.T) {
	oldRetention := serviceStatusRetentionDays
	t.Cleanup(func() { serviceStatusRetentionDays = oldRetention })
	serviceStatusRetentionDays = 30

	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	if got := serviceStatusCutoff(now); !got.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", got, want)
	}
}
