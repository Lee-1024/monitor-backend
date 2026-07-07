package main

import (
	"strings"
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

func TestProcessSnapshotCleanupUsesBatches(t *testing.T) {
	if processSnapshotCleanupBatchSize <= 0 {
		t.Fatalf("processSnapshotCleanupBatchSize = %d, want positive", processSnapshotCleanupBatchSize)
	}

	if got := cleanupBatchDeleteSQL("process_snapshots", "timestamp"); got == "" {
		t.Fatal("cleanupBatchDeleteSQL returned empty SQL")
	} else if !strings.Contains(got, "LIMIT ?") {
		t.Fatalf("cleanup SQL = %q, want LIMIT placeholder", got)
	} else if !strings.Contains(got, "process_snapshots") {
		t.Fatalf("cleanup SQL = %q, want process_snapshots table", got)
	} else if !strings.Contains(got, "timestamp < ?") {
		t.Fatalf("cleanup SQL = %q, want timestamp cutoff", got)
	}
}

func TestCleanupBatchDeleteSQLSupportsCustomCutoffColumn(t *testing.T) {
	got := cleanupBatchDeleteSQL("server_probe_results", "checked_at")

	if !strings.Contains(got, "server_probe_results") {
		t.Fatalf("cleanup SQL = %q, want server_probe_results table", got)
	}
	if !strings.Contains(got, "checked_at < ?") {
		t.Fatalf("cleanup SQL = %q, want checked_at cutoff", got)
	}
	if !strings.Contains(got, "LIMIT ?") {
		t.Fatalf("cleanup SQL = %q, want LIMIT placeholder", got)
	}
}

func TestCleanupAllBatchDeleteSQLUsesLimit(t *testing.T) {
	got := cleanupAllBatchDeleteSQL("service_statuses")

	if !strings.Contains(got, "service_statuses") {
		t.Fatalf("cleanup SQL = %q, want service_statuses table", got)
	}
	if !strings.Contains(got, "ORDER BY id") {
		t.Fatalf("cleanup SQL = %q, want stable id order", got)
	}
	if !strings.Contains(got, "LIMIT ?") {
		t.Fatalf("cleanup SQL = %q, want LIMIT placeholder", got)
	}
}

func TestStorageIndexStatementsCoverHighVolumeQueries(t *testing.T) {
	statements := storageIndexStatements()
	want := []string{
		"idx_logs_host_time_level",
		"idx_logs_time_level",
		"idx_service_status_host_name_id",
		"idx_service_status_host_time",
		"idx_script_executions_host_time",
		"idx_anomaly_events_host_time",
		"idx_inspection_records_report_id",
		"idx_inspection_reports_date_created",
	}

	for _, indexName := range want {
		found := false
		for _, statement := range statements {
			if strings.Contains(statement, indexName) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("storageIndexStatements() missing %s", indexName)
		}
	}
}

func TestCleanupThrottleDefaultsAreConservative(t *testing.T) {
	cfg := RetentionConfig{}

	if got := cfg.EffectiveCleanupBatchSize(); got > 1000 {
		t.Fatalf("EffectiveCleanupBatchSize() = %d, want <= 1000", got)
	}
	if got := cfg.EffectiveCleanupMaxBatchesPerRun(); got != 1 {
		t.Fatalf("EffectiveCleanupMaxBatchesPerRun() = %d, want 1", got)
	}
	if got := cfg.EffectiveCleanupIntervalSeconds(); got < 30 {
		t.Fatalf("EffectiveCleanupIntervalSeconds() = %d, want >= 30", got)
	}
}

func TestCleanupLimitStopsAfterConfiguredBatches(t *testing.T) {
	limit := newCleanupRunLimit(2)

	if !limit.allowNextBatch() {
		t.Fatal("first batch should be allowed")
	}
	if !limit.allowNextBatch() {
		t.Fatal("second batch should be allowed")
	}
	if limit.allowNextBatch() {
		t.Fatal("third batch should be blocked")
	}
}
