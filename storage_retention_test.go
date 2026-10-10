package main

import (
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm/schema"
)

func TestProcessSnapshotCleanupUsesTimestampCutoff(t *testing.T) {
	got := cleanupBatchDeleteSQL("process_snapshots", "timestamp")
	if !strings.Contains(got, "timestamp < ?") {
		t.Fatalf("cleanup SQL = %q, want timestamp cutoff", got)
	}
}

func TestSnapshotTruncateSQLRejectsTablesOutsideSnapshotWhitelist(t *testing.T) {
	if got, err := snapshotTruncateSQL("log_entries"); err == nil {
		t.Fatalf("snapshotTruncateSQL(log_entries) = %q, want error", got)
	}
}

func TestSnapshotTruncateSQLUsesPlainTableTruncate(t *testing.T) {
	for _, table := range []string{"process_snapshots", "docker_container_snapshots"} {
		got, err := snapshotCleanupSQL(table)
		if err != nil {
			t.Fatalf("snapshotTruncateSQL(%s) error = %v", table, err)
		}
		want := "TRUNCATE TABLE " + table
		if got != want {
			t.Fatalf("snapshotTruncateSQL(%s) = %q, want %q", table, got, want)
		}
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

func TestAlertHistoryCorootIndexStatementsUsePartialUniqueIndex(t *testing.T) {
	statements := alertHistoryCorootIndexStatements()
	if len(statements) != 2 {
		t.Fatalf("index statements = %d, want drop and create", len(statements))
	}
	if !strings.Contains(statements[0], "DROP INDEX IF EXISTS idx_alert_histories_coroot_id") {
		t.Fatalf("drop statement = %q", statements[0])
	}
	if !strings.Contains(statements[1], "CREATE UNIQUE INDEX") ||
		!strings.Contains(statements[1], "WHERE coroot_id <> ''") {
		t.Fatalf("create statement = %q, want partial unique index", statements[1])
	}
}

func TestAlertHistoryModelDoesNotAutoMigrateGlobalCorootUniqueIndex(t *testing.T) {
	field, ok := reflect.TypeOf(AlertHistory{}).FieldByName("CorootID")
	if !ok {
		t.Fatal("AlertHistory.CorootID field not found")
	}
	tag := schema.ParseTagSetting(field.Tag.Get("gorm"), ";")
	if _, exists := tag["UNIQUEINDEX"]; exists {
		t.Fatalf("CorootID gorm tag = %q, must not create a global unique index", field.Tag.Get("gorm"))
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
