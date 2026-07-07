package main

import "testing"

func TestHistoryFieldNameForCPUMax(t *testing.T) {
	got := historyFieldName("cpu", "usage_percent", "max")
	if got != "usage_percent_max" {
		t.Fatalf("historyFieldName() = %q, want %q", got, "usage_percent_max")
	}
}

func TestHistoryFieldNameKeepsCPUMeanCompatible(t *testing.T) {
	got := historyFieldName("cpu", "usage_percent", "mean")
	if got != "usage_percent" {
		t.Fatalf("historyFieldName() = %q, want %q", got, "usage_percent")
	}
}

func TestAgentListOrderExprUsesStableDisplayOrder(t *testing.T) {
	expr := agentListOrderExpr()
	want := "CASE WHEN status = 'online' AND last_seen > ? THEN 0 ELSE 1 END ASC, LOWER(COALESCE(NULLIF(hostname, ''), host_id)) ASC, host_id ASC"
	if expr.SQL != want {
		t.Fatalf("agentListOrderExpr SQL = %q, want %q", expr.SQL, want)
	}
	if len(expr.Vars) != 1 {
		t.Fatalf("agentListOrderExpr Vars length = %d, want 1", len(expr.Vars))
	}
}

func TestProcessHistorySelectColumnsOnlyIncludesChartFields(t *testing.T) {
	got := processHistorySelectColumns()
	want := "timestamp, name, pid, cpu_percent, memory_percent, memory_bytes"
	if got != want {
		t.Fatalf("processHistorySelectColumns() = %q, want %q", got, want)
	}
}

func TestBoundedQueryLimitDefaultsAndCaps(t *testing.T) {
	if got := boundedQueryLimit(0); got != defaultHistoryQueryLimit {
		t.Fatalf("boundedQueryLimit(0) = %d, want %d", got, defaultHistoryQueryLimit)
	}
	if got := boundedQueryLimit(-10); got != defaultHistoryQueryLimit {
		t.Fatalf("boundedQueryLimit(-10) = %d, want %d", got, defaultHistoryQueryLimit)
	}
	if got := boundedQueryLimit(42); got != 42 {
		t.Fatalf("boundedQueryLimit(42) = %d, want 42", got)
	}
	if got := boundedQueryLimit(maxHistoryQueryLimit + 1); got != maxHistoryQueryLimit {
		t.Fatalf("boundedQueryLimit(max+1) = %d, want %d", got, maxHistoryQueryLimit)
	}
}

func TestChunkUintIDsSplitsLargeBatches(t *testing.T) {
	chunks := chunkUintIDs([]uint{1, 2, 3, 4, 5}, 2)

	if len(chunks) != 3 {
		t.Fatalf("len(chunks) = %d, want 3", len(chunks))
	}
	if len(chunks[0]) != 2 || len(chunks[1]) != 2 || len(chunks[2]) != 1 {
		t.Fatalf("chunk sizes = %d,%d,%d; want 2,2,1", len(chunks[0]), len(chunks[1]), len(chunks[2]))
	}
}

func TestValidateServiceStatusDeleteIDsRejectsEmpty(t *testing.T) {
	if err := validateServiceStatusDeleteIDs(nil); err == nil {
		t.Fatal("expected empty ids to be rejected")
	}
	if err := validateServiceStatusDeleteIDs([]uint{}); err == nil {
		t.Fatal("expected empty ids to be rejected")
	}
}

func TestValidateServiceStatusDeleteIDsRejectsTooMany(t *testing.T) {
	ids := make([]uint, maxServiceStatusDeleteIDs+1)
	for i := range ids {
		ids[i] = uint(i + 1)
	}

	if err := validateServiceStatusDeleteIDs(ids); err == nil {
		t.Fatal("expected too many ids to be rejected")
	}
}
