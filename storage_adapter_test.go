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
