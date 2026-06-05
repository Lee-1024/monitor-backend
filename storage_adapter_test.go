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
