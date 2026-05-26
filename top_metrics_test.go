package main

import (
	"testing"

	"monitor-backend/api"
)

func TestLimitTopMetricsDeduplicatesAndLimits(t *testing.T) {
	metrics := []api.TopMetric{
		{HostID: "host-1", Value: 80},
		{HostID: "host-1", Value: 75},
		{HostID: "host-2", Value: 70},
		{HostID: "host-3", Value: 60},
	}

	got := limitTopMetrics(metrics, 2)

	if len(got) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(got))
	}
	if got[0].HostID != "host-1" || got[1].HostID != "host-2" {
		t.Fatalf("unexpected metrics: %#v", got)
	}
}
