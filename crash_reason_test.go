package main

import (
	"strings"
	"testing"
)

func TestAnalyzeCrashReasonUsesAlertRuleThresholds(t *testing.T) {
	metrics := &LastMetrics{CPU: 20, Memory: 94, Disk: 40}
	rules := []AlertRule{
		{
			Name:       "内存使用率过高",
			Enabled:    true,
			MetricType: "memory",
			Condition:  "gte",
			Threshold:  90,
		},
	}

	reason := AnalyzeCrashReasonWithRules(metrics, rules)

	if !strings.Contains(reason, "内存使用率过高") {
		t.Fatalf("expected reason to mention matched alert rule, got %q", reason)
	}
	if !strings.Contains(reason, "94.0%") {
		t.Fatalf("expected reason to include current metric value, got %q", reason)
	}
	if strings.Contains(reason, "未知原因") {
		t.Fatalf("expected rule match to avoid unknown reason, got %q", reason)
	}
}

func TestAnalyzeCrashReasonFallsBackToDefaultThresholdsWithoutRules(t *testing.T) {
	metrics := &LastMetrics{CPU: 20, Memory: 94, Disk: 40}

	reason := AnalyzeCrashReasonWithRules(metrics, nil)

	if reason != "未知原因，可能是网络中断或主机关机" {
		t.Fatalf("expected default fallback reason, got %q", reason)
	}
}
