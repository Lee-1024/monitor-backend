package notifier

import (
	"testing"
	"time"
)

func TestMetricTypeDisplayNameUsesChinese(t *testing.T) {
	cases := map[string]string{
		"cpu":             "CPU使用率",
		"memory":          "内存使用率",
		"disk":            "磁盘使用率",
		"network":         "网络",
		"host_down":       "主机宕机",
		"backend_health":  "后台服务健康",
		"service_port":    "服务端口",
		"server_probe":    "服务端探测",
		"gpu_unavailable": "GPU不可用",
		"custom_metric":   "custom_metric",
	}

	for metricType, expected := range cases {
		if got := metricTypeDisplayName(metricType); got != expected {
			t.Fatalf("metricTypeDisplayName(%q) = %q, expected %q", metricType, got, expected)
		}
	}
}

func TestNotificationTimeUsesStandardFormat(t *testing.T) {
	now := time.Date(2026, 5, 28, 15, 4, 5, 0, time.Local)

	if got := formatNotificationTime(now); got != "2026-05-28 15:04:05" {
		t.Fatalf("expected formatted notification time, got %q", got)
	}
}

func TestRuleDescriptionNotificationLine(t *testing.T) {
	if got := ruleDescriptionMarkdownLine("定位到服务端探测目标，确认业务入口是否可访问", ""); got != "**规则描述:** 定位到服务端探测目标，确认业务入口是否可访问  \n" {
		t.Fatalf("expected markdown description line, got %q", got)
	}

	if got := ruleDescriptionMarkdownLine("", ""); got != "" {
		t.Fatalf("expected empty markdown description line, got %q", got)
	}
}
