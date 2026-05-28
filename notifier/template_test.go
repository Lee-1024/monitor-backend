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
		"service_port":    "服务端口",
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
