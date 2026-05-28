package notifier

import "time"

func metricTypeDisplayName(metricType string) string {
	names := map[string]string{
		"cpu":             "CPU使用率",
		"memory":          "内存使用率",
		"disk":            "磁盘使用率",
		"network":         "网络",
		"host_down":       "主机宕机",
		"service_port":    "服务端口",
		"gpu_unavailable": "GPU不可用",
	}

	if name, ok := names[metricType]; ok {
		return name
	}
	return metricType
}

func formatNotificationTime(now time.Time) string {
	return now.Format("2006-01-02 15:04:05")
}
