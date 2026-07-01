package notifier

import (
	"fmt"
	"html"
	"strings"
	"time"
)

func metricTypeDisplayName(metricType string) string {
	names := map[string]string{
		"cpu":             "CPU使用率",
		"memory":          "内存使用率",
		"disk":            "磁盘使用率",
		"network":         "网络",
		"host_down":       "主机宕机",
		"backend_health":  "后台服务健康",
		"service_port":    "服务端口",
		"server_probe":    "服务端探测",
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

func ruleDescriptionMarkdownLine(description string, prefix string) string {
	description = strings.TrimSpace(description)
	if description == "" {
		return ""
	}
	return fmt.Sprintf("%s**规则描述:** %s  \n", prefix, description)
}

func ruleDescriptionHTMLBlock(description string) string {
	description = strings.TrimSpace(description)
	if description == "" {
		return ""
	}
	return fmt.Sprintf(`
            <div class="detail">
                <span class="detail-label">规则描述:</span> %s
            </div>`, html.EscapeString(description))
}
