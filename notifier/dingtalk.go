// ============================================
// 文件: notifier/dingtalk.go
// ============================================
package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
	"monitor-backend/api"
)

// DingTalkNotifier 钉钉通知器
type DingTalkNotifier struct {
	WebhookURL string
}

// NewDingTalkNotifier 创建钉钉通知器
func NewDingTalkNotifier(webhookURL string) *DingTalkNotifier {
	return &DingTalkNotifier{
		WebhookURL: webhookURL,
	}
}

// Type 返回通知器类型
func (d *DingTalkNotifier) Type() string {
	return "dingtalk"
}

// Send 发送钉钉通知
func (d *DingTalkNotifier) Send(history *api.AlertHistoryInfo, receivers []string) error {
	message := d.buildMessage(history)

	severityEmoji := map[string]string{
		"critical": "🔴",
		"warning":  "🟡",
		"info":     "🔵",
	}[history.Severity]
	if severityEmoji == "" {
		severityEmoji = "🔵"
	}
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": fmt.Sprintf("[%s] %s", severityEmoji, history.RuleName),
			"text":  message,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", d.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dingtalk webhook failed: %s", string(body))
	}

	return nil
}

// buildMessage 构建钉钉消息
func (d *DingTalkNotifier) buildMessage(history *api.AlertHistoryInfo) string {
	severityEmoji := map[string]string{
		"critical": "🔴",
		"warning":  "🟡",
		"info":     "🔵",
	}[history.Severity]

	statusEmoji := "🔴"
	if history.Status == "resolved" {
		statusEmoji = "🟢"
	}

	return fmt.Sprintf(`
# %s 告警

**规则名称:** %s  
**主机:** %s (%s)  
**严重程度:** %s  
**状态:** %s  
**指标类型:** %s  
**指标值:** %.2f  
**阈值:** %.2f  
**触发时间:** %s  
**消息:** %s
`, severityEmoji, history.RuleName, history.Hostname, history.HostID, severityEmoji, statusEmoji, history.MetricType, history.MetricValue, history.Threshold, history.FiredAt.Format("2006-01-02 15:04:05"), history.Message)
}

