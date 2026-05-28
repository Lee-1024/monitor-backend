// ============================================
// 文件: notifier/wechat.go
// ============================================
package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"monitor-backend/api"
	"net/http"
	"time"
)

// WeChatNotifier 企业微信通知器
type WeChatNotifier struct {
	WebhookURL string
}

// NewWeChatNotifier 创建企业微信通知器
func NewWeChatNotifier(webhookURL string) *WeChatNotifier {
	return &WeChatNotifier{
		WebhookURL: webhookURL,
	}
}

// Type 返回通知器类型
func (w *WeChatNotifier) Type() string {
	return "wechat"
}

// Send 发送企业微信通知
func (w *WeChatNotifier) Send(history *api.AlertHistoryInfo, receivers []string) error {
	message := w.buildMessage(history)

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": message,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", w.WebhookURL, bytes.NewBuffer(jsonData))
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
		return fmt.Errorf("wechat webhook failed: %s", string(body))
	}

	return nil
}

// buildMessage 构建企业微信消息
func (w *WeChatNotifier) buildMessage(history *api.AlertHistoryInfo) string {
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

> **规则名称:** %s  
> **主机:** %s (%s)  
> **严重程度:** %s  
> **状态:** %s  
> **指标类型:** %s  
> **指标值:** %.2f  
> **阈值:** %.2f  
> **触发时间:** %s  
> **通知时间:** %s  
> **消息:** %s
`, severityEmoji, history.RuleName, history.Hostname, history.HostID, severityEmoji, statusEmoji, metricTypeDisplayName(history.MetricType), history.MetricValue, history.Threshold, history.FiredAt.Format("2006-01-02 15:04:05"), formatNotificationTime(time.Now()), history.Message)
}
