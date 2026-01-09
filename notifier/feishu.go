// ============================================
// 文件: notifier/feishu.go
// ============================================
package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"monitor-backend/api"
)

// FeishuNotifier 飞书通知器
type FeishuNotifier struct {
	WebhookURL string
}

// NewFeishuNotifier 创建飞书通知器
func NewFeishuNotifier(webhookURL string) *FeishuNotifier {
	return &FeishuNotifier{
		WebhookURL: webhookURL,
	}
}

// Type 返回通知器类型
func (f *FeishuNotifier) Type() string {
	return "feishu"
}

// Send 发送飞书通知
func (f *FeishuNotifier) Send(history *api.AlertHistoryInfo, receivers []string) error {
	log.Printf("[FeishuNotifier] Send called: AlertID=%d, Rule=%s, Host=%s, WebhookURL=%s", 
		history.ID, history.RuleName, history.HostID, f.WebhookURL)
	
	if f.WebhookURL == "" {
		log.Printf("[FeishuNotifier] Error: WebhookURL is empty")
		return fmt.Errorf("feishu webhook URL is empty")
	}
	
	payload := map[string]interface{}{
		"msg_type": "interactive",
		"card": map[string]interface{}{
			"config": map[string]interface{}{
				"wide_screen_mode": true,
			},
			"header": map[string]interface{}{
				"title": map[string]string{
					"tag": "plain_text",
					"content": fmt.Sprintf("[%s] %s", f.getSeverityEmoji(history.Severity), history.RuleName),
				},
				"template": f.getSeverityColor(history.Severity),
			},
			"elements": []map[string]interface{}{
				{
					"tag": "div",
					"fields": []map[string]interface{}{
						{"is_short": true, "text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("**主机:**\n%s (%s)", history.Hostname, history.HostID)}},
						{"is_short": true, "text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("**状态:**\n%s", f.getStatusEmoji(history.Status))}},
						{"is_short": true, "text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("**严重程度:**\n%s", f.getSeverityEmoji(history.Severity))}},
						{"is_short": true, "text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("**指标类型:**\n%s", history.MetricType)}},
						{"is_short": true, "text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("**指标值:**\n%.2f", history.MetricValue)}},
					},
				},
				{
					"tag": "div",
					"text": map[string]string{
						"tag": "lark_md",
						"content": fmt.Sprintf("**消息:**\n%s", history.Message),
					},
				},
			},
		},
	}

	log.Printf("[FeishuNotifier] Building payload for alert ID=%d", history.ID)
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[FeishuNotifier] Error marshaling payload: %v", err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}
	log.Printf("[FeishuNotifier] Payload size: %d bytes", len(jsonData))

	log.Printf("[FeishuNotifier] Creating HTTP request to: %s", f.WebhookURL)
	req, err := http.NewRequest("POST", f.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[FeishuNotifier] Error creating HTTP request: %v", err)
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	log.Printf("[FeishuNotifier] Sending HTTP request (timeout: 10s)")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[FeishuNotifier] Error sending HTTP request: %v", err)
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("[FeishuNotifier] HTTP response status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[FeishuNotifier] Error response body: %s", string(body))
		return fmt.Errorf("feishu webhook failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[FeishuNotifier] Successfully sent notification to Feishu")
	return nil
}

// buildMessage 构建飞书消息（备用）
func (f *FeishuNotifier) buildMessage(history *api.AlertHistoryInfo) string {
	return fmt.Sprintf("[%s] %s - %s (%s)", history.Severity, history.RuleName, history.Hostname, history.HostID)
}

// getSeverityEmoji 获取严重程度对应的图标
func (f *FeishuNotifier) getSeverityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "warning":
		return "🟡"
	case "info":
		return "🔵"
	default:
		return "🔵"
	}
}

// getStatusEmoji 获取状态对应的图标
func (f *FeishuNotifier) getStatusEmoji(status string) string {
	if status == "resolved" {
		return "🟢 已恢复"
	}
	return "🔴 告警中"
}

// getSeverityColor 获取严重程度对应的颜色
func (f *FeishuNotifier) getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "red"
	case "warning":
		return "orange"
	default:
		return "blue"
	}
}

