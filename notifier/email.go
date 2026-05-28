// ============================================
// 文件: notifier/email.go
// ============================================
package notifier

import (
	"fmt"
	"monitor-backend/api"
	"net/smtp"
	"strings"
	"time"
)

// EmailNotifier 邮件通知器
type EmailNotifier struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

// NewEmailNotifier 创建邮件通知器
func NewEmailNotifier(smtpHost string, smtpPort int, smtpUser, smtpPassword, fromEmail, fromName string) *EmailNotifier {
	return &EmailNotifier{
		SMTPHost:     smtpHost,
		SMTPPort:     smtpPort,
		SMTPUser:     smtpUser,
		SMTPPassword: smtpPassword,
		FromEmail:    fromEmail,
		FromName:     fromName,
	}
}

// Type 返回通知器类型
func (e *EmailNotifier) Type() string {
	return "email"
}

// Send 发送邮件通知
func (e *EmailNotifier) Send(history *api.AlertHistoryInfo, receivers []string) error {
	if len(receivers) == 0 {
		return fmt.Errorf("no email receivers specified")
	}

	severityEmoji := map[string]string{
		"critical": "🔴",
		"warning":  "🟡",
		"info":     "🔵",
	}[history.Severity]
	if severityEmoji == "" {
		severityEmoji = "🔵"
	}
	subject := fmt.Sprintf("[%s] %s - %s", severityEmoji, history.RuleName, history.Hostname)
	body := e.buildEmailBody(history)

	msg := fmt.Sprintf("From: %s <%s>\r\n", e.FromName, e.FromEmail)
	msg += fmt.Sprintf("To: %s\r\n", strings.Join(receivers, ","))
	msg += fmt.Sprintf("Subject: %s\r\n", subject)
	msg += "MIME-Version: 1.0\r\n"
	msg += "Content-Type: text/html; charset=UTF-8\r\n"
	msg += "\r\n" + body

	addr := fmt.Sprintf("%s:%d", e.SMTPHost, e.SMTPPort)
	auth := smtp.PlainAuth("", e.SMTPUser, e.SMTPPassword, e.SMTPHost)

	return smtp.SendMail(addr, auth, e.FromEmail, receivers, []byte(msg))
}

// buildEmailBody 构建邮件内容
func (e *EmailNotifier) buildEmailBody(history *api.AlertHistoryInfo) string {
	statusBadge := "🔴 告警中"
	if history.Status == "resolved" {
		statusBadge = "🟢 已恢复"
	}

	severityBadge := map[string]string{
		"critical": "🔴 严重",
		"warning":  "🟡 警告",
		"info":     "🔵 信息",
	}[history.Severity]

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f4f4f4; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .content { background: #fff; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 3px; margin: 5px; }
        .critical { background: #ff6b6b; color: white; }
        .warning { background: #ffd93d; color: #333; }
        .info { background: #6bcf7f; color: white; }
        .detail { margin: 10px 0; }
        .detail-label { font-weight: bold; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>%s %s</h2>
        </div>
        <div class="content">
            <div class="detail">
                <span class="detail-label">规则名称:</span> %s
            </div>
            <div class="detail">
                <span class="detail-label">主机:</span> %s (%s)
            </div>
            <div class="detail">
                <span class="detail-label">严重程度:</span> %s
            </div>
            <div class="detail">
                <span class="detail-label">状态:</span> %s
            </div>
            <div class="detail">
                <span class="detail-label">指标类型:</span> %s
            </div>
            <div class="detail">
                <span class="detail-label">指标值:</span> %.2f
            </div>
            <div class="detail">
                <span class="detail-label">阈值:</span> %.2f
            </div>
            <div class="detail">
                <span class="detail-label">触发时间:</span> %s
            </div>
            <div class="detail">
                <span class="detail-label">通知时间:</span> %s
            </div>
            <div class="detail">
                <span class="detail-label">消息:</span> %s
            </div>
        </div>
    </div>
</body>
</html>
`, statusBadge, history.RuleName, history.RuleName, history.Hostname, history.HostID, severityBadge, statusBadge, metricTypeDisplayName(history.MetricType), history.MetricValue, history.Threshold, history.FiredAt.Format("2006-01-02 15:04:05"), formatNotificationTime(time.Now()), history.Message)

	return html
}
