package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type corootWebhookEvent struct {
	Status           string  `json:"status"`
	ID               string  `json:"id"`
	IncidentID       string  `json:"incident_id"`
	Application      string  `json:"application"`
	Severity         string  `json:"severity"`
	Description      string  `json:"description"`
	Message          string  `json:"message"`
	URL              string  `json:"url"`
	ImpactedRequests float64 `json:"impacted_requests"`
	OpenedAt         string  `json:"opened_at"`
	Timestamp        string  `json:"timestamp"`
}

func (s *APIServer) receiveCorootWebhook(c *gin.Context) {
	if s.config.Coroot.WebhookSecret == "" {
		c.JSON(http.StatusServiceUnavailable, Response{Code: http.StatusServiceUnavailable, Message: "Coroot Webhook 未配置"})
		return
	}
	provided := c.GetHeader("X-Coroot-Webhook-Secret")
	if subtle.ConstantTimeCompare([]byte(provided), []byte(s.config.Coroot.WebhookSecret)) != 1 {
		c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "Webhook 签名无效"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 256<<10)
	var event corootWebhookEvent
	decoder := json.NewDecoder(c.Request.Body)
	if err := decoder.Decode(&event); err != nil || event.ID == "" && event.IncidentID == "" {
		c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Webhook 数据无效"})
		return
	}
	if event.Timestamp != "" {
		if timestamp, err := time.Parse(time.RFC3339, event.Timestamp); err != nil || time.Since(timestamp) > 10*time.Minute || time.Since(timestamp) < -10*time.Minute {
			c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Webhook 已过期"})
			return
		}
	}
	corootID := event.ID
	if corootID == "" {
		corootID = event.IncidentID
	}
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok || db == nil {
		c.JSON(http.StatusServiceUnavailable, Response{Code: http.StatusServiceUnavailable, Message: "告警存储不可用"})
		return
	}
	var row struct {
		ID       uint
		Status   string
		CorootID string
	}
	if err := db.Table("alert_histories").Where("coroot_id = ?", corootID).First(&row).Error; err == nil {
		status := strings.ToLower(event.Status)
		if status == "ok" || status == "resolved" {
			now := time.Now()
			_ = db.Table("alert_histories").Where("id = ?", row.ID).Updates(map[string]interface{}{"status": "resolved", "resolved_at": now})
		}
		c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "Webhook 已处理", Data: map[string]interface{}{"id": row.ID, "duplicate": true}})
		return
	}
	severity := strings.ToLower(event.Severity)
	if severity == "" {
		severity = "critical"
	}
	message := event.Message
	if message == "" {
		message = event.Description
	}
	firedAt := time.Now()
	if event.OpenedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, event.OpenedAt); err == nil {
			firedAt = parsed
		}
	}
	history := &AlertHistoryInfo{RuleName: "Coroot", RuleDesc: event.Description, Hostname: event.Application, Severity: severity, Status: "firing", FiredAt: firedAt, MetricType: "coroot", MetricValue: event.ImpactedRequests, Message: message, Labels: map[string]string{"coroot_id": corootID, "url": event.URL}}
	created, err := s.storage.CreateAlertHistory(history)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "保存 Coroot 告警失败"})
		return
	}
	_ = db.Table("alert_histories").Where("id = ?", created.ID).Updates(map[string]interface{}{"coroot_id": corootID})
	c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "Webhook 已处理", Data: created})
}
