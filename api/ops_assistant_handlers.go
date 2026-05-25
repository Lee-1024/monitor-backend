package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"monitor-backend/opsassistant"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (s *APIServer) newOpsAssistant(userID uint) (*opsassistant.Assistant, error) {
	config, err := s.storage.GetDefaultLLMModelConfig()
	if err != nil {
		return nil, err
	}
	model, err := newOpsAssistantEinoModel(context.Background(), config)
	if err != nil {
		return nil, err
	}
	return opsassistant.NewAssistant(
		model,
		s.opsAssistantTools(),
		opsassistant.WithUserID(userID),
		opsassistant.WithSessionStore(s.opsAssistantSessions),
	), nil
}

func (s *APIServer) opsAssistantTools() []opsassistant.Tool {
	return []opsassistant.Tool{
		{
			Name:        "list_agents",
			Description: "查询主机列表",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				agents, total, err := s.storage.ListAgents("", 1, 100)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "list_agents",
					Summary: fmt.Sprintf("查询主机列表，共 %d 台", total),
					Content: mustJSON(map[string]interface{}{"total": total, "agents": agents}),
				}, nil
			},
		},
		{
			Name:        "get_agent_detail",
			Description: "查询所选主机详情",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				if req.HostID == "" {
					return opsassistant.ToolResult{Name: "get_agent_detail", Summary: "未指定主机，跳过主机详情查询", Content: "用户未指定 host_id"}, nil
				}
				agents, _, err := s.storage.ListAgents("", 1, 1000)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				for _, agent := range agents {
					if agent.HostID == req.HostID {
						return opsassistant.ToolResult{
							Name:    "get_agent_detail",
							Summary: "查询 " + req.HostID + " 主机详情",
							Content: mustJSON(agent),
						}, nil
					}
				}
				return opsassistant.ToolResult{
					Name:    "get_agent_detail",
					Summary: "未找到 " + req.HostID + " 主机详情",
					Content: "host not found: " + req.HostID,
				}, nil
			},
		},
		{
			Name:        "get_latest_metrics",
			Description: "查询主机最新指标",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				if req.HostID == "" {
					return opsassistant.ToolResult{Name: "get_latest_metrics", Summary: "未指定主机，跳过最新指标查询", Content: "用户未指定 host_id"}, nil
				}
				metrics, err := s.storage.GetLatestMetrics(req.HostID)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_latest_metrics",
					Summary: "查询 " + req.HostID + " 最新指标",
					Content: mustJSON(metrics),
				}, nil
			},
		},
		{
			Name:        "get_history_metrics",
			Description: "查询主机历史指标",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				if req.HostID == "" {
					return opsassistant.ToolResult{Name: "get_history_metrics", Summary: "未指定主机，跳过历史指标查询", Content: "用户未指定 host_id"}, nil
				}
				start, end := assistantMetricRange(req)
				payload := map[string]interface{}{}
				for _, metricType := range []string{"cpu", "memory", "disk"} {
					points, err := s.storage.GetHistoryMetrics(req.HostID, metricType, start, end, "10m")
					if err != nil {
						payload[metricType+"_error"] = err.Error()
						continue
					}
					if len(points) > 120 {
						points = points[len(points)-120:]
					}
					payload[metricType] = points
				}
				return opsassistant.ToolResult{
					Name:    "get_history_metrics",
					Summary: fmt.Sprintf("查询 %s 从 %s 到 %s 的历史指标", req.HostID, start, end),
					Content: mustJSON(payload),
				}, nil
			},
		},
		{
			Name:        "get_recent_alerts",
			Description: "查询近期告警",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				alerts, err := s.storage.ListAlertHistory(nil, req.HostID, "", 50)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_recent_alerts",
					Summary: fmt.Sprintf("查询近期告警 %d 条", len(alerts)),
					Content: mustJSON(alerts),
				}, nil
			},
		},
		{
			Name:        "get_anomaly_events",
			Description: "查询近期异常事件",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				resolved := false
				events, err := s.storage.GetAnomalyEvents(req.HostID, "", "", &resolved, 50)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_anomaly_events",
					Summary: fmt.Sprintf("查询未解决异常事件 %d 条", len(events)),
					Content: mustJSON(events),
				}, nil
			},
		},
		{
			Name:        "search_knowledge",
			Description: "检索知识库",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				items, err := s.searchKnowledgeForAssistant(req.Message)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "search_knowledge",
					Summary: fmt.Sprintf("检索知识库，返回 %d 条结果", len(items)),
					Content: mustJSON(items),
				}, nil
			},
		},
		{
			Name:        "get_latest_inspection_report",
			Description: "查询最新巡检报告",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				report, err := s.latestInspectionReportForAssistant()
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_latest_inspection_report",
					Summary: "查询最新巡检报告",
					Content: mustJSON(report),
				}, nil
			},
		},
	}
}

func assistantMetricRange(req opsassistant.ChatRequest) (string, string) {
	if req.TimeRange != nil {
		return req.TimeRange.From.Format(time.RFC3339), req.TimeRange.To.Format(time.RFC3339)
	}
	return "-24h", "now"
}

func (s *APIServer) searchKnowledgeForAssistant(message string) ([]map[string]interface{}, error) {
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		return nil, fmt.Errorf("failed to get database connection")
	}

	keyword := strings.TrimSpace(message)
	if len([]rune(keyword)) > 80 {
		keyword = string([]rune(keyword)[:80])
	}
	like := "%" + keyword + "%"

	results := make([]map[string]interface{}, 0, 10)
	searchTables := []struct {
		table    string
		category string
	}{
		{table: "troubleshooting_guides", category: "troubleshooting"},
		{table: "best_practices", category: "best_practice"},
		{table: "case_studies", category: "case_study"},
	}

	for _, item := range searchTables {
		var rows []map[string]interface{}
		err := db.Table(item.table).
			Select("id, title, category, summary, content, created_at").
			Where("is_published = ? AND (title LIKE ? OR content LIKE ? OR summary LIKE ?)", true, like, like, like).
			Order("created_at DESC").
			Limit(4).
			Find(&rows).Error
		if err != nil {
			continue
		}
		for _, row := range rows {
			row["category"] = item.category
			if content, ok := row["content"].(string); ok && len([]rune(content)) > 500 {
				row["content"] = string([]rune(content)[:500]) + "...[已截断]"
			}
			results = append(results, row)
			if len(results) >= 10 {
				return results, nil
			}
		}
	}

	return results, nil
}

func (s *APIServer) latestInspectionReportForAssistant() (map[string]interface{}, error) {
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		return nil, fmt.Errorf("failed to get database connection")
	}

	var reports []map[string]interface{}
	err := db.Table("inspection_reports").
		Select("id, date, status, total_hosts, online_hosts, offline_hosts, warning_hosts, critical_hosts, summary, key_findings, recommendations, created_at").
		Order("date DESC, created_at DESC").
		Limit(1).
		Find(&reports).Error
	if err != nil {
		return nil, err
	}
	if len(reports) == 0 {
		return map[string]interface{}{"message": "暂无巡检报告"}, nil
	}
	return reports[0], nil
}

func mustJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	if len(data) > 12000 {
		return string(data[:12000]) + "\n[内容已截断]"
	}
	return string(data)
}

func (s *APIServer) chatOpsAssistant(c *gin.Context) {
	var req opsassistant.ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}

	assistant, err := s.newOpsAssistant(currentUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: 500, Message: "Failed to initialize assistant: " + err.Error()})
		return
	}
	resp, err := assistant.Chat(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusOK, Response{Code: 500, Message: err.Error(), Data: map[string]interface{}{"error": err.Error()}})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "Success", Data: resp})
}

func (s *APIServer) streamOpsAssistant(c *gin.Context) {
	req := opsassistant.ChatRequest{
		Message:   c.Query("message"),
		SessionID: c.Query("session_id"),
		HostID:    c.Query("host_id"),
	}
	if fromStr, toStr := c.Query("from"), c.Query("to"); fromStr != "" && toStr != "" {
		from, fromErr := time.Parse(time.RFC3339, fromStr)
		to, toErr := time.Parse(time.RFC3339, toStr)
		if fromErr == nil && toErr == nil {
			req.TimeRange = &opsassistant.TimeRange{From: from, To: to}
		}
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	writeEvent := func(event opsassistant.StreamEvent) error {
		data, _ := json.Marshal(event)
		if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", string(data)); err != nil {
			return err
		}
		c.Writer.Flush()
		return nil
	}

	assistant, err := s.newOpsAssistant(currentUserID(c))
	if err != nil {
		_ = writeEvent(opsassistant.StreamEvent{Type: opsassistant.EventError, Message: "Failed to initialize assistant: " + err.Error()})
		return
	}
	if err := assistant.Stream(c.Request.Context(), req, writeEvent); err != nil {
		_ = writeEvent(opsassistant.StreamEvent{Type: opsassistant.EventError, Message: err.Error()})
	}
}

func (s *APIServer) listOpsAssistantSessions(c *gin.Context) {
	sessions, err := s.opsAssistantSessions.List(c.Request.Context(), currentUserID(c), 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "Success", Data: sessions})
}

func (s *APIServer) getOpsAssistantSession(c *gin.Context) {
	session, err := s.opsAssistantSessions.Get(c.Request.Context(), currentUserID(c), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Code: 404, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "Success", Data: session})
}

func (s *APIServer) deleteOpsAssistantSession(c *gin.Context) {
	if err := s.opsAssistantSessions.Delete(c.Request.Context(), currentUserID(c), c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, Response{Code: 404, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Code: 200, Message: "Success"})
}

func currentUserID(c *gin.Context) uint {
	if value, exists := c.Get("user_id"); exists {
		if id, ok := value.(uint); ok {
			return id
		}
	}
	return 1
}
