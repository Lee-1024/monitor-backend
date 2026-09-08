package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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
		s.corootAssistantTool("get_coroot_overview", "查询 Coroot 应用可观测性总览", "overview"),
		s.corootAssistantTool("list_coroot_applications", "查询 Coroot 应用列表", "applications"),
		s.corootAssistantTool("get_coroot_application", "查询 Coroot 应用详情，需要 resource_type 或 host_id 作为应用名", "application"),
		s.corootAssistantTool("list_coroot_incidents", "查询 Coroot Incident 列表", "incidents"),
		s.corootAssistantTool("get_coroot_incident", "查询 Coroot Incident 详情，需要 resource_type 或 host_id 作为 Incident ID", "incident"),
		s.corootAssistantTool("list_coroot_alerts", "查询 Coroot 告警列表。用户询问告警、检查项、日志告警或 PromQL 告警时使用，不要用 Incident 工具替代", "alerts"),
		s.corootAssistantTool("get_coroot_alert", "查询 Coroot 单条告警详情，需要 resource_type 或 host_id 作为告警 ID", "alert"),
		s.corootAssistantTool("get_coroot_topology", "查询 Coroot 服务拓扑", "topology"),
		s.corootAssistantTool("get_coroot_node", "查询 Coroot 节点详情，需要 resource_type 或 host_id 作为节点名", "node"),
		{
			Name:        "get_capacity_prediction",
			Description: "查询容量预测和阈值到达时间",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				result, err := s.capacityPredictionForAssistant(req)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_capacity_prediction",
					Summary: "查询 " + req.HostID + " 容量预测",
					Content: mustJSON(result),
				}, nil
			},
		},
		{
			Name:        "get_cost_optimization",
			Description: "查询主机资源成本优化证据",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				result, err := s.costOptimizationForAssistant(req)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_cost_optimization",
					Summary: "查询 " + req.HostID + " 成本优化证据",
					Content: mustJSON(result),
				}, nil
			},
		},
		{
			Name:        "get_performance_summary",
			Description: "查询主机性能瓶颈和资源效率摘要",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				result, err := s.performanceSummaryForAssistant(req)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "get_performance_summary",
					Summary: "查询 " + req.HostID + " 性能分析摘要",
					Content: mustJSON(result),
				}, nil
			},
		},
		{
			Name:        "detect_anomalies",
			Description: "查询主机异常检测结果和异常统计",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				result, err := s.anomalyEvidenceForAssistant(req)
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				return opsassistant.ToolResult{
					Name:    "detect_anomalies",
					Summary: "查询 " + req.HostID + " 异常检测证据",
					Content: mustJSON(result),
				}, nil
			},
		},
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
		assistantHostDataTool("get_host_services", "查询指定主机上的服务状态", func(ctx context.Context, hostID string) (interface{}, error) {
			return s.storage.GetServiceStatus(hostID)
		}),
		assistantHostDataTool("get_host_containers", "查询指定主机上的 Docker 容器状态和资源", func(ctx context.Context, hostID string) (interface{}, error) {
			items, _, err := s.storage.GetDockerContainersWithPagination(hostID, 1, 200)
			return items, err
		}),
		assistantHostDataTool("get_host_processes", "查询指定主机上的进程列表", func(ctx context.Context, hostID string) (interface{}, error) {
			return s.storage.GetProcesses(hostID, 200)
		}),
		assistantHostDataTool("get_host_logs", "查询指定主机最近的日志", func(ctx context.Context, hostID string) (interface{}, error) {
			end := time.Now()
			start := end.Add(-time.Duration(24) * time.Hour)
			return s.storage.GetLogs(hostID, "", start, end, 200)
		}),
		{
			Name: "get_server_probe_status", Description: "查询服务端探测目标最近的连通性、延迟和 HTTP 状态",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				targets, err := s.storage.ListServerProbeTargets()
				if err != nil {
					return opsassistant.ToolResult{}, err
				}
				name := strings.TrimSpace(req.Target)
				result := make([]map[string]interface{}, 0)
				for _, target := range targets {
					if name != "" && !strings.Contains(strings.ToLower(target.Name+" "+target.Host+" "+target.URL), strings.ToLower(name)) {
						continue
					}
					results, resultErr := s.storage.ListServerProbeResults(target.ID, 5)
					if resultErr != nil {
						continue
					}
					result = append(result, map[string]interface{}{"target": target, "recent_results": results})
				}
				return opsassistant.ToolResult{Name: "get_server_probe_status", Summary: "查询服务端探测状态", Content: mustJSON(map[string]interface{}{"scope": req.Scope, "target": name, "data": result})}, nil
			},
		},
	}
}

func assistantHostDataTool(name, description string, query func(context.Context, string) (interface{}, error)) opsassistant.Tool {
	return opsassistant.Tool{
		Name: name, Description: description,
		Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
			hostID := strings.TrimSpace(req.HostID)
			if hostID == "" {
				return opsassistant.ToolResult{Name: name, Summary: "缺少主机范围", Content: "该查询必须指定 host_id，不能执行全局查询"}, nil
			}
			data, err := query(ctx, hostID)
			if err != nil {
				return opsassistant.ToolResult{}, err
			}
			return opsassistant.ToolResult{Name: name, Summary: description, Content: mustJSON(map[string]interface{}{"scope": "host", "host_id": hostID, "data": data})}, nil
		},
	}
}

func (s *APIServer) corootAssistantTool(name, description, resource string) opsassistant.Tool {
	return opsassistant.Tool{
		Name:        name,
		Description: description,
		Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
			if s.corootAdapter == nil {
				return opsassistant.ToolResult{Name: name, Summary: "Coroot 当前不可用", Content: mustJSON(map[string]interface{}{"available": false, "error": "Coroot 未启用"})}, nil
			}
			resourceName := resource
			if resource == "application" || resource == "incident" || resource == "node" || resource == "alert" {
				id := strings.TrimSpace(req.ResourceType)
				if id == "" {
					id = strings.TrimSpace(req.HostID)
				}
				if id == "" {
					return opsassistant.ToolResult{Name: name, Summary: "缺少查询对象", Content: "需要提供应用、Incident、告警或节点标识"}, nil
				}
				resourceName += ":" + id
			}
			var data interface{}
			var query url.Values
			if resource == "alerts" {
				query = url.Values{"limit": []string{"50"}, "offset": []string{"0"}, "include_resolved": []string{"false"}, "sort_by": []string{"opened_at"}, "sort_desc": []string{"true"}}
			}
			if err := s.corootAdapter.Get(ctx, resourceName, query, &data); err != nil {
				return opsassistant.ToolResult{Name: name, Summary: "Coroot 暂时不可用", Content: mustJSON(map[string]interface{}{"available": false, "error": "Coroot 暂时不可用"})}, nil
			}
			return opsassistant.ToolResult{Name: name, Summary: description, Content: mustJSON(map[string]interface{}{"available": true, "checked_at": time.Now(), "data": data})}, nil
		},
	}
}

func assistantMetricRange(req opsassistant.ChatRequest) (string, string) {
	if req.TimeRange != nil {
		return req.TimeRange.From.Format(time.RFC3339), req.TimeRange.To.Format(time.RFC3339)
	}
	return "-24h", "now"
}

func (s *APIServer) capacityPredictionForAssistant(req opsassistant.ChatRequest) (map[string]interface{}, error) {
	if req.HostID == "" {
		return nil, fmt.Errorf("host_id is required")
	}
	if s.predictor == nil {
		return nil, fmt.Errorf("predictor not initialized")
	}
	resourceType := req.ResourceType
	if resourceType == "" || resourceType == "all" {
		resourceType = "cpu"
	}
	days := req.Days
	if days <= 0 {
		days = 30
	}
	threshold := req.Threshold
	if threshold <= 0 || threshold > 100 {
		threshold = 80
	}
	historyDays := days * 2
	if historyDays < 7 {
		historyDays = 7
	}
	dataPoints, err := s.storage.GetPredictionData(req.HostID, resourceType, historyDays)
	if err != nil {
		return nil, err
	}
	if len(dataPoints) < 2 {
		return nil, fmt.Errorf("insufficient historical data for prediction")
	}
	points := make([]PredictionMetricPoint, len(dataPoints))
	for i, point := range dataPoints {
		points[i] = PredictionMetricPoint{Timestamp: point.Timestamp, Value: point.Value}
	}
	prediction, err := s.predictor.Predict(points, days, threshold)
	if err != nil {
		return nil, err
	}
	capacity, err := s.predictor.PredictCapacityNeeds(points, resourceType, threshold)
	if err != nil {
		return nil, err
	}
	hostname := req.HostID
	if agent, err := s.storage.GetAgent(req.HostID); err == nil && agent != nil && agent.Hostname != "" {
		hostname = agent.Hostname
	}
	return map[string]interface{}{
		"host": map[string]interface{}{
			"host_id":  req.HostID,
			"hostname": hostname,
		},
		"resource_type": resourceType,
		"days":          days,
		"threshold":     threshold,
		"prediction":    prediction,
		"capacity":      capacity,
	}, nil
}

func (s *APIServer) costOptimizationForAssistant(req opsassistant.ChatRequest) (map[string]interface{}, error) {
	if req.HostID == "" {
		return nil, fmt.Errorf("host_id is required")
	}
	if s.predictor == nil {
		return nil, fmt.Errorf("predictor not initialized")
	}
	days := req.Days
	if days <= 0 {
		days = 30
	}
	threshold := req.Threshold
	if threshold <= 0 || threshold > 100 {
		threshold = 80
	}
	resourceTypes := []string{"cpu", "memory", "disk"}
	if req.ResourceType != "" && req.ResourceType != "all" {
		resourceTypes = []string{req.ResourceType}
	}
	predictions := make(map[string]interface{})
	for _, resourceType := range resourceTypes {
		dataPoints, err := s.storage.GetPredictionData(req.HostID, resourceType, 30)
		if err != nil || len(dataPoints) < 2 {
			continue
		}
		points := make([]PredictionMetricPoint, len(dataPoints))
		for i, point := range dataPoints {
			points[i] = PredictionMetricPoint{Timestamp: point.Timestamp, Value: point.Value}
		}
		result, err := s.predictor.Predict(points, days, threshold)
		if err == nil {
			predictions[resourceType] = result
		}
	}
	if len(predictions) == 0 {
		return nil, fmt.Errorf("no prediction data available for cost optimization")
	}
	hostname := req.HostID
	if agent, err := s.storage.GetAgent(req.HostID); err == nil && agent != nil && agent.Hostname != "" {
		hostname = agent.Hostname
	}
	return map[string]interface{}{
		"host_id":     req.HostID,
		"hostname":    hostname,
		"days":        days,
		"threshold":   threshold,
		"predictions": predictions,
		"guidance":    generateSimpleCostOptimization(predictions, hostname),
	}, nil
}

func (s *APIServer) performanceSummaryForAssistant(req opsassistant.ChatRequest) (map[string]interface{}, error) {
	if req.HostID == "" {
		return nil, fmt.Errorf("host_id is required")
	}
	hours := req.Hours
	if hours <= 0 {
		hours = 24
	}
	performanceData, err := s.collectPerformanceData(req.HostID, hours)
	if err != nil {
		return nil, err
	}
	bottlenecks := s.analyzeBottlenecks(performanceData)
	efficiency := s.evaluateEfficiency(performanceData)
	return map[string]interface{}{
		"host_id":      req.HostID,
		"hostname":     performanceData.Hostname,
		"time_range":   fmt.Sprintf("最近 %d 小时", hours),
		"cpu":          performanceData.CPU,
		"memory":       performanceData.Memory,
		"disk":         performanceData.Disk,
		"network":      performanceData.Network,
		"bottlenecks":  bottlenecks,
		"efficiency":   efficiency,
		"generated_at": time.Now().Format(time.RFC3339),
	}, nil
}

func (s *APIServer) anomalyEvidenceForAssistant(req opsassistant.ChatRequest) (map[string]interface{}, error) {
	if req.HostID == "" {
		return nil, fmt.Errorf("host_id is required")
	}
	limit := 50
	resolved := false
	events, err := s.storage.GetAnomalyEvents(req.HostID, "", req.ResourceType, &resolved, limit)
	if err != nil {
		return nil, err
	}
	stats, statErr := s.storage.GetAnomalyStatistics(req.HostID)
	result := map[string]interface{}{
		"host_id":           req.HostID,
		"resource_type":     req.ResourceType,
		"analysis_hours":    req.Hours,
		"unresolved_events": events,
		"event_count":       len(events),
	}
	if statErr == nil {
		result["statistics"] = stats
	}
	return result, nil
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
		Message:    c.Query("message"),
		SessionID:  c.Query("session_id"),
		HostID:     c.Query("host_id"),
		Scope:      c.Query("scope"),
		TargetType: c.Query("target_type"),
		Target:     c.Query("target"),
	}
	req.ResourceType = c.Query("resource_type")
	if days, err := strconv.Atoi(c.Query("days")); err == nil {
		req.Days = days
	}
	if threshold, err := strconv.ParseFloat(c.Query("threshold"), 64); err == nil {
		req.Threshold = threshold
	}
	if hours, err := strconv.Atoi(c.Query("hours")); err == nil {
		req.Hours = hours
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
