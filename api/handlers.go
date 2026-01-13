// ============================================
// 文件: api/handlers.go
// ============================================
package api

import (
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Response 统一响应格式
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// 健康检查
func (s *APIServer) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "OK",
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
		},
	})
}

// 获取Agent列表
func (s *APIServer) listAgents(c *gin.Context) {
	// 查询参数
	status := c.Query("status") // online/offline
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	pageNum, _ := strconv.Atoi(page)
	pageSizeNum, _ := strconv.Atoi(pageSize)

	agents, total, err := s.storage.ListAgents(status, pageNum, pageSizeNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get agents: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"agents":    agents,
			"total":     total,
			"page":      pageNum,
			"page_size": pageSizeNum,
		},
	})
}

// 获取单个Agent
func (s *APIServer) getAgent(c *gin.Context) {
	hostID := c.Param("id")

	agent, err := s.storage.GetAgent(hostID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Agent not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    agent,
	})
}

// 删除Agent
func (s *APIServer) deleteAgent(c *gin.Context) {
	hostID := c.Param("id")

	err := s.storage.DeleteAgent(hostID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete agent: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Agent deleted successfully",
	})
}

// 获取Agent指标
func (s *APIServer) getAgentMetrics(c *gin.Context) {
	hostID := c.Param("id")
	metricType := c.DefaultQuery("type", "cpu") // cpu/memory/disk/network
	start := c.DefaultQuery("start", "-1h")     // 默认最近1小时
	end := c.DefaultQuery("end", "now")

	metrics, err := s.storage.GetMetrics(hostID, metricType, start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get metrics: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    metrics,
	})
}

// 获取最新指标
func (s *APIServer) getLatestMetrics(c *gin.Context) {
	hostID := c.Query("host_id")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	metrics, err := s.storage.GetLatestMetrics(hostID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get latest metrics: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    metrics,
	})
}

// 获取历史指标
func (s *APIServer) getHistoryMetrics(c *gin.Context) {
	hostID := c.Query("host_id")
	metricType := c.DefaultQuery("type", "cpu")
	start := c.DefaultQuery("start", "-1h")
	end := c.DefaultQuery("end", "now")
	interval := c.DefaultQuery("interval", "1m")
	mountpoint := c.Query("mountpoint") // 磁盘专用参数

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	// 如果是磁盘类型且指定了挂载点，使用专门的查询方法
	if metricType == "disk" && mountpoint != "" {
		metrics, err := s.storage.GetDiskHistoryByMountpoint(hostID, mountpoint, start, end, interval)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Code:    500,
				Message: "Failed to get disk history: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, Response{
			Code:    200,
			Message: "Success",
			Data:    metrics,
		})
		return
	}

	metrics, err := s.storage.GetHistoryMetrics(hostID, metricType, start, end, interval)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get history metrics: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    metrics,
	})
}

// 获取聚合指标
func (s *APIServer) getAggregateMetrics(c *gin.Context) {
	metricType := c.DefaultQuery("type", "cpu")
	aggregation := c.DefaultQuery("aggregation", "mean") // mean/max/min
	start := c.DefaultQuery("start", "-1h")
	end := c.DefaultQuery("end", "now")

	metrics, err := s.storage.GetAggregateMetrics(metricType, aggregation, start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get aggregate metrics: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    metrics,
	})
}

// 获取概览统计
func (s *APIServer) getOverview(c *gin.Context) {
	overview, err := s.storage.GetOverview()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get overview: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    overview,
	})
}

// 获取Top指标
func (s *APIServer) getTopMetrics(c *gin.Context) {
	metricType := c.DefaultQuery("type", "cpu") // cpu/memory/disk
	limit := c.DefaultQuery("limit", "10")
	order := c.DefaultQuery("order", "desc") // desc/asc

	limitNum, _ := strconv.Atoi(limit)

	metrics, err := s.storage.GetTopMetrics(metricType, limitNum, order)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get top metrics: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    metrics,
	})
}

// getCrashEvents 获取宕机事件列表
func (s *APIServer) getCrashEvents(c *gin.Context) {
	hostID := c.Query("host_id")
	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	events, err := s.storage.GetCrashEvents(hostID, limit)
	if err != nil {
		log.Printf("Failed to get crash events: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get crash events: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    events,
	})
}

// getCrashEventDetail 获取宕机事件详情
func (s *APIServer) getCrashEventDetail(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid event ID",
		})
		return
	}

	event, err := s.storage.GetCrashEventDetail(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Crash event not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    event,
	})
}

// getCrashAnalysis 获取主机宕机分析
func (s *APIServer) getCrashAnalysis(c *gin.Context) {
	hostID := c.Param("host_id")

	// 获取最近的宕机事件
	events, err := s.storage.GetCrashEvents(hostID, 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get crash analysis",
		})
		return
	}

	// 统计已恢复数量
	resolvedCount := 0
	for _, event := range events {
		if event.IsResolved {
			resolvedCount++
		}
	}

	// 统计分析
	analysis := map[string]interface{}{
		"total_crashes":   len(events),
		"resolved_count":  resolvedCount,
		"recent_crashes":  events,
		"crash_frequency": calculateCrashFrequency(events),
		"main_reasons":    analyzeMainReasons(events),
		"avg_downtime":    calculateAvgDowntime(events),
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    analysis,
	})
}

func calculateCrashFrequency(events []CrashEvent) string {
	if len(events) == 0 {
		return "无宕机记录"
	}

	if len(events) == 1 {
		return "仅有1次宕机"
	}

	// 计算最早和最晚宕机的时间跨度
	first := events[len(events)-1].OfflineTime
	last := events[0].OfflineTime
	days := last.Sub(first).Hours() / 24

	if days < 1 {
		return fmt.Sprintf("1天内宕机%d次", len(events))
	}

	freq := float64(len(events)) / days
	return fmt.Sprintf("平均每天宕机%.1f次", freq)
}

func analyzeMainReasons(events []CrashEvent) map[string]int {
	reasons := make(map[string]int)

	for _, event := range events {
		if event.LastCPU > 90 {
			reasons["CPU过高"]++
		}
		if event.LastMemory > 95 {
			reasons["内存不足"]++
		}
		if event.LastDisk > 95 {
			reasons["磁盘满"]++
		}
		if event.LastCPU < 90 && event.LastMemory < 95 && event.LastDisk < 95 {
			reasons["网络/其他"]++
		}
	}

	return reasons
}

func calculateAvgDowntime(events []CrashEvent) string {
	if len(events) == 0 {
		return "0分钟"
	}

	var totalDuration int64
	resolvedCount := 0

	for _, event := range events {
		if event.IsResolved {
			totalDuration += event.Duration
			resolvedCount++
		}
	}

	if resolvedCount == 0 {
		return "暂无恢复记录"
	}

	avgSeconds := totalDuration / int64(resolvedCount)
	minutes := avgSeconds / 60

	if minutes < 60 {
		return fmt.Sprintf("%d分钟", minutes)
	}

	hours := minutes / 60
	return fmt.Sprintf("%d小时%d分钟", hours, minutes%60)
}

// ============================================
// 进程监控相关处理函数
// ============================================

// getProcesses 获取进程列表
func (s *APIServer) getProcesses(c *gin.Context) {
	hostID := c.Query("host_id")
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	processes, err := s.storage.GetProcesses(hostID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get processes: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    processes,
	})
}

// getProcessHistory 获取进程历史数据
func (s *APIServer) getProcessHistory(c *gin.Context) {
	hostID := c.Query("host_id")
	processNamesStr := c.Query("process_names") // 逗号分隔的进程名列表，如果为空则自动查找历史中占用最高的进程
	metricType := c.DefaultQuery("metric_type", "cpu") // cpu 或 memory，用于确定如何查找top进程
	topN := 10
	if topNStr := c.Query("top_n"); topNStr != "" {
		fmt.Sscanf(topNStr, "%d", &topN)
	}
	
	limit := 5000
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	var start, end time.Time
	if startStr := c.Query("start"); startStr != "" {
		start, _ = time.Parse(time.RFC3339, startStr)
	} else {
		// 默认查询最近1小时
		start = time.Now().Add(-1 * time.Hour)
	}
	if endStr := c.Query("end"); endStr != "" {
		end, _ = time.Parse(time.RFC3339, endStr)
	} else {
		end = time.Now()
	}

	var processNames []string
	if processNamesStr != "" {
		// 如果指定了进程名，使用指定的进程名
		names := strings.Split(processNamesStr, ",")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" {
				processNames = append(processNames, name)
			}
		}
	} else {
		// 如果没有指定进程名，从历史数据中查找CPU/内存占用最高的前N个进程
		topNames, err := s.storage.GetTopProcessNamesByHistory(hostID, start, end, metricType, topN)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Code:    500,
				Message: "Failed to get top process names: " + err.Error(),
			})
			return
		}
		processNames = topNames
		log.Printf("Auto-selected top %d processes by %s: %v", len(processNames), metricType, processNames)
	}

	if len(processNames) == 0 {
		c.JSON(http.StatusOK, Response{
			Code:    200,
			Message: "Success",
			Data:    []ProcessHistoryPoint{},
		})
		return
	}

	history, err := s.storage.GetProcessHistory(hostID, processNames, start, end, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get process history: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    history,
	})
}

// ============================================
// 日志相关处理函数
// ============================================

// getLogs 获取日志列表
func (s *APIServer) getLogs(c *gin.Context) {
	hostID := c.Query("host_id")
	level := c.Query("level")
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	var start, end time.Time
	if startStr := c.Query("start"); startStr != "" {
		start, _ = time.Parse(time.RFC3339, startStr)
	}
	if endStr := c.Query("end"); endStr != "" {
		end, _ = time.Parse(time.RFC3339, endStr)
	}

	logs, err := s.storage.GetLogs(hostID, level, start, end, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get logs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    logs,
	})
}

// ============================================
// 脚本执行相关处理函数
// ============================================

// getScriptExecutions 获取脚本执行记录
func (s *APIServer) getScriptExecutions(c *gin.Context) {
	hostID := c.Query("host_id")
	scriptID := c.Query("script_id")
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	executions, err := s.storage.GetScriptExecutions(hostID, scriptID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get script executions: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    executions,
	})
}

// ============================================
// 服务状态相关处理函数
// ============================================

// getServiceStatus 获取服务状态
func (s *APIServer) getServiceStatus(c *gin.Context) {
	hostID := c.Query("host_id")

	services, err := s.storage.GetServiceStatus(hostID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get service status: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    services,
	})
}

// ============================================
// 告警规则相关处理函数
// ============================================

// listAlertRules 获取告警规则列表
func (s *APIServer) listAlertRules(c *gin.Context) {
	enabledStr := c.Query("enabled")
	var enabled *bool
	if enabledStr != "" {
		e := enabledStr == "true"
		enabled = &e
	}

	rules, err := s.storage.ListAlertRules(enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to list alert rules: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    rules,
	})
}

// createAlertRule 创建告警规则
func (s *APIServer) createAlertRule(c *gin.Context) {
	var rule AlertRuleInfo
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	log.Printf("[createAlertRule] Received rule: Name=%s, NotifyChannels=%v, Receivers=%v", 
		rule.Name, rule.NotifyChannels, rule.Receivers)
	
	// 确保 NotifyChannels 和 Receivers 不是 nil
	if rule.NotifyChannels == nil {
		rule.NotifyChannels = []string{}
		log.Printf("[createAlertRule] NotifyChannels was nil, setting to empty array")
	}
	if rule.Receivers == nil {
		rule.Receivers = []string{}
		log.Printf("[createAlertRule] Receivers was nil, setting to empty array")
	}

	created, err := s.storage.CreateAlertRule(&rule)
	if err != nil {
		log.Printf("[createAlertRule] Failed to create rule: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create alert rule: " + err.Error(),
		})
		return
	}

	log.Printf("[createAlertRule] Rule created successfully: ID=%d, NotifyChannels=%v", 
		created.ID, created.NotifyChannels)

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    created,
	})
}

// getAlertRule 获取告警规则
func (s *APIServer) getAlertRule(c *gin.Context) {
	id := c.Param("id")
	var ruleID uint
	if _, err := fmt.Sscanf(id, "%d", &ruleID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid rule ID",
		})
		return
	}

	rule, err := s.storage.GetAlertRule(ruleID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Alert rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    rule,
	})
}

// updateAlertRule 更新告警规则
func (s *APIServer) updateAlertRule(c *gin.Context) {
	id := c.Param("id")
	var ruleID uint
	if _, err := fmt.Sscanf(id, "%d", &ruleID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid rule ID",
		})
		return
	}

	// 使用 map 来接收部分更新的字段
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 转换为 AlertRuleInfo 结构，但只包含实际提供的字段
	var rule AlertRuleInfo
	
	if name, ok := updateData["name"].(string); ok && name != "" {
		rule.Name = name
	}
	if description, ok := updateData["description"].(string); ok {
		rule.Description = description
	}
	if enabled, ok := updateData["enabled"].(bool); ok {
		rule.Enabled = enabled
	}
	if severity, ok := updateData["severity"].(string); ok && severity != "" {
		rule.Severity = severity
	}
	if metricType, ok := updateData["metric_type"].(string); ok && metricType != "" {
		rule.MetricType = metricType
	}
	if hostID, ok := updateData["host_id"].(string); ok {
		rule.HostID = hostID
	}
	if condition, ok := updateData["condition"].(string); ok && condition != "" {
		rule.Condition = condition
	}
	if threshold, ok := updateData["threshold"].(float64); ok {
		rule.Threshold = threshold
	}
	if duration, ok := updateData["duration"].(float64); ok {
		rule.Duration = int(duration)
	}
	if inhibitDuration, ok := updateData["inhibit_duration"].(float64); ok {
		rule.InhibitDuration = int(inhibitDuration)
	}
	// 检查 notify_channels 是否在 updateData 中
	// 即使它是空数组，我们也需要设置它，因为用户可能想要清空通知渠道
	if notifyChannelsRaw, exists := updateData["notify_channels"]; exists {
		if notifyChannels, ok := notifyChannelsRaw.([]interface{}); ok {
			log.Printf("[updateAlertRule] Handler: Received notify_channels=%v (exists=%v, isArray=%v)", notifyChannels, exists, ok)
			rule.NotifyChannels = make([]string, len(notifyChannels))
			for i, v := range notifyChannels {
				if str, ok := v.(string); ok {
					rule.NotifyChannels[i] = str
				}
			}
			log.Printf("[updateAlertRule] Handler: Parsed NotifyChannels=%v", rule.NotifyChannels)
		} else if notifyChannelsArray, ok := notifyChannelsRaw.([]string); ok {
			// 如果直接是 []string 类型（某些情况下可能发生）
			log.Printf("[updateAlertRule] Handler: Received notify_channels as []string=%v", notifyChannelsArray)
			rule.NotifyChannels = notifyChannelsArray
			log.Printf("[updateAlertRule] Handler: Parsed NotifyChannels=%v", rule.NotifyChannels)
		} else {
			log.Printf("[updateAlertRule] Handler: notify_channels exists but is not an array (type: %T, value: %v)", notifyChannelsRaw, notifyChannelsRaw)
			// 如果存在但不是数组，不设置（保留现有值）
		}
	} else {
		log.Printf("[updateAlertRule] Handler: notify_channels not found in updateData, will keep existing value")
	}
	if receivers, ok := updateData["receivers"].([]interface{}); ok {
		rule.Receivers = make([]string, len(receivers))
		for i, v := range receivers {
			if str, ok := v.(string); ok {
				rule.Receivers[i] = str
			}
		}
	}

	if err := s.storage.UpdateAlertRule(ruleID, &rule); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update alert rule: " + err.Error(),
		})
		return
	}

	// 返回更新后的数据
	updatedRule, err := s.storage.GetAlertRule(ruleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get updated alert rule: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    updatedRule,
	})
}

// deleteAlertRule 删除告警规则
func (s *APIServer) deleteAlertRule(c *gin.Context) {
	id := c.Param("id")
	var ruleID uint
	if _, err := fmt.Sscanf(id, "%d", &ruleID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid rule ID",
		})
		return
	}

	if err := s.storage.DeleteAlertRule(ruleID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete alert rule: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// ============================================
// 告警历史相关处理函数
// ============================================

// listAlertHistory 获取告警历史列表
func (s *APIServer) listAlertHistory(c *gin.Context) {
	ruleIDStr := c.Query("rule_id")
	hostID := c.Query("host_id")
	status := c.Query("status")
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	var ruleID *uint
	if ruleIDStr != "" {
		var id uint
		if _, err := fmt.Sscanf(ruleIDStr, "%d", &id); err == nil {
			ruleID = &id
		}
	}

	history, err := s.storage.ListAlertHistory(ruleID, hostID, status, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to list alert history: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    history,
	})
}

// getUnreadAlertCount 获取未读告警数量（firing状态的告警）
func (s *APIServer) getUnreadAlertCount(c *gin.Context) {
	history, err := s.storage.ListAlertHistory(nil, "", "firing", 10000) // 获取所有firing状态的告警，增加limit
	if err != nil {
		log.Printf("[getUnreadAlertCount] Failed to list alert history: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get unread alert count: " + err.Error(),
		})
		return
	}

	log.Printf("[getUnreadAlertCount] Found %d firing alerts", len(history))
	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    len(history),
	})
}

// getAlertHistory 获取告警历史详情
func (s *APIServer) getAlertHistory(c *gin.Context) {
	id := c.Param("id")
	var historyID uint
	if _, err := fmt.Sscanf(id, "%d", &historyID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid history ID",
		})
		return
	}

	history, err := s.storage.GetAlertHistory(historyID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Alert history not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    history,
	})
}

// deleteAlertHistory 删除告警历史
func (s *APIServer) deleteAlertHistory(c *gin.Context) {
	id := c.Param("id")
	var historyID uint
	if _, err := fmt.Sscanf(id, "%d", &historyID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid history ID",
		})
		return
	}

	if err := s.storage.DeleteAlertHistory(historyID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete alert history: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// deleteAlertHistories 批量删除告警历史
func (s *APIServer) deleteAlertHistories(c *gin.Context) {
	var request struct {
		IDs []uint `json:"ids" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	if len(request.IDs) == 0 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "No IDs provided",
		})
		return
	}

	if err := s.storage.DeleteAlertHistories(request.IDs); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete alert histories: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: fmt.Sprintf("Successfully deleted %d alert histories", len(request.IDs)),
	})
}

// ============================================
// 告警静默相关处理函数
// ============================================

// listAlertSilences 获取告警静默列表
func (s *APIServer) listAlertSilences(c *gin.Context) {
	enabledStr := c.Query("enabled")
	var enabled *bool
	if enabledStr != "" {
		e := enabledStr == "true"
		enabled = &e
	}

	silences, err := s.storage.ListAlertSilences(enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to list alert silences: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    silences,
	})
}

// createAlertSilence 创建告警静默
func (s *APIServer) createAlertSilence(c *gin.Context) {
	var silence AlertSilenceInfo
	if err := c.ShouldBindJSON(&silence); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// ShouldBindJSON 会自动解析 JSON 中的时间字符串
	// 如果时间字符串是 ISO 8601 格式（带 Z 或时区偏移），会正确解析为 UTC 时间
	// 如果时间字符串没有时区信息，Go 会将其当作 UTC 时间解析（这是正确的，因为前端已经转换为 UTC）
	// 所以这里不需要额外的解析逻辑

	created, err := s.storage.CreateAlertSilence(&silence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create alert silence: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    created,
	})
}

// updateAlertSilence 更新告警静默
func (s *APIServer) updateAlertSilence(c *gin.Context) {
	id := c.Param("id")
	var silenceID uint
	if _, err := fmt.Sscanf(id, "%d", &silenceID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid silence ID",
		})
		return
	}

	var silence AlertSilenceInfo
	if err := c.ShouldBindJSON(&silence); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	if err := s.storage.UpdateAlertSilence(silenceID, &silence); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update alert silence: " + err.Error(),
		})
		return
	}

	// 返回更新后的数据
	updatedSilence, err := s.storage.GetAlertSilence(silenceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get updated alert silence: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    updatedSilence,
	})
}

// deleteAlertSilence 删除告警静默
func (s *APIServer) deleteAlertSilence(c *gin.Context) {
	id := c.Param("id")
	var silenceID uint
	if _, err := fmt.Sscanf(id, "%d", &silenceID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid silence ID",
		})
		return
	}

	if err := s.storage.DeleteAlertSilence(silenceID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete alert silence: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// ============================================
// 通知渠道相关处理函数
// ============================================

// listNotificationChannels 获取通知渠道列表
func (s *APIServer) listNotificationChannels(c *gin.Context) {
	enabledStr := c.Query("enabled")
	var enabled *bool
	if enabledStr != "" {
		e := enabledStr == "true"
		enabled = &e
	}

	channels, err := s.storage.ListNotificationChannels(enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to list notification channels: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    channels,
	})
}

// createNotificationChannel 创建通知渠道
func (s *APIServer) createNotificationChannel(c *gin.Context) {
	var channel NotificationChannelInfo
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	created, err := s.storage.CreateNotificationChannel(&channel)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create notification channel: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    created,
	})
}

// testNotificationChannel 测试通知渠道
func (s *APIServer) testNotificationChannel(c *gin.Context) {
	var channel NotificationChannelInfo
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 验证必填字段
	if channel.Type == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Channel type is required",
		})
		return
	}

	// 根据类型验证必填配置
	if channel.Type == "email" {
		if channel.Config["smtp_host"] == "" {
			c.JSON(http.StatusBadRequest, Response{
				Code:    400,
				Message: "SMTP host is required for email channel",
			})
			return
		}
	} else if channel.Type == "dingtalk" || channel.Type == "wechat" || channel.Type == "feishu" {
		if channel.Config["webhook_url"] == "" {
			c.JSON(http.StatusBadRequest, Response{
				Code:    400,
				Message: "Webhook URL is required for " + channel.Type + " channel",
			})
			return
		}
	}

	// 使用反射或类型断言调用 NotificationManager 的 TestChannel 方法
	// 由于避免循环依赖，使用接口类型，需要通过反射调用
	nmValue := reflect.ValueOf(s.notificationManager)
	if !nmValue.IsValid() {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Notification manager not available",
		})
		return
	}

	testMethod := nmValue.MethodByName("TestChannel")
	if !testMethod.IsValid() {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "TestChannel method not found",
		})
		return
	}

	// 调用测试方法
	results := testMethod.Call([]reflect.Value{reflect.ValueOf(&channel)})
	if len(results) > 0 && !results[0].IsNil() {
		err := results[0].Interface().(error)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Test failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Test notification sent successfully",
	})
}

// getNotificationChannel 获取通知渠道
func (s *APIServer) getNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	var channelID uint
	if _, err := fmt.Sscanf(id, "%d", &channelID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid channel ID",
		})
		return
	}

	channel, err := s.storage.GetNotificationChannel(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Notification channel not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    channel,
	})
}

// updateNotificationChannel 更新通知渠道
func (s *APIServer) updateNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	var channelID uint
	if _, err := fmt.Sscanf(id, "%d", &channelID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid channel ID",
		})
		return
	}

	var channel NotificationChannelInfo
	if err := c.ShouldBindJSON(&channel); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	if err := s.storage.UpdateNotificationChannel(channelID, &channel); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update notification channel: " + err.Error(),
		})
		return
	}

	// 返回更新后的数据
	updatedChannel, err := s.storage.GetNotificationChannel(channelID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get updated notification channel: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    updatedChannel,
	})
}

// deleteNotificationChannel 删除通知渠道
func (s *APIServer) deleteNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	var channelID uint
	if _, err := fmt.Sscanf(id, "%d", &channelID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid channel ID",
		})
		return
	}

	if err := s.storage.DeleteNotificationChannel(channelID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete notification channel: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}
