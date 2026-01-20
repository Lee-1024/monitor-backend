// ============================================
// 文件: api/handlers.go
// ============================================
package api

import (
	"encoding/json"
	"fmt"
	"io"
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

// getCrashEvents 获取宕机事件列表（支持分页）
func (s *APIServer) getCrashEvents(c *gin.Context) {
	hostID := c.Query("host_id")
	
	// 检查是否使用分页参数
	pageStr := c.DefaultQuery("page", "")
	pageSizeStr := c.DefaultQuery("page_size", "")
	
	if pageStr != "" && pageSizeStr != "" {
		// 使用分页模式
		page, err := strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			page = 1
		}
		
		pageSize, err := strconv.Atoi(pageSizeStr)
		if err != nil || pageSize < 1 {
			pageSize = 20
		}
		if pageSize > 100 {
			pageSize = 100 // 限制最大每页数量
		}
		
		events, total, err := s.storage.GetCrashEventsWithPagination(hostID, page, pageSize)
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
			Data: map[string]interface{}{
				"events": events,
				"total":  total,
				"page":   page,
				"page_size": pageSize,
			},
		})
		return
	}
	
	// 兼容旧的非分页模式
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

// deleteCrashEvents 批量删除宕机事件
func (s *APIServer) deleteCrashEvents(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "No crash event IDs provided",
		})
		return
	}

	if err := s.storage.DeleteCrashEvents(req.IDs); err != nil {
		log.Printf("Failed to delete crash events: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete crash events: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: fmt.Sprintf("Successfully deleted %d crash event(s)", len(req.IDs)),
		Data:    map[string]interface{}{"deleted_count": len(req.IDs)},
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

// getLogs 获取日志列表（支持分页）
func (s *APIServer) getLogs(c *gin.Context) {
	hostID := c.Query("host_id")
	level := c.Query("level")
	
	var start, end time.Time
	if startStr := c.Query("start"); startStr != "" {
		start, _ = time.Parse(time.RFC3339, startStr)
	}
	if endStr := c.Query("end"); endStr != "" {
		end, _ = time.Parse(time.RFC3339, endStr)
	}

	// 检查是否使用分页参数
	pageStr := c.DefaultQuery("page", "")
	pageSizeStr := c.DefaultQuery("page_size", "")
	
	if pageStr != "" && pageSizeStr != "" {
		// 使用分页模式
		page, err := strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			page = 1
		}
		
		pageSize, err := strconv.Atoi(pageSizeStr)
		if err != nil || pageSize < 1 {
			pageSize = 20
		}
		if pageSize > 100 {
			pageSize = 100 // 限制最大每页数量
		}
		
		logs, total, err := s.storage.GetLogsWithPagination(hostID, level, start, end, page, pageSize)
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
			Data: map[string]interface{}{
				"logs":      logs,
				"total":     total,
				"page":      page,
				"page_size": pageSize,
			},
		})
		return
	}
	
	// 兼容旧的非分页模式
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
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
	if mountpoint, ok := updateData["mountpoint"].(string); ok {
		// mountpoint 可以为空字符串（表示不指定挂载点），所以不需要检查是否为空
		rule.Mountpoint = mountpoint
	}
	if servicePort, ok := updateData["service_port"].(float64); ok {
		rule.ServicePort = int(servicePort)
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

// 获取容量预测
func (s *APIServer) getCapacityPrediction(c *gin.Context) {
	hostID := c.Query("host_id")
	metricType := c.DefaultQuery("type", "cpu") // cpu, memory, disk
	days := c.DefaultQuery("days", "30")         // 预测未来多少天
	threshold := c.DefaultQuery("threshold", "80") // 阈值（百分比）

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	daysNum, err := strconv.Atoi(days)
	if err != nil || daysNum <= 0 {
		daysNum = 30
	}

	thresholdNum, err := strconv.ParseFloat(threshold, 64)
	if err != nil || thresholdNum <= 0 || thresholdNum > 100 {
		thresholdNum = 80
	}

	// 获取历史数据（用于预测）
	historyDays := daysNum * 2 // 获取2倍的历史数据用于分析
	if historyDays < 7 {
		historyDays = 7 // 至少7天
	}

	dataPoints, err := s.storage.GetPredictionData(hostID, metricType, historyDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get prediction data: " + err.Error(),
		})
		return
	}

	if len(dataPoints) < 2 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Insufficient historical data for prediction",
		})
		return
	}

	// 转换为预测器需要的格式
	points := make([]PredictionMetricPoint, len(dataPoints))
	for i, p := range dataPoints {
		points[i] = PredictionMetricPoint{p.Timestamp, p.Value}
	}

	// 使用预测器进行预测（通过接口调用）
	if s.predictor == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Predictor not initialized",
		})
		return
	}

	result, err := s.predictor.Predict(points, daysNum, thresholdNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to predict: " + err.Error(),
		})
		return
	}

	// 获取容量规划预测
	capacityPred, err := s.predictor.PredictCapacityNeeds(points, metricType, thresholdNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to predict capacity: " + err.Error(),
		})
		return
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID // 默认使用hostID
	if err != nil {
		log.Printf("Failed to get agent info: %v", err)
	} else if agent != nil {
		hostname = agent.Hostname
	}

	// 查询参数中是否包含enable_llm，如果为true才进行AI分析
	enableLLM := c.DefaultQuery("enable_llm", "false") == "true"
	
	var llmTaskID string
	if enableLLM {
		llmClient := s.llmManager.GetClient()
		if llmClient != nil && s.taskManager != nil {
			// 创建LLM分析任务
			llmReq := map[string]interface{}{
				"ResourceType":    metricType,
				"HostID":          hostID,
				"Hostname":        hostname,
				"CurrentUsage":    result.CurrentValue,
				"PredictedUsage":  result.PredictedValue,
				"DaysToThreshold": result.DaysToThreshold,
				"Trend":           result.Trend,
			}
			
			task, err := s.taskManager.CreateTask("capacity", llmReq)
			if err == nil {
				llmTaskID = task.ID
				// 异步处理任务
				go s.taskManager.ProcessCapacityAnalysisTask(task.ID, llmClient, llmReq)
			} else {
				log.Printf("Failed to create LLM task: %v", err)
			}
		}
	}

	response := map[string]interface{}{
		"prediction": result,
		"capacity":   capacityPred,
		"host": map[string]interface{}{
			"host_id":  hostID,
			"hostname": hostname,
		},
		"llm_task_id": llmTaskID, // 返回任务ID，前端轮询获取结果
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    response,
	})
}

// 获取成本优化建议
func (s *APIServer) getCostOptimization(c *gin.Context) {
	hostID := c.Query("host_id")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	llmClient := s.llmManager.GetClient()
	if llmClient == nil {
		c.JSON(http.StatusServiceUnavailable, Response{
			Code:    503,
			Message: "LLM service is not enabled",
		})
		return
	}

	// 检查预测器是否初始化
	if s.predictor == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Predictor not initialized",
		})
		return
	}

	// 获取所有资源的预测
	predictions := make(map[string]interface{})
	resourceTypes := []string{"cpu", "memory", "disk"}

	for _, resourceType := range resourceTypes {
		dataPoints, err := s.storage.GetPredictionData(hostID, resourceType, 30)
		if err != nil {
			log.Printf("Failed to get prediction data for %s/%s: %v", hostID, resourceType, err)
			continue
		}
		
		if len(dataPoints) < 2 {
			log.Printf("Insufficient data points for %s/%s: %d", hostID, resourceType, len(dataPoints))
			continue
		}

		points := make([]PredictionMetricPoint, len(dataPoints))
		for i, p := range dataPoints {
			points[i] = PredictionMetricPoint{p.Timestamp, p.Value}
		}

		result, err := s.predictor.Predict(points, 30, 80)
		if err != nil {
			log.Printf("Failed to predict for %s/%s: %v", hostID, resourceType, err)
			continue
		}
		predictions[resourceType] = result
	}

	// 检查是否有预测数据
	if len(predictions) == 0 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "No prediction data available for cost optimization",
		})
		return
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID // 默认使用hostID
	if err != nil {
		log.Printf("Failed to get agent info: %v", err)
	} else if agent != nil {
		hostname = agent.Hostname
	}

	// 如果启用了LLM，创建异步任务
	var llmTaskID string
	if llmClient != nil && s.taskManager != nil {
		// 创建成本优化任务
		taskParams := map[string]interface{}{
			"host_id":     hostID,
			"hostname":    hostname,
			"predictions": predictions,
		}
		
		task, err := s.taskManager.CreateTask("cost_optimization", taskParams)
		if err == nil {
			llmTaskID = task.ID
			// 异步处理任务
			go s.taskManager.ProcessCostOptimizationTask(task.ID, llmClient, hostID, hostname, predictions)
		} else {
			log.Printf("Failed to create LLM task: %v", err)
		}
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"host_id":     hostID,
			"hostname":    hostname,
			"predictions": predictions,
			"llm_task_id": llmTaskID, // 返回任务ID，前端轮询获取结果
		},
	})
}

// 获取LLM任务状态
func (s *APIServer) getLLMTaskStatus(c *gin.Context) {
	taskID := c.Param("task_id")
	
	if s.taskManager == nil {
		c.JSON(http.StatusServiceUnavailable, Response{
			Code:    503,
			Message: "Task manager not available",
		})
		return
	}

	task, err := s.taskManager.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Task not found: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    task,
	})
}

// streamCapacityAnalysis 流式获取容量分析（SSE）
func (s *APIServer) streamCapacityAnalysis(c *gin.Context) {
	hostID := c.Query("host_id")
	metricType := c.DefaultQuery("type", "cpu")
	days := c.DefaultQuery("days", "30")
	threshold := c.DefaultQuery("threshold", "80")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	daysNum, err := strconv.Atoi(days)
	if err != nil || daysNum <= 0 {
		daysNum = 30
	}

	thresholdNum, err := strconv.ParseFloat(threshold, 64)
	if err != nil || thresholdNum <= 0 || thresholdNum > 100 {
		thresholdNum = 80
	}

	// 获取历史数据
	historyDays := daysNum * 2
	if historyDays < 7 {
		historyDays = 7
	}

	dataPoints, err := s.storage.GetPredictionData(hostID, metricType, historyDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get prediction data: " + err.Error(),
		})
		return
	}

	if len(dataPoints) < 2 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Insufficient historical data for prediction",
		})
		return
	}

	// 转换为预测器需要的格式
	points := make([]PredictionMetricPoint, len(dataPoints))
	for i, p := range dataPoints {
		points[i] = PredictionMetricPoint{p.Timestamp, p.Value}
	}

	// 使用预测器进行预测
	if s.predictor == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Predictor not initialized",
		})
		return
	}

	result, err := s.predictor.Predict(points, daysNum, thresholdNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to predict: " + err.Error(),
		})
		return
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID
	if err != nil {
		log.Printf("Failed to get agent info: %v", err)
	} else if agent != nil {
		hostname = agent.Hostname
	}

	// 检查LLM是否可用
	llmClient := s.llmManager.GetClient()
	if llmClient == nil {
		c.JSON(http.StatusServiceUnavailable, Response{
			Code:    503,
			Message: "LLM service not available",
		})
		return
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // 禁用Nginx缓冲

	// 尝试通过类型断言获取 adapter，然后获取内部的 client
	// 由于无法直接导入 llm 包（避免循环导入），我们使用接口断言
	type ClientGetter interface {
		GetClient() interface{} // 返回 *LLMClient
	}
	
	var actualClient interface{}
	if getter, ok := llmClient.(ClientGetter); ok {
		actualClient = getter.GetClient()
	} else {
		// 如果 adapter 没有实现 GetClient，尝试通过反射调用
		llmClientValue := reflect.ValueOf(llmClient)
		if llmClientValue.Kind() == reflect.Ptr {
			llmClientValue = llmClientValue.Elem()
		}
		
		// 尝试调用 GetClient 方法
		getClientMethod := reflect.ValueOf(llmClient).MethodByName("GetClient")
		if getClientMethod.IsValid() {
			results := getClientMethod.Call(nil)
			if len(results) > 0 {
				actualClient = results[0].Interface()
			}
		}
	}
	
	// 如果无法获取实际的 client，回退到普通调用
	if actualClient == nil {
		log.Printf("[API] 无法获取LLM客户端实例，使用普通调用")
		response, err := llmClient.AnalyzeCapacity(map[string]interface{}{
			"ResourceType":    metricType,
			"HostID":          hostID,
			"Hostname":        hostname,
			"CurrentUsage":    result.CurrentValue,
			"PredictedUsage":  result.PredictedValue,
			"DaysToThreshold": result.DaysToThreshold,
			"Trend":           result.Trend,
		})
		if err != nil {
			log.Printf("[API] 分析失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
			return
		}
		content := formatAnalysisResponseForStream(response)
		chunk := map[string]interface{}{
			"content": content,
			"done":    true,
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
		c.Writer.Flush()
		return
	}
	
	// 通过反射调用 StreamCapacityAnalysis 方法
	streamMethod := reflect.ValueOf(actualClient).MethodByName("StreamCapacityAnalysis")
	if !streamMethod.IsValid() {
		log.Printf("[API] LLM客户端不支持流式输出，使用普通调用")
		// 回退到普通调用
		response, err := llmClient.AnalyzeCapacity(map[string]interface{}{
			"ResourceType":    metricType,
			"HostID":          hostID,
			"Hostname":        hostname,
			"CurrentUsage":    result.CurrentValue,
			"PredictedUsage":  result.PredictedValue,
			"DaysToThreshold": result.DaysToThreshold,
			"Trend":           result.Trend,
		})
		if err != nil {
			log.Printf("[API] 分析失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
			return
		}
		content := formatAnalysisResponseForStream(response)
		chunk := map[string]interface{}{
			"content": content,
			"done":    true,
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
		c.Writer.Flush()
		return
	}
	
	// 构建 AnalysisRequest（通过反射创建）
	// StreamCapacityAnalysis 方法签名: func (c *LLMClient) StreamCapacityAnalysis(req AnalysisRequest, writer io.Writer) error
	// 注意：req 是值类型，不是指针
	reqType := streamMethod.Type().In(0)
	
	// 创建值类型（不是指针）
	var reqValue reflect.Value
	if reqType.Kind() == reflect.Ptr {
		// 如果方法期望指针，创建指针
		reqValue = reflect.New(reqType.Elem())
	} else {
		// 如果方法期望值类型，创建值
		reqValue = reflect.New(reqType)
	}
	
	reqElem := reqValue.Elem()
	
	// 设置字段值
	if field := reqElem.FieldByName("ResourceType"); field.IsValid() && field.Kind() == reflect.String {
		field.SetString(metricType)
	}
	if field := reqElem.FieldByName("HostID"); field.IsValid() && field.Kind() == reflect.String {
		field.SetString(hostID)
	}
	if field := reqElem.FieldByName("Hostname"); field.IsValid() && field.Kind() == reflect.String {
		field.SetString(hostname)
	}
	if field := reqElem.FieldByName("CurrentUsage"); field.IsValid() && field.Kind() == reflect.Float64 {
		field.SetFloat(result.CurrentValue)
	}
	if field := reqElem.FieldByName("PredictedUsage"); field.IsValid() && field.Kind() == reflect.Float64 {
		field.SetFloat(result.PredictedValue)
	}
	if field := reqElem.FieldByName("DaysToThreshold"); field.IsValid() && field.Kind() == reflect.Float64 {
		field.SetFloat(result.DaysToThreshold)
	}
	if field := reqElem.FieldByName("Trend"); field.IsValid() && field.Kind() == reflect.String {
		field.SetString(result.Trend)
	}
	
	// 根据方法期望的类型传递参数
	var callArg reflect.Value
	if reqType.Kind() == reflect.Ptr {
		// 方法期望指针，传递指针
		callArg = reqValue
	} else {
		// 方法期望值类型，传递值（不是指针）
		callArg = reqElem
	}
	
	// 调用流式方法
	log.Printf("[API] 使用流式分析，参数类型: %v, 传递类型: %v", reqType, callArg.Type())
	results := streamMethod.Call([]reflect.Value{
		callArg,
		reflect.ValueOf(c.Writer),
	})
	
	if len(results) > 0 && !results[0].IsNil() {
		// 有错误
		if err, ok := results[0].Interface().(error); ok {
			log.Printf("[API] 流式分析失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
		}
	}
}

// formatAnalysisResponseForStream 格式化分析响应为流式文本
func formatAnalysisResponseForStream(resp interface{}) string {
	// 使用反射获取响应内容
	rv := reflect.ValueOf(resp)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	
	var result strings.Builder
	
	// 尝试获取常见字段
	if summary := rv.FieldByName("Summary"); summary.IsValid() && summary.Kind() == reflect.String {
		if s := summary.String(); s != "" {
			result.WriteString("## 摘要\n\n")
			result.WriteString(s)
			result.WriteString("\n\n")
		}
	}
	
	if analysis := rv.FieldByName("Analysis"); analysis.IsValid() && analysis.Kind() == reflect.String {
		if s := analysis.String(); s != "" {
			result.WriteString("## 详细分析\n\n")
			result.WriteString(s)
			result.WriteString("\n\n")
		}
	}
	
	if recs := rv.FieldByName("Recommendations"); recs.IsValid() && recs.Kind() == reflect.Slice {
		if recs.Len() > 0 {
			result.WriteString("## 建议\n\n")
			for i := 0; i < recs.Len(); i++ {
				rec := recs.Index(i)
				if rec.Kind() == reflect.String {
					result.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec.String()))
				}
			}
			result.WriteString("\n")
		}
	}
	
	if costOpt := rv.FieldByName("CostOptimization"); costOpt.IsValid() && costOpt.Kind() == reflect.String {
		if s := costOpt.String(); s != "" {
			result.WriteString("## 成本优化建议\n\n")
			result.WriteString(s)
			result.WriteString("\n\n")
		}
	}
	
	if risks := rv.FieldByName("Risks"); risks.IsValid() && risks.Kind() == reflect.Slice {
		if risks.Len() > 0 {
			result.WriteString("## 风险提示\n\n")
			for i := 0; i < risks.Len(); i++ {
				risk := risks.Index(i)
				if risk.Kind() == reflect.String {
					result.WriteString(fmt.Sprintf("%d. %s\n", i+1, risk.String()))
				}
			}
		}
	}
	
	return result.String()
}

// streamCostOptimization 流式获取成本优化建议（SSE）
func (s *APIServer) streamCostOptimization(c *gin.Context) {
	hostID := c.Query("host_id")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	// 检查预测器是否初始化
	if s.predictor == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Predictor not initialized",
		})
		return
	}

	// 获取所有资源的预测
	predictions := make(map[string]interface{})
	resourceTypes := []string{"cpu", "memory", "disk"}

	for _, resourceType := range resourceTypes {
		dataPoints, err := s.storage.GetPredictionData(hostID, resourceType, 30)
		if err != nil {
			log.Printf("Failed to get prediction data for %s/%s: %v", hostID, resourceType, err)
			continue
		}
		
		if len(dataPoints) < 2 {
			log.Printf("Insufficient data points for %s/%s: %d", hostID, resourceType, len(dataPoints))
			continue
		}

		points := make([]PredictionMetricPoint, len(dataPoints))
		for i, p := range dataPoints {
			points[i] = PredictionMetricPoint{p.Timestamp, p.Value}
		}

		result, err := s.predictor.Predict(points, 30, 80)
		if err != nil {
			log.Printf("Failed to predict for %s/%s: %v", hostID, resourceType, err)
			continue
		}
		predictions[resourceType] = result
	}

	// 检查是否有预测数据
	if len(predictions) == 0 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "No prediction data available for cost optimization",
		})
		return
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID // 默认使用hostID
	if err != nil {
		log.Printf("Failed to get agent info: %v", err)
	} else if agent != nil {
		hostname = agent.Hostname
	}

	// 检查LLM是否可用
	llmClient := s.llmManager.GetClient()
	if llmClient == nil {
		c.JSON(http.StatusServiceUnavailable, Response{
			Code:    503,
			Message: "LLM service not available",
		})
		return
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // 禁用Nginx缓冲

	// 尝试通过类型断言获取 adapter，然后获取内部的 client
	type ClientGetter interface {
		GetClient() interface{} // 返回 *LLMClient
	}
	
	var actualClient interface{}
	if getter, ok := llmClient.(ClientGetter); ok {
		actualClient = getter.GetClient()
	} else {
		// 如果 adapter 没有实现 GetClient，尝试通过反射调用
		llmClientValue := reflect.ValueOf(llmClient)
		if llmClientValue.Kind() == reflect.Ptr {
			llmClientValue = llmClientValue.Elem()
		}
		
		// 尝试调用 GetClient 方法
		getClientMethod := reflect.ValueOf(llmClient).MethodByName("GetClient")
		if getClientMethod.IsValid() {
			results := getClientMethod.Call(nil)
			if len(results) > 0 {
				actualClient = results[0].Interface()
			}
		}
	}
	
	// 如果无法获取实际的 client，回退到普通调用
	if actualClient == nil {
		log.Printf("[API] 无法获取LLM客户端实例，使用普通调用")
		response, err := llmClient.GenerateCostOptimization(hostID, hostname, predictions)
		if err != nil {
			log.Printf("[API] 成本优化分析失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
			return
		}
		chunk := map[string]interface{}{
			"content": response,
			"done":    true,
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
		c.Writer.Flush()
		return
	}
	
	// 通过反射调用 StreamCostOptimization 方法
	streamMethod := reflect.ValueOf(actualClient).MethodByName("StreamCostOptimization")
	if !streamMethod.IsValid() {
		log.Printf("[API] LLM客户端不支持流式输出，使用普通调用")
		// 回退到普通调用
		response, err := llmClient.GenerateCostOptimization(hostID, hostname, predictions)
		if err != nil {
			log.Printf("[API] 成本优化分析失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
			return
		}
		chunk := map[string]interface{}{
			"content": response,
			"done":    true,
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
		c.Writer.Flush()
		return
	}
	
	// StreamCostOptimization 方法签名: func (c *LLMClient) StreamCostOptimization(hostID, hostname string, predictions map[string]interface{}, writer io.Writer) error
	// 调用流式方法
	log.Printf("[API] 使用流式成本优化分析")
	results := streamMethod.Call([]reflect.Value{
		reflect.ValueOf(hostID),
		reflect.ValueOf(hostname),
		reflect.ValueOf(predictions),
		reflect.ValueOf(c.Writer),
	})
	
	if len(results) > 0 && !results[0].IsNil() {
		// 有错误
		if err, ok := results[0].Interface().(error); ok {
			log.Printf("[API] 流式成本优化分析失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
		}
	}
}

// generateSimpleCostOptimization 生成简单的成本优化建议（当LLM不可用时）
func generateSimpleCostOptimization(predictions map[string]interface{}, hostname string) string {
	var recommendations []string
	
	for resourceType, predData := range predictions {
		if predMap, ok := predData.(map[string]interface{}); ok {
			currentValue, _ := predMap["current_value"].(float64)
			predictedValue, _ := predMap["predicted_value"].(float64)
			daysToThreshold, _ := predMap["days_to_threshold"].(float64)
			trend, _ := predMap["trend"].(string)
			
			resourceName := map[string]string{
				"cpu":    "CPU",
				"memory": "内存",
				"disk":   "磁盘",
			}[resourceType]
			
			if daysToThreshold > 0 && daysToThreshold < 30 {
				recommendations = append(recommendations, 
					fmt.Sprintf("%s使用率预计在%.0f天内达到阈值，建议提前规划扩容。", resourceName, daysToThreshold))
			} else if trend == "increasing" && predictedValue > currentValue {
				recommendations = append(recommendations,
					fmt.Sprintf("%s使用率呈上升趋势（当前%.1f%%，预测%.1f%%），建议关注资源使用情况。", resourceName, currentValue, predictedValue))
			} else if currentValue > 80 {
				recommendations = append(recommendations,
					fmt.Sprintf("%s使用率较高（%.1f%%），建议考虑优化或扩容。", resourceName, currentValue))
			}
		}
	}
	
	if len(recommendations) == 0 {
		return fmt.Sprintf("主机 %s 的资源使用情况良好，暂无紧急优化建议。建议定期监控资源使用趋势。", hostname)
	}
	
	return fmt.Sprintf("基于 %s 的资源使用预测分析，建议如下：\n\n%s\n\n建议定期监控资源使用情况，并根据实际业务需求进行优化。", 
		hostname, strings.Join(recommendations, "\n"))
}

// 获取LLM模型配置列表
func (s *APIServer) listLLMModelConfigs(c *gin.Context) {
	enabledStr := c.Query("enabled")
	var enabled *bool
	if enabledStr != "" {
		enabledVal := enabledStr == "true"
		enabled = &enabledVal
	}

	configs, err := s.storage.ListLLMModelConfigs(enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to list LLM model configs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    configs,
	})
}

// 创建LLM模型配置
func (s *APIServer) createLLMModelConfig(c *gin.Context) {
	var config LLMModelConfigInfo
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 验证必填字段
	if config.Name == "" || config.Provider == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Name and provider are required",
		})
		return
	}

	result, err := s.storage.CreateLLMModelConfig(&config)
	if err != nil {
		// 检查是否是唯一约束冲突（配置名称重复）
		if strings.Contains(err.Error(), "已存在") || strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusBadRequest, Response{
				Code:    400,
				Message: err.Error(),
			})
			return
		}
		log.Printf("[API] 创建LLM配置失败: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to create LLM model config: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    result,
	})
}

// 更新LLM模型配置
func (s *APIServer) updateLLMModelConfig(c *gin.Context) {
	id := c.Param("id")
	var configID uint
	if _, err := fmt.Sscanf(id, "%d", &configID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid config ID",
		})
		return
	}

	var config LLMModelConfigInfo
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	if err := s.storage.UpdateLLMModelConfig(configID, &config); err != nil {
		// 检查是否是唯一约束冲突（配置名称重复）
		if strings.Contains(err.Error(), "已存在") || strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusBadRequest, Response{
				Code:    400,
				Message: err.Error(),
			})
			return
		}
		log.Printf("[API] 更新LLM配置失败: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to update LLM model config: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// 删除LLM模型配置
func (s *APIServer) deleteLLMModelConfig(c *gin.Context) {
	id := c.Param("id")
	var configID uint
	if _, err := fmt.Sscanf(id, "%d", &configID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid config ID",
		})
		return
	}

	if err := s.storage.DeleteLLMModelConfig(configID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to delete LLM model config: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// 获取LLM模型配置
func (s *APIServer) getLLMModelConfig(c *gin.Context) {
	id := c.Param("id")
	var configID uint
	if _, err := fmt.Sscanf(id, "%d", &configID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid config ID",
		})
		return
	}

	config, err := s.storage.GetLLMModelConfig(configID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get LLM model config: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    config,
	})
}

// 设置默认LLM模型配置
func (s *APIServer) setDefaultLLMModelConfig(c *gin.Context) {
	id := c.Param("id")
	var configID uint
	if _, err := fmt.Sscanf(id, "%d", &configID); err != nil {
		log.Printf("[LLM] 设置默认配置失败: 无效的ID: %s, 错误: %v", id, err)
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid config ID",
		})
		return
	}

	log.Printf("[LLM] 开始设置默认配置，ID: %d", configID)
	if err := s.storage.SetDefaultLLMModelConfig(configID); err != nil {
		log.Printf("[LLM] 设置默认配置失败: %v", err)
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to set default LLM model config: " + err.Error(),
		})
		return
	}

	// 验证设置是否成功
	config, err := s.storage.GetLLMModelConfig(configID)
	if err != nil {
		log.Printf("[LLM] 警告: 设置默认配置后无法验证，ID: %d, 错误: %v", configID, err)
	} else {
		log.Printf("[LLM] 默认配置设置成功，ID: %d, 名称: %s, is_default: %v", configID, config.Name, config.IsDefault)
	}

	// 重新加载LLM配置
	if s.llmManager != nil {
		if reloader, ok := s.llmManager.(interface{ Reload() }); ok {
			reloader.Reload()
			log.Printf("[LLM] LLM管理器已重新加载")
		}
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
	})
}

// 测试LLM模型配置
func (s *APIServer) testLLMModelConfig(c *gin.Context) {
	var config LLMModelConfigInfo
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// 验证必填字段
	if config.Provider == "" || config.APIKey == "" || config.Model == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Provider, API key and model are required",
		})
		return
	}

	// 使用LLM管理器创建临时客户端进行测试
	// 通过反射或接口调用，避免直接导入llm包造成循环依赖
	// 这里我们创建一个临时的测试配置并调用测试方法
	
	// 由于存在循环导入问题，我们需要通过其他方式测试
	// 最简单的方式是创建一个临时的LLM配置并保存到数据库，然后使用管理器测试
	// 或者直接在handler中实现测试逻辑
	
	// 临时方案：通过HTTP客户端直接测试API
	testResult := s.testLLMConnection(config)
	
	if !testResult.Success {
		c.JSON(http.StatusOK, Response{
			Code:    500,
			Message: "测试失败: " + testResult.Error,
			Data: map[string]interface{}{
				"success": false,
				"error":   testResult.Error,
			},
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "测试成功",
		Data: map[string]interface{}{
			"success":  true,
			"response": testResult.Response,
			"provider": config.Provider,
			"model":    config.Model,
		},
	})
}

// testLLMConnection 测试LLM连接（避免循环导入）
type testResult struct {
	Success  bool
	Response string
	Error    string
}

func (s *APIServer) testLLMConnection(config LLMModelConfigInfo) testResult {
	// 设置默认值
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30
	}
	maxTokens := config.MaxTokens
	if maxTokens == 0 {
		maxTokens = 100
	}
	temperature := config.Temperature
	if temperature == 0 {
		temperature = 0.7
	}

	// 构建测试请求
	testPrompt := "这是一个连接测试。请回复'测试成功'以确认连接正常。"
	
	// 根据不同的提供商构建不同的请求
	var url string
	var requestBody map[string]interface{}
	var headers map[string]string

	switch config.Provider {
	case "openai", "deepseek":
		if config.BaseURL != "" {
			url = config.BaseURL
		} else if config.Provider == "deepseek" {
			url = "https://api.deepseek.com/v1/chat/completions"
		} else {
			url = "https://api.openai.com/v1/chat/completions"
		}
		requestBody = map[string]interface{}{
			"model": config.Model,
			"messages": []map[string]interface{}{
				{
					"role":    "user",
					"content": testPrompt,
				},
			},
			"temperature": temperature,
			"max_tokens":  maxTokens,
		}
		headers = map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + config.APIKey,
		}
	case "claude":
		if config.BaseURL != "" {
			url = config.BaseURL
		} else {
			url = "https://api.anthropic.com/v1/messages"
		}
		requestBody = map[string]interface{}{
			"model": config.Model,
			"max_tokens": maxTokens,
			"messages": []map[string]interface{}{
				{
					"role":    "user",
					"content": testPrompt,
				},
			},
		}
		headers = map[string]string{
			"Content-Type":      "application/json",
			"x-api-key":         config.APIKey,
			"anthropic-version": "2023-06-01",
		}
	case "qwen":
		if config.BaseURL != "" {
			url = config.BaseURL
		} else {
			url = "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
		}
		requestBody = map[string]interface{}{
			"model": config.Model,
			"input": map[string]interface{}{
				"messages": []map[string]interface{}{
					{
						"role":    "user",
						"content": testPrompt,
					},
				},
			},
			"parameters": map[string]interface{}{
				"temperature": temperature,
				"max_tokens":   maxTokens,
			},
		}
		headers = map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + config.APIKey,
		}
	case "doubao":
		if config.BaseURL != "" {
			url = config.BaseURL
		} else {
			url = "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
		}
		requestBody = map[string]interface{}{
			"model": config.Model,
			"messages": []map[string]interface{}{
				{
					"role":    "user",
					"content": testPrompt,
				},
			},
			"temperature": temperature,
			"max_tokens":  maxTokens,
		}
		headers = map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + config.APIKey,
		}
	case "zhipu":
		if config.BaseURL != "" {
			url = config.BaseURL
		} else {
			url = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
		}
		requestBody = map[string]interface{}{
			"model": config.Model,
			"messages": []map[string]interface{}{
				{
					"role":    "user",
					"content": testPrompt,
				},
			},
			"temperature": temperature,
			"max_tokens":  maxTokens,
		}
		headers = map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + config.APIKey,
		}
	case "custom":
		log.Printf("[LLM Test] ========== 开始测试自定义模型 ==========")
		log.Printf("[LLM Test] Provider: %s", config.Provider)
		log.Printf("[LLM Test] BaseURL: %s", config.BaseURL)
		log.Printf("[LLM Test] Model: %s", config.Model)
		log.Printf("[LLM Test] API Key长度: %d", len(config.APIKey))
		log.Printf("[LLM Test] Temperature: %f", temperature)
		log.Printf("[LLM Test] Max Tokens: %d", maxTokens)
		
		if config.BaseURL == "" {
			log.Printf("[LLM Test] 错误: BaseURL为空")
			return testResult{
				Success: false,
				Error:   "自定义API需要提供base_url",
			}
		}
		url = strings.TrimSpace(config.BaseURL)
		log.Printf("[LLM Test] 清理后的URL: %s", url)
		
		// 判断是否使用OpenAI兼容格式
		useOpenAIFormat := strings.Contains(url, "chat/completions") || config.Model != ""
		log.Printf("[LLM Test] 格式检测: useOpenAIFormat=%v (URL包含chat/completions: %v, 有model: %v)", 
			useOpenAIFormat, strings.Contains(url, "chat/completions"), config.Model != "")
		
		if useOpenAIFormat {
			// 使用OpenAI兼容格式
			model := config.Model
			if model == "" {
				model = "gpt-3.5-turbo"
			}
			log.Printf("[LLM Test] 使用OpenAI兼容格式，模型: %s", model)
			requestBody = map[string]interface{}{
				"model": model,
				"messages": []map[string]interface{}{
					{
						"role":    "user",
						"content": testPrompt,
					},
				},
				"temperature": temperature,
				"max_tokens":  maxTokens,
			}
		} else {
			// 使用简单格式
			log.Printf("[LLM Test] 使用简单格式")
			requestBody = map[string]interface{}{
				"prompt":      testPrompt,
				"temperature": temperature,
				"max_tokens":  maxTokens,
			}
		}
		
		headers = map[string]string{
			"Content-Type": "application/json",
		}
		if config.APIKey != "" {
			headers["Authorization"] = "Bearer " + config.APIKey
			log.Printf("[LLM Test] 已设置Authorization头")
		} else {
			log.Printf("[LLM Test] 警告: 未设置API Key")
		}
	default:
		return testResult{
			Success: false,
			Error:   "不支持的提供商: " + config.Provider,
		}
	}

	// 发送HTTP请求
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[LLM Test] 错误: JSON序列化失败: %v", err)
		return testResult{
			Success: false,
			Error:   "构建请求失败: " + err.Error(),
		}
	}

	log.Printf("[LLM Test] 请求体大小: %d 字节", len(jsonData))
	if len(jsonData) < 500 {
		log.Printf("[LLM Test] 请求体内容: %s", string(jsonData))
	} else {
		log.Printf("[LLM Test] 请求体内容(前500字符): %s", string(jsonData[:500]))
	}

	log.Printf("[LLM Test] 创建HTTP请求到: %s", url)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		log.Printf("[LLM Test] 错误: 创建请求失败: %v", err)
		return testResult{
			Success: false,
			Error:   "创建请求失败: " + err.Error(),
		}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
		if k == "Authorization" {
			log.Printf("[LLM Test] 请求头: %s=%s (长度: %d)", k, "Bearer ***", len(v))
		} else {
			log.Printf("[LLM Test] 请求头: %s=%s", k, v)
		}
	}

	log.Printf("[LLM Test] 发送HTTP请求...")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[LLM Test] 错误: HTTP请求执行失败: %v", err)
		return testResult{
			Success: false,
			Error:   "请求失败: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	log.Printf("[LLM Test] HTTP响应状态: %s (状态码: %d)", resp.Status, resp.StatusCode)
	log.Printf("[LLM Test] 响应头: %+v", resp.Header)

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Printf("[LLM Test] 错误: 读取响应体失败: %v", readErr)
		return testResult{
			Success: false,
			Error:   "读取响应体失败: " + readErr.Error(),
		}
	}

	log.Printf("[LLM Test] 响应体大小: %d 字节", len(bodyBytes))
	if len(bodyBytes) < 1000 {
		log.Printf("[LLM Test] 响应体内容: %s", string(bodyBytes))
	} else {
		log.Printf("[LLM Test] 响应体内容(前1000字符): %s", string(bodyBytes[:1000]))
		log.Printf("[LLM Test] 响应体内容(后500字符): %s", string(bodyBytes[len(bodyBytes)-500:]))
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[LLM Test] 错误: API返回非200状态码: %d", resp.StatusCode)
		log.Printf("[LLM Test] 完整错误响应: %s", string(bodyBytes))
		return testResult{
			Success: false,
			Error:   fmt.Sprintf("API返回错误: %s (状态码: %d), 响应: %s", resp.Status, resp.StatusCode, string(bodyBytes)),
		}
	}

	// 解析响应（使用已读取的bodyBytes）
	log.Printf("[LLM Test] 开始解析响应JSON...")
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		log.Printf("[LLM Test] 错误: JSON解析失败: %v", err)
		log.Printf("[LLM Test] 尝试解析的响应体: %s", string(bodyBytes))
		return testResult{
			Success: false,
			Error:   "解析响应失败: " + err.Error(),
		}
	}
	log.Printf("[LLM Test] JSON解析成功")

	// 提取响应文本（根据不同提供商的响应格式）
	var responseText string
	switch config.Provider {
	case "openai", "deepseek", "doubao", "zhipu":
		if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						responseText = content
					}
				}
			}
		}
	case "claude":
		if content, ok := result["content"].([]interface{}); ok && len(content) > 0 {
			if text, ok := content[0].(map[string]interface{}); ok {
				if txt, ok := text["text"].(string); ok {
					responseText = txt
				}
			}
		}
	case "qwen":
		if output, ok := result["output"].(map[string]interface{}); ok {
			if choices, ok := output["choices"].([]interface{}); ok && len(choices) > 0 {
				if choice, ok := choices[0].(map[string]interface{}); ok {
					if message, ok := choice["message"].(map[string]interface{}); ok {
						if content, ok := message["content"].(string); ok {
							responseText = content
						}
					}
				}
			}
		}
	case "custom":
		// 自定义API可能返回OpenAI兼容格式或简单格式
		// 优先尝试OpenAI兼容格式（choices[0].message.content）
		if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						responseText = content
						log.Printf("[LLM Test] 从OpenAI兼容格式提取内容: %s", responseText)
					}
				}
			}
		}
		// 如果OpenAI格式没有内容，尝试简单格式
		if responseText == "" {
			if content, ok := result["content"].(string); ok {
				responseText = content
				log.Printf("[LLM Test] 从简单格式content字段提取内容: %s", responseText)
			} else if text, ok := result["text"].(string); ok {
				responseText = text
				log.Printf("[LLM Test] 从简单格式text字段提取内容: %s", responseText)
			} else if resp, ok := result["response"].(string); ok {
				responseText = resp
				log.Printf("[LLM Test] 从简单格式response字段提取内容: %s", responseText)
			}
		}
	}

	if responseText == "" {
		log.Printf("[LLM Test] 警告: 未能从响应中提取内容")
		log.Printf("[LLM Test] 响应结构: %+v", result)
		responseText = "连接成功，但未收到有效响应内容"
	} else {
		log.Printf("[LLM Test] 成功提取响应内容，长度: %d 字符", len(responseText))
	}

	return testResult{
		Success:  true,
		Response: responseText,
	}
}

// 通过ID测试LLM模型配置
func (s *APIServer) testLLMModelConfigByID(c *gin.Context) {
	id := c.Param("id")
	var configID uint
	if _, err := fmt.Sscanf(id, "%d", &configID); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid config ID",
		})
		return
	}

	// 从数据库获取完整配置（包括完整API密钥）
	config, err := s.storage.GetLLMModelConfigWithKey(configID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get LLM model config: " + err.Error(),
		})
		return
	}

	// 测试连接
	testResult := s.testLLMConnection(*config)
	
	if !testResult.Success {
		c.JSON(http.StatusOK, Response{
			Code:    500,
			Message: "测试失败: " + testResult.Error,
			Data: map[string]interface{}{
				"success": false,
				"error":   testResult.Error,
			},
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "测试成功",
		Data: map[string]interface{}{
			"success":  true,
			"response": testResult.Response,
			"provider": config.Provider,
			"model":    config.Model,
		},
	})
}
