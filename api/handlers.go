// ============================================
// 文件: api/handlers.go
// ============================================
package api

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
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

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
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
