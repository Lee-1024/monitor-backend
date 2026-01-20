// ============================================
// 文件: api/anomaly_handlers.go
// 异常检测相关接口
// ============================================
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// detectAnomalies 检测异常（指标和日志）
func (s *APIServer) detectAnomalies(c *gin.Context) {
	hostID := c.Query("host_id")
	metricType := c.DefaultQuery("metric_type", "") // cpu, memory, disk，空表示全部
	hours := c.DefaultQuery("hours", "24")         // 检测最近N小时的数据

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	hoursNum, err := strconv.Atoi(hours)
	if err != nil || hoursNum <= 0 {
		hoursNum = 24
	}

	// 获取异常检测器
	var detector AnomalyDetectorInterface
	if s.anomalyDetector != nil {
		if d, ok := s.anomalyDetector.(AnomalyDetectorInterface); ok {
			detector = d
		}
	}

	if detector == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Anomaly detector not initialized",
		})
		return
	}

	var allAnomalies []AnomalyDetectionResult

	// 1. 检测指标异常
	resourceTypes := []string{"cpu", "memory", "disk"}
	if metricType != "" {
		resourceTypes = []string{metricType}
	}

	metricsData := make(map[string][]AnomalyMetricDataPoint)
	for _, rt := range resourceTypes {
		// 获取历史指标数据
		endTime := time.Now()
		startTime := endTime.Add(-time.Duration(hoursNum) * time.Hour)
		
		// 获取更多历史数据以确保有足够的数据点（至少需要2倍的时间范围）
		days := (hoursNum * 2) / 24
		if days < 1 {
			days = 1
		}
		
		dataPoints, err := s.storage.GetPredictionData(hostID, rt, days)
		if err != nil {
			log.Printf("Failed to get prediction data for %s/%s: %v", hostID, rt, err)
			continue
		}

		if len(dataPoints) == 0 {
			log.Printf("No data points found for %s/%s", hostID, rt)
			continue
		}

		// 转换为异常检测器需要的格式
		metricPoints := make([]AnomalyMetricDataPoint, 0, len(dataPoints))
		for _, dp := range dataPoints {
			// 只使用指定时间范围内的数据（包含边界值）
			if (dp.Timestamp.Equal(startTime) || dp.Timestamp.After(startTime)) && 
			   (dp.Timestamp.Equal(endTime) || dp.Timestamp.Before(endTime)) {
				metricPoints = append(metricPoints, AnomalyMetricDataPoint{
					Timestamp: dp.Timestamp,
					Value:     dp.Value,
				})
			}
		}

		log.Printf("Anomaly detection: %s/%s - total data points: %d, filtered points: %d", hostID, rt, len(dataPoints), len(metricPoints))

		if len(metricPoints) < 10 {
			log.Printf("Insufficient data points for anomaly detection %s/%s: %d (need at least 10)", hostID, rt, len(metricPoints))
			continue
		}

		metricsData[rt] = metricPoints

		// 检测异常
		anomalies, err := detector.DetectMetricAnomalies(hostID, rt, metricPoints)
		if err != nil {
			log.Printf("Failed to detect anomalies for %s/%s: %v", hostID, rt, err)
			continue
		}

		log.Printf("Detected %d anomalies for %s/%s", len(anomalies), hostID, rt)
		allAnomalies = append(allAnomalies, anomalies...)
	}

	// 2. 检测日志异常
	endTime2 := time.Now()
	startTime2 := endTime2.Add(-time.Duration(hoursNum) * time.Hour)
	logs, err := s.storage.GetLogs(hostID, "", startTime2, endTime2, 1000)
	if err == nil && len(logs) > 0 {
		// 转换为异常检测器需要的格式
		logInfos := make([]AnomalyLogInfo, len(logs))
		for i, log := range logs {
			logInfos[i] = AnomalyLogInfo{
				ID:        log.ID,
				Timestamp: log.Timestamp,
				Source:    log.Source,
				Level:     log.Level,
				Message:   log.Message,
			}
		}

		logAnomalies, err := detector.DetectLogAnomalies(hostID, logInfos)
		if err == nil {
			allAnomalies = append(allAnomalies, logAnomalies...)
		}
	}

	// 3. 分析根因并生成建议
	anomalyEvents := make([]AnomalyEventInfo, 0, len(allAnomalies))
	for _, anomaly := range allAnomalies {
		// 分析根因
		rootCause := detector.AnalyzeRootCause(anomaly, metricsData, nil)
		
		// 生成建议
		recommendations := detector.GenerateRecommendations(anomaly)

		// 获取相关日志
		var relatedLogs []LogInfo
		if len(anomaly.RelatedLogs) > 0 {
			logIDs := make([]uint, len(anomaly.RelatedLogs))
			for i, logInfo := range anomaly.RelatedLogs {
				logIDs[i] = logInfo.ID
			}
			// 获取日志详情
			for _, logID := range logIDs {
				logs, _ := s.storage.GetLogs(hostID, "", time.Time{}, time.Time{}, 1000)
				for _, log := range logs {
					if log.ID == logID {
						relatedLogs = append(relatedLogs, log)
						break
					}
				}
			}
		}

		event := AnomalyEventInfo{
			HostID:          anomaly.HostID,
			Type:            anomaly.Type,
			Severity:        anomaly.Severity,
			MetricType:      anomaly.MetricType,
			Timestamp:       anomaly.Timestamp,
			Value:           anomaly.Value,
			ExpectedValue:   anomaly.ExpectedValue,
			Deviation:       anomaly.Deviation,
			Confidence:      anomaly.Confidence,
			Message:         anomaly.Message,
			RootCause:       rootCause,
			RelatedLogs:     relatedLogs,
			RelatedMetrics:  anomaly.RelatedMetrics,
			Recommendations: recommendations,
			IsResolved:      false,
		}

		// 保存到数据库
		if err := s.storage.CreateAnomalyEvent(&event); err != nil {
			log.Printf("Failed to save anomaly event: %v", err)
		}

		anomalyEvents = append(anomalyEvents, event)
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"anomalies": anomalyEvents,
			"count":     len(anomalyEvents),
		},
	})
}

// streamAnomalyAnalysis 流式获取异常分析（SSE）
func (s *APIServer) streamAnomalyAnalysis(c *gin.Context) {
	hostID := c.Query("host_id")
	metricType := c.DefaultQuery("metric_type", "")
	hours := c.DefaultQuery("hours", "24")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "host_id is required",
		})
		return
	}

	hoursNum, err := strconv.Atoi(hours)
	if err != nil || hoursNum <= 0 {
		hoursNum = 24
	}

	// 先执行异常检测（复用现有逻辑）
	// 获取异常检测器
	var detector AnomalyDetectorInterface
	if s.anomalyDetector != nil {
		if d, ok := s.anomalyDetector.(AnomalyDetectorInterface); ok {
			detector = d
		}
	}

	if detector == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Anomaly detector not initialized",
		})
		return
	}

	var allAnomalies []AnomalyDetectionResult

	// 检测指标异常
	resourceTypes := []string{"cpu", "memory", "disk"}
	if metricType != "" {
		resourceTypes = []string{metricType}
	}

	metricsData := make(map[string][]AnomalyMetricDataPoint)
	for _, rt := range resourceTypes {
		endTime := time.Now()
		startTime := endTime.Add(-time.Duration(hoursNum) * time.Hour)
		
		days := (hoursNum * 2) / 24
		if days < 1 {
			days = 1
		}
		
		dataPoints, err := s.storage.GetPredictionData(hostID, rt, days)
		if err != nil {
			log.Printf("Failed to get prediction data for %s/%s: %v", hostID, rt, err)
			continue
		}

		if len(dataPoints) == 0 {
			continue
		}

		metricPoints := make([]AnomalyMetricDataPoint, 0, len(dataPoints))
		for _, dp := range dataPoints {
			if (dp.Timestamp.Equal(startTime) || dp.Timestamp.After(startTime)) && 
			   (dp.Timestamp.Equal(endTime) || dp.Timestamp.Before(endTime)) {
				metricPoints = append(metricPoints, AnomalyMetricDataPoint{
					Timestamp: dp.Timestamp,
					Value:     dp.Value,
				})
			}
		}

		if len(metricPoints) < 10 {
			continue
		}

		metricsData[rt] = metricPoints
		anomalies, err := detector.DetectMetricAnomalies(hostID, rt, metricPoints)
		if err != nil {
			continue
		}
		allAnomalies = append(allAnomalies, anomalies...)
	}

	// 检测日志异常
	endTime2 := time.Now()
	startTime2 := endTime2.Add(-time.Duration(hoursNum) * time.Hour)
	logs, err := s.storage.GetLogs(hostID, "", startTime2, endTime2, 1000)
	if err == nil && len(logs) > 0 {
		logInfos := make([]AnomalyLogInfo, len(logs))
		for i, log := range logs {
			logInfos[i] = AnomalyLogInfo{
				ID:        log.ID,
				Timestamp: log.Timestamp,
				Source:    log.Source,
				Level:     log.Level,
				Message:   log.Message,
			}
		}
		logAnomalies, err := detector.DetectLogAnomalies(hostID, logInfos)
		if err == nil {
			allAnomalies = append(allAnomalies, logAnomalies...)
		}
	}

	// 转换为API格式
	anomalyEvents := make([]AnomalyEventInfo, 0, len(allAnomalies))
	for _, anomaly := range allAnomalies {
		rootCause := detector.AnalyzeRootCause(anomaly, metricsData, nil)
		recommendations := detector.GenerateRecommendations(anomaly)

		var relatedLogs []LogInfo
		if len(anomaly.RelatedLogs) > 0 {
			logIDs := make([]uint, len(anomaly.RelatedLogs))
			for i, logInfo := range anomaly.RelatedLogs {
				logIDs[i] = logInfo.ID
			}
			for _, logID := range logIDs {
				logs, _ := s.storage.GetLogs(hostID, "", time.Time{}, time.Time{}, 1000)
				for _, log := range logs {
					if log.ID == logID {
						relatedLogs = append(relatedLogs, log)
						break
					}
				}
			}
		}

		event := AnomalyEventInfo{
			HostID:          anomaly.HostID,
			Type:            anomaly.Type,
			Severity:        anomaly.Severity,
			MetricType:      anomaly.MetricType,
			Timestamp:       anomaly.Timestamp,
			Value:           anomaly.Value,
			ExpectedValue:   anomaly.ExpectedValue,
			Deviation:       anomaly.Deviation,
			Confidence:      anomaly.Confidence,
			Message:         anomaly.Message,
			RootCause:       rootCause,
			RelatedLogs:     relatedLogs,
			RelatedMetrics:  anomaly.RelatedMetrics,
			Recommendations: recommendations,
			IsResolved:      false,
		}

		if err := s.storage.CreateAnomalyEvent(&event); err != nil {
			log.Printf("Failed to save anomaly event: %v", err)
		}

		anomalyEvents = append(anomalyEvents, event)
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID
	if err == nil && agent != nil {
		hostname = agent.Hostname
	}

	// 准备统计信息
	stats := make(map[string]interface{})
	stats["total_anomalies"] = float64(len(anomalyEvents))
	unresolvedCount := 0
	bySeverity := make(map[string]int)
	byType := make(map[string]int)
	
	for _, event := range anomalyEvents {
		if !event.IsResolved {
			unresolvedCount++
		}
		bySeverity[event.Severity]++
		byType[event.Type]++
	}
	
	stats["unresolved_count"] = float64(unresolvedCount)
	bySeverityInterface := make(map[string]interface{})
	for k, v := range bySeverity {
		bySeverityInterface[k] = float64(v)
	}
	byTypeInterface := make(map[string]interface{})
	for k, v := range byType {
		byTypeInterface[k] = float64(v)
	}
	stats["by_severity"] = bySeverityInterface
	stats["by_type"] = byTypeInterface

	// 将异常事件转换为interface{}类型
	anomaliesInterface := make([]interface{}, len(anomalyEvents))
	for i, event := range anomalyEvents {
		anomaliesInterface[i] = event
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
	c.Header("X-Accel-Buffering", "no")

	// 通过反射调用 StreamAnomalyAnalysis 方法
	type ClientGetter interface {
		GetClient() interface{}
	}
	
	var actualClient interface{}
	if getter, ok := llmClient.(ClientGetter); ok {
		actualClient = getter.GetClient()
	} else {
		getClientMethod := reflect.ValueOf(llmClient).MethodByName("GetClient")
		if getClientMethod.IsValid() {
			results := getClientMethod.Call(nil)
			if len(results) > 0 {
				actualClient = results[0].Interface()
			}
		}
	}

	if actualClient == nil {
		// 回退到普通调用
		if analyzeMethod := reflect.ValueOf(llmClient).MethodByName("AnalyzeAnomalyDetection"); analyzeMethod.IsValid() {
			results := analyzeMethod.Call([]reflect.Value{
				reflect.ValueOf(hostID),
				reflect.ValueOf(hostname),
				reflect.ValueOf(anomaliesInterface),
				reflect.ValueOf(stats),
			})
			
			if len(results) == 2 && results[1].IsNil() {
				if summary, ok := results[0].Interface().(string); ok {
					chunk := map[string]interface{}{
						"content": summary,
						"done":    true,
					}
					data, _ := json.Marshal(chunk)
					fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
					c.Writer.Flush()
					return
				}
			}
		}
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to analyze anomalies",
		})
		return
	}

	// 调用流式方法
	streamMethod := reflect.ValueOf(actualClient).MethodByName("StreamAnomalyAnalysis")
	if !streamMethod.IsValid() {
		// 回退到普通调用
		if analyzeMethod := reflect.ValueOf(llmClient).MethodByName("AnalyzeAnomalyDetection"); analyzeMethod.IsValid() {
			results := analyzeMethod.Call([]reflect.Value{
				reflect.ValueOf(hostID),
				reflect.ValueOf(hostname),
				reflect.ValueOf(anomaliesInterface),
				reflect.ValueOf(stats),
			})
			
			if len(results) == 2 && results[1].IsNil() {
				if summary, ok := results[0].Interface().(string); ok {
					chunk := map[string]interface{}{
						"content": summary,
						"done":    true,
					}
					data, _ := json.Marshal(chunk)
					fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
					c.Writer.Flush()
					return
				}
			}
		}
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "LLM client does not support streaming",
		})
		return
	}

	log.Printf("[API] 使用流式异常分析")
	results := streamMethod.Call([]reflect.Value{
		reflect.ValueOf(hostID),
		reflect.ValueOf(hostname),
		reflect.ValueOf(anomaliesInterface),
		reflect.ValueOf(stats),
		reflect.ValueOf(c.Writer),
	})

	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			log.Printf("[API] 流式异常分析失败: %v", err)
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

// getAnomalyEvents 获取异常事件列表
func (s *APIServer) getAnomalyEvents(c *gin.Context) {
	hostID := c.Query("host_id")
	severity := c.Query("severity")
	anomalyType := c.Query("type")
	isResolvedStr := c.Query("is_resolved")
	limitStr := c.DefaultQuery("limit", "50")

	var isResolved *bool
	if isResolvedStr != "" {
		resolved := isResolvedStr == "true"
		isResolved = &resolved
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}

	events, err := s.storage.GetAnomalyEvents(hostID, severity, anomalyType, isResolved, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get anomaly events: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data: map[string]interface{}{
			"events": events,
			"count":  len(events),
		},
	})
}

// getAnomalyEventDetail 获取异常事件详情
func (s *APIServer) getAnomalyEventDetail(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid anomaly event ID",
		})
		return
	}

	event, err := s.storage.GetAnomalyEventDetail(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Anomaly event not found: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    event,
	})
}

// resolveAnomalyEvent 标记异常事件为已解决
func (s *APIServer) resolveAnomalyEvent(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid anomaly event ID",
		})
		return
	}

	// 获取当前用户（如果有认证）
	resolvedBy := "system"
	if username, exists := c.Get("username"); exists {
		if u, ok := username.(string); ok {
			resolvedBy = u
		}
	}

	err = s.storage.ResolveAnomalyEvent(uint(id), resolvedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to resolve anomaly event: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Anomaly event resolved successfully",
	})
}

// getAnomalyStatistics 获取异常统计信息
func (s *APIServer) getAnomalyStatistics(c *gin.Context) {
	hostID := c.Query("host_id")

	stats, err := s.storage.GetAnomalyStatistics(hostID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get anomaly statistics: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    stats,
	})
}
