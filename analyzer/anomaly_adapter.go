// ============================================
// 文件: analyzer/anomaly_adapter.go
// 异常检测器适配器（实现api.AnomalyDetectorInterface，避免循环导入）
// ============================================
package analyzer

import (
	"monitor-backend/api"
)

// AnomalyDetectorAdapter 异常检测器适配器
type AnomalyDetectorAdapter struct {
	detector *AnomalyDetector
}

// NewAnomalyDetectorAdapter 创建异常检测器适配器
func NewAnomalyDetectorAdapter() *AnomalyDetectorAdapter {
	return &AnomalyDetectorAdapter{
		detector: NewAnomalyDetector(),
	}
}

// DetectMetricAnomalies 检测指标异常
func (a *AnomalyDetectorAdapter) DetectMetricAnomalies(hostID, metricType string, dataPoints []api.AnomalyMetricDataPoint) ([]api.AnomalyDetectionResult, error) {
	// 转换为内部格式
	internalPoints := make([]MetricDataPoint, len(dataPoints))
	for i, p := range dataPoints {
		internalPoints[i] = MetricDataPoint{
			Timestamp: p.Timestamp,
			Value:     p.Value,
		}
	}

	// 调用检测
	results, err := a.detector.DetectMetricAnomalies(hostID, metricType, internalPoints)
	if err != nil {
		return nil, err
	}

	// 转换为API格式
	apiResults := make([]api.AnomalyDetectionResult, len(results))
	for i, r := range results {
		// 转换相关日志
		relatedLogs := make([]api.AnomalyLogInfo, len(r.RelatedLogs))
		for j, log := range r.RelatedLogs {
			relatedLogs[j] = api.AnomalyLogInfo{
				ID:        log.ID,
				Timestamp: log.Timestamp,
				Source:    log.Source,
				Level:     log.Level,
				Message:   log.Message,
				Pattern:   log.Pattern,
			}
		}

		apiResults[i] = api.AnomalyDetectionResult{
			ID:            r.ID,
			HostID:        r.HostID,
			Type:          string(r.Type),
			Severity:      string(r.Severity),
			MetricType:    r.MetricType,
			Timestamp:     r.Timestamp,
			Value:         r.Value,
			ExpectedValue: r.ExpectedValue,
			Deviation:     r.Deviation,
			Confidence:    r.Confidence,
			Message:       r.Message,
			RootCause:     r.RootCause,
			RelatedLogs:   relatedLogs,
			RelatedMetrics: r.RelatedMetrics,
			Recommendations: r.Recommendations,
		}
	}

	return apiResults, nil
}

// DetectLogAnomalies 检测日志异常
func (a *AnomalyDetectorAdapter) DetectLogAnomalies(hostID string, logs []api.AnomalyLogInfo) ([]api.AnomalyDetectionResult, error) {
	// 转换为内部格式
	internalLogs := make([]LogAnomalyInfo, len(logs))
	for i, log := range logs {
		internalLogs[i] = LogAnomalyInfo{
			ID:        log.ID,
			Timestamp: log.Timestamp,
			Source:    log.Source,
			Level:     log.Level,
			Message:   log.Message,
			Pattern:   log.Pattern,
		}
	}

	// 调用检测
	results, err := a.detector.DetectLogAnomalies(hostID, internalLogs)
	if err != nil {
		return nil, err
	}

	// 转换为API格式
	apiResults := make([]api.AnomalyDetectionResult, len(results))
	for i, r := range results {
		// 转换相关日志
		relatedLogs := make([]api.AnomalyLogInfo, len(r.RelatedLogs))
		for j, log := range r.RelatedLogs {
			relatedLogs[j] = api.AnomalyLogInfo{
				ID:        log.ID,
				Timestamp: log.Timestamp,
				Source:    log.Source,
				Level:     log.Level,
				Message:   log.Message,
				Pattern:   log.Pattern,
			}
		}

		apiResults[i] = api.AnomalyDetectionResult{
			ID:            r.ID,
			HostID:        r.HostID,
			Type:          string(r.Type),
			Severity:      string(r.Severity),
			MetricType:    r.MetricType,
			Timestamp:     r.Timestamp,
			Value:         r.Value,
			ExpectedValue: r.ExpectedValue,
			Deviation:     r.Deviation,
			Confidence:    r.Confidence,
			Message:       r.Message,
			RootCause:     r.RootCause,
			RelatedLogs:   relatedLogs,
			RelatedMetrics: r.RelatedMetrics,
			Recommendations: r.Recommendations,
		}
	}

	return apiResults, nil
}

// AnalyzeRootCause 分析根因
func (a *AnomalyDetectorAdapter) AnalyzeRootCause(anomaly api.AnomalyDetectionResult, metrics map[string][]api.AnomalyMetricDataPoint, logs []api.AnomalyLogInfo) string {
	// 转换为内部格式
	internalAnomaly := AnomalyDetectionResult{
		ID:            anomaly.ID,
		HostID:        anomaly.HostID,
		Type:          AnomalyType(anomaly.Type),
		Severity:      AnomalySeverity(anomaly.Severity),
		MetricType:    anomaly.MetricType,
		Timestamp:     anomaly.Timestamp,
		Value:         anomaly.Value,
		ExpectedValue: anomaly.ExpectedValue,
		Deviation:     anomaly.Deviation,
		Confidence:    anomaly.Confidence,
		Message:       anomaly.Message,
		RootCause:     anomaly.RootCause,
		RelatedMetrics: anomaly.RelatedMetrics,
		Recommendations: anomaly.Recommendations,
	}

	// 转换指标数据
	internalMetrics := make(map[string][]MetricDataPoint)
	for k, v := range metrics {
		points := make([]MetricDataPoint, len(v))
		for i, p := range v {
			points[i] = MetricDataPoint{
				Timestamp: p.Timestamp,
				Value:     p.Value,
			}
		}
		internalMetrics[k] = points
	}

	// 转换日志
	internalLogs := make([]LogAnomalyInfo, len(logs))
	for i, log := range logs {
		internalLogs[i] = LogAnomalyInfo{
			ID:        log.ID,
			Timestamp: log.Timestamp,
			Source:    log.Source,
			Level:     log.Level,
			Message:   log.Message,
			Pattern:   log.Pattern,
		}
	}

	return a.detector.AnalyzeRootCause(internalAnomaly, internalMetrics, internalLogs)
}

// GenerateRecommendations 生成建议
func (a *AnomalyDetectorAdapter) GenerateRecommendations(anomaly api.AnomalyDetectionResult) []string {
	// 转换为内部格式
	internalAnomaly := AnomalyDetectionResult{
		ID:            anomaly.ID,
		HostID:        anomaly.HostID,
		Type:          AnomalyType(anomaly.Type),
		Severity:      AnomalySeverity(anomaly.Severity),
		MetricType:    anomaly.MetricType,
		Timestamp:     anomaly.Timestamp,
		Value:         anomaly.Value,
		ExpectedValue: anomaly.ExpectedValue,
		Deviation:     anomaly.Deviation,
		Confidence:    anomaly.Confidence,
		Message:       anomaly.Message,
		RootCause:     anomaly.RootCause,
		RelatedMetrics: anomaly.RelatedMetrics,
		Recommendations: anomaly.Recommendations,
	}

	return a.detector.GenerateRecommendations(internalAnomaly)
}
