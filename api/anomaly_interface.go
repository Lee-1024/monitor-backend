// ============================================
// 文件: api/anomaly_interface.go
// 异常检测器接口（避免循环导入）
// ============================================
package api

import "time"

// AnomalyDetectorInterface 异常检测器接口
type AnomalyDetectorInterface interface {
	// DetectMetricAnomalies 检测指标异常
	DetectMetricAnomalies(hostID, metricType string, dataPoints []AnomalyMetricDataPoint) ([]AnomalyDetectionResult, error)
	// DetectLogAnomalies 检测日志异常
	DetectLogAnomalies(hostID string, logs []AnomalyLogInfo) ([]AnomalyDetectionResult, error)
	// AnalyzeRootCause 分析根因
	AnalyzeRootCause(anomaly AnomalyDetectionResult, metrics map[string][]AnomalyMetricDataPoint, logs []AnomalyLogInfo) string
	// GenerateRecommendations 生成建议
	GenerateRecommendations(anomaly AnomalyDetectionResult) []string
}

// AnomalyMetricDataPoint 指标数据点（用于异常检测）
type AnomalyMetricDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// AnomalyLogInfo 日志信息（用于异常检测）
type AnomalyLogInfo struct {
	ID        uint      `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Pattern   string    `json:"pattern,omitempty"`
}

// AnomalyDetectionResult 异常检测结果（用于接口）
type AnomalyDetectionResult struct {
	ID            string                 `json:"id"`
	HostID        string                 `json:"host_id"`
	Type          string                 `json:"type"`
	Severity      string                 `json:"severity"`
	MetricType    string                 `json:"metric_type,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Value         float64                `json:"value"`
	ExpectedValue float64                `json:"expected_value,omitempty"`
	Deviation     float64                `json:"deviation"`
	Confidence    float64                `json:"confidence"`
	Message       string                 `json:"message"`
	RootCause     string                 `json:"root_cause,omitempty"`
	RelatedLogs   []AnomalyLogInfo      `json:"related_logs,omitempty"`
	RelatedMetrics map[string]interface{} `json:"related_metrics,omitempty"`
	Recommendations []string             `json:"recommendations,omitempty"`
}
