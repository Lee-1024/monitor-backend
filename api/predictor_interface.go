// ============================================
// 文件: api/predictor_interface.go
// ============================================
package api

import "time"

// PredictorInterface 预测器接口
type PredictorInterface interface {
	// Predict 预测资源使用趋势
	// points: 历史数据点
	// days: 预测未来多少天
	// threshold: 阈值（百分比）
	Predict(points []PredictionMetricPoint, days int, threshold float64) (*PredictionResult, error)
	
	// PredictCapacityNeeds 预测容量需求
	PredictCapacityNeeds(points []PredictionMetricPoint, resourceType string, threshold float64) (*CapacityPrediction, error)
}

// LLMClientInterface LLM客户端接口
type LLMClientInterface interface {
	// AnalyzeCapacity 分析容量规划
	AnalyzeCapacity(req interface{}) (interface{}, error)
	
	// GenerateCostOptimization 生成成本优化建议
	GenerateCostOptimization(hostID, hostname string, predictions map[string]interface{}) (string, error)
}

// PredictionMetricPoint 预测指标数据点（用于预测）
type PredictionMetricPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// PredictionResult 预测结果
type PredictionResult struct {
	CurrentValue     float64   `json:"current_value"`
	PredictedValue   float64   `json:"predicted_value"`
	PredictedTime    time.Time `json:"predicted_time"`
	GrowthRate       float64   `json:"growth_rate"`        // 增长率（百分比/天）
	DaysToThreshold  float64   `json:"days_to_threshold"`  // 达到阈值所需天数
	Trend            string    `json:"trend"`               // 趋势：increasing, decreasing, stable
	Confidence       float64   `json:"confidence"`          // 置信度 0-1
	Recommendation   string    `json:"recommendation"`      // 建议
}

// CapacityPrediction 容量规划预测
type CapacityPrediction struct {
	ResourceType    string    `json:"resource_type"`     // cpu, memory, disk
	CurrentUsage    float64   `json:"current_usage"`     // 当前使用率
	Threshold       float64   `json:"threshold"`          // 阈值
	DaysToThreshold float64   `json:"days_to_threshold"` // 达到阈值所需天数
	PredictedDate   time.Time `json:"predicted_date"`     // 预测日期
	Urgency         string    `json:"urgency"`            // 紧急程度：critical, high, medium, low
	Recommendation  string    `json:"recommendation"`     // 建议
}
