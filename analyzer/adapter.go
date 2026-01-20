// ============================================
// 文件: analyzer/adapter.go
// ============================================
package analyzer

import (
	"monitor-backend/api"
)

// PredictorAdapter 预测器适配器，实现api.PredictorInterface
type PredictorAdapter struct {
	predictor *Predictor
}

// NewPredictorAdapter 创建预测器适配器
func NewPredictorAdapter(threshold float64) *PredictorAdapter {
	return &PredictorAdapter{
		predictor: NewPredictor(threshold),
	}
}

// Predict 实现api.PredictorInterface
func (a *PredictorAdapter) Predict(points []api.PredictionMetricPoint, days int, threshold float64) (*api.PredictionResult, error) {
	// 更新阈值
	a.predictor = NewPredictor(threshold)

	// 转换为内部格式
	internalPoints := make([]MetricPoint, len(points))
	for i, p := range points {
		internalPoints[i] = MetricPoint{
			Timestamp: p.Timestamp,
			Value:     p.Value,
		}
	}

	// 调用预测
	result, err := a.predictor.Predict(internalPoints, days)
	if err != nil {
		return nil, err
	}

	// 转换为API格式
	return &api.PredictionResult{
		CurrentValue:     result.CurrentValue,
		PredictedValue:   result.PredictedValue,
		PredictedTime:    result.PredictedTime,
		GrowthRate:       result.GrowthRate,
		DaysToThreshold:  result.DaysToThreshold,
		Trend:            result.Trend,
		Confidence:       result.Confidence,
		Recommendation:   result.Recommendation,
	}, nil
}

// PredictCapacityNeeds 实现api.PredictorInterface
func (a *PredictorAdapter) PredictCapacityNeeds(points []api.PredictionMetricPoint, resourceType string, threshold float64) (*api.CapacityPrediction, error) {
	// 更新阈值
	a.predictor = NewPredictor(threshold)

	// 转换为内部格式
	internalPoints := make([]MetricPoint, len(points))
	for i, p := range points {
		internalPoints[i] = MetricPoint{
			Timestamp: p.Timestamp,
			Value:     p.Value,
		}
	}

	// 调用预测
	result, err := a.predictor.PredictCapacityNeeds(internalPoints, resourceType)
	if err != nil {
		return nil, err
	}

	// 转换为API格式
	return &api.CapacityPrediction{
		ResourceType:    result.ResourceType,
		CurrentUsage:    result.CurrentUsage,
		Threshold:       result.Threshold,
		DaysToThreshold: result.DaysToThreshold,
		PredictedDate:   result.PredictedDate,
		Urgency:         result.Urgency,
		Recommendation:  result.Recommendation,
	}, nil
}
