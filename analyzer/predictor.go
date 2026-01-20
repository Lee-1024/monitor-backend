// ============================================
// 文件: analyzer/predictor.go
// ============================================
package analyzer

import (
	"fmt"
	"math"
	"time"
)

// MetricPoint 指标数据点
type MetricPoint struct {
	Timestamp time.Time
	Value     float64
}

// PredictionResult 预测结果
type PredictionResult struct {
	CurrentValue    float64   `json:"current_value"`
	PredictedValue  float64   `json:"predicted_value"`
	PredictedTime   time.Time `json:"predicted_time"`
	GrowthRate      float64   `json:"growth_rate"`      // 增长率（百分比/天）
	DaysToThreshold float64   `json:"days_to_threshold"` // 达到阈值所需天数
	Trend           string    `json:"trend"`            // 趋势：increasing, decreasing, stable
	Confidence      float64   `json:"confidence"`       // 置信度 0-1
	Recommendation  string    `json:"recommendation"`   // 建议
}

// Predictor 预测器
type Predictor struct {
	threshold float64 // 阈值（如80%表示80%使用率）
}

// NewPredictor 创建预测器
func NewPredictor(threshold float64) *Predictor {
	return &Predictor{
		threshold: threshold,
	}
}

// Predict 基于历史数据预测未来趋势
// data: 历史数据点（按时间排序）
// days: 预测未来多少天
func (p *Predictor) Predict(data []MetricPoint, days int) (*PredictionResult, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data points: need at least 2, got %d", len(data))
	}

	// 计算线性回归
	slope, _, r2 := p.linearRegression(data)

	// 当前值（最后一个数据点）
	currentValue := data[len(data)-1].Value
	currentTime := data[len(data)-1].Timestamp

	// 预测时间点
	predictedTime := currentTime.Add(time.Duration(days) * 24 * time.Hour)

	// 预测值（基于线性回归）
	predictedValue := slope*float64(days) + currentValue

	// 增长率（每天）
	growthRate := slope

	// 计算达到阈值所需天数
	var daysToThreshold float64 = -1
	if slope > 0 && predictedValue > p.threshold {
		// 如果趋势上升且会超过阈值
		daysToThreshold = (p.threshold - currentValue) / slope
		if daysToThreshold < 0 {
			daysToThreshold = 0
		}
	} else if slope > 0 {
		// 趋势上升但不会超过阈值
		daysToThreshold = -1
	}

	// 判断趋势
	var trend string
	if math.Abs(slope) < 0.01 {
		trend = "stable"
	} else if slope > 0 {
		trend = "increasing"
	} else {
		trend = "decreasing"
	}

	// 置信度（基于R²）
	confidence := math.Max(0, math.Min(1, r2))

	// 生成建议
	recommendation := p.generateRecommendation(currentValue, predictedValue, daysToThreshold, trend, confidence)

	return &PredictionResult{
		CurrentValue:     currentValue,
		PredictedValue:   predictedValue,
		PredictedTime:    predictedTime,
		GrowthRate:       growthRate * 100, // 转换为百分比
		DaysToThreshold:  daysToThreshold,
		Trend:            trend,
		Confidence:       confidence,
		Recommendation:   recommendation,
	}, nil
}

// linearRegression 线性回归分析
// 返回：斜率、截距、R²（决定系数）
func (p *Predictor) linearRegression(data []MetricPoint) (slope, intercept, r2 float64) {
	n := float64(len(data))
	if n < 2 {
		return 0, 0, 0
	}

	// 将时间转换为相对于第一个时间点的天数
	baseTime := data[0].Timestamp
	var sumX, sumY, sumXY, sumX2, sumY2 float64

	for _, point := range data {
		days := point.Timestamp.Sub(baseTime).Hours() / 24.0
		value := point.Value

		sumX += days
		sumY += value
		sumXY += days * value
		sumX2 += days * days
		sumY2 += value * value
	}

	// 计算斜率和截距
	denominator := n*sumX2 - sumX*sumX
	if math.Abs(denominator) < 1e-10 {
		return 0, sumY / n, 0
	}

	slope = (n*sumXY - sumX*sumY) / denominator
	intercept = (sumY - slope*sumX) / n

	// 计算R²
	meanY := sumY / n
	var ssRes, ssTot float64
	for _, point := range data {
		days := point.Timestamp.Sub(baseTime).Hours() / 24.0
		predicted := slope*days + intercept
		ssRes += (point.Value - predicted) * (point.Value - predicted)
		ssTot += (point.Value - meanY) * (point.Value - meanY)
	}

	if ssTot < 1e-10 {
		r2 = 0
	} else {
		r2 = 1 - (ssRes / ssTot)
	}

	return slope, intercept, r2
}

// generateRecommendation 生成建议
func (p *Predictor) generateRecommendation(current, predicted float64, daysToThreshold float64, trend string, confidence float64) string {
	if trend == "decreasing" {
		return "资源使用率呈下降趋势，当前无需扩容。"
	}

	if trend == "stable" {
		if current > p.threshold*0.9 {
			return "资源使用率稳定但接近阈值，建议持续监控。"
		}
		return "资源使用率稳定，当前状态良好。"
	}

	// 趋势上升
	if daysToThreshold > 0 && daysToThreshold <= 7 {
		return fmt.Sprintf("资源使用率快速上升，预计%.1f天后将达到阈值，建议立即开始扩容准备。", daysToThreshold)
	} else if daysToThreshold > 0 && daysToThreshold <= 30 {
		return fmt.Sprintf("资源使用率上升，预计%.1f天后将达到阈值，建议在%.0f天内开始扩容。", daysToThreshold, daysToThreshold*0.7)
	} else if daysToThreshold > 0 {
		return fmt.Sprintf("资源使用率上升，预计%.1f天后将达到阈值，建议制定扩容计划。", daysToThreshold)
	} else if predicted > p.threshold {
		return "预测值将超过阈值，建议尽快扩容。"
	} else {
		return "资源使用率上升但预计不会超过阈值，建议持续监控。"
	}
}

// PredictCapacity 容量规划预测
// 预测何时需要扩容（达到指定阈值）
type CapacityPrediction struct {
	ResourceType    string    `json:"resource_type"`     // cpu, memory, disk
	CurrentUsage    float64   `json:"current_usage"`      // 当前使用率
	Threshold       float64   `json:"threshold"`         // 阈值
	DaysToThreshold float64   `json:"days_to_threshold"`  // 达到阈值所需天数
	PredictedDate   time.Time `json:"predicted_date"`    // 预测日期
	Urgency         string    `json:"urgency"`            // 紧急程度：critical, high, medium, low
	Recommendation  string    `json:"recommendation"`    // 建议
}

// PredictCapacityNeeds 预测容量需求
func (p *Predictor) PredictCapacityNeeds(data []MetricPoint, resourceType string) (*CapacityPrediction, error) {
	result, err := p.Predict(data, 90) // 预测未来90天
	if err != nil {
		return nil, err
	}

	var urgency string
	var recommendation string

	if result.DaysToThreshold > 0 {
		if result.DaysToThreshold <= 7 {
			urgency = "critical"
			recommendation = fmt.Sprintf("紧急：%s使用率预计在%.1f天内达到阈值，建议立即扩容。", resourceType, result.DaysToThreshold)
		} else if result.DaysToThreshold <= 30 {
			urgency = "high"
			recommendation = fmt.Sprintf("高优先级：%s使用率预计在%.1f天内达到阈值，建议在%.0f天内开始扩容。", resourceType, result.DaysToThreshold, result.DaysToThreshold*0.7)
		} else if result.DaysToThreshold <= 60 {
			urgency = "medium"
			recommendation = fmt.Sprintf("中等优先级：%s使用率预计在%.1f天内达到阈值，建议制定扩容计划。", resourceType, result.DaysToThreshold)
		} else {
			urgency = "low"
			recommendation = fmt.Sprintf("低优先级：%s使用率预计在%.1f天内达到阈值，建议持续监控。", resourceType, result.DaysToThreshold)
		}
	} else if result.PredictedValue > p.threshold {
		urgency = "critical"
		recommendation = fmt.Sprintf("紧急：%s使用率预测将超过阈值，建议立即扩容。", resourceType)
	} else {
		urgency = "low"
		recommendation = fmt.Sprintf("%s使用率预计不会超过阈值，当前状态良好。", resourceType)
	}

	predictedDate := time.Now()
	if result.DaysToThreshold > 0 {
		predictedDate = predictedDate.Add(time.Duration(result.DaysToThreshold) * 24 * time.Hour)
	}

	return &CapacityPrediction{
		ResourceType:    resourceType,
		CurrentUsage:    result.CurrentValue,
		Threshold:       p.threshold,
		DaysToThreshold: result.DaysToThreshold,
		PredictedDate:   predictedDate,
		Urgency:         urgency,
		Recommendation:  recommendation,
	}, nil
}
