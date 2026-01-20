// ============================================
// 文件: analyzer/anomaly_detector.go
// 异常检测器 - 基于机器学习的异常模式识别
// ============================================
package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// AnomalyType 异常类型
type AnomalyType string

const (
	AnomalyTypeMetricSpike    AnomalyType = "metric_spike"    // 指标突增
	AnomalyTypeMetricDrop     AnomalyType = "metric_drop"     // 指标突降
	AnomalyTypeMetricDrift    AnomalyType = "metric_drift"    // 指标漂移
	AnomalyTypeLogError       AnomalyType = "log_error"       // 日志错误
	AnomalyTypeLogPattern     AnomalyType = "log_pattern"     // 日志模式异常
	AnomalyTypeCorrelation    AnomalyType = "correlation"     // 关联异常
	AnomalyTypeBehavior       AnomalyType = "behavior"         // 行为异常
)

// AnomalySeverity 异常严重程度
type AnomalySeverity string

const (
	SeverityCritical AnomalySeverity = "critical" // 严重
	SeverityHigh     AnomalySeverity = "high"     // 高
	SeverityMedium   AnomalySeverity = "medium"   // 中
	SeverityLow      AnomalySeverity = "low"       // 低
)

// AnomalyDetectionResult 异常检测结果
type AnomalyDetectionResult struct {
	ID              string                 `json:"id"`
	HostID          string                 `json:"host_id"`
	Type            AnomalyType            `json:"type"`
	Severity        AnomalySeverity        `json:"severity"`
	MetricType      string                 `json:"metric_type,omitempty"`      // cpu, memory, disk等
	Timestamp       time.Time              `json:"timestamp"`
	Value           float64                `json:"value"`
	ExpectedValue   float64                `json:"expected_value,omitempty"`   // 期望值
	Deviation       float64                `json:"deviation"`                  // 偏差
	Confidence      float64                `json:"confidence"`                 // 置信度 (0-1)
	Message         string                 `json:"message"`
	RootCause       string                 `json:"root_cause,omitempty"`       // 根因分析
	RelatedLogs     []LogAnomalyInfo       `json:"related_logs,omitempty"`    // 相关日志
	RelatedMetrics  map[string]interface{} `json:"related_metrics,omitempty"`  // 相关指标
	Recommendations []string               `json:"recommendations,omitempty"` // 建议
}

// LogAnomalyInfo 日志异常信息
type LogAnomalyInfo struct {
	ID        uint      `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Pattern   string    `json:"pattern,omitempty"` // 匹配的模式
}

// MetricDataPoint 指标数据点
type MetricDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// AnomalyDetector 异常检测器
type AnomalyDetector struct {
	// 配置参数
	zScoreThreshold    float64 // Z-score阈值（默认3.0）
	iqrMultiplier      float64 // IQR倍数（默认1.5）
	windowSize         int     // 滑动窗口大小（默认20）
	minDataPoints      int     // 最小数据点数（默认10）
	errorLogThreshold  int     // 错误日志阈值（每分钟）
}

// NewAnomalyDetector 创建异常检测器
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		zScoreThreshold:   2.5, // 降低阈值，从3.0改为2.5，更容易检测到异常
		iqrMultiplier:     1.5,
		windowSize:        20,
		minDataPoints:     10,
		errorLogThreshold: 5, // 每分钟5条错误日志视为异常
	}
}

// DetectMetricAnomalies 检测指标异常
func (d *AnomalyDetector) DetectMetricAnomalies(hostID, metricType string, dataPoints []MetricDataPoint) ([]AnomalyDetectionResult, error) {
	if len(dataPoints) < d.minDataPoints {
		return nil, fmt.Errorf("insufficient data points: %d < %d", len(dataPoints), d.minDataPoints)
	}

	var anomalies []AnomalyDetectionResult

	// 1. 使用Z-score方法检测异常
	zScoreAnomalies := d.detectByZScore(hostID, metricType, dataPoints)
	anomalies = append(anomalies, zScoreAnomalies...)

	// 2. 使用IQR方法检测异常
	iqrAnomalies := d.detectByIQR(hostID, metricType, dataPoints)
	anomalies = append(anomalies, iqrAnomalies...)

	// 3. 使用移动平均方法检测异常
	maAnomalies := d.detectByMovingAverage(hostID, metricType, dataPoints)
	anomalies = append(anomalies, maAnomalies...)

	// 4. 去重和合并相似异常
	anomalies = d.deduplicateAnomalies(anomalies)

	// 5. 计算置信度和严重程度
	for i := range anomalies {
		anomalies[i].Confidence = d.calculateConfidence(anomalies[i], dataPoints)
		anomalies[i].Severity = d.calculateSeverity(anomalies[i])
	}

	return anomalies, nil
}

// detectByZScore 使用Z-score方法检测异常
func (d *AnomalyDetector) detectByZScore(hostID, metricType string, dataPoints []MetricDataPoint) []AnomalyDetectionResult {
	var anomalies []AnomalyDetectionResult

	// 计算均值和标准差
	mean, stdDev := d.calculateMeanStdDev(dataPoints)
	if stdDev == 0 {
		return anomalies // 标准差为0，无异常
	}

	// 检查每个数据点
	for _, point := range dataPoints {
		zScore := math.Abs((point.Value - mean) / stdDev)
		if zScore > d.zScoreThreshold {
			deviation := point.Value - mean
			anomalyType := AnomalyTypeMetricSpike
			if deviation < 0 {
				anomalyType = AnomalyTypeMetricDrop
			}

			anomalies = append(anomalies, AnomalyDetectionResult{
				ID:            fmt.Sprintf("%s-%s-%d", hostID, metricType, point.Timestamp.Unix()),
				HostID:        hostID,
				Type:          anomalyType,
				MetricType:    metricType,
				Timestamp:     point.Timestamp,
				Value:         point.Value,
				ExpectedValue: mean,
				Deviation:     deviation,
				Confidence:    math.Min(zScore/d.zScoreThreshold, 1.0),
				Message:       fmt.Sprintf("%s指标异常: 当前值%.2f, 期望值%.2f, Z-score=%.2f", metricType, point.Value, mean, zScore),
			})
		}
	}

	return anomalies
}

// detectByIQR 使用IQR（四分位距）方法检测异常
func (d *AnomalyDetector) detectByIQR(hostID, metricType string, dataPoints []MetricDataPoint) []AnomalyDetectionResult {
	var anomalies []AnomalyDetectionResult

	// 提取值并排序
	values := make([]float64, len(dataPoints))
	for i, point := range dataPoints {
		values[i] = point.Value
	}
	sort.Float64s(values)

	// 计算四分位数
	q1 := d.percentile(values, 25)
	q3 := d.percentile(values, 75)
	iqr := q3 - q1

	if iqr == 0 {
		return anomalies // IQR为0，无异常
	}

	lowerBound := q1 - d.iqrMultiplier*iqr
	upperBound := q3 + d.iqrMultiplier*iqr

	// 检查每个数据点
	for _, point := range dataPoints {
		if point.Value < lowerBound || point.Value > upperBound {
			deviation := point.Value - (q1+q3)/2
			anomalyType := AnomalyTypeMetricSpike
			if point.Value < lowerBound {
				anomalyType = AnomalyTypeMetricDrop
			}

			anomalies = append(anomalies, AnomalyDetectionResult{
				ID:            fmt.Sprintf("%s-%s-%d-iqr", hostID, metricType, point.Timestamp.Unix()),
				HostID:        hostID,
				Type:          anomalyType,
				MetricType:    metricType,
				Timestamp:     point.Timestamp,
				Value:         point.Value,
				ExpectedValue: (q1 + q3) / 2,
				Deviation:     deviation,
				Confidence:    0.7, // IQR方法置信度稍低
				Message:       fmt.Sprintf("%s指标异常: 当前值%.2f超出正常范围[%.2f, %.2f]", metricType, point.Value, lowerBound, upperBound),
			})
		}
	}

	return anomalies
}

// detectByMovingAverage 使用移动平均方法检测异常
func (d *AnomalyDetector) detectByMovingAverage(hostID, metricType string, dataPoints []MetricDataPoint) []AnomalyDetectionResult {
	var anomalies []AnomalyDetectionResult

	if len(dataPoints) < d.windowSize {
		return anomalies
	}

	// 计算移动平均和标准差
	for i := d.windowSize; i < len(dataPoints); i++ {
		window := dataPoints[i-d.windowSize : i]
		mean, stdDev := d.calculateMeanStdDev(window)

		if stdDev == 0 {
			continue
		}

		currentPoint := dataPoints[i]
		zScore := math.Abs((currentPoint.Value - mean) / stdDev)

		if zScore > d.zScoreThreshold {
			deviation := currentPoint.Value - mean
			anomalyType := AnomalyTypeMetricSpike
			if deviation < 0 {
				anomalyType = AnomalyTypeMetricDrop
			}

			anomalies = append(anomalies, AnomalyDetectionResult{
				ID:            fmt.Sprintf("%s-%s-%d-ma", hostID, metricType, currentPoint.Timestamp.Unix()),
				HostID:        hostID,
				Type:          anomalyType,
				MetricType:    metricType,
				Timestamp:     currentPoint.Timestamp,
				Value:         currentPoint.Value,
				ExpectedValue: mean,
				Deviation:     deviation,
				Confidence:    math.Min(zScore/d.zScoreThreshold, 1.0),
				Message:       fmt.Sprintf("%s指标异常: 当前值%.2f偏离移动平均%.2f, 偏差%.2f", metricType, currentPoint.Value, mean, deviation),
			})
		}
	}

	return anomalies
}

// DetectLogAnomalies 检测日志异常
func (d *AnomalyDetector) DetectLogAnomalies(hostID string, logs []LogAnomalyInfo) ([]AnomalyDetectionResult, error) {
	var anomalies []AnomalyDetectionResult

	// 1. 检测错误日志频率异常
	errorAnomalies := d.detectErrorLogFrequency(hostID, logs)
	anomalies = append(anomalies, errorAnomalies...)

	// 2. 检测日志模式异常
	patternAnomalies := d.detectLogPatterns(hostID, logs)
	anomalies = append(anomalies, patternAnomalies...)

	return anomalies, nil
}

// detectErrorLogFrequency 检测错误日志频率异常
func (d *AnomalyDetector) detectErrorLogFrequency(hostID string, logs []LogAnomalyInfo) []AnomalyDetectionResult {
	var anomalies []AnomalyDetectionResult

	// 按时间窗口统计错误日志
	errorLogsByMinute := make(map[int64][]LogAnomalyInfo)
	for _, log := range logs {
		if log.Level == "ERROR" || log.Level == "FATAL" {
			minute := log.Timestamp.Unix() / 60
			errorLogsByMinute[minute] = append(errorLogsByMinute[minute], log)
		}
	}

	// 检查每分钟错误日志数量
	for minute, errorLogs := range errorLogsByMinute {
		if len(errorLogs) >= d.errorLogThreshold {
			anomalies = append(anomalies, AnomalyDetectionResult{
				ID:          fmt.Sprintf("%s-log-error-%d", hostID, minute),
				HostID:      hostID,
				Type:        AnomalyTypeLogError,
				Timestamp:   time.Unix(minute*60, 0),
				Value:       float64(len(errorLogs)),
				Confidence:  math.Min(float64(len(errorLogs))/float64(d.errorLogThreshold*2), 1.0),
				Message:     fmt.Sprintf("错误日志频率异常: %d分钟内出现%d条错误日志", 1, len(errorLogs)),
				RelatedLogs: errorLogs,
			})
		}
	}

	return anomalies
}

// detectLogPatterns 检测日志模式异常
func (d *AnomalyDetector) detectLogPatterns(hostID string, logs []LogAnomalyInfo) []AnomalyDetectionResult {
	var anomalies []AnomalyDetectionResult

	// 统计日志消息模式
	patternCount := make(map[string]int)
	patternLogs := make(map[string][]LogAnomalyInfo)

	for _, log := range logs {
		// 提取日志模式（简化：去除时间戳、IP等动态内容）
		pattern := d.extractLogPattern(log.Message)
		patternCount[pattern]++
		patternLogs[pattern] = append(patternLogs[pattern], log)
	}

	// 检测异常频繁的模式
	threshold := len(logs) / 10 // 如果某个模式出现超过10%，视为异常
	for pattern, count := range patternCount {
		if count > threshold && count > 5 {
			anomalies = append(anomalies, AnomalyDetectionResult{
				ID:          fmt.Sprintf("%s-log-pattern-%s", hostID, pattern),
				HostID:      hostID,
				Type:        AnomalyTypeLogPattern,
				Timestamp:   time.Now(),
				Value:       float64(count),
				Confidence:  math.Min(float64(count)/float64(threshold*2), 1.0),
				Message:     fmt.Sprintf("日志模式异常: 模式'%s'出现%d次", pattern, count),
				RelatedLogs: patternLogs[pattern],
			})
		}
	}

	return anomalies
}

// extractLogPattern 提取日志模式（去除动态内容）
func (d *AnomalyDetector) extractLogPattern(message string) string {
	// 简单的模式提取：去除数字、IP地址等
	pattern := message
	// 去除数字
	pattern = strings.ReplaceAll(pattern, "0", "N")
	pattern = strings.ReplaceAll(pattern, "1", "N")
	pattern = strings.ReplaceAll(pattern, "2", "N")
	pattern = strings.ReplaceAll(pattern, "3", "N")
	pattern = strings.ReplaceAll(pattern, "4", "N")
	pattern = strings.ReplaceAll(pattern, "5", "N")
	pattern = strings.ReplaceAll(pattern, "6", "N")
	pattern = strings.ReplaceAll(pattern, "7", "N")
	pattern = strings.ReplaceAll(pattern, "8", "N")
	pattern = strings.ReplaceAll(pattern, "9", "N")
	// 可以进一步优化，使用正则表达式去除IP、时间戳等
	return pattern
}

// AnalyzeRootCause 分析异常根因（结合指标和日志）
func (d *AnomalyDetector) AnalyzeRootCause(anomaly AnomalyDetectionResult, metrics map[string][]MetricDataPoint, logs []LogAnomalyInfo) string {
	var rootCauses []string

	// 1. 分析指标关联
	if anomaly.MetricType != "" {
		// 检查其他指标是否也有异常
		for metricType, dataPoints := range metrics {
			if metricType == anomaly.MetricType {
				continue
			}
			// 在异常时间点附近检查其他指标
			for _, point := range dataPoints {
				timeDiff := math.Abs(float64(point.Timestamp.Sub(anomaly.Timestamp).Seconds()))
				if timeDiff < 300 { // 5分钟内
					// 检查是否有异常
					windowMean, stdDev := d.calculateMeanStdDev(dataPoints)
					if stdDev > 0 {
						zScore := math.Abs((point.Value - windowMean) / stdDev)
						if zScore > 2.0 {
							rootCauses = append(rootCauses, fmt.Sprintf("%s指标同时异常，可能存在关联", metricType))
						}
					}
				}
			}
		}
	}

	// 2. 分析相关日志
	if len(anomaly.RelatedLogs) > 0 {
		errorCount := 0
		for _, log := range anomaly.RelatedLogs {
			if log.Level == "ERROR" || log.Level == "FATAL" {
				errorCount++
			}
		}
		if errorCount > 0 {
			rootCauses = append(rootCauses, fmt.Sprintf("检测到%d条相关错误日志", errorCount))
		}
	}

	// 3. 根据异常类型提供根因分析
	switch anomaly.Type {
	case AnomalyTypeMetricSpike:
		if anomaly.MetricType == "cpu" {
			rootCauses = append(rootCauses, "CPU使用率突增可能由以下原因导致：进程异常、系统负载过高、恶意程序运行")
		} else if anomaly.MetricType == "memory" {
			rootCauses = append(rootCauses, "内存使用率突增可能由以下原因导致：内存泄漏、大文件加载、缓存未释放")
		} else if anomaly.MetricType == "disk" {
			rootCauses = append(rootCauses, "磁盘使用率突增可能由以下原因导致：大量文件写入、日志文件增长、临时文件未清理")
		}
	case AnomalyTypeMetricDrop:
		rootCauses = append(rootCauses, "指标突降可能表示服务异常停止或资源释放异常")
	case AnomalyTypeLogError:
		rootCauses = append(rootCauses, "错误日志频率异常可能表示应用程序故障、配置错误或外部依赖问题")
	}

	if len(rootCauses) == 0 {
		return "需要进一步调查以确定根因"
	}

	return strings.Join(rootCauses, "; ")
}

// calculateMeanStdDev 计算均值和标准差
func (d *AnomalyDetector) calculateMeanStdDev(dataPoints []MetricDataPoint) (float64, float64) {
	if len(dataPoints) == 0 {
		return 0, 0
	}

	var sum float64
	for _, point := range dataPoints {
		sum += point.Value
	}
	mean := sum / float64(len(dataPoints))

	var variance float64
	for _, point := range dataPoints {
		variance += math.Pow(point.Value-mean, 2)
	}
	stdDev := math.Sqrt(variance / float64(len(dataPoints)))

	return mean, stdDev
}

// percentile 计算百分位数
func (d *AnomalyDetector) percentile(sortedValues []float64, p float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}
	index := float64(len(sortedValues)-1) * p / 100.0
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))
	if lower == upper {
		return sortedValues[lower]
	}
	return sortedValues[lower] + (sortedValues[upper]-sortedValues[lower])*(index-float64(lower))
}

// deduplicateAnomalies 去重和合并相似异常
func (d *AnomalyDetector) deduplicateAnomalies(anomalies []AnomalyDetectionResult) []AnomalyDetectionResult {
	seen := make(map[string]bool)
	var unique []AnomalyDetectionResult

	for _, anomaly := range anomalies {
		key := fmt.Sprintf("%s-%s-%d", anomaly.HostID, anomaly.MetricType, anomaly.Timestamp.Unix()/60) // 按分钟去重
		if !seen[key] {
			seen[key] = true
			unique = append(unique, anomaly)
		}
	}

	return unique
}

// calculateConfidence 计算置信度
func (d *AnomalyDetector) calculateConfidence(anomaly AnomalyDetectionResult, dataPoints []MetricDataPoint) float64 {
	// 基于偏差大小和一致性计算置信度
	if len(dataPoints) == 0 {
		return anomaly.Confidence
	}

	_, stdDev := d.calculateMeanStdDev(dataPoints)
	if stdDev == 0 {
		return anomaly.Confidence
	}

	zScore := math.Abs(anomaly.Deviation / stdDev)
	confidence := math.Min(zScore/d.zScoreThreshold, 1.0)

	// 如果多个方法都检测到异常，提高置信度
	return math.Min(confidence*1.2, 1.0)
}

// calculateSeverity 计算严重程度
func (d *AnomalyDetector) calculateSeverity(anomaly AnomalyDetectionResult) AnomalySeverity {
	// 基于偏差大小和置信度计算严重程度
	deviationPercent := math.Abs(anomaly.Deviation / math.Max(anomaly.ExpectedValue, 1.0) * 100)

	if anomaly.Confidence > 0.9 && deviationPercent > 50 {
		return SeverityCritical
	} else if anomaly.Confidence > 0.7 && deviationPercent > 30 {
		return SeverityHigh
	} else if anomaly.Confidence > 0.5 && deviationPercent > 15 {
		return SeverityMedium
	}
	return SeverityLow
}

// GenerateRecommendations 生成建议
func (d *AnomalyDetector) GenerateRecommendations(anomaly AnomalyDetectionResult) []string {
	var recommendations []string

	switch anomaly.Type {
	case AnomalyTypeMetricSpike:
		if anomaly.MetricType == "cpu" {
			recommendations = append(recommendations, "检查CPU密集型进程，考虑优化或限制资源使用")
			recommendations = append(recommendations, "检查系统负载，考虑扩容或负载均衡")
		} else if anomaly.MetricType == "memory" {
			recommendations = append(recommendations, "检查内存泄漏，重启相关服务")
			recommendations = append(recommendations, "清理缓存和临时文件")
		} else if anomaly.MetricType == "disk" {
			recommendations = append(recommendations, "检查磁盘空间使用情况，清理不必要的文件")
			recommendations = append(recommendations, "检查日志文件大小，考虑日志轮转")
		}
	case AnomalyTypeMetricDrop:
		recommendations = append(recommendations, "检查服务是否正常运行")
		recommendations = append(recommendations, "检查资源是否被正确分配")
	case AnomalyTypeLogError:
		recommendations = append(recommendations, "查看详细错误日志，定位问题")
		recommendations = append(recommendations, "检查应用程序配置和依赖")
		recommendations = append(recommendations, "检查外部服务连接状态")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "持续监控异常情况，收集更多数据进行分析")
	}

	return recommendations
}
