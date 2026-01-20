// ============================================
// 文件: api/performance_handlers.go
// 性能分析相关API处理
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

// PerformanceMetrics 性能指标数据
type PerformanceMetrics struct {
	HostID    string                 `json:"host_id"`
	Hostname  string                 `json:"hostname"`
	Timestamp time.Time              `json:"timestamp"`
	CPU       CPUMetrics             `json:"cpu"`
	Memory    MemoryMetrics          `json:"memory"`
	Disk      DiskMetrics            `json:"disk"`
	Network   NetworkMetrics         `json:"network"`
	Summary   PerformanceSummary     `json:"summary"`
}

// CPUMetrics CPU指标
type CPUMetrics struct {
	UsagePercent float64   `json:"usage_percent"`
	LoadAvg1     float64   `json:"load_avg_1"`
	LoadAvg5     float64   `json:"load_avg_5"`
	LoadAvg15    float64   `json:"load_avg_15"`
	CoreCount    int       `json:"core_count"`
	History      []float64 `json:"history"` // 历史使用率
	AvgUsage     float64   `json:"avg_usage"`
	MaxUsage     float64   `json:"max_usage"`
	MinUsage     float64   `json:"min_usage"`
}

// MemoryMetrics 内存指标
type MemoryMetrics struct {
	Total       uint64    `json:"total"`
	Used        uint64    `json:"used"`
	Free        uint64    `json:"free"`
	UsedPercent float64   `json:"used_percent"`
	Available   uint64    `json:"available"`
	History     []float64 `json:"history"` // 历史使用率
	AvgUsage    float64   `json:"avg_usage"`
	MaxUsage    float64   `json:"max_usage"`
	MinUsage    float64   `json:"min_usage"`
}

// DiskMetrics 磁盘指标
type DiskMetrics struct {
	Partitions []PartitionMetrics `json:"partitions"`
	TotalUsage float64            `json:"total_usage"` // 所有分区的平均使用率
	MaxUsage   float64            `json:"max_usage"`  // 最高使用率
}

// PartitionMetrics 分区指标
type PartitionMetrics struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// NetworkMetrics 网络指标
type NetworkMetrics struct {
	Interfaces []InterfaceMetrics `json:"interfaces"`
	TotalBytesSent   uint64 `json:"total_bytes_sent"`
	TotalBytesRecv   uint64 `json:"total_bytes_recv"`
	TotalPacketsSent uint64 `json:"total_packets_sent"`
	TotalPacketsRecv uint64 `json:"total_packets_recv"`
}

// InterfaceMetrics 网卡指标
type InterfaceMetrics struct {
	Name        string `json:"name"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	Errin       uint64 `json:"errin"`
	Errout      uint64 `json:"errout"`
}

// PerformanceSummary 性能摘要
type PerformanceSummary struct {
	Bottlenecks    []BottleneckInfo    `json:"bottlenecks"`
	Efficiency     EfficiencyInfo       `json:"efficiency"`
	Recommendations []string            `json:"recommendations"`
}

// BottleneckInfo 瓶颈信息
type BottleneckInfo struct {
	Type        string  `json:"type"`        // cpu/memory/disk/network
	Severity    string  `json:"severity"`   // critical/high/medium/low
	Description string  `json:"description"`
	Value       float64 `json:"value"`
	Threshold   float64 `json:"threshold"`
}

// EfficiencyInfo 效率信息
type EfficiencyInfo struct {
	CPU    float64 `json:"cpu"`    // CPU使用效率 (0-100)
	Memory float64 `json:"memory"` // 内存使用效率 (0-100)
	Disk   float64 `json:"disk"`   // 磁盘使用效率 (0-100)
	Overall float64 `json:"overall"` // 整体效率 (0-100)
}

// streamPerformanceAnalysis 流式获取性能分析（SSE）
func (s *APIServer) streamPerformanceAnalysis(c *gin.Context) {
	hostID := c.Query("host_id")
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

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID
	if err == nil && agent != nil {
		hostname = agent.Hostname
	}

	// 收集性能数据
	performanceData, err := s.collectPerformanceData(hostID, hoursNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to collect performance data: " + err.Error(),
		})
		return
	}

	// 分析性能瓶颈
	bottlenecks := s.analyzeBottlenecks(performanceData)
	
	// 评估资源使用效率
	efficiency := s.evaluateEfficiency(performanceData)

	// 准备LLM输入数据（转换为map以便序列化）
	cpuMap := map[string]interface{}{
		"usage_percent": performanceData.CPU.UsagePercent,
		"load_avg_1":    performanceData.CPU.LoadAvg1,
		"load_avg_5":    performanceData.CPU.LoadAvg5,
		"load_avg_15":   performanceData.CPU.LoadAvg15,
		"core_count":    float64(performanceData.CPU.CoreCount),
		"avg_usage":     performanceData.CPU.AvgUsage,
		"max_usage":     performanceData.CPU.MaxUsage,
		"min_usage":     performanceData.CPU.MinUsage,
	}

	memoryMap := map[string]interface{}{
		"total":        float64(performanceData.Memory.Total),
		"used":         float64(performanceData.Memory.Used),
		"free":         float64(performanceData.Memory.Free),
		"used_percent": performanceData.Memory.UsedPercent,
		"available":   float64(performanceData.Memory.Available),
		"avg_usage":    performanceData.Memory.AvgUsage,
		"max_usage":    performanceData.Memory.MaxUsage,
		"min_usage":    performanceData.Memory.MinUsage,
	}

	diskMap := map[string]interface{}{
		"total_usage": performanceData.Disk.TotalUsage,
		"max_usage":   performanceData.Disk.MaxUsage,
		"partitions":  performanceData.Disk.Partitions,
	}

	bottlenecksInterface := make([]interface{}, len(bottlenecks))
	for i, b := range bottlenecks {
		bottlenecksInterface[i] = map[string]interface{}{
			"type":        b.Type,
			"severity":    b.Severity,
			"description": b.Description,
			"value":       b.Value,
			"threshold":   b.Threshold,
		}
	}

	efficiencyMap := map[string]interface{}{
		"cpu":     efficiency.CPU,
		"memory":  efficiency.Memory,
		"disk":    efficiency.Disk,
		"overall": efficiency.Overall,
	}

	llmData := map[string]interface{}{
		"host_id":     hostID,
		"hostname":    hostname,
		"cpu":         cpuMap,
		"memory":      memoryMap,
		"disk":        diskMap,
		"network":     performanceData.Network,
		"bottlenecks": bottlenecksInterface,
		"efficiency":  efficiencyMap,
		"time_range":  fmt.Sprintf("最近 %d 小时", hoursNum),
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

	// 通过反射调用 StreamPerformanceAnalysis 方法
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
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get LLM client",
		})
		return
	}

	// 调用流式方法
	streamMethod := reflect.ValueOf(actualClient).MethodByName("StreamPerformanceAnalysis")
	if !streamMethod.IsValid() {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "LLM client does not support performance analysis streaming",
		})
		return
	}

	log.Printf("[API] 使用流式性能分析")
	results := streamMethod.Call([]reflect.Value{
		reflect.ValueOf(hostID),
		reflect.ValueOf(hostname),
		reflect.ValueOf(llmData),
		reflect.ValueOf(c.Writer),
	})

	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			log.Printf("[API] 流式性能分析失败: %v", err)
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

// collectPerformanceData 收集性能数据
func (s *APIServer) collectPerformanceData(hostID string, hours int) (*PerformanceMetrics, error) {
	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	// 获取CPU数据
	cpuData, err := s.storage.GetPredictionData(hostID, "cpu", hours/24+1)
	if err != nil {
		log.Printf("Failed to get CPU data: %v", err)
	}
	
	// 获取内存数据
	memoryData, err := s.storage.GetPredictionData(hostID, "memory", hours/24+1)
	if err != nil {
		log.Printf("Failed to get memory data: %v", err)
	}

	// 获取磁盘数据
	diskData, err := s.storage.GetPredictionData(hostID, "disk", hours/24+1)
	if err != nil {
		log.Printf("Failed to get disk data: %v", err)
	}

	// 处理CPU数据
	cpuMetrics := CPUMetrics{}
	if len(cpuData) > 0 {
		values := make([]float64, 0, len(cpuData))
		var sum, max, min float64 = 0, 0, 100
		for _, dp := range cpuData {
			if dp.Timestamp.After(startTime) || dp.Timestamp.Equal(startTime) {
				values = append(values, dp.Value)
				sum += dp.Value
				if dp.Value > max {
					max = dp.Value
				}
				if dp.Value < min {
					min = dp.Value
				}
			}
		}
		if len(values) > 0 {
			cpuMetrics.History = values
			cpuMetrics.AvgUsage = sum / float64(len(values))
			cpuMetrics.MaxUsage = max
			cpuMetrics.MinUsage = min
			if len(values) > 0 {
				cpuMetrics.UsagePercent = values[len(values)-1] // 最新值
			}
		}
	}

	// 处理内存数据
	memoryMetrics := MemoryMetrics{}
	if len(memoryData) > 0 {
		values := make([]float64, 0, len(memoryData))
		var sum, max, min float64 = 0, 0, 100
		for _, dp := range memoryData {
			if dp.Timestamp.After(startTime) || dp.Timestamp.Equal(startTime) {
				values = append(values, dp.Value)
				sum += dp.Value
				if dp.Value > max {
					max = dp.Value
				}
				if dp.Value < min {
					min = dp.Value
				}
			}
		}
		if len(values) > 0 {
			memoryMetrics.History = values
			memoryMetrics.AvgUsage = sum / float64(len(values))
			memoryMetrics.MaxUsage = max
			memoryMetrics.MinUsage = min
			if len(values) > 0 {
				memoryMetrics.UsedPercent = values[len(values)-1] // 最新值
			}
		}
	}

	// 处理磁盘数据
	diskMetrics := DiskMetrics{}
	if len(diskData) > 0 {
		values := make([]float64, 0, len(diskData))
		var sum, max float64 = 0, 0
		for _, dp := range diskData {
			if dp.Timestamp.After(startTime) || dp.Timestamp.Equal(startTime) {
				values = append(values, dp.Value)
				sum += dp.Value
				if dp.Value > max {
					max = dp.Value
				}
			}
		}
		if len(values) > 0 {
			diskMetrics.TotalUsage = sum / float64(len(values))
			diskMetrics.MaxUsage = max
		}
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	hostname := hostID
	if err == nil && agent != nil {
		hostname = agent.Hostname
	}

	return &PerformanceMetrics{
		HostID:    hostID,
		Hostname:  hostname,
		Timestamp: endTime,
		CPU:       cpuMetrics,
		Memory:    memoryMetrics,
		Disk:      diskMetrics,
		Network:   NetworkMetrics{}, // 网络数据需要单独处理
	}, nil
}

// analyzeBottlenecks 分析性能瓶颈
func (s *APIServer) analyzeBottlenecks(data *PerformanceMetrics) []BottleneckInfo {
	bottlenecks := make([]BottleneckInfo, 0)

	// CPU瓶颈
	if data.CPU.AvgUsage > 80 {
		severity := "medium"
		if data.CPU.AvgUsage > 90 {
			severity = "critical"
		} else if data.CPU.AvgUsage > 85 {
			severity = "high"
		}
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:        "cpu",
			Severity:    severity,
			Description: fmt.Sprintf("CPU平均使用率 %.2f%%，最高 %.2f%%，可能存在CPU瓶颈", data.CPU.AvgUsage, data.CPU.MaxUsage),
			Value:       data.CPU.AvgUsage,
			Threshold:   80,
		})
	}

	// 内存瓶颈
	if data.Memory.AvgUsage > 80 {
		severity := "medium"
		if data.Memory.AvgUsage > 90 {
			severity = "critical"
		} else if data.Memory.AvgUsage > 85 {
			severity = "high"
		}
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:        "memory",
			Severity:    severity,
			Description: fmt.Sprintf("内存平均使用率 %.2f%%，最高 %.2f%%，可能存在内存瓶颈", data.Memory.AvgUsage, data.Memory.MaxUsage),
			Value:       data.Memory.AvgUsage,
			Threshold:   80,
		})
	}

	// 磁盘瓶颈
	if data.Disk.MaxUsage > 85 {
		severity := "medium"
		if data.Disk.MaxUsage > 95 {
			severity = "critical"
		} else if data.Disk.MaxUsage > 90 {
			severity = "high"
		}
		bottlenecks = append(bottlenecks, BottleneckInfo{
			Type:        "disk",
			Severity:    severity,
			Description: fmt.Sprintf("磁盘最高使用率 %.2f%%，平均 %.2f%%，可能存在磁盘空间不足", data.Disk.MaxUsage, data.Disk.TotalUsage),
			Value:       data.Disk.MaxUsage,
			Threshold:   85,
		})
	}

	return bottlenecks
}

// evaluateEfficiency 评估资源使用效率
func (s *APIServer) evaluateEfficiency(data *PerformanceMetrics) EfficiencyInfo {
	// CPU效率：使用率在40-70%之间为最佳，过高或过低都降低效率分
	cpuEfficiency := 100.0
	if data.CPU.AvgUsage > 70 {
		cpuEfficiency = 100 - (data.CPU.AvgUsage-70)*2 // 超过70%每1%扣2分
		if cpuEfficiency < 0 {
			cpuEfficiency = 0
		}
	} else if data.CPU.AvgUsage < 40 {
		cpuEfficiency = data.CPU.AvgUsage * 1.5 // 低于40%按比例给分
	}

	// 内存效率：使用率在50-80%之间为最佳
	memoryEfficiency := 100.0
	if data.Memory.AvgUsage > 80 {
		memoryEfficiency = 100 - (data.Memory.AvgUsage-80)*2
		if memoryEfficiency < 0 {
			memoryEfficiency = 0
		}
	} else if data.Memory.AvgUsage < 50 {
		memoryEfficiency = data.Memory.AvgUsage * 1.2
	}

	// 磁盘效率：使用率在60-85%之间为最佳
	diskEfficiency := 100.0
	if data.Disk.TotalUsage > 85 {
		diskEfficiency = 100 - (data.Disk.TotalUsage-85)*2
		if diskEfficiency < 0 {
			diskEfficiency = 0
		}
	} else if data.Disk.TotalUsage < 60 {
		diskEfficiency = data.Disk.TotalUsage * 1.2
	}

	// 整体效率：加权平均
	overallEfficiency := (cpuEfficiency*0.4 + memoryEfficiency*0.4 + diskEfficiency*0.2)

	return EfficiencyInfo{
		CPU:     cpuEfficiency,
		Memory:  memoryEfficiency,
		Disk:    diskEfficiency,
		Overall: overallEfficiency,
	}
}
