// ============================================
// 文件: storage_adapter.go
// ============================================
package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"monitor-backend/api"
)

// StorageAdapter 适配器，实现API的StorageInterface
type StorageAdapter struct {
	storage *Storage
}

func NewStorageAdapter(storage *Storage) *StorageAdapter {
	return &StorageAdapter{
		storage: storage,
	}
}

// ListAgents 获取Agent列表
func (s *StorageAdapter) ListAgents(status string, page, pageSize int) ([]api.AgentInfo, int64, error) {
	var agents []Agent
	var total int64

	query := s.storage.postgres.Model(&Agent{})

	// 过滤状态
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// 获取总数
	query.Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Order("last_seen DESC").Find(&agents).Error
	if err != nil {
		return nil, 0, err
	}

	// 转换为API格式
	result := make([]api.AgentInfo, len(agents))
	for i, agent := range agents {
		result[i] = api.AgentInfo{
			HostID:    agent.HostID,
			Hostname:  agent.Hostname,
			IP:        agent.IP,
			OS:        agent.OS,
			Arch:      agent.Arch,
			Tags:      agent.Tags,
			Status:    agent.Status,
			LastSeen:  agent.LastSeen,
			CreatedAt: agent.CreatedAt,
		}
	}

	return result, total, nil
}

// GetAgent 获取单个Agent
func (s *StorageAdapter) GetAgent(hostID string) (*api.AgentInfo, error) {
	var agent Agent
	err := s.storage.postgres.Where("host_id = ?", hostID).First(&agent).Error
	if err != nil {
		return nil, err
	}

	return &api.AgentInfo{
		HostID:    agent.HostID,
		Hostname:  agent.Hostname,
		IP:        agent.IP,
		OS:        agent.OS,
		Arch:      agent.Arch,
		Tags:      agent.Tags,
		Status:    agent.Status,
		LastSeen:  agent.LastSeen,
		CreatedAt: agent.CreatedAt,
	}, nil
}

// DeleteAgent 删除Agent
func (s *StorageAdapter) DeleteAgent(hostID string) error {
	return s.storage.postgres.Where("host_id = ?", hostID).Delete(&Agent{}).Error
}

// GetMetrics 获取指标数据
func (s *StorageAdapter) GetMetrics(hostID, metricType, start, end string) ([]api.MetricPoint, error) {
	ctx := context.Background()

	// 构建Flux查询
	query := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: %s, stop: %s)
		|> filter(fn: (r) => r["_measurement"] == "%s")
		|> filter(fn: (r) => r["host_id"] == "%s")
	`, s.storage.config.InfluxDB.Bucket, start, end, metricType, hostID)

	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer result.Close()

	// 解析结果
	points := make([]api.MetricPoint, 0)
	currentTime := time.Time{}
	currentValues := make(map[string]interface{})

	for result.Next() {
		record := result.Record()
		recordTime := record.Time()

		// 如果是新的时间点，保存上一个点
		if !currentTime.IsZero() && !recordTime.Equal(currentTime) {
			points = append(points, api.MetricPoint{
				Timestamp: currentTime,
				Values:    currentValues,
			})
			currentValues = make(map[string]interface{})
		}

		currentTime = recordTime
		currentValues[record.Field()] = record.Value()
	}

	// 添加最后一个点
	if !currentTime.IsZero() {
		points = append(points, api.MetricPoint{
			Timestamp: currentTime,
			Values:    currentValues,
		})
	}

	return points, nil
}

// GetLatestMetrics 获取最新指标
func (s *StorageAdapter) GetLatestMetrics(hostID string) (*api.LatestMetrics, error) {
	ctx := context.Background()
	latest := &api.LatestMetrics{
		HostID:  hostID,
		CPU:     make(map[string]interface{}),
		Memory:  make(map[string]interface{}),
		Disk:    make(map[string]interface{}),
		Network: make(map[string]interface{}),
	}

	measurements := []string{"cpu", "memory", "disk", "network"}

	for _, measurement := range measurements {
		query := fmt.Sprintf(`
			from(bucket: "%s")
			|> range(start: -5m)
			|> filter(fn: (r) => r["_measurement"] == "%s")
			|> filter(fn: (r) => r["host_id"] == "%s")
			|> last()
		`, s.storage.config.InfluxDB.Bucket, measurement, hostID)

		queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
		result, err := queryAPI.Query(ctx, query)
		if err != nil {
			continue
		}

		values := make(map[string]interface{})
		var timestamp time.Time

		for result.Next() {
			record := result.Record()
			timestamp = record.Time()
			values[record.Field()] = record.Value()
		}
		result.Close()

		if !timestamp.IsZero() {
			latest.Timestamp = timestamp
		}

		switch measurement {
		case "cpu":
			latest.CPU = values
		case "memory":
			latest.Memory = values
		case "disk":
			latest.Disk = values
		case "network":
			latest.Network = values
		}
	}

	return latest, nil
}

// GetHistoryMetrics 获取历史指标
func (s *StorageAdapter) GetHistoryMetrics(hostID, metricType, start, end, interval string) ([]api.MetricPoint, error) {
	ctx := context.Background()

	// 构建Flux查询 - 简化版本，只使用start参数
	// Flux语法要求：range的参数必须直接是时间值，不能是字符串变量
	query := fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "%s")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> aggregateWindow(every: %s, fn: mean, createEmpty: false)`,
		s.storage.config.InfluxDB.Bucket,
		start, // 直接使用 -1h, -6h 等
		metricType,
		hostID,
		interval) // 直接使用 1m, 5m 等

	log.Printf("Executing InfluxDB query for %s/%s", hostID, metricType)
	log.Printf("Query: %s", query)

	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		log.Printf("InfluxDB query error: %v", err)
		return nil, fmt.Errorf("influxdb query failed: %v", err)
	}
	defer result.Close()

	// 检查查询错误
	if result.Err() != nil {
		log.Printf("InfluxDB result error: %v", result.Err())
		return nil, fmt.Errorf("influxdb result error: %v", result.Err())
	}

	// 解析结果 - 使用Unix时间戳作为key避免时区问题
	pointsMap := make(map[int64]map[string]interface{})
	recordCount := 0

	for result.Next() {
		record := result.Record()
		recordCount++

		// 使用Unix时间戳
		timestamp := record.Time().Unix()

		if _, exists := pointsMap[timestamp]; !exists {
			pointsMap[timestamp] = make(map[string]interface{})
		}

		// 获取字段和值
		fieldName := record.Field()
		fieldValue := record.Value()

		if fieldValue != nil {
			pointsMap[timestamp][fieldName] = fieldValue
		}
	}

	log.Printf("Query returned %d records, grouped into %d time points", recordCount, len(pointsMap))

	// 没有数据时返回空数组
	if len(pointsMap) == 0 {
		log.Printf("No data found for host_id=%s, type=%s, start=%s", hostID, metricType, start)
		return []api.MetricPoint{}, nil
	}

	// 转换为切片并排序
	timestamps := make([]int64, 0, len(pointsMap))
	for ts := range pointsMap {
		timestamps = append(timestamps, ts)
	}

	// 排序
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	// 构建结果
	points := make([]api.MetricPoint, 0, len(timestamps))
	for _, ts := range timestamps {
		points = append(points, api.MetricPoint{
			Timestamp: time.Unix(ts, 0),
			Values:    pointsMap[ts],
		})
	}

	log.Printf("Returning %d data points", len(points))
	return points, nil
}

// GetAggregateMetrics 获取聚合指标
func (s *StorageAdapter) GetAggregateMetrics(metricType, aggregation, start, end string) ([]api.AggregateMetric, error) {
	ctx := context.Background()

	// 根据聚合类型选择函数
	aggFunc := "mean"
	switch aggregation {
	case "max":
		aggFunc = "max"
	case "min":
		aggFunc = "min"
	case "sum":
		aggFunc = "sum"
	}

	query := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: %s, stop: %s)
		|> filter(fn: (r) => r["_measurement"] == "%s")
		|> group(columns: ["host_id"])
		|> %s()
	`, s.storage.config.InfluxDB.Bucket, start, end, metricType, aggFunc)

	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer result.Close()

	// 解析结果
	metricsMap := make(map[string]map[string]interface{})

	for result.Next() {
		record := result.Record()
		hostID := record.ValueByKey("host_id").(string)

		if _, exists := metricsMap[hostID]; !exists {
			metricsMap[hostID] = make(map[string]interface{})
		}
		metricsMap[hostID][record.Field()] = record.Value()
	}

	// 转换为切片
	metrics := make([]api.AggregateMetric, 0, len(metricsMap))
	for hostID, values := range metricsMap {
		metrics = append(metrics, api.AggregateMetric{
			HostID: hostID,
			Values: values,
		})
	}

	return metrics, nil
}

// GetOverview 获取概览统计
func (s *StorageAdapter) GetOverview() (*api.Overview, error) {
	overview := &api.Overview{}

	// 统计Agent数量
	s.storage.postgres.Model(&Agent{}).Count(&overview.TotalAgents)
	s.storage.postgres.Model(&Agent{}).Where("status = ?", "online").Count(&overview.OnlineAgents)
	overview.OfflineAgents = overview.TotalAgents - overview.OnlineAgents

	// 获取平均CPU和内存（最近5分钟）
	ctx := context.Background()

	// 平均CPU
	cpuQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: -5m)
		|> filter(fn: (r) => r["_measurement"] == "cpu")
		|> filter(fn: (r) => r["_field"] == "usage_percent")
		|> mean()
	`, s.storage.config.InfluxDB.Bucket)

	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, cpuQuery)
	if err == nil {
		for result.Next() {
			if val, ok := result.Record().Value().(float64); ok {
				overview.AvgCPU = val
			}
		}
		result.Close()
	}

	// 平均内存
	memQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: -5m)
		|> filter(fn: (r) => r["_measurement"] == "memory")
		|> filter(fn: (r) => r["_field"] == "used_percent")
		|> mean()
	`, s.storage.config.InfluxDB.Bucket)

	result, err = queryAPI.Query(ctx, memQuery)
	if err == nil {
		for result.Next() {
			if val, ok := result.Record().Value().(float64); ok {
				overview.AvgMemory = val
			}
		}
		result.Close()
	}

	// 指标数量估算
	overview.TotalMetrics = overview.OnlineAgents * 100

	return overview, nil
}

// GetTopMetrics 获取Top指标
func (s *StorageAdapter) GetTopMetrics(metricType string, limit int, order string) ([]api.TopMetric, error) {
	ctx := context.Background()

	// 确定字段
	field := "usage_percent"
	if metricType == "memory" {
		field = "used_percent"
	} else if metricType == "disk" {
		field = "used_percent"
	}

	// 排序方式
	sortFunc := "top"
	if order == "asc" {
		sortFunc = "bottom"
	}

	query := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: -5m)
		|> filter(fn: (r) => r["_measurement"] == "%s")
		|> filter(fn: (r) => r["_field"] == "%s")
		|> mean()
		|> group(columns: ["host_id"])
		|> %s(n: %d)
	`, s.storage.config.InfluxDB.Bucket, metricType, field, sortFunc, limit)

	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer result.Close()

	// 解析结果
	metrics := make([]api.TopMetric, 0)
	agentCache := make(map[string]string)

	for result.Next() {
		record := result.Record()
		hostID := record.ValueByKey("host_id").(string)
		value, _ := record.Value().(float64)

		// 获取hostname
		hostname := hostID
		if cached, exists := agentCache[hostID]; exists {
			hostname = cached
		} else {
			var agent Agent
			if err := s.storage.postgres.Where("host_id = ?", hostID).First(&agent).Error; err == nil {
				hostname = agent.Hostname
				agentCache[hostID] = hostname
			}
		}

		metrics = append(metrics, api.TopMetric{
			HostID:   hostID,
			Hostname: hostname,
			Value:    value,
		})
	}

	return metrics, nil
}
