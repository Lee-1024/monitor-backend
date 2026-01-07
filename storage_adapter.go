// ============================================
// 文件: storage_adapter.go
// ============================================
package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
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

// GetLatestMetrics 获取最新指标（优先从Redis缓存获取）
func (s *StorageAdapter) GetLatestMetrics(hostID string) (*api.LatestMetrics, error) {
	// 先尝试从Redis缓存获取
	if cachedMetrics, err := s.storage.GetCachedLatestMetrics(hostID); err == nil {
		log.Printf("Cache hit for latest metrics: %s", hostID)
		// 转换为API格式
		latest := &api.LatestMetrics{
			HostID:    hostID,
			Timestamp: cachedMetrics.Timestamp,
			CPU: map[string]interface{}{
				"usage_percent": cachedMetrics.CPU.UsagePercent,
				"load_avg_1":    cachedMetrics.CPU.LoadAvg1,
				"load_avg_5":    cachedMetrics.CPU.LoadAvg5,
				"load_avg_15":   cachedMetrics.CPU.LoadAvg15,
				"core_count":    cachedMetrics.CPU.CoreCount,
			},
			Memory: map[string]interface{}{
				"total":        cachedMetrics.Memory.Total,
				"used":         cachedMetrics.Memory.Used,
				"free":         cachedMetrics.Memory.Free,
				"used_percent": cachedMetrics.Memory.UsedPercent,
				"available":    cachedMetrics.Memory.Available,
			},
			Disk:    make(map[string]interface{}),
			Network: make(map[string]interface{}),
		}

		// 添加磁盘数据
		if len(cachedMetrics.Disk.Partitions) > 0 {
			p := cachedMetrics.Disk.Partitions[0]
			latest.Disk = map[string]interface{}{
				"device":       p.Device,
				"mountpoint":   p.Mountpoint,
				"fstype":       p.Fstype,
				"total":        p.Total,
				"used":         p.Used,
				"free":         p.Free,
				"used_percent": p.UsedPercent,
			}
		}

		// 添加网络数据
		if len(cachedMetrics.Network.Interfaces) > 0 {
			iface := cachedMetrics.Network.Interfaces[0]
			latest.Network = map[string]interface{}{
				"bytes_sent":   iface.BytesSent,
				"bytes_recv":   iface.BytesRecv,
				"packets_sent": iface.PacketsSent,
				"packets_recv": iface.PacketsRecv,
			}
		}

		return latest, nil
	}

	// 缓存未命中，从InfluxDB查询
	log.Printf("Cache miss for latest metrics: %s, querying InfluxDB", hostID)
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
		var query string

		// 对于磁盘和网络，需要特殊处理多个分区/接口的情况
		if measurement == "disk" {
			// 磁盘：先尝试查询根分区，如果没有则查询所有分区
			// 先检查是否有根分区数据
			checkQuery := fmt.Sprintf(`
				from(bucket: "%s")
				|> range(start: -5m)
				|> filter(fn: (r) => r["_measurement"] == "%s")
				|> filter(fn: (r) => r["host_id"] == "%s")
				|> filter(fn: (r) => r["mountpoint"] == "/")
				|> limit(n: 1)
			`, s.storage.config.InfluxDB.Bucket, measurement, hostID)

			checkAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
			checkResult, err := checkAPI.Query(ctx, checkQuery)
			hasRootPartition := false
			if err == nil {
				hasRootPartition = checkResult.Next()
				checkResult.Close()
			}

			if hasRootPartition {
				// 有根分区，查询根分区的最新数据
				query = fmt.Sprintf(`
					from(bucket: "%s")
					|> range(start: -5m)
					|> filter(fn: (r) => r["_measurement"] == "%s")
					|> filter(fn: (r) => r["host_id"] == "%s")
					|> filter(fn: (r) => r["mountpoint"] == "/")
					|> last()
				`, s.storage.config.InfluxDB.Bucket, measurement, hostID)
			} else {
				// 没有根分区，查询所有分区的最新数据
				query = fmt.Sprintf(`
					from(bucket: "%s")
					|> range(start: -5m)
					|> filter(fn: (r) => r["_measurement"] == "%s")
					|> filter(fn: (r) => r["host_id"] == "%s")
					|> group(columns: ["mountpoint", "device"])
					|> last()
				`, s.storage.config.InfluxDB.Bucket, measurement, hostID)
			}
		} else if measurement == "network" {
			// 网络：聚合所有接口的数据，按字段名分组求和
			query = fmt.Sprintf(`
				from(bucket: "%s")
				|> range(start: -5m)
				|> filter(fn: (r) => r["_measurement"] == "%s")
				|> filter(fn: (r) => r["host_id"] == "%s")
				|> group(columns: ["_field"])
				|> aggregateWindow(every: 1m, fn: sum, createEmpty: false)
				|> last()
				|> group()
			`, s.storage.config.InfluxDB.Bucket, measurement, hostID)
		} else {
			// CPU和内存：直接获取最新数据
			query = fmt.Sprintf(`
				from(bucket: "%s")
				|> range(start: -5m)
				|> filter(fn: (r) => r["_measurement"] == "%s")
				|> filter(fn: (r) => r["host_id"] == "%s")
				|> last()
			`, s.storage.config.InfluxDB.Bucket, measurement, hostID)
		}

		queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
		result, err := queryAPI.Query(ctx, query)
		if err != nil {
			continue
		}

		values := make(map[string]interface{})
		var timestamp time.Time

		// 对于磁盘，返回所有分区数据，前端可以选择显示
		if measurement == "disk" {
			// 如果查询已经过滤了根分区，直接处理结果
			hasRootFilter := false
			if query != "" {
				hasRootFilter = strings.Contains(query, `r["mountpoint"] == "/"`)
			}

			if hasRootFilter {
				// 直接处理根分区的数据
				for result.Next() {
					record := result.Record()
					timestamp = record.Time()
					fieldName := record.Field()
					if fieldName != "" {
						values[fieldName] = record.Value()
					}
				}
				result.Close()
				// 添加分区标识
				values["_mountpoint"] = "/"
				log.Printf("Found root partition disk data with %d fields", len(values))
			} else {
				// 处理多个分区，返回所有分区数据（以根分区为主，其他分区作为额外信息）
				partitions := make(map[string]map[string]interface{})
				partitionTimestamps := make(map[string]time.Time)
				var maxTotal uint64
				var mainMountpoint string
				var allPartitions []map[string]interface{}

				recordCount := 0
				for result.Next() {
					record := result.Record()
					recordCount++

					// 从 tag 中获取 mountpoint
					mountpoint := ""
					mountpointVal := record.ValueByKey("mountpoint")
					if mountpointVal != nil {
						if mpStr, ok := mountpointVal.(string); ok {
							mountpoint = mpStr
						}
					}

					// 如果还是没有，尝试从其他方式获取
					if mountpoint == "" {
						// 尝试从所有 tag 中查找
						for key, val := range record.Values() {
							if key == "mountpoint" {
								if mpStr, ok := val.(string); ok {
									mountpoint = mpStr
									break
								}
							}
						}
					}

					if mountpoint == "" {
						log.Printf("Warning: disk record %d has no mountpoint tag", recordCount)
						continue
					}

					if partitions[mountpoint] == nil {
						partitions[mountpoint] = make(map[string]interface{})
						partitionTimestamps[mountpoint] = record.Time()
					}

					fieldName := record.Field()
					if fieldName != "" {
						partitions[mountpoint][fieldName] = record.Value()
					}

					// 如果是根分区，优先选择
					if mountpoint == "/" {
						mainMountpoint = mountpoint
					}
				}
				result.Close()

				log.Printf("Found %d disk records, %d partitions", recordCount, len(partitions))

				// 如果没有找到根分区，选择最大的分区
				if mainMountpoint == "" {
					for mp, partData := range partitions {
						var total uint64
						if totalVal, ok := partData["total"]; ok {
							switch v := totalVal.(type) {
							case uint64:
								total = v
							case int64:
								total = uint64(v)
							case float64:
								total = uint64(v)
							}
							if total > maxTotal {
								maxTotal = total
								mainMountpoint = mp
							}
						}
					}
				}

				// 如果还是没有，选择第一个分区
				if mainMountpoint == "" && len(partitions) > 0 {
					for mp := range partitions {
						mainMountpoint = mp
						break
					}
				}

				// 设置主分区数据
				if mainMountpoint != "" && partitions[mainMountpoint] != nil {
					values = partitions[mainMountpoint]
					values["_mountpoint"] = mainMountpoint
					timestamp = partitionTimestamps[mainMountpoint]

					// 收集所有分区信息（用于前端展示）
					for mp, partData := range partitions {
						if mp != mainMountpoint {
							partInfo := make(map[string]interface{})
							for k, v := range partData {
								partInfo[k] = v
							}
							partInfo["_mountpoint"] = mp
							allPartitions = append(allPartitions, partInfo)
						}
					}

					// 如果有其他分区，添加到values中
					if len(allPartitions) > 0 {
						values["_partitions"] = allPartitions
					}

					log.Printf("Selected disk partition: %s with %d fields, %d other partitions", mainMountpoint, len(values), len(allPartitions))
				} else {
					log.Printf("Warning: No disk partition selected, found %d partitions", len(partitions))
				}
			}
		} else if measurement == "network" {
			// 网络：聚合所有接口的数据
			for result.Next() {
				record := result.Record()
				timestamp = record.Time()
				fieldName := record.Field()
				if fieldName != "" {
					// 累加相同字段的值（多个接口的数据）
					if existingValue, exists := values[fieldName]; exists {
						// 如果已存在，累加
						if existingNum, ok := existingValue.(float64); ok {
							if newNum, ok := record.Value().(float64); ok {
								values[fieldName] = existingNum + newNum
							} else if newNum, ok := record.Value().(int64); ok {
								values[fieldName] = existingNum + float64(newNum)
							}
						} else if existingNum, ok := existingValue.(int64); ok {
							if newNum, ok := record.Value().(int64); ok {
								values[fieldName] = existingNum + newNum
							} else if newNum, ok := record.Value().(float64); ok {
								values[fieldName] = float64(existingNum) + newNum
							}
						}
					} else {
						// 如果不存在，直接设置
						values[fieldName] = record.Value()
					}
				}
			}
			result.Close()
		} else {
			// CPU和内存：正常处理
			for result.Next() {
				record := result.Record()
				timestamp = record.Time()
				values[record.Field()] = record.Value()
			}
			result.Close()
		}

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

	// 构建Flux查询 - 对于磁盘，需要选择主分区（根分区或最大分区）
	var query string
	if metricType == "disk" {
		// 磁盘：先尝试查询根分区，如果没有则查询所有分区并选择最大的
		// 先检查是否有根分区数据
		checkQuery := fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "%s")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> filter(fn: (r) => r["mountpoint"] == "/")
  |> limit(n: 1)`,
			s.storage.config.InfluxDB.Bucket,
			start,
			metricType,
			hostID)

		queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
		checkResult, err := queryAPI.Query(ctx, checkQuery)
		hasRootPartition := false
		if err == nil {
			hasRootPartition = checkResult.Next()
			checkResult.Close()
		}

		if hasRootPartition {
			// 有根分区，查询根分区数据
			query = fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "%s")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> filter(fn: (r) => r["mountpoint"] == "/")
  |> aggregateWindow(every: %s, fn: mean, createEmpty: false)`,
				s.storage.config.InfluxDB.Bucket,
				start,
				metricType,
				hostID,
				interval)
		} else {
			// 没有根分区，查询所有分区，按total排序选择最大的
			query = fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "%s")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> group(columns: ["mountpoint"])
  |> aggregateWindow(every: %s, fn: mean, createEmpty: false)
  |> group()
  |> sort(columns: ["total"], desc: true)
  |> limit(n: 1)
  |> group()`,
				s.storage.config.InfluxDB.Bucket,
				start,
				metricType,
				hostID,
				interval)
		}
	} else if metricType == "network" {
		// 网络：聚合所有接口的数据，按字段分组求和
		query = fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "%s")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> group(columns: ["_field"])
  |> aggregateWindow(every: %s, fn: sum, createEmpty: false)
  |> group()`,
			s.storage.config.InfluxDB.Bucket,
			start,
			metricType,
			hostID,
			interval)
	} else {
		// CPU和内存：正常查询
		query = fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "%s")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> aggregateWindow(every: %s, fn: mean, createEmpty: false)`,
			s.storage.config.InfluxDB.Bucket,
			start,
			metricType,
			hostID,
			interval)
	}

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

		if fieldValue != nil && fieldName != "" {
			// 对于网络数据，如果字段已存在，需要累加（多个接口的数据）
			if metricType == "network" {
				if existingValue, exists := pointsMap[timestamp][fieldName]; exists {
					// 累加相同字段的值
					if existingNum, ok := existingValue.(float64); ok {
						if newNum, ok := fieldValue.(float64); ok {
							pointsMap[timestamp][fieldName] = existingNum + newNum
						} else if newNum, ok := fieldValue.(int64); ok {
							pointsMap[timestamp][fieldName] = existingNum + float64(newNum)
						} else {
							pointsMap[timestamp][fieldName] = fieldValue
						}
					} else if existingNum, ok := existingValue.(int64); ok {
						if newNum, ok := fieldValue.(int64); ok {
							pointsMap[timestamp][fieldName] = existingNum + newNum
						} else if newNum, ok := fieldValue.(float64); ok {
							pointsMap[timestamp][fieldName] = float64(existingNum) + newNum
						} else {
							pointsMap[timestamp][fieldName] = fieldValue
						}
					} else {
						pointsMap[timestamp][fieldName] = fieldValue
					}
				} else {
					pointsMap[timestamp][fieldName] = fieldValue
				}
			} else {
				// 其他指标：直接设置
				pointsMap[timestamp][fieldName] = fieldValue
			}
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
	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)

	// 平均CPU - 先获取每个主机的最新值，然后计算平均值
	cpuQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: -5m)
		|> filter(fn: (r) => r["_measurement"] == "cpu")
		|> filter(fn: (r) => r["_field"] == "usage_percent")
		|> group(columns: ["host_id"])
		|> last()
		|> group()
		|> mean(column: "_value")
	`, s.storage.config.InfluxDB.Bucket)

	result, err := queryAPI.Query(ctx, cpuQuery)
	if err == nil {
		found := false
		for result.Next() {
			record := result.Record()
			if val := record.Value(); val != nil {
				if floatVal, ok := val.(float64); ok {
					overview.AvgCPU = floatVal
					found = true
					log.Printf("Found average CPU: %.2f%%", floatVal)
					break
				}
			}
		}
		if !found {
			log.Printf("No CPU data found in query result")
		}
		if result.Err() != nil {
			log.Printf("Error reading CPU query result: %v", result.Err())
		}
		result.Close()
	} else {
		log.Printf("Failed to query CPU metrics: %v", err)
	}

	// 平均内存
	memQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: -5m)
		|> filter(fn: (r) => r["_measurement"] == "memory")
		|> filter(fn: (r) => r["_field"] == "used_percent")
		|> group(columns: ["host_id"])
		|> last()
		|> group()
		|> mean(column: "_value")
	`, s.storage.config.InfluxDB.Bucket)

	result, err = queryAPI.Query(ctx, memQuery)
	if err == nil {
		found := false
		for result.Next() {
			record := result.Record()
			if val := record.Value(); val != nil {
				if floatVal, ok := val.(float64); ok {
					overview.AvgMemory = floatVal
					found = true
					log.Printf("Found average memory: %.2f%%", floatVal)
					break
				}
			}
		}
		if !found {
			log.Printf("No memory data found in query result")
		}
		if result.Err() != nil {
			log.Printf("Error reading memory query result: %v", result.Err())
		}
		result.Close()
	} else {
		log.Printf("Failed to query memory metrics: %v", err)
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

// ============================================
// 宕机分析相关方法
// ============================================

// GetCrashEvents 获取宕机事件列表
func (s *StorageAdapter) GetCrashEvents(hostID string, limit int) ([]api.CrashEvent, error) {
	var events []CrashEvent
	query := s.storage.postgres.Order("offline_time DESC")

	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&events).Error
	if err != nil {
		return nil, err
	}

	// 检查并自动修复：如果Agent当前是online状态，但事件未标记为已恢复，则自动标记
	for i := range events {
		if !events[i].IsResolved {
			// 检查Agent当前状态
			var agent Agent
			if err := s.storage.postgres.Where("host_id = ?", events[i].HostID).First(&agent).Error; err == nil {
				if agent.Status == "online" {
					// Agent已恢复，但事件未标记，自动修复
					now := time.Now()
					duration := now.Sub(events[i].OfflineTime).Seconds()
					s.storage.postgres.Model(&events[i]).Updates(map[string]interface{}{
						"online_time": &now,
						"duration":    int64(duration),
						"is_resolved": true,
					})
					events[i].IsResolved = true
					events[i].OnlineTime = &now
					events[i].Duration = int64(duration)
					log.Printf("Auto-resolved crash event %d for host %s (agent is online)", events[i].ID, events[i].HostID)
				}
			}
		}
	}

	// 转换为API格式
	result := make([]api.CrashEvent, len(events))
	for i, event := range events {
		result[i] = api.CrashEvent{
			ID:              event.ID,
			HostID:          event.HostID,
			Hostname:        event.Hostname,
			OfflineTime:     event.OfflineTime,
			OnlineTime:      event.OnlineTime,
			Duration:        event.Duration,
			LastCPU:         event.LastCPU,
			LastMemory:      event.LastMemory,
			LastDisk:        event.LastDisk,
			LastNetwork:     event.LastNetwork,
			Reason:          event.Reason,
			IsResolved:      event.IsResolved,
			MetricsSnapshot: event.MetricsSnapshot,
		}
	}

	return result, nil
}

// GetCrashEventDetail 获取单个宕机事件详情
func (s *StorageAdapter) GetCrashEventDetail(id uint) (*api.CrashEvent, error) {
	event, err := s.storage.GetCrashEventDetail(id)
	if err != nil {
		return nil, err
	}

	// 转换为API格式
	result := &api.CrashEvent{
		ID:              event.ID,
		HostID:          event.HostID,
		Hostname:        event.Hostname,
		OfflineTime:     event.OfflineTime,
		OnlineTime:      event.OnlineTime,
		Duration:        event.Duration,
		LastCPU:         event.LastCPU,
		LastMemory:      event.LastMemory,
		LastDisk:        event.LastDisk,
		LastNetwork:     event.LastNetwork,
		Reason:          event.Reason,
		IsResolved:      event.IsResolved,
		MetricsSnapshot: event.MetricsSnapshot,
	}

	return result, nil
}

// GetCrashAnalysis 获取宕机分析
func (s *StorageAdapter) GetCrashAnalysis(hostID string) (*api.CrashAnalysis, error) {
	// 获取最近的宕机事件
	events, err := s.GetCrashEvents(hostID, 10)
	if err != nil {
		return nil, err
	}

	// 统计已恢复数量
	resolvedCount := 0
	for _, event := range events {
		if event.IsResolved {
			resolvedCount++
		}
	}

	log.Printf("Crash analysis for %s: total=%d, resolved=%d", hostID, len(events), resolvedCount)

	// 计算统计信息
	analysis := &api.CrashAnalysis{
		TotalCrashes:   len(events),
		ResolvedCount:  resolvedCount,
		RecentCrashes:  events,
		CrashFrequency: s.calculateCrashFrequency(events),
		MainReasons:    s.analyzeMainReasons(events),
		AvgDowntime:    s.calculateAvgDowntime(events),
	}

	return analysis, nil
}

// ============================================
// 进程监控相关方法
// ============================================

// GetProcesses 获取进程列表
func (s *StorageAdapter) GetProcesses(hostID string, limit int) ([]api.ProcessInfo, error) {
	var processes []ProcessSnapshot
	query := s.storage.postgres.Order("timestamp DESC")

	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&processes).Error
	if err != nil {
		return nil, err
	}

	result := make([]api.ProcessInfo, len(processes))
	for i, p := range processes {
		result[i] = api.ProcessInfo{
			ID:            p.ID,
			HostID:        p.HostID,
			Timestamp:     p.Timestamp,
			PID:           p.PID,
			Name:          p.Name,
			User:          p.User,
			CPUPercent:    p.CPUPercent,
			MemoryPercent: p.MemoryPercent,
			MemoryBytes:   p.MemoryBytes,
			Status:        p.Status,
			Command:       p.Command,
		}
	}

	return result, nil
}

// GetProcessHistory 获取进程历史数据（按进程名分组）
func (s *StorageAdapter) GetProcessHistory(hostID string, processNames []string, start, end time.Time, limit int) ([]api.ProcessHistoryPoint, error) {
	var processes []ProcessSnapshot
	query := s.storage.postgres.Order("timestamp ASC")

	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}

	if !start.IsZero() {
		query = query.Where("timestamp >= ?", start)
	}

	if !end.IsZero() {
		query = query.Where("timestamp <= ?", end)
	}

	if len(processNames) > 0 {
		query = query.Where("name IN ?", processNames)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&processes).Error
	if err != nil {
		return nil, err
	}

	result := make([]api.ProcessHistoryPoint, len(processes))
	for i, p := range processes {
		result[i] = api.ProcessHistoryPoint{
			Timestamp:     p.Timestamp,
			ProcessName:   p.Name,
			CPUPercent:    p.CPUPercent,
			MemoryPercent: p.MemoryPercent,
			MemoryBytes:   p.MemoryBytes,
		}
	}

	return result, nil
}

// ============================================
// 日志相关方法
// ============================================

// GetLogs 获取日志列表
func (s *StorageAdapter) GetLogs(hostID, level string, start, end time.Time, limit int) ([]api.LogInfo, error) {
	var logs []LogEntry
	query := s.storage.postgres.Order("timestamp DESC")

	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if level != "" {
		query = query.Where("level = ?", level)
	}
	if !start.IsZero() {
		query = query.Where("timestamp >= ?", start)
	}
	if !end.IsZero() {
		query = query.Where("timestamp <= ?", end)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&logs).Error
	if err != nil {
		return nil, err
	}

	result := make([]api.LogInfo, len(logs))
	for i, l := range logs {
		result[i] = api.LogInfo{
			ID:        l.ID,
			HostID:    l.HostID,
			Timestamp: l.Timestamp,
			Source:    l.Source,
			Level:     l.Level,
			Message:   l.Message,
			Tags:      l.Tags,
		}
	}

	return result, nil
}

// ============================================
// 脚本执行相关方法
// ============================================

// GetScriptExecutions 获取脚本执行记录
func (s *StorageAdapter) GetScriptExecutions(hostID, scriptID string, limit int) ([]api.ScriptExecutionInfo, error) {
	var executions []ScriptExecution
	query := s.storage.postgres.Order("timestamp DESC")

	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if scriptID != "" {
		query = query.Where("script_id = ?", scriptID)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&executions).Error
	if err != nil {
		return nil, err
	}

	result := make([]api.ScriptExecutionInfo, len(executions))
	for i, e := range executions {
		result[i] = api.ScriptExecutionInfo{
			ID:         e.ID,
			HostID:     e.HostID,
			ScriptID:   e.ScriptID,
			ScriptName: e.ScriptName,
			Timestamp:  e.Timestamp,
			Success:    e.Success,
			Output:     e.Output,
			Error:      e.Error,
			ExitCode:   e.ExitCode,
			Duration:   e.Duration,
		}
	}

	return result, nil
}

// ============================================
// 服务状态相关方法
// ============================================

// GetServiceStatus 获取服务状态
func (s *StorageAdapter) GetServiceStatus(hostID string) ([]api.ServiceInfo, error) {
	var services []ServiceStatus

	if hostID != "" {
		// 获取指定主机每个服务的最新状态
		// 使用窗口函数或子查询获取每个服务的最新记录
		subQuery := s.storage.postgres.Table("service_statuses").
			Select("MAX(id) as id").
			Where("host_id = ?", hostID).
			Group("name")

		var maxIDs []uint
		rows, err := subQuery.Rows()
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var id uint
			if err := rows.Scan(&id); err == nil {
				maxIDs = append(maxIDs, id)
			}
		}

		if len(maxIDs) > 0 {
			err = s.storage.postgres.Where("id IN ?", maxIDs).Find(&services).Error
		} else {
			// 如果没有找到记录，返回空列表
			return []api.ServiceInfo{}, nil
		}

		if err != nil {
			return nil, err
		}
	} else {
		// 获取所有主机的最新服务状态
		// 对于每个(host_id, name)组合，只取最新的记录
		// 使用子查询获取每个主机每个服务的最新ID
		type ServiceID struct {
			HostID string
			Name   string
			MaxID  uint
		}

		var serviceIDs []ServiceID
		err := s.storage.postgres.Table("service_statuses").
			Select("host_id, name, MAX(id) as max_id").
			Group("host_id, name").
			Scan(&serviceIDs).Error

		if err != nil {
			return nil, err
		}

		if len(serviceIDs) == 0 {
			return []api.ServiceInfo{}, nil
		}

		var maxIDs []uint
		for _, sid := range serviceIDs {
			maxIDs = append(maxIDs, sid.MaxID)
		}

		err = s.storage.postgres.Where("id IN ?", maxIDs).Order("host_id, name").Find(&services).Error
		if err != nil {
			return nil, err
		}
	}

	result := make([]api.ServiceInfo, len(services))
	for i, svc := range services {
		result[i] = api.ServiceInfo{
			ID:          svc.ID,
			HostID:      svc.HostID,
			Timestamp:   svc.Timestamp,
			Name:        svc.Name,
			Status:      svc.Status,
			Enabled:     svc.Enabled,
			Description: svc.Description,
			Uptime:      svc.Uptime,
		}
	}

	return result, nil
}

// calculateCrashFrequency 计算宕机频率
func (s *StorageAdapter) calculateCrashFrequency(events []api.CrashEvent) string {
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

// analyzeMainReasons 分析主要原因
func (s *StorageAdapter) analyzeMainReasons(events []api.CrashEvent) map[string]int {
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

// calculateAvgDowntime 计算平均宕机时长
func (s *StorageAdapter) calculateAvgDowntime(events []api.CrashEvent) string {
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

// ============================================
// 用户管理相关方法
// ============================================

// CreateUser 创建用户
func (s *StorageAdapter) CreateUser(username, email, password, role string) (*api.UserInfo, error) {
	// 检查用户名是否已存在
	var existingUser User
	if err := s.storage.postgres.Where("username = ?", username).First(&existingUser).Error; err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// 检查邮箱是否已存在
	if err := s.storage.postgres.Where("email = ?", email).First(&existingUser).Error; err == nil {
		return nil, fmt.Errorf("email already exists")
	}

	// 创建用户
	user := User{
		Username: username,
		Email:    email,
		Password: password, // 密码应该在调用前已经加密
		Role:     role,
		Status:   "active",
	}

	if err := s.storage.postgres.Create(&user).Error; err != nil {
		return nil, err
	}

	return &api.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Status:   user.Status,
	}, nil
}

// GetUserByID 根据ID获取用户
func (s *StorageAdapter) GetUserByID(id uint) (*api.UserInfo, error) {
	var user User
	if err := s.storage.postgres.First(&user, id).Error; err != nil {
		return nil, err
	}

	return &api.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Status:   user.Status,
	}, nil
}

// GetUserByUsername 根据用户名获取用户（返回密码哈希）
func (s *StorageAdapter) GetUserByUsername(username string) (*api.UserInfo, string, error) {
	var user User
	if err := s.storage.postgres.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, "", err
	}

	return &api.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Status:   user.Status,
	}, user.Password, nil
}

// GetUserByEmail 根据邮箱获取用户
func (s *StorageAdapter) GetUserByEmail(email string) (*api.UserInfo, error) {
	var user User
	if err := s.storage.postgres.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}

	return &api.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Status:   user.Status,
	}, nil
}

// ListUsers 获取用户列表
func (s *StorageAdapter) ListUsers(page, pageSize int) ([]api.UserInfo, int64, error) {
	var users []User
	var total int64

	query := s.storage.postgres.Model(&User{})

	// 获取总数
	query.Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&users).Error
	if err != nil {
		return nil, 0, err
	}

	// 转换为API格式
	result := make([]api.UserInfo, len(users))
	for i, user := range users {
		result[i] = api.UserInfo{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			Role:     user.Role,
			Status:   user.Status,
		}
	}

	return result, total, nil
}

// UpdateUser 更新用户信息
func (s *StorageAdapter) UpdateUser(id uint, email, role, status string) error {
	updates := make(map[string]interface{})
	if email != "" {
		updates["email"] = email
	}
	if role != "" {
		updates["role"] = role
	}
	if status != "" {
		updates["status"] = status
	}

	if len(updates) == 0 {
		return fmt.Errorf("no fields to update")
	}

	return s.storage.postgres.Model(&User{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateUserPassword 更新用户密码
func (s *StorageAdapter) UpdateUserPassword(id uint, newPassword string) error {
	return s.storage.postgres.Model(&User{}).Where("id = ?", id).Update("password", newPassword).Error
}

// UpdateUserLastLogin 更新用户最后登录时间
func (s *StorageAdapter) UpdateUserLastLogin(id uint) error {
	now := time.Now()
	return s.storage.postgres.Model(&User{}).Where("id = ?", id).Update("last_login", now).Error
}

// DeleteUser 删除用户（软删除）
func (s *StorageAdapter) DeleteUser(id uint) error {
	return s.storage.postgres.Delete(&User{}, id).Error
}
