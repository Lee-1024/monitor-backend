// ============================================
// 文件: storage_adapter.go
// ============================================
package main

import (
	"context"
	"database/sql"
	"encoding/json"
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

// GetAgentStatus 获取Agent状态
func (s *StorageAdapter) GetAgentStatus(hostID string) (string, error) {
	return s.storage.GetAgentStatus(hostID)
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

		// 添加磁盘数据 - 返回所有分区数组
		if len(cachedMetrics.Disk.Partitions) > 0 {
			var partitions []map[string]interface{}
			var rootPartition map[string]interface{}
			var otherPartitions []map[string]interface{}

			for _, p := range cachedMetrics.Disk.Partitions {
				partData := map[string]interface{}{
					"device":       p.Device,
					"mountpoint":   p.Mountpoint,
					"fstype":       p.Fstype,
					"total":        p.Total,
					"used":         p.Used,
					"free":         p.Free,
					"used_percent": p.UsedPercent,
				}

				if p.Mountpoint == "/" {
					rootPartition = partData
				} else {
					otherPartitions = append(otherPartitions, partData)
				}
			}

			// 按挂载点排序（根分区优先）
			sort.Slice(otherPartitions, func(i, j int) bool {
				mpI := otherPartitions[i]["mountpoint"].(string)
				mpJ := otherPartitions[j]["mountpoint"].(string)
				return mpI < mpJ
			})

			// 构建最终数组（根分区在前）
			if rootPartition != nil {
				partitions = append(partitions, rootPartition)
			}
			partitions = append(partitions, otherPartitions...)

			latest.Disk = map[string]interface{}{
				"partitions": partitions,
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
			// 磁盘：统一查询所有分区的最新数据
			query = fmt.Sprintf(`
				from(bucket: "%s")
				|> range(start: -5m)
				|> filter(fn: (r) => r["_measurement"] == "%s")
				|> filter(fn: (r) => r["host_id"] == "%s")
				|> group(columns: ["mountpoint", "device"])
				|> last()
			`, s.storage.config.InfluxDB.Bucket, measurement, hostID)
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

		// 对于磁盘，统一返回所有分区数据数组
		if measurement == "disk" {
			// 处理所有分区数据
			partitions := make(map[string]map[string]interface{})
			partitionTimestamps := make(map[string]time.Time)

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
					// 从tag中获取device和fstype
					if deviceVal := record.ValueByKey("device"); deviceVal != nil {
						if deviceStr, ok := deviceVal.(string); ok {
							partitions[mountpoint]["device"] = deviceStr
						}
					}
					if fstypeVal := record.ValueByKey("fstype"); fstypeVal != nil {
						if fstypeStr, ok := fstypeVal.(string); ok {
							partitions[mountpoint]["fstype"] = fstypeStr
						}
					}
					partitions[mountpoint]["mountpoint"] = mountpoint
				}

				fieldName := record.Field()
				if fieldName != "" {
					partitions[mountpoint][fieldName] = record.Value()
				}
			}
			result.Close()

			log.Printf("Found %d disk records, %d partitions", recordCount, len(partitions))

			// 转换为数组，按挂载点排序（根分区优先）
			var allPartitions []map[string]interface{}
			var rootPartition map[string]interface{}

			for mp, partData := range partitions {
				// 计算 used_percent（如果缺失）
				if _, ok := partData["used_percent"]; !ok {
					if totalVal, ok := partData["total"]; ok {
						var total uint64
						switch v := totalVal.(type) {
						case uint64:
							total = v
						case int64:
							total = uint64(v)
						case float64:
							total = uint64(v)
						}
						if total > 0 {
							if usedVal, ok := partData["used"]; ok {
								var used uint64
								switch v := usedVal.(type) {
								case uint64:
									used = v
								case int64:
									used = uint64(v)
								case float64:
									used = uint64(v)
								}
								partData["used_percent"] = float64(used) / float64(total) * 100
							}
						}
					}
				}

				// 计算 free（如果缺失）
				if _, ok := partData["free"]; !ok {
					if totalVal, ok := partData["total"]; ok {
						var total uint64
						switch v := totalVal.(type) {
						case uint64:
							total = v
						case int64:
							total = uint64(v)
						case float64:
							total = uint64(v)
						}
						if usedVal, ok := partData["used"]; ok {
							var used uint64
							switch v := usedVal.(type) {
							case uint64:
								used = v
							case int64:
								used = uint64(v)
							case float64:
								used = uint64(v)
							}
							partData["free"] = total - used
						}
					}
				}

				if mp == "/" {
					rootPartition = partData
				} else {
					allPartitions = append(allPartitions, partData)
				}
			}

			// 按挂载点排序（根分区除外）
			sort.Slice(allPartitions, func(i, j int) bool {
				mpI := allPartitions[i]["mountpoint"].(string)
				mpJ := allPartitions[j]["mountpoint"].(string)
				return mpI < mpJ
			})

			// 构建最终的分区数组（根分区在前）
			finalPartitions := []map[string]interface{}{}
			if rootPartition != nil {
				finalPartitions = append(finalPartitions, rootPartition)
			}
			finalPartitions = append(finalPartitions, allPartitions...)

			// 设置时间戳（使用最新的）
			if len(finalPartitions) > 0 {
				latestTimestamp := partitionTimestamps[finalPartitions[0]["mountpoint"].(string)]
				for _, part := range finalPartitions {
					if mp, ok := part["mountpoint"].(string); ok {
						if ts, ok := partitionTimestamps[mp]; ok && ts.After(latestTimestamp) {
							latestTimestamp = ts
						}
					}
				}
				timestamp = latestTimestamp
			}

			// 统一返回所有分区数组
			values = map[string]interface{}{
				"partitions": finalPartitions,
			}

			log.Printf("Returning %d disk partitions", len(finalPartitions))
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

// GetDiskHistoryByMountpoint 获取指定挂载点的磁盘历史数据
func (s *StorageAdapter) GetDiskHistoryByMountpoint(hostID, mountpoint, start, end, interval string) ([]api.MetricPoint, error) {
	ctx := context.Background()

	// 构建Flux查询，查询指定挂载点的数据
	query := fmt.Sprintf(`from(bucket: "%s")
  |> range(start: %s)
  |> filter(fn: (r) => r["_measurement"] == "disk")
  |> filter(fn: (r) => r["host_id"] == "%s")
  |> filter(fn: (r) => r["mountpoint"] == "%s")
  |> aggregateWindow(every: %s, fn: mean, createEmpty: false)`,
		s.storage.config.InfluxDB.Bucket,
		start,
		hostID,
		mountpoint,
		interval)

	log.Printf("Executing InfluxDB query for disk history: host_id=%s, mountpoint=%s", hostID, mountpoint)

	queryAPI := s.storage.influxClient.QueryAPI(s.storage.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		log.Printf("InfluxDB query error: %v", err)
		return nil, fmt.Errorf("influxdb query failed: %v", err)
	}
	defer result.Close()

	if result.Err() != nil {
		log.Printf("InfluxDB result error: %v", result.Err())
		return nil, fmt.Errorf("influxdb result error: %v", result.Err())
	}

	// 解析结果
	pointsMap := make(map[int64]map[string]interface{})
	recordCount := 0

	for result.Next() {
		record := result.Record()
		recordCount++

		timestamp := record.Time().Unix()

		if _, exists := pointsMap[timestamp]; !exists {
			pointsMap[timestamp] = make(map[string]interface{})
		}

		fieldName := record.Field()
		fieldValue := record.Value()

		if fieldValue != nil && fieldName != "" {
			pointsMap[timestamp][fieldName] = fieldValue
		}
	}

	log.Printf("Query returned %d records, grouped into %d time points", recordCount, len(pointsMap))

	if len(pointsMap) == 0 {
		return []api.MetricPoint{}, nil
	}

	// 转换为切片并排序
	timestamps := make([]int64, 0, len(pointsMap))
	for ts := range pointsMap {
		timestamps = append(timestamps, ts)
	}

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

// GetProcesses 获取进程列表（去重，只返回每个PID的最新记录）
func (s *StorageAdapter) GetProcesses(hostID string, limit int) ([]api.ProcessInfo, error) {
	// 直接使用窗口函数方式，避免DISTINCT ON和子查询的字段映射问题
	return s.getProcessesAlternative(hostID, limit)
}

// getProcessesAlternative 备用方法：使用窗口函数去重
func (s *StorageAdapter) getProcessesAlternative(hostID string, limit int) ([]api.ProcessInfo, error) {
	var processes []ProcessSnapshot

	// 只返回最近10秒内上报的进程（确保只显示活跃进程，与top命令一致）
	// Agent默认采集间隔是10秒，这里设置为10秒基本只显示最近一次采集周期的数据
	// 如果一个进程在最近10秒内没有上报数据，说明它很可能已经停止
	// 这样可以更及时地过滤掉已停止的进程，避免显示过时的进程信息
	// 注意：如果Agent采集间隔设置为更长时间（如30秒），可能需要相应调整此窗口为采集间隔+2秒
	recentTime := time.Now().Add(-10 * time.Second)

	// 使用窗口函数ROW_NUMBER()来去重
	// 明确指定所有字段，避免字段映射问题
	// 只查询最近10秒内的进程快照，确保只显示活跃进程
	sql := `
		SELECT id, created_at, host_id, timestamp, pid, name, "user", cpu_percent, memory_percent, memory_bytes, status, command
		FROM (
			SELECT id, created_at, host_id, timestamp, pid, name, "user", cpu_percent, memory_percent, memory_bytes, status, command,
				ROW_NUMBER() OVER (PARTITION BY host_id, pid ORDER BY timestamp DESC) as rn
			FROM process_snapshots
			WHERE timestamp >= ?`

	args := []interface{}{recentTime}
	if hostID != "" {
		sql += " AND host_id = ?"
		args = append(args, hostID)
	}

	sql += `
		) as ranked
		WHERE rn = 1
		ORDER BY cpu_percent DESC, timestamp DESC, pid ASC`

	if limit > 0 {
		sql += fmt.Sprintf(" LIMIT %d", limit)
	}

	log.Printf("Executing process query SQL: %s", sql)
	err := s.storage.postgres.Raw(sql, args...).Scan(&processes).Error
	if err != nil {
		log.Printf("Error executing process query: %v, SQL: %s", err, sql)
		return nil, fmt.Errorf("failed to query processes: %v", err)
	}

	// 在内存中再次去重（以防万一，确保每个PID只出现一次）
	pidMap := make(map[string]*ProcessSnapshot)
	for i := range processes {
		p := &processes[i]
		key := fmt.Sprintf("%s_%d", p.HostID, p.PID)
		if existing, exists := pidMap[key]; exists {
			// 如果已存在，保留时间戳更新的
			if p.Timestamp.After(existing.Timestamp) {
				pidMap[key] = p
			}
		} else {
			pidMap[key] = p
		}
	}

	// 转换为结果
	result := make([]api.ProcessInfo, 0, len(pidMap))
	for _, p := range pidMap {
		result = append(result, api.ProcessInfo{
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
		})
	}

	// 按CPU使用率降序排序（与top命令一致），然后按内存使用率降序排序，最后按PID排序
	sort.Slice(result, func(i, j int) bool {
		// 首先按CPU使用率降序排序
		if result[i].CPUPercent != result[j].CPUPercent {
			return result[i].CPUPercent > result[j].CPUPercent
		}
		// 如果CPU使用率相同，按内存使用率降序排序
		if result[i].MemoryPercent != result[j].MemoryPercent {
			return result[i].MemoryPercent > result[j].MemoryPercent
		}
		// 如果CPU和内存都相同，按PID升序排序
		return result[i].PID < result[j].PID
	})

	// 如果有限制，只返回前limit个
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

// GetTopProcessNamesByHistory 从历史数据中获取CPU/内存占用最高的前N个进程名
func (s *StorageAdapter) GetTopProcessNamesByHistory(hostID string, start, end time.Time, metricType string, topN int) ([]string, error) {
	if topN <= 0 {
		topN = 10
	}

	// 根据指标类型选择排序字段
	orderBy := "cpu_percent"
	if metricType == "memory" {
		orderBy = "memory_percent"
	}

	// 查询指定时间范围内的进程，按CPU或内存使用率降序排序，取前N个进程名
	// 先找到每个进程名在该时间范围内的最大CPU/内存使用率，然后排序取前N个
	sql := fmt.Sprintf(`
		SELECT name
		FROM (
			SELECT name, MAX(%s) as max_usage
			FROM process_snapshots
			WHERE timestamp >= ? AND timestamp <= ?`, orderBy)

	args := []interface{}{start, end}
	if hostID != "" {
		sql += " AND host_id = ?"
		args = append(args, hostID)
	}

	sql += fmt.Sprintf(`
			GROUP BY name
			ORDER BY max_usage DESC
			LIMIT %d
		) as top_processes`, topN)

	// 使用 Raw 查询获取进程名列表
	type ProcessNameResult struct {
		Name string `gorm:"column:name"`
	}
	var results []ProcessNameResult
	err := s.storage.postgres.Raw(sql, args...).Scan(&results).Error
	if err != nil {
		log.Printf("Error querying top process names: %v, SQL: %s", err, sql)
		return nil, fmt.Errorf("failed to get top process names: %v", err)
	}

	processNames := make([]string, 0, len(results))
	for _, r := range results {
		if r.Name != "" {
			processNames = append(processNames, r.Name)
		}
	}

	log.Printf("Found top %d process names by %s: %v", len(processNames), metricType, processNames)
	return processNames, nil
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

// ============================================
// 告警规则相关方法
// ============================================

// CreateAlertRule 创建告警规则
func (s *StorageAdapter) CreateAlertRule(rule *api.AlertRuleInfo) (*api.AlertRuleInfo, error) {
	log.Printf("[CreateAlertRule] Creating rule: Name=%s, NotifyChannels=%v, Receivers=%v",
		rule.Name, rule.NotifyChannels, rule.Receivers)

	// 确保 NotifyChannels 和 Receivers 不是 nil，至少是空数组
	notifyChannels := rule.NotifyChannels
	if notifyChannels == nil {
		notifyChannels = []string{}
		log.Printf("[CreateAlertRule] NotifyChannels was nil, using empty array")
	}
	receivers := rule.Receivers
	if receivers == nil {
		receivers = []string{}
		log.Printf("[CreateAlertRule] Receivers was nil, using empty array")
	}

	// 确保转换为 StringSliceJSON 类型
	var notifyChannelsJSON StringSliceJSON
	if notifyChannels != nil {
		notifyChannelsJSON = StringSliceJSON(notifyChannels)
	} else {
		notifyChannelsJSON = StringSliceJSON([]string{})
	}

	var receiversJSON StringSliceJSON
	if receivers != nil {
		receiversJSON = StringSliceJSON(receivers)
	} else {
		receiversJSON = StringSliceJSON([]string{})
	}

	alertRule := &AlertRule{
		Name:            rule.Name,
		Description:     rule.Description,
		Enabled:         rule.Enabled,
		Severity:        rule.Severity,
		MetricType:      rule.MetricType,
		HostID:          rule.HostID,
		Condition:       rule.Condition,
		Threshold:       rule.Threshold,
		Duration:        rule.Duration,
		NotifyChannels:  notifyChannelsJSON,
		Receivers:       receiversJSON,
		SilenceStart:    rule.SilenceStart,
		SilenceEnd:      rule.SilenceEnd,
		InhibitDuration: rule.InhibitDuration,
	}

	log.Printf("[CreateAlertRule] AlertRule before save: NotifyChannels=%v, Receivers=%v",
		alertRule.NotifyChannels, alertRule.Receivers)

	if err := s.storage.postgres.Create(alertRule).Error; err != nil {
		log.Printf("[CreateAlertRule] Failed to save to database: %v", err)
		return nil, err
	}

	log.Printf("[CreateAlertRule] Rule saved successfully: ID=%d", alertRule.ID)

	// 验证保存后的数据
	var savedRule AlertRule
	if err := s.storage.postgres.First(&savedRule, alertRule.ID).Error; err == nil {
		log.Printf("[CreateAlertRule] Verified saved rule: ID=%d, NotifyChannels=%v, Receivers=%v",
			savedRule.ID, savedRule.NotifyChannels, savedRule.Receivers)
	}

	return s.alertRuleToAPI(alertRule), nil
}

// UpdateAlertRule 更新告警规则
func (s *StorageAdapter) UpdateAlertRule(id uint, rule *api.AlertRuleInfo) error {
	// 先获取现有记录
	var existing AlertRule
	if err := s.storage.postgres.First(&existing, id).Error; err != nil {
		return fmt.Errorf("failed to get alert rule: %w", err)
	}

	// 验证 JSON 字段是否有效（如果存在）
	// 这可以帮助捕获数据库中的无效 JSON 数据
	if existing.NotifyChannels != nil {
		// 尝试序列化和反序列化以验证 JSON 格式
		if data, err := json.Marshal(existing.NotifyChannels); err != nil {
			log.Printf("Warning: Invalid NotifyChannels JSON for rule %d: %v", id, err)
			// 重置为 nil 以避免后续错误
			existing.NotifyChannels = nil
		} else {
			_ = data // 验证通过
		}
	}
	if existing.Receivers != nil {
		if data, err := json.Marshal(existing.Receivers); err != nil {
			log.Printf("Warning: Invalid Receivers JSON for rule %d: %v", id, err)
			existing.Receivers = nil
		} else {
			_ = data // 验证通过
		}
	}

	// 使用 map 来构建更新字段，只更新实际提供的字段
	updates := make(map[string]interface{})

	log.Printf("[UpdateAlertRule] Updating rule ID=%d: NotifyChannels=%v, Receivers=%v", id, rule.NotifyChannels, rule.Receivers)

	// 检查是否有其他字段被设置（除了 enabled）
	// 由于 handler 中已经处理了部分更新，如果字段在 JSON 中存在就会被设置
	// 所以我们可以通过检查字段是否为零值来判断是否提供了该字段
	hasOtherFields := rule.Name != "" || rule.Description != "" || rule.Severity != "" ||
		rule.MetricType != "" || rule.Condition != "" || rule.Threshold != 0 ||
		rule.Duration != 0 || rule.InhibitDuration != 0 || rule.NotifyChannels != nil ||
		rule.Receivers != nil || rule.SilenceStart != nil || rule.SilenceEnd != nil

	log.Printf("[UpdateAlertRule] Rule ID=%d: hasOtherFields=%v", id, hasOtherFields)

	// 只更新实际提供的字段
	// 由于 handler 中已经处理了部分更新，如果字段在 JSON 中存在就会被设置到 rule 中
	// 所以我们可以通过检查字段是否为零值来判断是否提供了该字段
	// 但对于 bool 类型和数值类型，需要特殊处理

	// enabled 字段：由于 handler 中已经检查了 JSON 中是否包含该字段
	// 如果 rule.Enabled 被设置（无论是 true 还是 false），就更新它
	updates["enabled"] = rule.Enabled

	// 更新其他字段（只更新非零值字段）
	if rule.Name != "" {
		updates["name"] = rule.Name
	}
	if rule.Description != "" {
		updates["description"] = rule.Description
	}
	if rule.Severity != "" {
		updates["severity"] = rule.Severity
	}
	if rule.MetricType != "" {
		updates["metric_type"] = rule.MetricType
	}
	// HostID 可以为空字符串（表示所有主机），所以需要检查是否在 JSON 中提供
	// 由于 handler 中只有当 updateData["host_id"] 存在时才会设置 rule.HostID
	// 所以如果 rule.HostID 被设置了（即使为空字符串），说明 JSON 中提供了该字段
	// 但是，如果只更新 enabled，rule.HostID 会是空字符串（零值），我们无法区分"未提供"和"提供了空字符串"
	// 解决方案：检查 rule.HostID 是否与现有值不同，如果不同，说明 JSON 中提供了该字段
	// 但这也有问题：如果现有值是 "host1"，JSON 中提供了 "host1"，它们相同，但我们也应该更新（虽然值相同）
	// 更简单的方法：只有当 hasOtherFields 为 true 时才更新 host_id
	// 或者：检查 rule.HostID 是否在 hasOtherFields 检查中被包含
	// 实际上，如果只更新 enabled，hasOtherFields 为 false，rule.HostID 是空字符串（零值）
	// 所以我们可以：只有当 hasOtherFields 为 true 或者 rule.HostID 与现有值不同时才更新
	// 但更安全的方法是：只有当 hasOtherFields 为 true 时才更新 host_id
	// 如果只更新 host_id 而不更新其他字段，hasOtherFields 会是 false，但 rule.HostID 会被设置
	// 所以我们需要检查 rule.HostID 是否与现有值不同
	// 如果不同，说明 JSON 中提供了该字段（即使 hasOtherFields 为 false）
	// HostID 更新逻辑：
	// 1. 如果只更新 enabled，handler 中不会设置 rule.HostID，所以 rule.HostID 是空字符串（零值）
	// 2. 如果现有值不是空字符串，rule.HostID != existing.HostID 为 true，会错误地更新 host_id
	// 3. 所以我们需要检查：只有当 rule.HostID 与现有值不同，且 rule.HostID 不是空字符串（零值）时才更新
	// 4. 或者：只有当 hasOtherFields 为 true 时才更新 host_id
	// 5. 更简单的方法：只有当 rule.HostID 与现有值不同，且 rule.HostID 不是空字符串时才更新
	// 6. 但如果现有值是空字符串，JSON 中提供了空字符串，rule.HostID == existing.HostID，不会更新（正确）
	// 7. 如果现有值不是空字符串，只更新 enabled，rule.HostID 是空字符串，rule.HostID != existing.HostID 为 true，会错误地更新
	// 8. 所以我们需要检查：如果 rule.HostID 是空字符串，且 hasOtherFields 为 false，不更新
	// 9. 如果 rule.HostID 不是空字符串，或者 hasOtherFields 为 true，且 rule.HostID 与现有值不同，更新
	if rule.HostID != existing.HostID {
		// 如果 rule.HostID 与现有值不同，说明 JSON 中提供了该字段
		// 但如果只更新 enabled，rule.HostID 是空字符串（零值），如果现有值不是空字符串，会错误地更新
		// 所以我们需要检查：如果 rule.HostID 是空字符串，且 hasOtherFields 为 false，不更新
		if rule.HostID != "" || hasOtherFields {
			updates["host_id"] = rule.HostID
		}
	}
	if rule.Condition != "" {
		updates["condition"] = rule.Condition
	}

	// 对于数值字段，检查是否在 JSON 中提供
	// 由于 handler 中已经检查了，如果字段存在就会被设置
	// 但我们需要区分"提供了0"和"未提供"
	// 如果只有 enabled 被设置，说明是只更新状态，不更新数值字段
	// 如果有其他字段，说明是完整更新，就更新所有提供的字段
	if hasOtherFields {
		// 有其他字段，更新所有提供的字段（包括数值字段）
		// 由于 handler 中已经检查了 JSON，如果字段存在就会被设置
		// 所以我们可以直接更新（包括0值）
		updates["threshold"] = rule.Threshold
		updates["duration"] = rule.Duration
		updates["inhibit_duration"] = rule.InhibitDuration

		// NotifyChannels 和 Receivers 可能为 nil（如果前端没有发送）
		// 或者可能为空数组 []（如果前端发送了空数组）
		// 我们需要区分"未提供"和"提供但为空"的情况
		// 由于 handler 中只有当 updateData["notify_channels"] 存在时才会设置 rule.NotifyChannels
		// 所以如果 rule.NotifyChannels 不是 nil，说明前端提供了该字段（即使是空数组）
		if rule.NotifyChannels != nil {
			log.Printf("[UpdateAlertRule] Rule ID=%d: Updating notify_channels to %v (provided in request)", id, rule.NotifyChannels)
			// 手动序列化为 JSON，因为使用 Updates(map) 时 GORM 不会调用 MarshalJSON
			jsonData, err := json.Marshal(rule.NotifyChannels)
			if err != nil {
				log.Printf("[UpdateAlertRule] Rule ID=%d: Failed to marshal NotifyChannels: %v", id, err)
				return fmt.Errorf("failed to marshal notify_channels: %w", err)
			}
			// 使用原始 SQL 更新，确保 JSON 字符串正确存储
			log.Printf("[UpdateAlertRule] Rule ID=%d: Marshaled notify_channels JSON: %s", id, string(jsonData))
			updates["notify_channels"] = string(jsonData)
		} else {
			log.Printf("[UpdateAlertRule] Rule ID=%d: notify_channels not provided in request, keeping existing value", id)
		}
		if rule.Receivers != nil {
			log.Printf("[UpdateAlertRule] Rule ID=%d: Updating receivers to %v (provided in request)", id, rule.Receivers)
			// 手动序列化为 JSON，因为使用 Updates(map) 时 GORM 不会调用 MarshalJSON
			jsonData, err := json.Marshal(rule.Receivers)
			if err != nil {
				log.Printf("[UpdateAlertRule] Rule ID=%d: Failed to marshal Receivers: %v", id, err)
				return fmt.Errorf("failed to marshal receivers: %w", err)
			}
			log.Printf("[UpdateAlertRule] Rule ID=%d: Marshaled receivers JSON: %s", id, string(jsonData))
			updates["receivers"] = string(jsonData)
		} else {
			log.Printf("[UpdateAlertRule] Rule ID=%d: receivers not provided in request, keeping existing value", id)
		}
		if rule.SilenceStart != nil {
			updates["silence_start"] = rule.SilenceStart
		}
		if rule.SilenceEnd != nil {
			updates["silence_end"] = rule.SilenceEnd
		}
	} else {
		// 即使没有其他字段，如果 NotifyChannels 或 Receivers 被明确设置，也应该更新
		// 因为用户可能只想更新通知渠道
		// 由于 handler 中只有当 updateData["notify_channels"] 存在时才会设置 rule.NotifyChannels
		// 所以如果 rule.NotifyChannels 不是 nil，说明前端提供了该字段（即使是空数组）
		if rule.NotifyChannels != nil {
			log.Printf("[UpdateAlertRule] Rule ID=%d: Only NotifyChannels provided, updating to %v", id, rule.NotifyChannels)
			// 手动序列化为 JSON，因为使用 Updates(map) 时 GORM 不会调用 MarshalJSON
			jsonData, err := json.Marshal(rule.NotifyChannels)
			if err != nil {
				log.Printf("[UpdateAlertRule] Rule ID=%d: Failed to marshal NotifyChannels: %v", id, err)
				return fmt.Errorf("failed to marshal notify_channels: %w", err)
			}
			log.Printf("[UpdateAlertRule] Rule ID=%d: Marshaled notify_channels JSON: %s", id, string(jsonData))
			updates["notify_channels"] = string(jsonData)
		} else {
			log.Printf("[UpdateAlertRule] Rule ID=%d: NotifyChannels not provided, keeping existing value", id)
		}
		if rule.Receivers != nil {
			log.Printf("[UpdateAlertRule] Rule ID=%d: Only Receivers provided, updating to %v", id, rule.Receivers)
			// 手动序列化为 JSON，因为使用 Updates(map) 时 GORM 不会调用 MarshalJSON
			jsonData, err := json.Marshal(rule.Receivers)
			if err != nil {
				log.Printf("[UpdateAlertRule] Rule ID=%d: Failed to marshal Receivers: %v", id, err)
				return fmt.Errorf("failed to marshal receivers: %w", err)
			}
			log.Printf("[UpdateAlertRule] Rule ID=%d: Marshaled receivers JSON: %s", id, string(jsonData))
			updates["receivers"] = string(jsonData)
		} else {
			log.Printf("[UpdateAlertRule] Rule ID=%d: Receivers not provided, keeping existing value", id)
		}
	}
	// 如果只有 enabled 被设置，就只更新 enabled（已经在上面设置了）

	// 如果没有要更新的字段，返回错误
	if len(updates) == 0 {
		return fmt.Errorf("no fields to update")
	}

	// 添加 updated_at
	updates["updated_at"] = time.Now()

	log.Printf("[UpdateAlertRule] Rule ID=%d: Executing update with fields: %v", id, updates)
	err := s.storage.postgres.Model(&AlertRule{}).Where("id = ?", id).Updates(updates).Error
	if err != nil {
		log.Printf("[UpdateAlertRule] Rule ID=%d: Update failed: %v", id, err)
		return err
	}
	log.Printf("[UpdateAlertRule] Rule ID=%d: Update successful", id)
	return nil
}

// DeleteAlertRule 删除告警规则
func (s *StorageAdapter) DeleteAlertRule(id uint) error {
	return s.storage.postgres.Delete(&AlertRule{}, id).Error
}

// GetAlertRule 获取告警规则
func (s *StorageAdapter) GetAlertRule(id uint) (*api.AlertRuleInfo, error) {
	// 使用原始 SQL 查询，将 JSON 字段作为文本读取，避免自动反序列化
	sqlQuery := `
		SELECT id, created_at, updated_at, name, description, enabled, severity,
		       metric_type, host_id, condition, threshold, duration,
		       notify_channels, receivers, silence_start, silence_end, inhibit_duration
		FROM alert_rules
		WHERE id = ?
	`

	row := s.storage.postgres.Raw(sqlQuery, id).Row()

	var rule AlertRule
	var notifyChannelsStr, receiversStr sql.NullString
	var silenceStart, silenceEnd sql.NullTime

	err := row.Scan(
		&rule.ID, &rule.CreatedAt, &rule.UpdatedAt,
		&rule.Name, &rule.Description, &rule.Enabled, &rule.Severity,
		&rule.MetricType, &rule.HostID, &rule.Condition,
		&rule.Threshold, &rule.Duration,
		&notifyChannelsStr, &receiversStr,
		&silenceStart, &silenceEnd,
		&rule.InhibitDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get alert rule: %w", err)
	}

	// 手动解析 JSON 字段，容忍无效数据
	if notifyChannelsStr.Valid && notifyChannelsStr.String != "" {
		trimmed := strings.TrimSpace(notifyChannelsStr.String)
		if trimmed == "false" || trimmed == "null" || trimmed == `""` {
			rule.NotifyChannels = []string{}
			s.storage.postgres.Exec("UPDATE alert_rules SET notify_channels = '[]' WHERE id = ?", rule.ID)
		} else {
			if err := json.Unmarshal([]byte(notifyChannelsStr.String), &rule.NotifyChannels); err != nil {
				log.Printf("Warning: Invalid NotifyChannels JSON for rule %d: %v, resetting to empty array", rule.ID, err)
				rule.NotifyChannels = []string{}
				s.storage.postgres.Exec("UPDATE alert_rules SET notify_channels = '[]' WHERE id = ?", rule.ID)
			}
		}
	} else {
		rule.NotifyChannels = []string{}
	}

	if receiversStr.Valid && receiversStr.String != "" {
		trimmed := strings.TrimSpace(receiversStr.String)
		if trimmed == "false" || trimmed == "null" || trimmed == `""` {
			rule.Receivers = []string{}
			s.storage.postgres.Exec("UPDATE alert_rules SET receivers = '[]' WHERE id = ?", rule.ID)
		} else {
			if err := json.Unmarshal([]byte(receiversStr.String), &rule.Receivers); err != nil {
				log.Printf("Warning: Invalid Receivers JSON for rule %d: %v, resetting to empty array", rule.ID, err)
				rule.Receivers = []string{}
				s.storage.postgres.Exec("UPDATE alert_rules SET receivers = '[]' WHERE id = ?", rule.ID)
			}
		}
	} else {
		rule.Receivers = []string{}
	}

	if silenceStart.Valid {
		rule.SilenceStart = &silenceStart.Time
	}
	if silenceEnd.Valid {
		rule.SilenceEnd = &silenceEnd.Time
	}

	return s.alertRuleToAPI(&rule), nil
}

// ListAlertRules 列出告警规则
func (s *StorageAdapter) ListAlertRules(enabled *bool) ([]api.AlertRuleInfo, error) {
	// 使用原始 SQL 查询，将 JSON 字段作为文本读取，避免自动反序列化
	sqlQuery := `
		SELECT id, created_at, updated_at, name, description, enabled, severity,
		       metric_type, host_id, condition, threshold, duration,
		       notify_channels, receivers, silence_start, silence_end, inhibit_duration
		FROM alert_rules
	`
	args := []interface{}{}

	if enabled != nil {
		sqlQuery += " WHERE enabled = ?"
		args = append(args, *enabled)
	}

	sqlQuery += " ORDER BY created_at DESC"

	rows, err := s.storage.postgres.Raw(sqlQuery, args...).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to query alert rules: %w", err)
	}
	defer rows.Close()

	result := make([]api.AlertRuleInfo, 0)
	for rows.Next() {
		var rule AlertRule
		var notifyChannelsStr, receiversStr sql.NullString
		var silenceStart, silenceEnd sql.NullTime

		err := rows.Scan(
			&rule.ID, &rule.CreatedAt, &rule.UpdatedAt,
			&rule.Name, &rule.Description, &rule.Enabled, &rule.Severity,
			&rule.MetricType, &rule.HostID, &rule.Condition,
			&rule.Threshold, &rule.Duration,
			&notifyChannelsStr, &receiversStr,
			&silenceStart, &silenceEnd,
			&rule.InhibitDuration,
		)
		if err != nil {
			log.Printf("Warning: Failed to scan alert rule: %v", err)
			continue
		}

		// 手动解析 JSON 字段，容忍无效数据
		log.Printf("[ListAlertRules] Rule ID=%d: notifyChannelsStr.Valid=%v, notifyChannelsStr.String=%q",
			rule.ID, notifyChannelsStr.Valid, notifyChannelsStr.String)

		if notifyChannelsStr.Valid && notifyChannelsStr.String != "" {
			// 处理特殊情况：如果值是 "false" 或 "null"，设置为空数组
			trimmed := strings.TrimSpace(notifyChannelsStr.String)
			log.Printf("[ListAlertRules] Rule ID=%d: trimmed notify_channels=%q", rule.ID, trimmed)

			if trimmed == "false" || trimmed == "null" || trimmed == `""` {
				log.Printf("[ListAlertRules] Rule ID=%d: notify_channels is invalid value (%q), resetting to empty array", rule.ID, trimmed)
				rule.NotifyChannels = []string{}
				// 修复数据库
				s.storage.postgres.Exec("UPDATE alert_rules SET notify_channels = '[]' WHERE id = ?", rule.ID)
			} else {
				if err := json.Unmarshal([]byte(notifyChannelsStr.String), &rule.NotifyChannels); err != nil {
					log.Printf("[ListAlertRules] Warning: Invalid NotifyChannels JSON for rule %d: %v, raw value=%q, resetting to empty array",
						rule.ID, err, notifyChannelsStr.String)
					rule.NotifyChannels = []string{}
					// 修复数据库
					s.storage.postgres.Exec("UPDATE alert_rules SET notify_channels = '[]' WHERE id = ?", rule.ID)
				} else {
					log.Printf("[ListAlertRules] Rule ID=%d: Successfully parsed NotifyChannels=%v", rule.ID, rule.NotifyChannels)
				}
			}
		} else {
			log.Printf("[ListAlertRules] Rule ID=%d: notifyChannelsStr is invalid or empty, setting to empty array", rule.ID)
			rule.NotifyChannels = []string{}
		}

		if receiversStr.Valid && receiversStr.String != "" {
			trimmed := strings.TrimSpace(receiversStr.String)
			if trimmed == "false" || trimmed == "null" || trimmed == `""` {
				rule.Receivers = []string{}
				// 修复数据库
				s.storage.postgres.Exec("UPDATE alert_rules SET receivers = '[]' WHERE id = ?", rule.ID)
			} else {
				if err := json.Unmarshal([]byte(receiversStr.String), &rule.Receivers); err != nil {
					log.Printf("Warning: Invalid Receivers JSON for rule %d: %v, resetting to empty array", rule.ID, err)
					rule.Receivers = []string{}
					// 修复数据库
					s.storage.postgres.Exec("UPDATE alert_rules SET receivers = '[]' WHERE id = ?", rule.ID)
				}
			}
		} else {
			rule.Receivers = []string{}
		}

		if silenceStart.Valid {
			rule.SilenceStart = &silenceStart.Time
		}
		if silenceEnd.Valid {
			rule.SilenceEnd = &silenceEnd.Time
		}

		result = append(result, *s.alertRuleToAPI(&rule))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert rules: %w", err)
	}

	return result, nil
}

// validateAndFixAlertRuleJSON 验证并修复告警规则的 JSON 字段
func (s *StorageAdapter) validateAndFixAlertRuleJSON(rule *AlertRule) error {
	// 验证 NotifyChannels
	if rule.NotifyChannels != nil {
		if data, err := json.Marshal(rule.NotifyChannels); err != nil {
			log.Printf("Warning: Invalid NotifyChannels JSON for rule %d: %v, resetting to nil", rule.ID, err)
			rule.NotifyChannels = nil
			// 尝试修复数据库中的无效数据
			if updateErr := s.storage.postgres.Model(rule).Update("notify_channels", nil).Error; updateErr != nil {
				log.Printf("Error: Failed to fix NotifyChannels for rule %d: %v", rule.ID, updateErr)
			}
		} else {
			_ = data // 验证通过
		}
	}

	// 验证 Receivers
	if rule.Receivers != nil {
		if data, err := json.Marshal(rule.Receivers); err != nil {
			log.Printf("Warning: Invalid Receivers JSON for rule %d: %v, resetting to nil", rule.ID, err)
			rule.Receivers = nil
			// 尝试修复数据库中的无效数据
			if updateErr := s.storage.postgres.Model(rule).Update("receivers", nil).Error; updateErr != nil {
				log.Printf("Error: Failed to fix Receivers for rule %d: %v", rule.ID, updateErr)
			}
		} else {
			_ = data // 验证通过
		}
	}

	return nil
}

// alertRuleToAPI 转换为API格式
func (s *StorageAdapter) alertRuleToAPI(rule *AlertRule) *api.AlertRuleInfo {
	return &api.AlertRuleInfo{
		ID:              rule.ID,
		CreatedAt:       rule.CreatedAt,
		UpdatedAt:       rule.UpdatedAt,
		Name:            rule.Name,
		Description:     rule.Description,
		Enabled:         rule.Enabled,
		Severity:        rule.Severity,
		MetricType:      rule.MetricType,
		HostID:          rule.HostID,
		Condition:       rule.Condition,
		Threshold:       rule.Threshold,
		Duration:        rule.Duration,
		NotifyChannels:  rule.NotifyChannels,
		Receivers:       rule.Receivers,
		SilenceStart:    rule.SilenceStart,
		SilenceEnd:      rule.SilenceEnd,
		InhibitDuration: rule.InhibitDuration,
	}
}

// ============================================
// 告警历史相关方法
// ============================================

// CreateAlertHistory 创建告警历史
func (s *StorageAdapter) CreateAlertHistory(history *api.AlertHistoryInfo) (*api.AlertHistoryInfo, error) {
	alertHistory := &AlertHistory{
		RuleID:       history.RuleID,
		RuleName:     history.RuleName,
		HostID:       history.HostID,
		Hostname:     history.Hostname,
		Severity:     history.Severity,
		Status:       history.Status,
		FiredAt:      history.FiredAt,
		ResolvedAt:   history.ResolvedAt,
		MetricType:   history.MetricType,
		MetricValue:  history.MetricValue,
		Threshold:    history.Threshold,
		Message:      history.Message,
		Labels:       history.Labels,
		NotifyStatus: history.NotifyStatus,
		NotifyError:  history.NotifyError,
	}

	if err := s.storage.postgres.Create(alertHistory).Error; err != nil {
		return nil, err
	}

	return s.alertHistoryToAPI(alertHistory), nil
}

// UpdateAlertHistory 更新告警历史
func (s *StorageAdapter) UpdateAlertHistory(id uint, status string, resolvedAt *time.Time) error {
	updates := map[string]interface{}{
		"status": status,
	}
	if resolvedAt != nil {
		updates["resolved_at"] = *resolvedAt
	} else if status == "firing" {
		// 当状态更新为 firing 时，清除 resolved_at
		updates["resolved_at"] = nil
	}
	return s.storage.postgres.Model(&AlertHistory{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateAlertHistoryFiredAt 更新告警历史的触发时间
func (s *StorageAdapter) UpdateAlertHistoryFiredAt(id uint, firedAt time.Time) error {
	updates := map[string]interface{}{
		"fired_at": firedAt,
	}
	return s.storage.postgres.Model(&AlertHistory{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateAlertHistoryMetricValue 更新告警历史的指标值和消息
func (s *StorageAdapter) UpdateAlertHistoryMetricValue(id uint, metricValue float64, message string) error {
	updates := map[string]interface{}{
		"metric_value": metricValue,
		"message":      message,
	}
	return s.storage.postgres.Model(&AlertHistory{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateAlertHistoryNotifyStatus 更新告警历史的通知状态
func (s *StorageAdapter) UpdateAlertHistoryNotifyStatus(id uint, notifyStatus string, notifyError string) error {
	updates := map[string]interface{}{
		"notify_status": notifyStatus,
	}
	if notifyError != "" {
		updates["notify_error"] = notifyError
	}
	return s.storage.postgres.Model(&AlertHistory{}).Where("id = ?", id).Updates(updates).Error
}

// ListAlertHistory 列出告警历史
func (s *StorageAdapter) ListAlertHistory(ruleID *uint, hostID string, status string, limit int) ([]api.AlertHistoryInfo, error) {
	var alertHistories []AlertHistory
	query := s.storage.postgres.Model(&AlertHistory{})

	if ruleID != nil {
		query = query.Where("rule_id = ?", *ruleID)
	}
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Order("fired_at DESC").Find(&alertHistories).Error; err != nil {
		return nil, err
	}

	result := make([]api.AlertHistoryInfo, len(alertHistories))
	for i, history := range alertHistories {
		result[i] = *s.alertHistoryToAPI(&history)
	}

	return result, nil
}

// GetAlertHistory 获取告警历史
func (s *StorageAdapter) GetAlertHistory(id uint) (*api.AlertHistoryInfo, error) {
	var alertHistory AlertHistory
	if err := s.storage.postgres.First(&alertHistory, id).Error; err != nil {
		return nil, err
	}
	return s.alertHistoryToAPI(&alertHistory), nil
}

// DeleteAlertHistory 删除告警历史
func (s *StorageAdapter) DeleteAlertHistory(id uint) error {
	return s.storage.postgres.Delete(&AlertHistory{}, id).Error
}

// DeleteAlertHistories 批量删除告警历史
func (s *StorageAdapter) DeleteAlertHistories(ids []uint) error {
	if len(ids) == 0 {
		return fmt.Errorf("no ids provided")
	}
	return s.storage.postgres.Where("id IN ?", ids).Delete(&AlertHistory{}).Error
}

// alertHistoryToAPI 转换为API格式
func (s *StorageAdapter) alertHistoryToAPI(history *AlertHistory) *api.AlertHistoryInfo {
	return &api.AlertHistoryInfo{
		ID:           history.ID,
		CreatedAt:    history.CreatedAt,
		RuleID:       history.RuleID,
		RuleName:     history.RuleName,
		HostID:       history.HostID,
		Hostname:     history.Hostname,
		Severity:     history.Severity,
		Status:       history.Status,
		FiredAt:      history.FiredAt,
		ResolvedAt:   history.ResolvedAt,
		MetricType:   history.MetricType,
		MetricValue:  history.MetricValue,
		Threshold:    history.Threshold,
		Message:      history.Message,
		Labels:       history.Labels,
		NotifyStatus: history.NotifyStatus,
		NotifyError:  history.NotifyError,
	}
}

// ============================================
// 告警静默相关方法
// ============================================

// CreateAlertSilence 创建告警静默
func (s *StorageAdapter) CreateAlertSilence(silence *api.AlertSilenceInfo) (*api.AlertSilenceInfo, error) {
	alertSilence := &AlertSilence{
		Name:      silence.Name,
		RuleIDs:   silence.RuleIDs,
		HostIDs:   silence.HostIDs,
		StartTime: silence.StartTime,
		EndTime:   silence.EndTime,
		Enabled:   silence.Enabled,
		Comment:   silence.Comment,
		Creator:   silence.Creator,
	}

	if err := s.storage.postgres.Create(alertSilence).Error; err != nil {
		return nil, err
	}

	return s.alertSilenceToAPI(alertSilence), nil
}

// UpdateAlertSilence 更新告警静默
func (s *StorageAdapter) UpdateAlertSilence(id uint, silence *api.AlertSilenceInfo) error {
	// 先获取现有记录
	var existing AlertSilence
	if err := s.storage.postgres.First(&existing, id).Error; err != nil {
		return err
	}

	// 更新字段
	if silence.Name != "" {
		existing.Name = silence.Name
	}
	if silence.RuleIDs != nil {
		existing.RuleIDs = silence.RuleIDs
	}
	if silence.HostIDs != nil {
		existing.HostIDs = silence.HostIDs
	}
	if !silence.StartTime.IsZero() {
		existing.StartTime = silence.StartTime
	}
	if !silence.EndTime.IsZero() {
		existing.EndTime = silence.EndTime
	}
	// 直接设置 enabled，确保 false 值也能更新
	existing.Enabled = silence.Enabled
	if silence.Comment != "" {
		existing.Comment = silence.Comment
	}
	if silence.Creator != "" {
		existing.Creator = silence.Creator
	}

	// 使用 Select 明确指定要更新的字段，确保所有字段（包括 false 和 JSON 序列化字段）都能正确更新
	return s.storage.postgres.Model(&AlertSilence{}).
		Where("id = ?", id).
		Select("name", "rule_ids", "host_ids", "start_time", "end_time", "enabled", "comment", "creator", "updated_at").
		Updates(&existing).Error
}

// DeleteAlertSilence 删除告警静默
func (s *StorageAdapter) DeleteAlertSilence(id uint) error {
	return s.storage.postgres.Delete(&AlertSilence{}, id).Error
}

// GetAlertSilence 获取告警静默
func (s *StorageAdapter) GetAlertSilence(id uint) (*api.AlertSilenceInfo, error) {
	var alertSilence AlertSilence
	if err := s.storage.postgres.First(&alertSilence, id).Error; err != nil {
		return nil, err
	}
	return s.alertSilenceToAPI(&alertSilence), nil
}

// ListAlertSilences 列出告警静默
func (s *StorageAdapter) ListAlertSilences(enabled *bool) ([]api.AlertSilenceInfo, error) {
	var alertSilences []AlertSilence
	query := s.storage.postgres.Model(&AlertSilence{})

	if enabled != nil {
		query = query.Where("enabled = ?", *enabled)
	}

	// 移除过期过滤，返回所有静默（包括已过期的），让前端决定是否显示
	// 这样用户可以查看所有历史静默记录，包括已过期的
	// 如果需要只显示未过期的，可以在前端过滤

	if err := query.Order("created_at DESC").Find(&alertSilences).Error; err != nil {
		return nil, err
	}

	result := make([]api.AlertSilenceInfo, len(alertSilences))
	for i, silence := range alertSilences {
		result[i] = *s.alertSilenceToAPI(&silence)
	}

	return result, nil
}

// IsRuleSilenced 检查规则是否被静默
func (s *StorageAdapter) IsRuleSilenced(ruleID uint, hostID string) bool {
	var count int64
	now := time.Now()

	query := s.storage.postgres.Model(&AlertSilence{}).
		Where("enabled = ?", true).
		Where("start_time <= ?", now).
		Where("end_time > ?", now)

	// 检查是否有匹配的静默
	// 1. 规则ID匹配（空数组表示所有规则）
	// 2. 主机ID匹配（空数组表示所有主机）
	query = query.Where(
		"(rule_ids IS NULL OR rule_ids = '[]' OR rule_ids LIKE ? OR rule_ids LIKE ? OR rule_ids LIKE ?)",
		fmt.Sprintf("%%\"%d\"%%", ruleID),
		fmt.Sprintf("%%[%d]%%", ruleID),
		fmt.Sprintf("%%,%d]%%", ruleID),
	).Where(
		"(host_ids IS NULL OR host_ids = '[]' OR host_ids LIKE ?)",
		fmt.Sprintf("%%\"%s\"%%", hostID),
	)

	query.Count(&count)
	isSilenced := count > 0
	log.Printf("[IsRuleSilenced] RuleID=%d, HostID=%s, Count=%d, IsSilenced=%v", ruleID, hostID, count, isSilenced)
	return isSilenced
}

// alertSilenceToAPI 转换为API格式
func (s *StorageAdapter) alertSilenceToAPI(silence *AlertSilence) *api.AlertSilenceInfo {
	return &api.AlertSilenceInfo{
		ID:        silence.ID,
		CreatedAt: silence.CreatedAt,
		UpdatedAt: silence.UpdatedAt,
		Name:      silence.Name,
		RuleIDs:   silence.RuleIDs,
		HostIDs:   silence.HostIDs,
		StartTime: silence.StartTime,
		EndTime:   silence.EndTime,
		Enabled:   silence.Enabled,
		Comment:   silence.Comment,
		Creator:   silence.Creator,
	}
}

// ============================================
// 通知渠道相关方法
// ============================================

// CreateNotificationChannel 创建通知渠道
func (s *StorageAdapter) CreateNotificationChannel(channel *api.NotificationChannelInfo) (*api.NotificationChannelInfo, error) {
	notifChannel := &NotificationChannel{
		Type:        channel.Type,
		Name:        channel.Name,
		Enabled:     channel.Enabled,
		Config:      channel.Config,
		Description: channel.Description,
	}

	if err := s.storage.postgres.Create(notifChannel).Error; err != nil {
		return nil, err
	}

	return s.notificationChannelToAPI(notifChannel), nil
}

// UpdateNotificationChannel 更新通知渠道
func (s *StorageAdapter) UpdateNotificationChannel(id uint, channel *api.NotificationChannelInfo) error {
	// 先获取现有记录
	var existing NotificationChannel
	if err := s.storage.postgres.First(&existing, id).Error; err != nil {
		return err
	}

	// 更新字段
	if channel.Name != "" {
		existing.Name = channel.Name
	}
	// 直接设置 enabled，确保 false 值也能更新
	existing.Enabled = channel.Enabled

	if channel.Config != nil {
		existing.Config = channel.Config
	}
	if channel.Description != "" {
		existing.Description = channel.Description
	}

	// 使用 Select 明确指定要更新的字段，确保所有字段（包括 false 和 map）都能正确更新
	return s.storage.postgres.Model(&NotificationChannel{}).
		Where("id = ?", id).
		Select("name", "enabled", "config", "description", "updated_at").
		Updates(&existing).Error
}

// DeleteNotificationChannel 删除通知渠道
func (s *StorageAdapter) DeleteNotificationChannel(id uint) error {
	return s.storage.postgres.Delete(&NotificationChannel{}, id).Error
}

// GetNotificationChannel 获取通知渠道
func (s *StorageAdapter) GetNotificationChannel(id uint) (*api.NotificationChannelInfo, error) {
	var notifChannel NotificationChannel
	if err := s.storage.postgres.First(&notifChannel, id).Error; err != nil {
		return nil, err
	}
	return s.notificationChannelToAPI(&notifChannel), nil
}

// GetNotificationChannelByType 根据类型获取通知渠道
func (s *StorageAdapter) GetNotificationChannelByType(channelType string) (*api.NotificationChannelInfo, error) {
	var notifChannel NotificationChannel
	if err := s.storage.postgres.Where("type = ?", channelType).First(&notifChannel).Error; err != nil {
		return nil, err
	}
	return s.notificationChannelToAPI(&notifChannel), nil
}

// ListNotificationChannels 列出通知渠道
func (s *StorageAdapter) ListNotificationChannels(enabled *bool) ([]api.NotificationChannelInfo, error) {
	var notifChannels []NotificationChannel
	query := s.storage.postgres.Model(&NotificationChannel{})

	if enabled != nil {
		query = query.Where("enabled = ?", *enabled)
	}

	if err := query.Order("created_at DESC").Find(&notifChannels).Error; err != nil {
		return nil, err
	}

	result := make([]api.NotificationChannelInfo, len(notifChannels))
	for i, channel := range notifChannels {
		result[i] = *s.notificationChannelToAPI(&channel)
	}

	return result, nil
}

// notificationChannelToAPI 转换为API格式
func (s *StorageAdapter) notificationChannelToAPI(channel *NotificationChannel) *api.NotificationChannelInfo {
	return &api.NotificationChannelInfo{
		ID:          channel.ID,
		CreatedAt:   channel.CreatedAt,
		UpdatedAt:   channel.UpdatedAt,
		Type:        channel.Type,
		Name:        channel.Name,
		Enabled:     channel.Enabled,
		Config:      channel.Config,
		Description: channel.Description,
	}
}
