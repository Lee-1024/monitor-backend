// ============================================
// 文件: storage.go (优化版本)
// ============================================
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Storage struct {
	influxClient influxdb2.Client
	influxWrite  api.WriteAPIBlocking
	postgres     *gorm.DB
	redis        *redis.Client
	config       *Config
}

func NewStorage(config *Config) *Storage {
	storage := &Storage{
		config: config,
	}

	// 初始化InfluxDB
	storage.influxClient = influxdb2.NewClient(
		config.InfluxDB.URL,
		config.InfluxDB.Token,
	)
	storage.influxWrite = storage.influxClient.WriteAPIBlocking(
		config.InfluxDB.Org,
		config.InfluxDB.Bucket,
	)

	// 初始化PostgreSQL
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.PostgreSQL.Host,
		config.PostgreSQL.Port,
		config.PostgreSQL.User,
		config.PostgreSQL.Password,
		config.PostgreSQL.Database,
	)
	var err error
	storage.postgres, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// 自动迁移数据库表
	storage.postgres.AutoMigrate(
		&Agent{},
		&CrashEvent{},
		&User{},
		&ProcessSnapshot{},
		&LogEntry{},
		&ScriptExecution{},
		&ServiceStatus{},
		&AlertRule{},
		&AlertHistory{},
		&AlertSilence{},
		&NotificationChannel{},
		&LLMModelConfig{},
		&AnomalyEvent{},
		&KnowledgeBase{},
		&TroubleshootingGuide{},
		&BestPractice{},
		&CaseStudy{},
		&InspectionReport{},
		&InspectionRecord{},
	)

	// 初始化默认管理员用户
	storage.InitDefaultAdmin()

	// 初始化Redis
	storage.redis = redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// 启动Agent状态监控
	storage.StartAgentMonitor()

	log.Println("Storage initialized successfully")
	return storage
}

func (s *Storage) Close() {
	s.influxClient.Close()
	if sqlDB, err := s.postgres.DB(); err == nil {
		sqlDB.Close()
	}
	s.redis.Close()
}

// SaveAgent 保存或更新Agent信息（使用Upsert）
func (s *Storage) SaveAgent(agent *Agent) error {
	return s.postgres.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "host_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"hostname", "ip", "os", "arch", "tags",
			"status", "last_seen", "updated_at",
		}),
	}).Create(agent).Error
}

// UpdateAgentLastSeen 更新Agent最后上报时间
func (s *Storage) UpdateAgentLastSeen(hostID string) error {
	// 先检查Agent当前状态
	var agent Agent
	err := s.postgres.Where("host_id = ?", hostID).First(&agent).Error
	if err != nil {
		// Agent不存在，直接返回
		return err
	}

	// 检查是否从offline变为online（恢复）
	wasOffline := agent.Status == "offline"

	// 更新Agent状态
	err = s.postgres.Model(&Agent{}).
		Where("host_id = ?", hostID).
		Updates(map[string]interface{}{
			"last_seen": time.Now(),
			"status":    "online",
		}).Error

	if err != nil {
		return err
	}

	// 如果Agent从offline恢复为online，标记宕机事件为已恢复
	if wasOffline {
		go func() {
			if err := s.ResolveCrashEvent(hostID); err != nil {
				// 如果找不到未解决的宕机事件，这是正常的（可能已经被标记过了）
				log.Printf("Agent %s recovered, but no unresolved crash event found (this is normal if already resolved)", hostID)
			} else {
				log.Printf("Agent %s recovered, crash event marked as resolved", hostID)
			}
		}()
	}

	return nil
}

// MarkAgentOffline 标记超时的Agent为离线（增强版）
func (s *Storage) MarkAgentOffline(timeout time.Duration) error {
	cutoffTime := time.Now().Add(-timeout)

	// 查找需要标记为离线的Agent
	var agents []Agent
	s.postgres.Where("last_seen < ? AND status = ?", cutoffTime, "online").
		Find(&agents)

	if len(agents) > 0 {
		// 批量更新状态
		result := s.postgres.Model(&Agent{}).
			Where("last_seen < ? AND status = ?", cutoffTime, "online").
			Update("status", "offline")

		if result.Error != nil {
			return result.Error
		}

		log.Printf("Marked %d agents as offline", result.RowsAffected)

		// 为每个离线的Agent创建宕机事件记录
		for _, agent := range agents {
			go s.CreateCrashEvent(agent.HostID, agent.Hostname, agent.LastSeen)

			// 推送WebSocket通知
			// if s.wsHub != nil {
			// 	s.wsHub.BroadcastAgentStatus(agent.HostID, "offline")
			// }
		}
	}

	return nil
}

// CreateCrashEvent 创建宕机事件记录
func (s *Storage) CreateCrashEvent(hostID, hostname string, lastSeen time.Time) {
	//ctx := context.Background()

	// 获取离线前最后一次的指标数据
	lastMetrics, err := s.GetLastMetricsBeforeTime(hostID, lastSeen)
	if err != nil {
		log.Printf("Failed to get last metrics for %s: %v", hostID, err)
		lastMetrics = &LastMetrics{}
	}

	// 分析宕机原因
	reason := s.AnalyzeCrashReason(lastMetrics)

	// 创建宕机事件
	event := &CrashEvent{
		HostID:          hostID,
		Hostname:        hostname,
		OfflineTime:     time.Now(),
		LastCPU:         lastMetrics.CPU,
		LastMemory:      lastMetrics.Memory,
		LastDisk:        lastMetrics.Disk,
		LastNetwork:     lastMetrics.Network,
		Reason:          reason,
		IsResolved:      false,
		MetricsSnapshot: lastMetrics.Snapshot,
	}

	if err := s.postgres.Create(event).Error; err != nil {
		log.Printf("Failed to create crash event: %v", err)
	} else {
		log.Printf("Created crash event for %s: %s", hostID, reason)
	}
}

// LastMetrics 最后的指标数据
type LastMetrics struct {
	CPU      float64
	Memory   float64
	Disk     float64
	Network  string
	Snapshot string
}

// GetLastMetricsBeforeTime 获取指定时间前最后一次指标
func (s *Storage) GetLastMetricsBeforeTime(hostID string, beforeTime time.Time) (*LastMetrics, error) {
	ctx := context.Background()

	// 查询离线前5分钟的数据
	startTime := beforeTime.Add(-5 * time.Minute).Format(time.RFC3339)
	endTime := beforeTime.Format(time.RFC3339)

	// 查询CPU
	cpuQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: %s, stop: %s)
		|> filter(fn: (r) => r["_measurement"] == "cpu")
		|> filter(fn: (r) => r["host_id"] == "%s")
		|> filter(fn: (r) => r["_field"] == "usage_percent")
		|> last()
	`, s.config.InfluxDB.Bucket, startTime, endTime, hostID)

	var cpu float64
	queryAPI := s.influxClient.QueryAPI(s.config.InfluxDB.Org)
	result, err := queryAPI.Query(ctx, cpuQuery)
	if err == nil {
		for result.Next() {
			if val, ok := result.Record().Value().(float64); ok {
				cpu = val
			}
		}
		result.Close()
	}

	// 查询内存
	memQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: %s, stop: %s)
		|> filter(fn: (r) => r["_measurement"] == "memory")
		|> filter(fn: (r) => r["host_id"] == "%s")
		|> filter(fn: (r) => r["_field"] == "used_percent")
		|> last()
	`, s.config.InfluxDB.Bucket, startTime, endTime, hostID)

	var memory float64
	result, err = queryAPI.Query(ctx, memQuery)
	if err == nil {
		for result.Next() {
			if val, ok := result.Record().Value().(float64); ok {
				memory = val
			}
		}
		result.Close()
	}

	// 查询磁盘（取最高使用率的分区）
	diskQuery := fmt.Sprintf(`
		from(bucket: "%s")
		|> range(start: %s, stop: %s)
		|> filter(fn: (r) => r["_measurement"] == "disk")
		|> filter(fn: (r) => r["host_id"] == "%s")
		|> filter(fn: (r) => r["_field"] == "used_percent")
		|> max()
	`, s.config.InfluxDB.Bucket, startTime, endTime, hostID)

	var disk float64
	result, err = queryAPI.Query(ctx, diskQuery)
	if err == nil {
		for result.Next() {
			if val, ok := result.Record().Value().(float64); ok {
				disk = val
			}
		}
		result.Close()
	}

	return &LastMetrics{
		CPU:      cpu,
		Memory:   memory,
		Disk:     disk,
		Network:  "normal",
		Snapshot: fmt.Sprintf(`{"cpu":%.2f,"memory":%.2f,"disk":%.2f}`, cpu, memory, disk),
	}, nil
}

// AnalyzeCrashReason 分析宕机原因
func (s *Storage) AnalyzeCrashReason(metrics *LastMetrics) string {
	reasons := make([]string, 0)

	// CPU过高
	if metrics.CPU > 90 {
		reasons = append(reasons, fmt.Sprintf("CPU负载过高(%.1f%%)", metrics.CPU))
	}

	// 内存不足
	if metrics.Memory > 95 {
		reasons = append(reasons, fmt.Sprintf("内存不足(%.1f%%)", metrics.Memory))
	}

	// 磁盘满
	if metrics.Disk > 95 {
		reasons = append(reasons, fmt.Sprintf("磁盘空间不足(%.1f%%)", metrics.Disk))
	}

	if len(reasons) == 0 {
		return "未知原因，可能是网络中断或主机关机"
	}

	result := "可能原因："
	for i, r := range reasons {
		if i > 0 {
			result += "；"
		}
		result += r
	}

	return result
}

// ResolveCrashEvent 标记宕机事件已恢复
func (s *Storage) ResolveCrashEvent(hostID string) error {
	now := time.Now()

	// 查找未解决的宕机事件
	var event CrashEvent
	err := s.postgres.Where("host_id = ? AND is_resolved = ?", hostID, false).
		Order("offline_time DESC").
		First(&event).Error

	if err != nil {
		// 如果没有找到未解决的事件，返回错误（但这是正常的，可能已经被标记过了）
		return err
	}

	// 计算离线持续时间
	duration := now.Sub(event.OfflineTime).Seconds()

	// 更新事件
	updateErr := s.postgres.Model(&event).Updates(map[string]interface{}{
		"online_time": &now,
		"duration":    int64(duration),
		"is_resolved": true,
	}).Error

	if updateErr != nil {
		log.Printf("Failed to resolve crash event for %s: %v", hostID, updateErr)
		return updateErr
	}

	log.Printf("Crash event resolved for %s: duration=%.0f seconds", hostID, duration)
	return nil
}

// GetCrashEvents 获取宕机事件列表
func (s *Storage) GetCrashEvents(hostID string, limit int) ([]CrashEvent, error) {
	var events []CrashEvent
	query := s.postgres.Order("offline_time DESC")

	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&events).Error
	return events, err
}

// GetCrashEventDetail 获取单个宕机事件详情
func (s *Storage) GetCrashEventDetail(id uint) (*CrashEvent, error) {
	var event CrashEvent
	err := s.postgres.First(&event, id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// StartAgentMonitor 启动Agent状态监控（定期检查并标记离线Agent）
func (s *Storage) StartAgentMonitor() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// 2分钟未上报视为离线
			if err := s.MarkAgentOffline(2 * time.Minute); err != nil {
				log.Printf("Failed to mark agents offline: %v", err)
			}
		}
	}()

	log.Println("Agent monitor started")
}

// GetAgentStatus 获取Agent状态
func (s *Storage) GetAgentStatus(hostID string) (string, error) {
	var agent Agent
	err := s.postgres.Select("status", "last_seen").
		Where("host_id = ?", hostID).
		First(&agent).Error
	if err != nil {
		return "unknown", err
	}

	// 双重检查：即使数据库status是online，也要检查时间
	if agent.Status == "online" && time.Since(agent.LastSeen) > 2*time.Minute {
		return "offline", nil
	}

	return agent.Status, nil
}

// SaveMetrics 保存指标数据到InfluxDB（完整版）
func (s *Storage) SaveMetrics(metrics *Metrics) error {
	ctx := context.Background()
	var points []*write.Point

	// CPU指标
	cpuPoint := influxdb2.NewPoint(
		"cpu",
		map[string]string{"host_id": metrics.HostID},
		map[string]interface{}{
			"usage_percent": metrics.CPU.UsagePercent,
			"load_avg_1":    metrics.CPU.LoadAvg1,
			"load_avg_5":    metrics.CPU.LoadAvg5,
			"load_avg_15":   metrics.CPU.LoadAvg15,
			"core_count":    metrics.CPU.CoreCount,
		},
		metrics.Timestamp,
	)
	points = append(points, cpuPoint)

	// 内存指标
	memPoint := influxdb2.NewPoint(
		"memory",
		map[string]string{"host_id": metrics.HostID},
		map[string]interface{}{
			"total":        metrics.Memory.Total,
			"used":         metrics.Memory.Used,
			"free":         metrics.Memory.Free,
			"used_percent": metrics.Memory.UsedPercent,
			"available":    metrics.Memory.Available,
		},
		metrics.Timestamp,
	)
	points = append(points, memPoint)

	// 磁盘指标 - 为每个分区创建数据点
	if len(metrics.Disk.Partitions) > 0 {
		for _, partition := range metrics.Disk.Partitions {
			diskPoint := influxdb2.NewPoint(
				"disk",
				map[string]string{
					"host_id":    metrics.HostID,
					"device":     partition.Device,
					"mountpoint": partition.Mountpoint,
					"fstype":     partition.Fstype,
				},
				map[string]interface{}{
					"total":        partition.Total,
					"used":         partition.Used,
					"free":         partition.Free,
					"used_percent": partition.UsedPercent,
				},
				metrics.Timestamp,
			)
			points = append(points, diskPoint)
		}
	}

	// 网络指标 - 为每个网卡创建数据点
	if len(metrics.Network.Interfaces) > 0 {
		for _, iface := range metrics.Network.Interfaces {
			netPoint := influxdb2.NewPoint(
				"network",
				map[string]string{
					"host_id":   metrics.HostID,
					"interface": iface.Name,
				},
				map[string]interface{}{
					"bytes_sent":   iface.BytesSent,
					"bytes_recv":   iface.BytesRecv,
					"packets_sent": iface.PacketsSent,
					"packets_recv": iface.PacketsRecv,
					"errin":        iface.Errin,
					"errout":       iface.Errout,
				},
				metrics.Timestamp,
			)
			points = append(points, netPoint)
		}
	}

	// 批量写入所有数据点
	for _, point := range points {
		if err := s.influxWrite.WritePoint(ctx, point); err != nil {
			log.Printf("Failed to write point: %v", err)
			return err
		}
	}

	return nil
}

// GetOnlineAgentCount 获取在线Agent数量
func (s *Storage) GetOnlineAgentCount() (int64, error) {
	var count int64
	err := s.postgres.Model(&Agent{}).
		Where("status = ? AND last_seen > ?", "online", time.Now().Add(-2*time.Minute)).
		Count(&count).Error
	return count, err
}

// GetAllAgents 获取所有Agent
func (s *Storage) GetAllAgents() ([]Agent, error) {
	var agents []Agent
	err := s.postgres.Order("last_seen DESC").Find(&agents).Error
	return agents, err
}

// DeleteAgent 删除Agent及其所有数据
func (s *Storage) DeleteAgent(hostID string) error {
	// 软删除Agent记录
	err := s.postgres.Where("host_id = ?", hostID).Delete(&Agent{}).Error
	if err != nil {
		return err
	}

	// TODO: 可选择删除InfluxDB中的历史数据
	// 这需要根据实际需求决定是否保留历史数据

	log.Printf("Agent deleted: %s", hostID)
	return nil
}

// CleanupOldMetrics 清理旧的指标数据（保留策略）
func (s *Storage) CleanupOldMetrics(retention time.Duration) error {
	ctx := context.Background()

	// InfluxDB通常有自己的retention policy
	// 这里可以手动删除超过保留期的数据
	deleteQuery := fmt.Sprintf(`
		DELETE FROM metrics 
		WHERE time < now() - %s
	`, retention.String())

	queryAPI := s.influxClient.QueryAPI(s.config.InfluxDB.Org)
	_, err := queryAPI.Query(ctx, deleteQuery)

	return err
}

// ============================================
// Redis缓存相关方法
// ============================================

// CacheLatestMetrics 缓存最新指标（减轻InfluxDB压力）
func (s *Storage) CacheLatestMetrics(hostID string, metrics *Metrics) error {
	ctx := context.Background()
	key := fmt.Sprintf("metrics:latest:%s", hostID)

	// 构建缓存数据结构
	cacheData := map[string]interface{}{
		"host_id":   metrics.HostID,
		"timestamp": metrics.Timestamp.Unix(),
		"cpu": map[string]interface{}{
			"usage_percent": metrics.CPU.UsagePercent,
			"load_avg_1":    metrics.CPU.LoadAvg1,
			"load_avg_5":    metrics.CPU.LoadAvg5,
			"load_avg_15":   metrics.CPU.LoadAvg15,
			"core_count":    metrics.CPU.CoreCount,
		},
		"memory": map[string]interface{}{
			"total":        metrics.Memory.Total,
			"used":         metrics.Memory.Used,
			"free":         metrics.Memory.Free,
			"used_percent": metrics.Memory.UsedPercent,
			"available":    metrics.Memory.Available,
		},
	}

	// 添加磁盘数据（缓存所有分区，以支持按挂载点告警）
	if len(metrics.Disk.Partitions) > 0 {
		var partitions []map[string]interface{}
		for _, p := range metrics.Disk.Partitions {
			partitions = append(partitions, map[string]interface{}{
				"device":       p.Device,
				"mountpoint":   p.Mountpoint,
				"fstype":       p.Fstype,
				"total":        p.Total,
				"used":         p.Used,
				"free":         p.Free,
				"used_percent": p.UsedPercent,
			})
		}
		cacheData["disk"] = map[string]interface{}{
			"partitions": partitions,
		}
	}

	// 添加网络数据（聚合所有接口）
	if len(metrics.Network.Interfaces) > 0 {
		var totalBytesSent, totalBytesRecv, totalPacketsSent, totalPacketsRecv uint64
		for _, iface := range metrics.Network.Interfaces {
			totalBytesSent += iface.BytesSent
			totalBytesRecv += iface.BytesRecv
			totalPacketsSent += iface.PacketsSent
			totalPacketsRecv += iface.PacketsRecv
		}
		cacheData["network"] = map[string]interface{}{
			"bytes_sent":   totalBytesSent,
			"bytes_recv":   totalBytesRecv,
			"packets_sent": totalPacketsSent,
			"packets_recv": totalPacketsRecv,
		}
	}

	// 序列化为JSON并缓存5分钟
	jsonData, err := json.Marshal(cacheData)
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %v", err)
	}

	return s.redis.Set(ctx, key, jsonData, 5*time.Minute).Err()
}

// GetCachedLatestMetrics 从缓存获取最新指标
func (s *Storage) GetCachedLatestMetrics(hostID string) (*Metrics, error) {
	ctx := context.Background()
	key := fmt.Sprintf("metrics:latest:%s", hostID)

	// 从Redis获取JSON数据
	jsonData, err := s.redis.Get(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("cache miss: %v", err)
	}

	// 反序列化JSON
	var cacheData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &cacheData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache data: %v", err)
	}

	// 构建Metrics对象
	metrics := &Metrics{
		HostID: hostID,
	}

	// 解析时间戳
	if ts, ok := cacheData["timestamp"].(float64); ok {
		metrics.Timestamp = time.Unix(int64(ts), 0)
	} else {
		metrics.Timestamp = time.Now()
	}

	// 解析CPU数据
	if cpuData, ok := cacheData["cpu"].(map[string]interface{}); ok {
		metrics.CPU = CPUMetrics{
			UsagePercent: getFloat64(cpuData["usage_percent"]),
			LoadAvg1:     getFloat64(cpuData["load_avg_1"]),
			LoadAvg5:     getFloat64(cpuData["load_avg_5"]),
			LoadAvg15:    getFloat64(cpuData["load_avg_15"]),
			CoreCount:    getInt(cpuData["core_count"]),
		}
	}

	// 解析内存数据
	if memData, ok := cacheData["memory"].(map[string]interface{}); ok {
		metrics.Memory = MemoryMetrics{
			Total:       getUint64(memData["total"]),
			Used:        getUint64(memData["used"]),
			Free:        getUint64(memData["free"]),
			UsedPercent: getFloat64(memData["used_percent"]),
			Available:   getUint64(memData["available"]),
		}
	}

	// 解析磁盘数据（支持新格式：partitions数组，也兼容旧格式：单个分区）
	if diskData, ok := cacheData["disk"].(map[string]interface{}); ok {
		var partitions []PartitionMetrics
		
		// 检查是否是新格式（partitions数组）
		if partitionsData, ok := diskData["partitions"].([]interface{}); ok {
			// 新格式：包含所有分区的数组
			for _, partData := range partitionsData {
				if partMap, ok := partData.(map[string]interface{}); ok {
					partitions = append(partitions, PartitionMetrics{
						Device:      getString(partMap["device"]),
						Mountpoint:  getString(partMap["mountpoint"]),
						Fstype:      getString(partMap["fstype"]),
						Total:       getUint64(partMap["total"]),
						Used:        getUint64(partMap["used"]),
						Free:        getUint64(partMap["free"]),
						UsedPercent: getFloat64(partMap["used_percent"]),
					})
				}
			}
		} else {
			// 旧格式：单个分区（兼容性处理）
			partitions = []PartitionMetrics{
				{
					Device:      getString(diskData["device"]),
					Mountpoint:  getString(diskData["mountpoint"]),
					Fstype:      getString(diskData["fstype"]),
					Total:       getUint64(diskData["total"]),
					Used:        getUint64(diskData["used"]),
					Free:        getUint64(diskData["free"]),
					UsedPercent: getFloat64(diskData["used_percent"]),
				},
			}
		}
		
		metrics.Disk = DiskMetrics{
			Partitions: partitions,
		}
	}

	// 解析网络数据
	if netData, ok := cacheData["network"].(map[string]interface{}); ok {
		metrics.Network = NetworkMetrics{
			Interfaces: []InterfaceMetrics{
				{
					Name:        "aggregated",
					BytesSent:   getUint64(netData["bytes_sent"]),
					BytesRecv:   getUint64(netData["bytes_recv"]),
					PacketsSent: getUint64(netData["packets_sent"]),
					PacketsRecv: getUint64(netData["packets_recv"]),
				},
			},
		}
	}

	return metrics, nil
}

// 辅助函数：类型转换
func getFloat64(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case uint64:
		return float64(val)
	default:
		return 0
	}
}

func getUint64(v interface{}) uint64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case uint64:
		return val
	case int64:
		return uint64(val)
	case int:
		return uint64(val)
	case float64:
		return uint64(val)
	default:
		return 0
	}
}

func getInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	default:
		return 0
	}
}

func getString(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// ============================================
// 测试和诊断方法
// ============================================

// Ping 测试所有存储连接
func (s *Storage) Ping() error {
	// 测试PostgreSQL
	sqlDB, err := s.postgres.DB()
	if err != nil {
		return fmt.Errorf("postgres error: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("postgres ping error: %v", err)
	}

	// 测试Redis
	ctx := context.Background()
	if err := s.redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis error: %v", err)
	}

	// 测试InfluxDB
	health, err := s.influxClient.Health(context.Background())
	if err != nil {
		return fmt.Errorf("influxdb error: %v", err)
	}
	if health.Status != "pass" {
		return fmt.Errorf("influxdb unhealthy: %s", health.Status)
	}

	return nil
}

// InitDefaultAdmin 初始化默认管理员用户
func (s *Storage) InitDefaultAdmin() {
	defaultUsername := "admin"
	defaultEmail := "admin@monitor.local"
	defaultPassword := "admin123" // 默认密码，建议首次登录后修改

	// 检查是否已存在admin用户
	var existingUser User
	err := s.postgres.Where("username = ?", defaultUsername).First(&existingUser).Error
	if err == nil {
		// admin用户已存在，跳过创建
		log.Printf("Default admin user '%s' already exists", defaultUsername)
		return
	}

	// 使用bcrypt加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Failed to hash default admin password: %v", err)
		return
	}

	// 创建默认管理员
	adminUser := User{
		Username: defaultUsername,
		Email:    defaultEmail,
		Password: string(hashedPassword),
		Role:     "admin",
		Status:   "active",
	}

	if err := s.postgres.Create(&adminUser).Error; err != nil {
		log.Printf("Failed to create default admin user: %v", err)
		return
	}

	log.Printf("Default admin user created successfully!")
	log.Printf("  Username: %s", defaultUsername)
	log.Printf("  Password: %s", defaultPassword)
	log.Printf("  Email: %s", defaultEmail)
	log.Printf("  ⚠️  Please change the default password after first login!")
}

// GetStats 获取存储统计信息
func (s *Storage) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Agent统计
	var totalAgents, onlineAgents int64
	s.postgres.Model(&Agent{}).Count(&totalAgents)
	s.postgres.Model(&Agent{}).Where("status = ?", "online").Count(&onlineAgents)

	stats["total_agents"] = totalAgents
	stats["online_agents"] = onlineAgents
	stats["offline_agents"] = totalAgents - onlineAgents

	// PostgreSQL统计
	sqlDB, _ := s.postgres.DB()
	if sqlDB != nil {
		pgStats := sqlDB.Stats()
		stats["postgres_connections"] = pgStats.OpenConnections
	}

	// Redis统计
	ctx := context.Background()
	if info, err := s.redis.Info(ctx, "stats").Result(); err == nil {
		stats["redis_info"] = info
	}

	return stats
}
