// ============================================
// 文件: storage.go (优化版本)
// ============================================
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/redis/go-redis/v9"
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
	storage.postgres.AutoMigrate(&Agent{})

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
	return s.postgres.Model(&Agent{}).
		Where("host_id = ?", hostID).
		Updates(map[string]interface{}{
			"last_seen": time.Now(),
			"status":    "online",
		}).Error
}

// MarkAgentOffline 标记超时的Agent为离线
func (s *Storage) MarkAgentOffline(timeout time.Duration) error {
	cutoffTime := time.Now().Add(-timeout)
	result := s.postgres.Model(&Agent{}).
		Where("last_seen < ? AND status = ?", cutoffTime, "online").
		Update("status", "offline")

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected > 0 {
		log.Printf("Marked %d agents as offline", result.RowsAffected)
	}

	return nil
}

// StartAgentMonitor 启动Agent状态监控（定期检查并标记离线Agent）
func (s *Storage) StartAgentMonitor() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// 2分钟未上报视为离
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

// SaveMetrics 保存指标数据到InfluxDB
func (s *Storage) SaveMetrics(metrics *Metrics) error {
	ctx := context.Background()

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

	// 批量写入
	if err := s.influxWrite.WritePoint(ctx, cpuPoint); err != nil {
		return err
	}
	if err := s.influxWrite.WritePoint(ctx, memPoint); err != nil {
		return err
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

	// 序列化为JSON
	data := map[string]interface{}{
		"timestamp": metrics.Timestamp.Unix(),
		"cpu":       metrics.CPU,
		"memory":    metrics.Memory,
	}

	// 缓存5分钟
	return s.redis.Set(ctx, key, data, 5*time.Minute).Err()
}

// GetCachedLatestMetrics 从缓存获取最新指标
func (s *Storage) GetCachedLatestMetrics(hostID string) (*Metrics, error) {
	ctx := context.Background()
	key := fmt.Sprintf("metrics:latest:%s", hostID)

	// 这里简化了，实际需要反序列化JSON
	exists, err := s.redis.Exists(ctx, key).Result()
	if err != nil || exists == 0 {
		return nil, fmt.Errorf("cache miss")
	}

	// TODO: 实现完整的反序列化逻辑
	return nil, nil
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

// ============================================
// 使用示例
// ============================================
/*
// 在main.go中使用

storage := NewStorage(config)
defer storage.Close()

// 定期检查存储健康状态
go func() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		if err := storage.Ping(); err != nil {
			log.Printf("Storage health check failed: %v", err)
		}
	}
}()

// 定期输出统计信息
go func() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		stats := storage.GetStats()
		log.Printf("Storage stats: %+v", stats)
	}
}()
*/
