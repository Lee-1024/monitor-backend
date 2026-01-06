package main

import (
	"time"

	"gorm.io/gorm"
)

// Agent 主机Agent模型
type Agent struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	HostID   string            `gorm:"uniqueIndex;size:64" json:"host_id"`
	Hostname string            `gorm:"size:255" json:"hostname"`
	IP       string            `gorm:"size:64" json:"ip"`
	OS       string            `gorm:"size:64" json:"os"`
	Arch     string            `gorm:"size:32" json:"arch"`
	Tags     map[string]string `gorm:"serializer:json" json:"tags"`
	Status   string            `gorm:"size:32;default:offline" json:"status"`
	LastSeen time.Time         `json:"last_seen"`
}

// CrashEvent 宕机事件记录
type CrashEvent struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	HostID      string     `gorm:"index;size:64" json:"host_id"`
	Hostname    string     `gorm:"size:255" json:"hostname"`
	OfflineTime time.Time  `gorm:"index" json:"offline_time"` // 离线时间
	OnlineTime  *time.Time `json:"online_time,omitempty"`     // 恢复时间
	Duration    int64      `json:"duration"`                  // 离线持续时间（秒）

	// 离线前的系统状态
	LastCPU     float64 `json:"last_cpu"`
	LastMemory  float64 `json:"last_memory"`
	LastDisk    float64 `json:"last_disk"`
	LastNetwork string  `json:"last_network"`

	// 分析原因
	Reason     string `gorm:"size:255" json:"reason"`
	IsResolved bool   `gorm:"default:false" json:"is_resolved"`

	// 详细信息（JSON格式存储完整指标）
	MetricsSnapshot string `gorm:"type:text" json:"metrics_snapshot"`
}

// Metrics 指标数据（内部使用）
type Metrics struct {
	HostID    string
	Timestamp time.Time
	CPU       CPUMetrics
	Memory    MemoryMetrics
	Disk      DiskMetrics
	Network   NetworkMetrics
}

type CPUMetrics struct {
	UsagePercent float64
	LoadAvg1     float64
	LoadAvg5     float64
	LoadAvg15    float64
	CoreCount    int
}

type MemoryMetrics struct {
	Total       uint64
	Used        uint64
	Free        uint64
	UsedPercent float64
	Available   uint64
}

type DiskMetrics struct {
	Partitions []PartitionMetrics
}

type PartitionMetrics struct {
	Device      string
	Mountpoint  string
	Fstype      string
	Total       uint64
	Used        uint64
	Free        uint64
	UsedPercent float64
}

type NetworkMetrics struct {
	Interfaces []InterfaceMetrics
}

type InterfaceMetrics struct {
	Name        string
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	Errin       uint64
	Errout      uint64
}
