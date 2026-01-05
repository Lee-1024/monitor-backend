// ============================================
// 文件: models.go
// ============================================
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
	Status   string            `gorm:"size:32;default:offline" json:"status"` // online, offline
	LastSeen time.Time         `json:"last_seen"`
}

// Metrics 指标数据（内部使用）
type Metrics struct {
	HostID    string
	Timestamp time.Time
	CPU       CPUMetrics
	Memory    MemoryMetrics
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
