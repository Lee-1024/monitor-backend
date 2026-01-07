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

// User 用户模型
type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Username string `gorm:"uniqueIndex;size:64;not null" json:"username"`
	Email    string `gorm:"uniqueIndex;size:255;not null" json:"email"`
	Password string `gorm:"size:255;not null" json:"-"` // 不返回密码
	Role     string `gorm:"size:32;default:user" json:"role"` // admin, user
	Status   string `gorm:"size:32;default:active" json:"status"` // active, inactive
	LastLogin *time.Time `json:"last_login,omitempty"`
}

// ProcessSnapshot 进程快照
type ProcessSnapshot struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	HostID    string    `gorm:"index;size:64" json:"host_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	
	PID          int32   `json:"pid"`
	Name         string  `gorm:"size:255" json:"name"`
	User         string  `gorm:"size:64" json:"user"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryBytes  uint64  `json:"memory_bytes"`
	Status       string  `gorm:"size:32" json:"status"`
	Command      string  `gorm:"type:text" json:"command"`
}

// LogEntry 日志条目
type LogEntry struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	HostID    string    `gorm:"index;size:64" json:"host_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	
	Source    string            `gorm:"size:255" json:"source"`
	Level     string            `gorm:"size:32;index" json:"level"` // INFO, WARN, ERROR
	Message   string            `gorm:"type:text" json:"message"`
	Tags      map[string]string `gorm:"serializer:json" json:"tags"`
}

// ScriptExecution 脚本执行记录
type ScriptExecution struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	HostID     string    `gorm:"index;size:64" json:"host_id"`
	ScriptID   string    `gorm:"index;size:64" json:"script_id"`
	ScriptName string    `gorm:"size:255" json:"script_name"`
	Timestamp  time.Time `gorm:"index" json:"timestamp"`
	
	Success   bool   `json:"success"`
	Output    string `gorm:"type:text" json:"output"`
	Error     string `gorm:"type:text" json:"error"`
	ExitCode  int    `json:"exit_code"`
	Duration  int64  `json:"duration_ms"` // 毫秒
}

// ServiceStatus 服务状态记录
type ServiceStatus struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	HostID    string    `gorm:"index;size:64" json:"host_id"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	
	Name        string `gorm:"index;size:255" json:"name"`
	Status      string `gorm:"size:32;index" json:"status"` // running, stopped, failed
	Enabled     bool   `json:"enabled"`
	Description string `gorm:"type:text" json:"description"`
	Uptime      int64  `json:"uptime_seconds"`
}
