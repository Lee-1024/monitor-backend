package main

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// StringSliceJSON is a tolerant JSON slice that accepts false/null as empty array.
type StringSliceJSON []string

func (s *StringSliceJSON) UnmarshalJSON(b []byte) error {
	trim := string(b)
	if trim == "false" || trim == "null" || trim == `""` {
		*s = []string{}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		// 如果数据格式异常，返回空切片而不是报错，避免查询失败
		*s = []string{}
		return nil
	}
	*s = arr
	return nil
}

func (s StringSliceJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s))
}

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

// AlertRule 告警规则
type AlertRule struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name        string `gorm:"size:255;not null" json:"name"`         // 规则名称
	Description string `gorm:"type:text" json:"description"`          // 规则描述
	Enabled     bool   `gorm:"default:true" json:"enabled"`           // 是否启用
	Severity    string `gorm:"size:32;default:warning" json:"severity"` // critical, warning, info

	// 规则条件
	MetricType  string `gorm:"size:32;not null" json:"metric_type"`  // cpu, memory, disk, network
	HostID      string `gorm:"size:64;index" json:"host_id"`         // 空表示所有主机
	Condition   string `gorm:"size:32;not null" json:"condition"`    // gt, gte, lt, lte, eq, neq
	Threshold   float64 `gorm:"not null" json:"threshold"`           // 阈值
	Duration    int     `gorm:"default:60" json:"duration"`          // 持续时间（秒）

	// 通知配置
	NotifyChannels StringSliceJSON `gorm:"serializer:json" json:"notify_channels"` // email, dingtalk, wechat, feishu
	Receivers      StringSliceJSON `gorm:"serializer:json" json:"receivers"`       // 接收人列表

	// 静默和抑制
	SilenceStart *time.Time `json:"silence_start,omitempty"` // 静默开始时间
	SilenceEnd   *time.Time `json:"silence_end,omitempty"`   // 静默结束时间
	InhibitDuration int     `gorm:"default:300" json:"inhibit_duration"` // 抑制持续时间（秒），默认5分钟，相同告警在此时间内只发送一次通知
}

// AlertHistory 告警历史记录
type AlertHistory struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`

	RuleID      uint      `gorm:"index;not null" json:"rule_id"`     // 规则ID
	RuleName    string    `gorm:"size:255" json:"rule_name"`         // 规则名称
	HostID      string    `gorm:"index;size:64" json:"host_id"`      // 主机ID
	Hostname    string    `gorm:"size:255" json:"hostname"`          // 主机名
	Severity    string    `gorm:"size:32;index" json:"severity"`     // 严重程度
	Status      string    `gorm:"size:32;index" json:"status"`       // firing, resolved
	FiredAt     time.Time `gorm:"index" json:"fired_at"`             // 触发时间
	ResolvedAt  *time.Time `gorm:"index" json:"resolved_at,omitempty"` // 恢复时间

	// 告警详情
	MetricType  string  `gorm:"size:32" json:"metric_type"`          // 指标类型
	MetricValue float64 `json:"metric_value"`                        // 指标值
	Threshold   float64 `json:"threshold"`                           // 阈值
	Message     string  `gorm:"type:text" json:"message"`            // 告警消息
	Labels      map[string]string `gorm:"serializer:json" json:"labels"` // 标签

	// 通知状态
	NotifyStatus string `gorm:"size:32;default:pending" json:"notify_status"` // pending, success, failed
	NotifyError  string `gorm:"type:text" json:"notify_error,omitempty"`      // 通知错误信息
}

// AlertSilence 告警静默配置
type AlertSilence struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name      string    `gorm:"size:255;not null" json:"name"`       // 静默名称
	RuleIDs   []uint    `gorm:"serializer:json" json:"rule_ids"`     // 规则ID列表（空表示所有规则）
	HostIDs   []string  `gorm:"serializer:json" json:"host_ids"`     // 主机ID列表（空表示所有主机）
	StartTime time.Time `gorm:"index" json:"start_time"`             // 开始时间
	EndTime   time.Time `gorm:"index" json:"end_time"`               // 结束时间
	Enabled   bool      `gorm:"default:true" json:"enabled"`         // 是否启用
	Comment   string    `gorm:"type:text" json:"comment"`            // 备注
	Creator   string    `gorm:"size:64" json:"creator"`              // 创建人
}

// NotificationChannel 通知渠道配置
type NotificationChannel struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Type        string            `gorm:"size:32;not null;uniqueIndex" json:"type"` // email, dingtalk, wechat, feishu
	Name        string            `gorm:"size:255;not null" json:"name"`            // 渠道名称
	Enabled     bool              `gorm:"default:true" json:"enabled"`              // 是否启用
	Config      map[string]string `gorm:"serializer:json" json:"config"`           // 配置信息（JSON格式）
	Description string            `gorm:"type:text" json:"description"`              // 描述
}
