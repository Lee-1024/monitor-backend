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
	
	PID          int32   `gorm:"column:pid" json:"pid"`
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

// AnomalyEvent 异常事件
type AnomalyEvent struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	HostID          string                 `gorm:"index;size:64" json:"host_id"`
	Type            string                 `gorm:"size:32;index" json:"type"`            // metric_spike, metric_drop, log_error等
	Severity        string                 `gorm:"size:32;index" json:"severity"`       // critical, high, medium, low
	MetricType      string                 `gorm:"size:32" json:"metric_type,omitempty"` // cpu, memory, disk等
	Timestamp       time.Time              `gorm:"index" json:"timestamp"`
	Value           float64                `json:"value"`
	ExpectedValue   float64                `json:"expected_value,omitempty"`
	Deviation       float64                `json:"deviation"`
	Confidence      float64                `json:"confidence"`
	Message         string                 `gorm:"type:text" json:"message"`
	RootCause       string                 `gorm:"type:text" json:"root_cause,omitempty"`
	RelatedLogs     string                 `gorm:"type:text" json:"-"`                  // JSON格式存储相关日志ID
	RelatedMetrics  string                 `gorm:"type:text" json:"-"`                  // JSON格式存储相关指标
	Recommendations string                 `gorm:"type:text" json:"-"`                   // JSON格式存储建议
	IsResolved      bool                   `gorm:"default:false;index" json:"is_resolved"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy      string                 `gorm:"size:64" json:"resolved_by,omitempty"`
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
	
	Name          string `gorm:"index;size:255" json:"name"`
	Status        string `gorm:"size:32;index" json:"status"` // running, stopped, failed
	Enabled       bool   `json:"enabled"`
	Description   string `gorm:"type:text" json:"description"`
	Uptime        int64  `json:"uptime_seconds"`
	Port          int    `gorm:"default:0" json:"port,omitempty"`          // 服务端口
	PortAccessible bool `gorm:"default:false" json:"port_accessible,omitempty"` // 端口是否可访问
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
	MetricType  string `gorm:"size:32;not null" json:"metric_type"`  // cpu, memory, disk, network, host_down, service_port
	HostID      string `gorm:"size:64;index" json:"host_id"`         // 空表示所有主机
	Mountpoint  string `gorm:"size:255" json:"mountpoint,omitempty"`  // 挂载点（仅用于 disk 指标，例如：/、/var、/home）
	ServicePort int    `gorm:"default:0" json:"service_port,omitempty"` // 服务端口（仅用于 service_port 指标）
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

// LLMModelConfig LLM模型配置
type LLMModelConfig struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name        string            `gorm:"size:255;not null;uniqueIndex" json:"name"` // 配置名称
	Provider    string            `gorm:"size:32;not null" json:"provider"`            // openai, deepseek, qwen, doubao, zhipu, claude, custom
	APIKey      string            `gorm:"type:text" json:"api_key"`                    // API密钥
	BaseURL     string            `gorm:"size:512" json:"base_url"`                   // API地址
	Model       string            `gorm:"size:128" json:"model"`                      // 模型名称
	Temperature float64           `gorm:"default:0.7" json:"temperature"`             // 温度参数
	MaxTokens   int               `gorm:"default:8000" json:"max_tokens"`             // 最大token数（默认8000，确保巡检日报等长文本生成完整）
	Timeout     int               `gorm:"default:30" json:"timeout"`                  // 超时时间（秒）
	Enabled     bool              `gorm:"default:true" json:"enabled"`                 // 是否启用
	IsDefault   bool              `gorm:"default:false" json:"is_default"`           // 是否默认配置
	Description string            `gorm:"type:text" json:"description"`              // 描述
	Config      map[string]string `gorm:"serializer:json" json:"config"`              // 额外配置
}

// KnowledgeBase 知识库基础模型
type KnowledgeBase struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Title       string            `gorm:"size:255;not null" json:"title"`           // 标题
	Category    string            `gorm:"size:64;index" json:"category"`            // 分类：troubleshooting/best_practice/case_study
	Tags        StringSliceJSON   `gorm:"type:json" json:"tags"`                    // 标签
	Content     string            `gorm:"type:text;not null" json:"content"`       // 内容
	Summary     string            `gorm:"type:text" json:"summary"`                 // 摘要（LLM生成）
	Author      string            `gorm:"size:64" json:"author"`                    // 作者
	ViewCount   int               `gorm:"default:0" json:"view_count"`               // 查看次数
	LikeCount   int               `gorm:"default:0" json:"like_count"`               // 点赞次数
	IsPublished bool              `gorm:"default:true" json:"is_published"`        // 是否发布
	Metadata    map[string]string `gorm:"serializer:json" json:"metadata"`          // 元数据（存储额外信息）
}

// TroubleshootingGuide 故障处理知识库
type TroubleshootingGuide struct {
	KnowledgeBase `gorm:"embedded"`

	ProblemType    string   `gorm:"size:64;index" json:"problem_type"`    // 问题类型：cpu/memory/disk/network/application
	Severity       string   `gorm:"size:32" json:"severity"`                // 严重程度：critical/high/medium/low
	Symptoms       StringSliceJSON `gorm:"type:json" json:"symptoms"`      // 症状描述
	RootCauses     StringSliceJSON `gorm:"type:json" json:"root_causes"`   // 根本原因
	Solutions      StringSliceJSON `gorm:"type:json" json:"solutions"`     // 解决方案
	PreventionTips StringSliceJSON `gorm:"type:json" json:"prevention_tips"` // 预防建议
	RelatedCases   StringSliceJSON `gorm:"type:json" json:"related_cases"` // 相关案例ID
}

// BestPractice 最佳实践文档
type BestPractice struct {
	KnowledgeBase `gorm:"embedded"`

	Domain        string   `gorm:"size:64;index" json:"domain"`            // 领域：monitoring/alerting/optimization/security
	Applicability string   `gorm:"size:64" json:"applicability"`           // 适用场景
	Benefits      StringSliceJSON `gorm:"type:json" json:"benefits"`       // 收益
	Implementation StringSliceJSON `gorm:"type:json" json:"implementation"` // 实施步骤
	References    StringSliceJSON `gorm:"type:json" json:"references"`     // 参考资源
}

// CaseStudy 故障案例库
type CaseStudy struct {
	KnowledgeBase `gorm:"embedded"`

	IncidentDate   time.Time `gorm:"index" json:"incident_date"`            // 事件发生时间
	ResolvedDate   *time.Time `json:"resolved_date,omitempty"`             // 解决时间
	HostID         string    `gorm:"size:64;index" json:"host_id"`         // 相关主机ID
	Hostname       string    `gorm:"size:255" json:"hostname"`              // 主机名
	ProblemType    string    `gorm:"size:64;index" json:"problem_type"`    // 问题类型
	Severity       string    `gorm:"size:32" json:"severity"`               // 严重程度
	Impact         string    `gorm:"type:text" json:"impact"`                // 影响范围
	Timeline       string    `gorm:"type:text" json:"timeline"`             // 时间线
	Resolution     string    `gorm:"type:text" json:"resolution"`             // 解决方案
	LessonsLearned string    `gorm:"type:text" json:"lessons_learned"`      // 经验教训
	RelatedGuides  StringSliceJSON `gorm:"type:json" json:"related_guides"` // 相关故障处理指南ID
}

// InspectionRecord 巡检记录（单次巡检的主机数据）
type InspectionRecord struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	ReportID uint      `gorm:"index;not null" json:"report_id"` // 关联的巡检日报ID
	HostID   string    `gorm:"index;size:64;not null" json:"host_id"`
	Hostname string    `gorm:"size:255" json:"hostname"`
	Status   string    `gorm:"size:32;index" json:"status"` // online, offline, warning, critical

	// 系统信息
	OS      string    `gorm:"size:64" json:"os"`
	Arch    string    `gorm:"size:32" json:"arch"`
	Uptime  int64     `gorm:"column:uptime_seconds" json:"uptime_seconds"`  // 运行时长（秒）
	LastSeen time.Time `gorm:"column:last_seen" json:"last_seen"`      // 最后在线时间

	// 资源使用情况
	CPUUsage    float64 `json:"cpu_usage"`     // CPU使用率
	MemoryUsage float64 `json:"memory_usage"`  // 内存使用率
	DiskUsage   float64 `json:"disk_usage"`    // 磁盘使用率（根分区）
	
	// 详细指标（JSON格式）
	Metrics      string            `gorm:"type:text" json:"metrics"`      // 完整指标数据（JSON）
	Issues       StringSliceJSON   `gorm:"type:json" json:"issues"`       // 发现的问题列表
	Warnings     StringSliceJSON   `gorm:"type:json" json:"warnings"`     // 警告列表
	Recommendations StringSliceJSON `gorm:"type:json" json:"recommendations"` // 优化建议

	// 服务状态
	ServiceCount     int `json:"service_count"`        // 服务总数
	ServiceRunning   int `json:"service_running"`      // 运行中的服务数
	ServiceStopped   int `json:"service_stopped"`      // 停止的服务数
	ServiceFailed    int `json:"service_failed"`       // 失败的服务数

	// 异常和告警
	AnomalyCount     int `json:"anomaly_count"`        // 异常事件数量
	AlertCount       int `json:"alert_count"`          // 告警数量
	CriticalAlertCount int `json:"critical_alert_count"` // 严重告警数量
}

// InspectionReport 巡检日报
type InspectionReport struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`

	Date      time.Time `gorm:"type:date;uniqueIndex" json:"date"` // 巡检日期（唯一索引，每天只能有一个报告）
	StartTime time.Time `json:"start_time"`                         // 巡检开始时间
	EndTime   *time.Time `json:"end_time,omitempty"`                // 巡检结束时间
	Status    string    `gorm:"size:32;index" json:"status"`        // running, completed, failed

	// 巡检统计
	TotalHosts     int `json:"total_hosts"`        // 总主机数
	OnlineHosts    int `json:"online_hosts"`       // 在线主机数
	OfflineHosts   int `json:"offline_hosts"`      // 离线主机数
	WarningHosts   int `json:"warning_hosts"`      // 告警主机数
	CriticalHosts  int `json:"critical_hosts"`     // 严重告警主机数

	// LLM生成的日报内容
	Summary        string `gorm:"type:text" json:"summary"`         // 巡检总结
	ReportContent  string `gorm:"type:text" json:"report_content"`  // 完整日报内容（Markdown格式）
	KeyFindings    string `gorm:"type:text" json:"key_findings"`    // 关键发现
	Recommendations string `gorm:"type:text" json:"recommendations"` // 整体建议
	GeneratedBy    string `gorm:"size:64" json:"generated_by"`      // 生成者（LLM模型名称）

	// 关联的巡检记录
	Records []InspectionRecord `gorm:"foreignKey:ReportID" json:"records,omitempty"`
}
