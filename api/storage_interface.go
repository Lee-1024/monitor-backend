// ============================================
// 文件: api/storage_interface.go
// ============================================
package api

import "time"

// StorageInterface 存储接口
type StorageInterface interface {
	// Agent相关
	ListAgents(status string, page, pageSize int) ([]AgentInfo, int64, error)
	GetAgent(hostID string) (*AgentInfo, error)
	GetAgentStatus(hostID string) (string, error)
	DeleteAgent(hostID string) error

	// 指标相关
	GetMetrics(hostID, metricType, start, end string) ([]MetricPoint, error)
	GetLatestMetrics(hostID string) (*LatestMetrics, error)
	GetHistoryMetrics(hostID, metricType, start, end, interval string) ([]MetricPoint, error)
	GetDiskHistoryByMountpoint(hostID, mountpoint, start, end, interval string) ([]MetricPoint, error)
	GetAggregateMetrics(metricType, aggregation, start, end string) ([]AggregateMetric, error)

	// 统计相关
	GetOverview() (*Overview, error)
	GetTopMetrics(metricType string, limit int, order string) ([]TopMetric, error)

	// 宕机分析相关（新增）
	GetCrashEvents(hostID string, limit int) ([]CrashEvent, error)
	GetCrashEventDetail(id uint) (*CrashEvent, error)
	GetCrashAnalysis(hostID string) (*CrashAnalysis, error)

	// 用户管理相关
	CreateUser(username, email, password, role string) (*UserInfo, error)
	GetUserByID(id uint) (*UserInfo, error)
	GetUserByUsername(username string) (*UserInfo, string, error) // 返回用户信息和密码哈希
	GetUserByEmail(email string) (*UserInfo, error)
	ListUsers(page, pageSize int) ([]UserInfo, int64, error)
	UpdateUser(id uint, email, role, status string) error
	UpdateUserPassword(id uint, newPassword string) error
	UpdateUserLastLogin(id uint) error
	DeleteUser(id uint) error

	// 进程监控相关
	GetProcesses(hostID string, limit int) ([]ProcessInfo, error)
	GetProcessHistory(hostID string, processNames []string, start, end time.Time, limit int) ([]ProcessHistoryPoint, error)
	GetTopProcessNamesByHistory(hostID string, start, end time.Time, metricType string, topN int) ([]string, error)
	
	// 日志相关
	GetLogs(hostID, level string, start, end time.Time, limit int) ([]LogInfo, error)
	
	// 脚本执行相关
	GetScriptExecutions(hostID, scriptID string, limit int) ([]ScriptExecutionInfo, error)
	
	// 服务状态相关
	GetServiceStatus(hostID string) ([]ServiceInfo, error)

	// 告警规则相关
	CreateAlertRule(rule *AlertRuleInfo) (*AlertRuleInfo, error)
	UpdateAlertRule(id uint, rule *AlertRuleInfo) error
	DeleteAlertRule(id uint) error
	GetAlertRule(id uint) (*AlertRuleInfo, error)
	ListAlertRules(enabled *bool) ([]AlertRuleInfo, error)

	// 告警历史相关
	CreateAlertHistory(history *AlertHistoryInfo) (*AlertHistoryInfo, error)
	UpdateAlertHistory(id uint, status string, resolvedAt *time.Time) error
	UpdateAlertHistoryFiredAt(id uint, firedAt time.Time) error
	UpdateAlertHistoryNotifyStatus(id uint, notifyStatus string, notifyError string) error
	UpdateAlertHistoryMetricValue(id uint, metricValue float64, message string) error
	ListAlertHistory(ruleID *uint, hostID string, status string, limit int) ([]AlertHistoryInfo, error)
	GetAlertHistory(id uint) (*AlertHistoryInfo, error)
	DeleteAlertHistory(id uint) error
	DeleteAlertHistories(ids []uint) error

	// 告警静默相关
	CreateAlertSilence(silence *AlertSilenceInfo) (*AlertSilenceInfo, error)
	UpdateAlertSilence(id uint, silence *AlertSilenceInfo) error
	DeleteAlertSilence(id uint) error
	GetAlertSilence(id uint) (*AlertSilenceInfo, error)
	ListAlertSilences(enabled *bool) ([]AlertSilenceInfo, error)
	IsRuleSilenced(ruleID uint, hostID string) bool

	// 通知渠道相关
	CreateNotificationChannel(channel *NotificationChannelInfo) (*NotificationChannelInfo, error)
	UpdateNotificationChannel(id uint, channel *NotificationChannelInfo) error
	DeleteNotificationChannel(id uint) error
	GetNotificationChannel(id uint) (*NotificationChannelInfo, error)
	GetNotificationChannelByType(channelType string) (*NotificationChannelInfo, error)
	ListNotificationChannels(enabled *bool) ([]NotificationChannelInfo, error)
}

// ProcessHistoryPoint 进程历史数据点
type ProcessHistoryPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	ProcessName   string    `json:"process_name"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	MemoryBytes   uint64    `json:"memory_bytes"`
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	ID            uint      `json:"id"`
	HostID        string    `json:"host_id"`
	Timestamp     time.Time `json:"timestamp"`
	PID           int32     `json:"pid"`
	Name          string    `json:"name"`
	User          string    `json:"user"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	MemoryBytes   uint64    `json:"memory_bytes"`
	Status        string    `json:"status"`
	Command       string    `json:"command"`
}

// LogInfo 日志信息
type LogInfo struct {
	ID        uint      `json:"id"`
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Tags      map[string]string `json:"tags"`
}

// ScriptExecutionInfo 脚本执行信息
type ScriptExecutionInfo struct {
	ID         uint      `json:"id"`
	HostID     string    `json:"host_id"`
	ScriptID   string    `json:"script_id"`
	ScriptName string    `json:"script_name"`
	Timestamp  time.Time `json:"timestamp"`
	Success    bool      `json:"success"`
	Output     string    `json:"output"`
	Error      string    `json:"error"`
	ExitCode   int       `json:"exit_code"`
	Duration   int64     `json:"duration_ms"`
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	ID          uint      `json:"id"`
	HostID      string    `json:"host_id"`
	Timestamp   time.Time `json:"timestamp"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description"`
	Uptime      int64     `json:"uptime_seconds"`
}

// AgentInfo Agent信息
type AgentInfo struct {
	HostID    string            `json:"host_id"`
	Hostname  string            `json:"hostname"`
	IP        string            `json:"ip"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	Tags      map[string]string `json:"tags"`
	Status    string            `json:"status"`
	LastSeen  time.Time         `json:"last_seen"`
	CreatedAt time.Time         `json:"created_at"`
}

// MetricPoint 指标数据点
type MetricPoint struct {
	Timestamp time.Time              `json:"timestamp"`
	Values    map[string]interface{} `json:"values"`
}

// LatestMetrics 最新指标
type LatestMetrics struct {
	HostID    string                 `json:"host_id"`
	Timestamp time.Time              `json:"timestamp"`
	CPU       map[string]interface{} `json:"cpu"`
	Memory    map[string]interface{} `json:"memory"`
	Disk      map[string]interface{} `json:"disk"`
	Network   map[string]interface{} `json:"network"`
}

// AggregateMetric 聚合指标
type AggregateMetric struct {
	HostID string                 `json:"host_id"`
	Values map[string]interface{} `json:"values"`
}

// Overview 概览统计
type Overview struct {
	TotalAgents   int64   `json:"total_agents"`
	OnlineAgents  int64   `json:"online_agents"`
	OfflineAgents int64   `json:"offline_agents"`
	AvgCPU        float64 `json:"avg_cpu"`
	AvgMemory     float64 `json:"avg_memory"`
	TotalMetrics  int64   `json:"total_metrics"`
}

// TopMetric Top指标
type TopMetric struct {
	HostID   string  `json:"host_id"`
	Hostname string  `json:"hostname"`
	Value    float64 `json:"value"`
}

// CrashEvent 宕机事件
type CrashEvent struct {
	ID              uint       `json:"id"`
	HostID          string     `json:"host_id"`
	Hostname        string     `json:"hostname"`
	OfflineTime     time.Time  `json:"offline_time"`
	OnlineTime      *time.Time `json:"online_time,omitempty"`
	Duration        int64      `json:"duration"`
	LastCPU         float64    `json:"last_cpu"`
	LastMemory      float64    `json:"last_memory"`
	LastDisk        float64    `json:"last_disk"`
	LastNetwork     string     `json:"last_network"`
	Reason          string     `json:"reason"`
	IsResolved      bool       `json:"is_resolved"`
	MetricsSnapshot string     `json:"metrics_snapshot"`
}

// CrashAnalysis 宕机分析
type CrashAnalysis struct {
	TotalCrashes   int            `json:"total_crashes"`
	ResolvedCount  int            `json:"resolved_count"`  // 已恢复数量
	RecentCrashes  []CrashEvent   `json:"recent_crashes"`
	CrashFrequency string         `json:"crash_frequency"`
	MainReasons    map[string]int `json:"main_reasons"`
	AvgDowntime    string         `json:"avg_downtime"`
}

// AlertRuleInfo 告警规则信息
type AlertRuleInfo struct {
	ID             uint       `json:"id"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Enabled        bool       `json:"enabled"`
	Severity       string     `json:"severity"`
	MetricType     string     `json:"metric_type"`
	HostID         string     `json:"host_id"`
	Condition      string     `json:"condition"`
	Threshold      float64    `json:"threshold"`
	Duration       int        `json:"duration"`
	NotifyChannels []string   `json:"notify_channels"`
	Receivers      []string   `json:"receivers"`
	SilenceStart   *time.Time `json:"silence_start,omitempty"`
	SilenceEnd     *time.Time `json:"silence_end,omitempty"`
	InhibitDuration int       `json:"inhibit_duration"` // 抑制持续时间（秒）
}

// AlertHistoryInfo 告警历史信息
type AlertHistoryInfo struct {
	ID           uint              `json:"id"`
	CreatedAt    time.Time         `json:"created_at"`
	RuleID       uint              `json:"rule_id"`
	RuleName     string            `json:"rule_name"`
	HostID       string            `json:"host_id"`
	Hostname     string            `json:"hostname"`
	Severity     string            `json:"severity"`
	Status       string            `json:"status"`
	FiredAt      time.Time         `json:"fired_at"`
	ResolvedAt   *time.Time        `json:"resolved_at,omitempty"`
	MetricType   string            `json:"metric_type"`
	MetricValue  float64           `json:"metric_value"`
	Threshold    float64           `json:"threshold"`
	Message      string            `json:"message"`
	Labels       map[string]string `json:"labels"`
	NotifyStatus string            `json:"notify_status"`
	NotifyError  string            `json:"notify_error,omitempty"`
}

// AlertSilenceInfo 告警静默信息
type AlertSilenceInfo struct {
	ID        uint      `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
	RuleIDs   []uint    `json:"rule_ids"`
	HostIDs   []string  `json:"host_ids"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Enabled   bool      `json:"enabled"`
	Comment   string    `json:"comment"`
	Creator   string    `json:"creator"`
}

// NotificationChannelInfo 通知渠道信息
type NotificationChannelInfo struct {
	ID          uint              `json:"id"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config"`
	Description string            `json:"description"`
}
