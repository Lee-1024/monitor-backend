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
	GetCrashEventsWithPagination(hostID string, page, pageSize int) ([]CrashEvent, int64, error) // 分页获取宕机事件
	GetCrashEventDetail(id uint) (*CrashEvent, error)
	GetCrashAnalysis(hostID string) (*CrashAnalysis, error)
	DeleteCrashEvents(ids []uint) error // 批量删除宕机事件

	// 异常检测相关
	CreateAnomalyEvent(event *AnomalyEventInfo) error
	GetAnomalyEvents(hostID, severity, anomalyType string, isResolved *bool, limit int) ([]AnomalyEventInfo, error)
	GetAnomalyEventDetail(id uint) (*AnomalyEventInfo, error)
	ResolveAnomalyEvent(id uint, resolvedBy string) error
	GetAnomalyStatistics(hostID string) (*AnomalyStatistics, error)

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
	GetLogsWithPagination(hostID, level string, start, end time.Time, page, pageSize int) ([]LogInfo, int64, error) // 分页获取日志

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

	// 预测分析相关
	GetPredictionData(hostID, metricType string, days int) ([]PredictionDataPoint, error)

	// LLM模型配置相关
	CreateLLMModelConfig(config *LLMModelConfigInfo) (*LLMModelConfigInfo, error)
	UpdateLLMModelConfig(id uint, config *LLMModelConfigInfo) error
	DeleteLLMModelConfig(id uint) error
	GetLLMModelConfig(id uint) (*LLMModelConfigInfo, error)
	GetLLMModelConfigWithKey(id uint) (*LLMModelConfigInfo, error) // 获取完整配置（包含完整API密钥）
	GetDefaultLLMModelConfig() (*LLMModelConfigInfo, error)
	ListLLMModelConfigs(enabled *bool) ([]LLMModelConfigInfo, error)
	SetDefaultLLMModelConfig(id uint) error

	// Redis访问（用于任务管理）
	GetRedis() interface{} // 返回Redis客户端

	// 数据库访问（用于知识库等需要直接操作数据库的场景）
	GetDB() interface{} // 返回*gorm.DB
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
	ID        uint              `json:"id"`
	HostID    string            `json:"host_id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
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
	ID             uint      `json:"id"`
	HostID         string    `json:"host_id"`
	Timestamp      time.Time `json:"timestamp"`
	Name           string    `json:"name"`
	Status         string    `json:"status"`
	Enabled        bool      `json:"enabled"`
	Description    string    `json:"description"`
	Uptime         int64     `json:"uptime_seconds"`
	Port           int       `json:"port,omitempty"`            // 服务端口
	PortAccessible bool      `json:"port_accessible,omitempty"` // 端口是否可访问
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
	ResolvedCount  int            `json:"resolved_count"` // 已恢复数量
	RecentCrashes  []CrashEvent   `json:"recent_crashes"`
	CrashFrequency string         `json:"crash_frequency"`
	MainReasons    map[string]int `json:"main_reasons"`
	AvgDowntime    string         `json:"avg_downtime"`
}

// AlertRuleInfo 告警规则信息
type AlertRuleInfo struct {
	ID              uint       `json:"id"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Enabled         bool       `json:"enabled"`
	Severity        string     `json:"severity"`
	MetricType      string     `json:"metric_type"`
	HostID          string     `json:"host_id"`
	Mountpoint      string     `json:"mountpoint,omitempty"`   // 挂载点（仅用于 disk 指标）
	ServicePort     int        `json:"service_port,omitempty"` // 服务端口（仅用于 service_port 指标）
	Condition       string     `json:"condition"`
	Threshold       float64    `json:"threshold"`
	Duration        int        `json:"duration"`
	NotifyChannels  []string   `json:"notify_channels"`
	Receivers       []string   `json:"receivers"`
	SilenceStart    *time.Time `json:"silence_start,omitempty"`
	SilenceEnd      *time.Time `json:"silence_end,omitempty"`
	InhibitDuration int        `json:"inhibit_duration"` // 抑制持续时间（秒）
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

// PredictionDataPoint 预测数据点
type PredictionDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// LLMModelConfigInfo LLM模型配置信息
type LLMModelConfigInfo struct {
	ID          uint              `json:"id"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`    // openai, deepseek, qwen, doubao, zhipu, claude, custom
	APIKey      string            `json:"api_key"`     // API密钥（返回时可能隐藏部分）
	BaseURL     string            `json:"base_url"`    // API地址
	Model       string            `json:"model"`       // 模型名称
	Temperature float64           `json:"temperature"` // 温度参数
	MaxTokens   int               `json:"max_tokens"`  // 最大token数
	Timeout     int               `json:"timeout"`     // 超时时间（秒）
	Enabled     bool              `json:"enabled"`     // 是否启用
	IsDefault   bool              `json:"is_default"`  // 是否默认配置
	Description string            `json:"description"` // 描述
	Config      map[string]string `json:"config"`      // 额外配置
}

// AnomalyEventInfo 异常事件信息
type AnomalyEventInfo struct {
	ID              uint                   `json:"id"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	HostID          string                 `json:"host_id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	MetricType      string                 `json:"metric_type,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	Value           float64                `json:"value"`
	ExpectedValue   float64                `json:"expected_value,omitempty"`
	Deviation       float64                `json:"deviation"`
	Confidence      float64                `json:"confidence"`
	Message         string                 `json:"message"`
	RootCause       string                 `json:"root_cause,omitempty"`
	RelatedLogs     []LogInfo              `json:"related_logs,omitempty"`
	RelatedMetrics  map[string]interface{} `json:"related_metrics,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
	IsResolved      bool                   `json:"is_resolved"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy      string                 `json:"resolved_by,omitempty"`
}

// AnomalyStatistics 异常统计
type AnomalyStatistics struct {
	TotalAnomalies  int                `json:"total_anomalies"`
	UnresolvedCount int                `json:"unresolved_count"`
	BySeverity      map[string]int     `json:"by_severity"`
	ByType          map[string]int     `json:"by_type"`
	RecentAnomalies []AnomalyEventInfo `json:"recent_anomalies"`
}
