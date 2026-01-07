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
	DeleteAgent(hostID string) error

	// 指标相关
	GetMetrics(hostID, metricType, start, end string) ([]MetricPoint, error)
	GetLatestMetrics(hostID string) (*LatestMetrics, error)
	GetHistoryMetrics(hostID, metricType, start, end, interval string) ([]MetricPoint, error)
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
