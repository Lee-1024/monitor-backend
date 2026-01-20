// ============================================
// 文件: api/llm_task.go
// LLM异步任务管理
// ============================================
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// LLMTask LLM分析任务
type LLMTask struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // "capacity" or "cost_optimization"
	Status      string                 `json:"status"` // "pending", "processing", "completed", "failed"
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Params      map[string]interface{} `json:"params,omitempty"`
}

// LLMTaskManager LLM任务管理器
type LLMTaskManager struct {
	redis  *redis.Client
	ctx    context.Context
	prefix string
}

// NewLLMTaskManager 创建LLM任务管理器
func NewLLMTaskManager(redisClient *redis.Client) *LLMTaskManager {
	return &LLMTaskManager{
		redis:  redisClient,
		ctx:    context.Background(),
		prefix: "llm_task:",
	}
}

// NewLLMTaskManagerFromInterface 从interface{}创建LLM任务管理器
func NewLLMTaskManagerFromInterface(redisClient interface{}) *LLMTaskManager {
	if redis, ok := redisClient.(*redis.Client); ok {
		return NewLLMTaskManager(redis)
	}
	return nil
}

// CreateTask 创建任务
func (m *LLMTaskManager) CreateTask(taskType string, params map[string]interface{}) (*LLMTask, error) {
	taskID := fmt.Sprintf("%s_%d", taskType, time.Now().UnixNano())
	task := &LLMTask{
		ID:        taskID,
		Type:      taskType,
		Status:    "pending",
		CreatedAt: time.Now(),
		Params:    params,
	}

	// 保存到Redis，过期时间1小时
	taskData, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}

	key := m.prefix + taskID
	if err := m.redis.Set(m.ctx, key, taskData, time.Hour).Err(); err != nil {
		return nil, err
	}

	return task, nil
}

// GetTask 获取任务
func (m *LLMTaskManager) GetTask(taskID string) (*LLMTask, error) {
	key := m.prefix + taskID
	data, err := m.redis.Get(m.ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("task not found")
		}
		return nil, err
	}

	var task LLMTask
	if err := json.Unmarshal([]byte(data), &task); err != nil {
		return nil, err
	}

	return &task, nil
}

// UpdateTaskStatus 更新任务状态
func (m *LLMTaskManager) UpdateTaskStatus(taskID, status string, result interface{}, err error) error {
	task, err2 := m.GetTask(taskID)
	if err2 != nil {
		return err2
	}

	task.Status = status
	now := time.Now()
	if status == "completed" || status == "failed" {
		task.CompletedAt = &now
	}

	if result != nil {
		task.Result = result
	}
	if err != nil {
		task.Error = err.Error()
	}

	taskData, err2 := json.Marshal(task)
	if err2 != nil {
		return err2
	}

	key := m.prefix + taskID
	return m.redis.Set(m.ctx, key, taskData, time.Hour).Err()
}

// ProcessCapacityAnalysisTask 处理容量分析任务
func (m *LLMTaskManager) ProcessCapacityAnalysisTask(taskID string, llmClient LLMClientInterface, params map[string]interface{}) {
	// 更新状态为处理中
	m.UpdateTaskStatus(taskID, "processing", nil, nil)

	log.Printf("[LLM Task] 开始处理容量分析任务: %s, 参数: %+v", taskID, params)
	
	// 调用LLM分析
	llmResp, err := llmClient.AnalyzeCapacity(params)
	if err != nil {
		log.Printf("[LLM Task] 容量分析失败: %v", err)
		m.UpdateTaskStatus(taskID, "failed", nil, err)
		return
	}

	if llmResp == nil {
		log.Printf("[LLM Task] 警告: LLM返回的响应为nil")
		m.UpdateTaskStatus(taskID, "failed", nil, fmt.Errorf("LLM returned nil response"))
		return
	}

	log.Printf("[LLM Task] 容量分析成功，任务ID: %s", taskID)
	// 更新状态为完成
	m.UpdateTaskStatus(taskID, "completed", llmResp, nil)
}

// ProcessCostOptimizationTask 处理成本优化任务
func (m *LLMTaskManager) ProcessCostOptimizationTask(taskID string, llmClient LLMClientInterface, hostID, hostname string, predictions map[string]interface{}) {
	// 更新状态为处理中
	m.UpdateTaskStatus(taskID, "processing", nil, nil)

	// 调用LLM生成成本优化建议
	recommendation, err := llmClient.GenerateCostOptimization(hostID, hostname, predictions)
	if err != nil {
		log.Printf("LLM cost optimization failed: %v", err)
		m.UpdateTaskStatus(taskID, "failed", nil, err)
		return
	}

	// 更新状态为完成
	m.UpdateTaskStatus(taskID, "completed", recommendation, nil)
}
