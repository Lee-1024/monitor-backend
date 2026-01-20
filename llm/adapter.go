// ============================================
// 文件: llm/adapter.go
// ============================================
package llm

import (
	"fmt"
)

// LLMClientAdapter LLM客户端适配器，实现api.LLMClientInterface
type LLMClientAdapter struct {
	client *LLMClient
}

// NewLLMClientAdapter 创建LLM客户端适配器
func NewLLMClientAdapter(config LLMConfig) *LLMClientAdapter {
	return &LLMClientAdapter{
		client: NewLLMClient(config),
	}
}

// AnalyzeCapacity 实现api.LLMClientInterface
func (a *LLMClientAdapter) AnalyzeCapacity(req interface{}) (interface{}, error) {
	// 类型断言
	apiReq, ok := req.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request type")
	}

	llmReq := AnalysisRequest{
		ResourceType:    getString(apiReq, "ResourceType"),
		HostID:          getString(apiReq, "HostID"),
		Hostname:        getString(apiReq, "Hostname"),
		CurrentUsage:    getFloat64(apiReq, "CurrentUsage"),
		PredictedUsage:  getFloat64(apiReq, "PredictedUsage"),
		DaysToThreshold: getFloat64(apiReq, "DaysToThreshold"),
		Trend:           getString(apiReq, "Trend"),
	}

	return a.client.AnalyzeCapacity(llmReq)
}

// GenerateCostOptimization 实现api.LLMClientInterface
func (a *LLMClientAdapter) GenerateCostOptimization(hostID, hostname string, predictions map[string]interface{}) (string, error) {
	return a.client.GenerateCostOptimization(hostID, hostname, predictions)
}

// GetClient 获取内部的LLMClient（用于流式输出）
func (a *LLMClientAdapter) GetClient() *LLMClient {
	return a.client
}

// 辅助函数
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getFloat64(m map[string]interface{}, key string) float64 {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
	}
	return 0
}
