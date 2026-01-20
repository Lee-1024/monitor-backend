// ============================================
// 文件: llm/manager.go
// ============================================
package llm

import (
	"log"
	"monitor-backend/api"
)

// LLMManager LLM管理器，动态从数据库加载配置
type LLMManager struct {
	storage api.StorageInterface
	client  api.LLMClientInterface
}

// NewLLMManager 创建LLM管理器
func NewLLMManager(storage api.StorageInterface) *LLMManager {
	manager := &LLMManager{
		storage: storage,
	}
	
	// 初始化时加载默认配置
	manager.loadDefaultConfig()
	
	return manager
}

// GetClient 获取LLM客户端（如果已启用）
func (m *LLMManager) GetClient() api.LLMClientInterface {
	return m.client
}

// loadDefaultConfig 加载默认配置
func (m *LLMManager) loadDefaultConfig() {
	config, err := m.storage.GetDefaultLLMModelConfig()
	if err != nil {
		log.Printf("Failed to get default LLM config: %v, LLM features will be disabled", err)
		m.client = nil
		return
	}

	if config == nil {
		log.Printf("No default LLM config found, LLM features will be disabled")
		m.client = nil
		return
	}

	if !config.Enabled {
		log.Printf("Default LLM config is disabled")
		m.client = nil
		return
	}

	// 创建LLM客户端
	llmConfig := LLMConfig{
		Provider:    LLMProvider(config.Provider),
		APIKey:      config.APIKey,
		BaseURL:     config.BaseURL,
		Model:       config.Model,
		Temperature: config.Temperature,
		MaxTokens:   config.MaxTokens,
		Timeout:     config.Timeout,
		Enabled:     config.Enabled,
	}

	m.client = NewLLMClientAdapter(llmConfig)
	log.Printf("LLM client loaded: %s (%s)", config.Name, config.Provider)
}

// Reload 重新加载配置（当配置更新时调用）
func (m *LLMManager) Reload() {
	m.loadDefaultConfig()
}
