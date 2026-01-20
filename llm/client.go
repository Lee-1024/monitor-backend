// ============================================
// 文件: llm/client.go
// ============================================
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// LLMProvider LLM提供商类型
type LLMProvider string

const (
	ProviderOpenAI   LLMProvider = "openai"
	ProviderClaude   LLMProvider = "claude"
	ProviderDeepSeek LLMProvider = "deepseek"
	ProviderQwen     LLMProvider = "qwen"   // 阿里千问
	ProviderDoubao   LLMProvider = "doubao" // 豆包
	ProviderZhipu    LLMProvider = "zhipu"  // 智普
	ProviderCustom   LLMProvider = "custom"
)

// LLMConfig LLM配置
type LLMConfig struct {
	Provider    LLMProvider `yaml:"provider"`
	APIKey      string      `yaml:"api_key"`
	BaseURL     string      `yaml:"base_url"`    // 自定义API地址
	Model       string      `yaml:"model"`       // 模型名称
	Temperature float64     `yaml:"temperature"` // 温度参数
	MaxTokens   int         `yaml:"max_tokens"`  // 最大token数
	Timeout     int         `yaml:"timeout"`     // 超时时间（秒）
	Enabled     bool        `yaml:"enabled"`     // 是否启用
}

// LLMClient LLM客户端
type LLMClient struct {
	config LLMConfig
	client *http.Client
}

// NewLLMClient 创建LLM客户端
func NewLLMClient(config LLMConfig) *LLMClient {
	timeout := time.Duration(config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &LLMClient{
		config: config,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// AnalysisRequest 分析请求
type AnalysisRequest struct {
	ResourceType    string                   `json:"resource_type"` // cpu, memory, disk
	HostID          string                   `json:"host_id"`
	Hostname        string                   `json:"hostname"`
	CurrentUsage    float64                  `json:"current_usage"`
	PredictedUsage  float64                  `json:"predicted_usage"`
	DaysToThreshold float64                  `json:"days_to_threshold"`
	Trend           string                   `json:"trend"`
	HistoricalData  []map[string]interface{} `json:"historical_data,omitempty"`
	Context         map[string]interface{}   `json:"context,omitempty"`
}

// AnalysisResponse 分析响应
type AnalysisResponse struct {
	Summary          string   `json:"summary"`                     // 摘要
	Analysis         string   `json:"analysis"`                    // 详细分析
	Recommendations  []string `json:"recommendations"`             // 建议列表
	CostOptimization string   `json:"cost_optimization,omitempty"` // 成本优化建议
	Risks            []string `json:"risks,omitempty"`             // 风险提示
}

// TestConnection 测试LLM连接
func (c *LLMClient) TestConnection() (string, error) {
	testPrompt := "这是一个连接测试。请回复'测试成功'以确认连接正常。"

	var response *AnalysisResponse
	var err error

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek:
		response, err = c.callOpenAICompatible(testPrompt)
	case ProviderClaude:
		response, err = c.callClaude(testPrompt)
	case ProviderQwen:
		response, err = c.callQwen(testPrompt)
	case ProviderDoubao:
		response, err = c.callDoubao(testPrompt)
	case ProviderZhipu:
		response, err = c.callZhipu(testPrompt)
	case ProviderCustom:
		response, err = c.callCustom(testPrompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s", c.config.Provider)
	}

	if err != nil {
		return "", fmt.Errorf("LLM API call failed: %v", err)
	}

	if response == nil {
		return "", fmt.Errorf("no response received")
	}

	// 提取响应内容
	responseText := response.Analysis
	if responseText == "" {
		responseText = response.Summary
	}
	if responseText == "" && len(response.Recommendations) > 0 {
		responseText = response.Recommendations[0]
	}
	if responseText == "" {
		responseText = "连接成功，但未收到有效响应内容"
	}

	return responseText, nil
}

// AnalyzeCapacity 分析容量规划
func (c *LLMClient) AnalyzeCapacity(req AnalysisRequest) (*AnalysisResponse, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM] 开始容量分析，Provider: %s, Model: %s", c.config.Provider, c.config.Model)
	prompt := c.buildCapacityAnalysisPrompt(req)
	log.Printf("[LLM] 提示词长度: %d 字符", len(prompt))

	var response *AnalysisResponse
	var err error

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek:
		// DeepSeek使用OpenAI兼容的API格式
		log.Printf("[LLM] 调用OpenAI兼容API")
		response, err = c.callOpenAICompatible(prompt)
	case ProviderClaude:
		log.Printf("[LLM] 调用Claude API")
		response, err = c.callClaude(prompt)
	case ProviderQwen:
		log.Printf("[LLM] 调用Qwen API")
		response, err = c.callQwen(prompt)
	case ProviderDoubao:
		log.Printf("[LLM] 调用Doubao API")
		response, err = c.callDoubao(prompt)
	case ProviderZhipu:
		log.Printf("[LLM] 调用Zhipu API")
		response, err = c.callZhipu(prompt)
	case ProviderCustom:
		log.Printf("[LLM] 调用Custom API")
		response, err = c.callCustom(prompt)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", c.config.Provider)
	}

	if err != nil {
		log.Printf("[LLM] API调用失败: %v", err)
		return nil, fmt.Errorf("LLM API call failed: %v", err)
	}

	if response == nil {
		log.Printf("[LLM] 警告: API返回的响应为nil")
		return nil, fmt.Errorf("LLM API returned nil response")
	}

	log.Printf("[LLM] API调用成功，返回响应")
	return response, nil
}

// buildCapacityAnalysisPrompt 构建容量分析提示词
func (c *LLMClient) buildCapacityAnalysisPrompt(req AnalysisRequest) string {
	// 对主机名进行特殊处理，确保特殊字符不会被误解析
	hostname := req.Hostname
	if hostname == "" {
		hostname = req.HostID
	}

	prompt := fmt.Sprintf(`你是一个专业的运维和容量规划专家。请基于以下信息提供详细的容量分析和建议：

资源类型：%s
主机ID：%s
主机名：%s
当前使用率：%.2f%%
预测使用率：%.2f%%
达到阈值所需天数：%.1f天
趋势：%s

请按照以下格式提供详细的分析报告：

## 摘要
（用1-2句话总结当前资源使用情况和主要发现）

## 详细分析
（包括以下内容：
- 当前资源使用状态分析
- 资源使用趋势分析（上升/下降/稳定）
- 预测数据解读（预测使用率、达到阈值的时间）
- 潜在问题和瓶颈分析
- 历史数据对比（如果有的话）
）

## 建议
（提供3-5条具体、可操作的建议，每条建议用数字编号，例如：
1. 建议内容1
2. 建议内容2
3. 建议内容3
）

## 成本优化建议
（提供具体的成本优化方案，包括：
- 是否可以降配或升级
- 资源利用率优化建议
- 预计可以节省的成本
- 实施建议和时间安排
）

## 风险提示
（列出需要注意的风险点，例如：
- 资源不足的风险
- 性能下降的风险
- 业务影响的风险
）

请用中文回答，回答要专业、详细、可操作。每个部分都要有实质性内容，不要使用占位符或通用性描述。

注意：主机名可能包含特殊字符（如连字符、点号等），请完整显示主机名，不要截断。`,
		req.ResourceType, req.HostID, hostname, req.CurrentUsage, req.PredictedUsage,
		req.DaysToThreshold, req.Trend)

	return prompt
}

// callOpenAICompatible 调用OpenAI兼容的API（OpenAI、DeepSeek等）
func (c *LLMClient) callOpenAICompatible(prompt string) (*AnalysisResponse, error) {
	url := "https://api.openai.com/v1/chat/completions"
	if c.config.Provider == ProviderDeepSeek {
		url = "https://api.deepseek.com/v1/chat/completions"
	}
	if c.config.BaseURL != "" {
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		model = "gpt-3.5-turbo"
	}

	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": c.config.Temperature,
		"max_tokens":  c.config.MaxTokens,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OpenAI API error: %s, body: %s", resp.Status, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		log.Printf("[LLM] OpenAI API返回的choices为空")
		return nil, fmt.Errorf("no response from OpenAI")
	}

	content := result.Choices[0].Message.Content
	log.Printf("[LLM] OpenAI API返回内容长度: %d 字符", len(content))
	if len(content) == 0 {
		log.Printf("[LLM] 警告: OpenAI API返回的内容为空")
		return nil, fmt.Errorf("OpenAI API returned empty content")
	}
	return c.parseLLMResponse(content), nil
}

// callClaude 调用Claude API
func (c *LLMClient) callClaude(prompt string) (*AnalysisResponse, error) {
	url := "https://api.anthropic.com/v1/messages"
	if c.config.BaseURL != "" {
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		model = "claude-3-sonnet-20240229"
	}

	requestBody := map[string]interface{}{
		"model":      model,
		"max_tokens": c.config.MaxTokens,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Claude API error: %s, body: %s", resp.Status, string(body))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no response from Claude")
	}

	content := result.Content[0].Text
	return c.parseLLMResponse(content), nil
}

// callCustom 调用自定义API
// 默认使用OpenAI兼容格式，如果URL包含/v1/chat/completions则使用OpenAI格式
// 否则尝试简单格式
func (c *LLMClient) callCustom(prompt string) (*AnalysisResponse, error) {
	url := strings.TrimSpace(c.config.BaseURL)
	if url == "" {
		return nil, fmt.Errorf("custom API base_url is required")
	}

	log.Printf("[LLM] ========== 开始调用自定义API ==========")
	log.Printf("[LLM] API地址: %s", url)
	log.Printf("[LLM] 模型: %s", c.config.Model)
	log.Printf("[LLM] API Key长度: %d", len(c.config.APIKey))
	log.Printf("[LLM] Temperature: %f", c.config.Temperature)
	log.Printf("[LLM] Max Tokens: %d", c.config.MaxTokens)

	var requestBody map[string]interface{}
	var result struct {
		// OpenAI兼容格式
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		// 简单格式
		Content  string `json:"content"`
		Text     string `json:"text"`
		Response string `json:"response"`
	}

	// 判断是否使用OpenAI兼容格式（URL包含chat/completions或提供了model）
	useOpenAIFormat := strings.Contains(url, "chat/completions") || c.config.Model != ""
	log.Printf("[LLM] 格式检测: useOpenAIFormat=%v (URL包含chat/completions: %v, 有model: %v)",
		useOpenAIFormat, strings.Contains(url, "chat/completions"), c.config.Model != "")

	if useOpenAIFormat {
		// 使用OpenAI兼容格式
		model := c.config.Model
		if model == "" {
			model = "gpt-3.5-turbo" // 默认模型
		}
		log.Printf("[LLM] 使用OpenAI兼容格式，模型: %s", model)
		requestBody = map[string]interface{}{
			"model": model,
			"messages": []map[string]string{
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"temperature": c.config.Temperature,
			"max_tokens":  c.config.MaxTokens,
		}
	} else {
		// 使用简单格式
		log.Printf("[LLM] 使用简单格式")
		requestBody = map[string]interface{}{
			"prompt":      prompt,
			"temperature": c.config.Temperature,
			"max_tokens":  c.config.MaxTokens,
		}
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[LLM] 错误: JSON序列化失败: %v", err)
		return nil, fmt.Errorf("JSON序列化失败: %v", err)
	}

	log.Printf("[LLM] 请求体大小: %d 字节", len(jsonData))
	if len(jsonData) < 500 {
		log.Printf("[LLM] 请求体内容: %s", string(jsonData))
	} else {
		log.Printf("[LLM] 请求体内容(前500字符): %s", string(jsonData[:500]))
	}

	log.Printf("[LLM] 创建HTTP请求...")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[LLM] 错误: 创建请求失败: %v", err)
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	log.Printf("[LLM] HTTP请求创建成功")

	req.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		authHeader := "Bearer " + c.config.APIKey
		req.Header.Set("Authorization", authHeader)
		log.Printf("[LLM] 已设置Authorization头 (长度: %d)", len(authHeader))
	} else {
		log.Printf("[LLM] 警告: 未设置API Key")
	}

	log.Printf("[LLM] 发送HTTP请求到: %s", url)
	log.Printf("[LLM] 请求头: Content-Type=%s, Authorization=%v",
		req.Header.Get("Content-Type"), req.Header.Get("Authorization") != "")

	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("[LLM] 错误: HTTP请求执行失败: %v", err)
		return nil, fmt.Errorf("API请求失败: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("[LLM] HTTP响应状态: %s (状态码: %d)", resp.Status, resp.StatusCode)
	log.Printf("[LLM] 响应头: %+v", resp.Header)

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Printf("[LLM] 错误: 读取响应体失败: %v", readErr)
		return nil, fmt.Errorf("读取响应体失败: %v", readErr)
	}

	log.Printf("[LLM] 响应体大小: %d 字节", len(bodyBytes))
	if len(bodyBytes) < 1000 {
		log.Printf("[LLM] 响应体内容: %s", string(bodyBytes))
	} else {
		log.Printf("[LLM] 响应体内容(前1000字符): %s", string(bodyBytes[:1000]))
		log.Printf("[LLM] 响应体内容(后500字符): %s", string(bodyBytes[len(bodyBytes)-500:]))
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[LLM] 错误: API返回非200状态码: %d", resp.StatusCode)
		log.Printf("[LLM] 完整错误响应: %s", string(bodyBytes))
		return nil, fmt.Errorf("API返回错误: %s (状态码: %d), 响应: %s", resp.Status, resp.StatusCode, string(bodyBytes))
	}

	log.Printf("[LLM] 开始解析响应JSON...")
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		log.Printf("[LLM] 错误: JSON解析失败: %v", err)
		log.Printf("[LLM] 尝试解析的响应体: %s", string(bodyBytes))
		return nil, fmt.Errorf("解析响应失败: %v, 响应体: %s", err, string(bodyBytes))
	}
	log.Printf("[LLM] JSON解析成功")

	// 优先使用OpenAI格式的响应
	var content string
	if useOpenAIFormat && len(result.Choices) > 0 {
		content = result.Choices[0].Message.Content
		log.Printf("[LLM] 从OpenAI格式响应中提取内容，choices数量: %d, 内容长度: %d",
			len(result.Choices), len(content))
	} else {
		// 尝试简单格式
		content = result.Content
		if content == "" {
			content = result.Text
		}
		if content == "" {
			content = result.Response
		}
		log.Printf("[LLM] 从简单格式响应中提取内容，Content长度: %d, Text长度: %d, Response长度: %d",
			len(result.Content), len(result.Text), len(result.Response))
	}

	if content == "" {
		log.Printf("[LLM] 错误: API响应中未找到内容")
		log.Printf("[LLM] 完整响应结构: Choices数量=%d, Content=%v, Text=%v, Response=%v",
			len(result.Choices), result.Content != "", result.Text != "", result.Response != "")
		return nil, fmt.Errorf("API响应中未找到内容，响应体: %s", string(bodyBytes))
	}

	log.Printf("[LLM] 成功提取内容，长度: %d 字符", len(content))
	log.Printf("[LLM] ========== 自定义API调用完成 ==========")

	return c.parseLLMResponse(content), nil
}

// callQwen 调用阿里千问API
func (c *LLMClient) callQwen(prompt string) (*AnalysisResponse, error) {
	url := "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
	if c.config.BaseURL != "" {
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		model = "qwen-turbo"
	}

	requestBody := map[string]interface{}{
		"model": model,
		"input": map[string]interface{}{
			"messages": []map[string]interface{}{
				{
					"role":    "user",
					"content": prompt,
				},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": c.config.Temperature,
			"max_tokens":  c.config.MaxTokens,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Qwen API error: %s, body: %s", resp.Status, string(body))
	}

	var result struct {
		Output struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Output.Choices) == 0 {
		return nil, fmt.Errorf("no response from Qwen")
	}

	content := result.Output.Choices[0].Message.Content
	return c.parseLLMResponse(content), nil
}

// callDoubao 调用豆包API
func (c *LLMClient) callDoubao(prompt string) (*AnalysisResponse, error) {
	url := "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
	if c.config.BaseURL != "" {
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		model = "doubao-pro-32k"
	}

	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": c.config.Temperature,
		"max_tokens":  c.config.MaxTokens,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Doubao API error: %s, body: %s", resp.Status, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from Doubao")
	}

	content := result.Choices[0].Message.Content
	return c.parseLLMResponse(content), nil
}

// callZhipu 调用智普API
func (c *LLMClient) callZhipu(prompt string) (*AnalysisResponse, error) {
	url := "https://open.bigmodel.cn/api/paas/v4/chat/completions"
	if c.config.BaseURL != "" {
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		model = "glm-4"
	}

	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": c.config.Temperature,
		"max_tokens":  c.config.MaxTokens,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	log.Printf("[LLM] Zhipu API 发送请求...")
	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("[LLM] Zhipu API 请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("[LLM] Zhipu API 响应状态码: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[LLM] Zhipu API 错误响应: %s", string(body))
		return nil, fmt.Errorf("Zhipu API error: %s, body: %s", resp.Status, string(body))
	}

	// 读取完整响应体用于调试
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[LLM] Zhipu API 读取响应体失败: %v", err)
		return nil, err
	}

	log.Printf("[LLM] Zhipu API 响应体长度: %d 字节", len(bodyBytes))
	if len(bodyBytes) > 500 {
		// 按rune截取，避免中文乱码
		bodyStr := string(bodyBytes)
		bodyRunes := []rune(bodyStr)
		if len(bodyRunes) > 500 {
			log.Printf("[LLM] Zhipu API 响应体前500字符: %s", string(bodyRunes[:500]))
			log.Printf("[LLM] Zhipu API 响应体后500字符: %s", string(bodyRunes[len(bodyRunes)-500:]))
		} else {
			log.Printf("[LLM] Zhipu API 响应体: %s", bodyStr)
		}
	} else {
		log.Printf("[LLM] Zhipu API 响应体: %s", string(bodyBytes))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"` // GLM-4.5-flash模型的推理内容
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}

	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		log.Printf("[LLM] Zhipu API 响应解析失败: %v, 原始响应: %s", err, string(bodyBytes))
		return nil, err
	}

	if result.Error.Message != "" {
		log.Printf("[LLM] Zhipu API 返回错误: %s (类型: %s)", result.Error.Message, result.Error.Type)
		return nil, fmt.Errorf("Zhipu API error: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		log.Printf("[LLM] Zhipu API 返回的choices为空，完整响应: %s", string(bodyBytes))
		return nil, fmt.Errorf("no response from Zhipu")
	}

	// GLM-4.5-flash模型可能将内容放在reasoning_content字段中
	content := result.Choices[0].Message.Content
	reasoningContent := result.Choices[0].Message.ReasoningContent

	// 优先使用reasoning_content，如果为空则使用content
	if reasoningContent != "" {
		log.Printf("[LLM] Zhipu API 使用reasoning_content，长度: %d 字符", len(reasoningContent))
		content = reasoningContent
	} else {
		log.Printf("[LLM] Zhipu API 使用content，长度: %d 字符", len(content))
	}

	if len(content) == 0 {
		log.Printf("[LLM] 警告: Zhipu API 返回的内容为空，完整响应: %s", string(bodyBytes))
		return nil, fmt.Errorf("Zhipu API returned empty content")
	}
	return c.parseLLMResponse(content), nil
}

// parseLLMResponse 解析LLM响应
// 尝试从文本中提取结构化信息
func (c *LLMClient) parseLLMResponse(content string) *AnalysisResponse {
	// 记录原始内容用于调试
	log.Printf("[LLM] 原始响应内容长度: %d 字符", len(content))
	if len(content) > 500 {
		// 按rune截取，避免中文乱码
		contentRunes := []rune(content)
		if len(contentRunes) > 500 {
			log.Printf("[LLM] 原始响应内容前500字符: %s", string(contentRunes[:500]))
			log.Printf("[LLM] 原始响应内容后500字符: %s", string(contentRunes[len(contentRunes)-500:]))
		} else {
			log.Printf("[LLM] 原始响应内容: %s", content)
		}
	} else {
		log.Printf("[LLM] 原始响应内容: %s", content)
	}

	// 尝试解析为JSON
	var response AnalysisResponse
	if err := json.Unmarshal([]byte(content), &response); err == nil {
		// 验证JSON响应是否完整
		if response.Summary != "" || response.Analysis != "" {
			log.Printf("[LLM] 成功解析为JSON格式")
			return &response
		}
		log.Printf("[LLM] JSON格式但内容为空，继续文本解析")
	}

	// 如果不是JSON，尝试从文本中提取结构化信息
	log.Printf("[LLM] 开始文本解析")
	response = AnalysisResponse{}

	// 按行分割内容
	lines := strings.Split(content, "\n")
	var currentSection string
	var summaryBuilder, analysisBuilder, costBuilder strings.Builder
	var recommendations []string
	var risks []string

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// 跳过完全空的行，但保留有空格的行（可能是格式化的空行）
		if trimmedLine == "" {
			// 如果当前有章节，添加换行
			if currentSection != "" {
				switch currentSection {
				case "analysis":
					if analysisBuilder.Len() > 0 {
						analysisBuilder.WriteString("\n")
					}
				case "cost":
					if costBuilder.Len() > 0 {
						costBuilder.WriteString("\n")
					}
				}
			}
			continue
		}

		// 检测章节标题 - 优先检测 ## 开头的Markdown标题
		lowerLine := strings.ToLower(trimmedLine)
		isMarkdownTitle := strings.HasPrefix(trimmedLine, "##") || strings.HasPrefix(trimmedLine, "#")

		// 如果是以 ## 开头的标题，提取标题文本（去除 # 和空格）
		var titleText string
		if isMarkdownTitle {
			// 移除 # 号
			titleText = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmedLine, "##"), "#"))
			lowerLine = strings.ToLower(titleText)
		}

		// 摘要部分
		if strings.Contains(lowerLine, "摘要") || strings.Contains(lowerLine, "summary") ||
			strings.Contains(lowerLine, "概述") || strings.Contains(lowerLine, "总结") {
			currentSection = "summary"
			// 如果标题行本身有内容（去除标题标记后），也加入摘要
			if titleText != "" && !strings.Contains(titleText, "摘要") && !strings.Contains(titleText, "summary") {
				summaryBuilder.WriteString(titleText)
			}
			continue
		}

		// 详细分析部分
		// 注意：如果包含"当前资源使用情况分析"等成本优化相关的内容，应该放入 cost 而不是 analysis
		if (strings.Contains(lowerLine, "详细分析") || strings.Contains(lowerLine, "详细") ||
			strings.Contains(lowerLine, "分析") || strings.Contains(lowerLine, "analysis") ||
			strings.Contains(lowerLine, "当前状态") || strings.Contains(lowerLine, "趋势分析")) &&
			!strings.Contains(lowerLine, "资源使用情况") && !strings.Contains(lowerLine, "资源使用") {
			currentSection = "analysis"
			// 如果标题行本身有内容，也加入分析
			if titleText != "" && !strings.Contains(titleText, "分析") && !strings.Contains(titleText, "analysis") {
				if analysisBuilder.Len() > 0 {
					analysisBuilder.WriteString("\n")
				}
				analysisBuilder.WriteString(titleText)
			}
			continue
		}

		// 资源使用情况分析（成本优化相关）
		if strings.Contains(lowerLine, "资源使用情况") || strings.Contains(lowerLine, "资源使用") ||
			strings.Contains(lowerLine, "当前资源") || strings.Contains(lowerLine, "资源分析") {
			currentSection = "cost"
			// 如果标题行本身有内容，也加入成本优化
			if titleText != "" {
				if costBuilder.Len() > 0 {
					costBuilder.WriteString("\n\n")
				}
				costBuilder.WriteString(trimmedLine) // 保留原始格式（包括 ##）
			}
			continue
		}

		// 建议部分
		if strings.Contains(lowerLine, "建议") || strings.Contains(lowerLine, "recommendation") ||
			strings.Contains(lowerLine, "建议：") || strings.Contains(lowerLine, "建议:") ||
			strings.Contains(lowerLine, "具体建议") {
			currentSection = "recommendations"
			continue
		}

		// 成本优化部分（包括优化建议、预计节省成本、实施建议等）
		if strings.Contains(lowerLine, "成本优化") || strings.Contains(lowerLine, "成本") ||
			strings.Contains(lowerLine, "cost") || strings.Contains(lowerLine, "优化建议") ||
			strings.Contains(lowerLine, "节省成本") || strings.Contains(lowerLine, "实施建议") ||
			strings.Contains(lowerLine, "预计节省") || strings.Contains(lowerLine, "预计成本") {
			currentSection = "cost"
			// 如果标题行本身有内容，也加入成本优化（保留原始格式）
			if titleText != "" {
				if costBuilder.Len() > 0 {
					costBuilder.WriteString("\n\n")
				}
				costBuilder.WriteString(trimmedLine) // 保留原始格式（包括 ##）
			}
			continue
		}

		// 风险提示部分
		if strings.Contains(lowerLine, "风险") || strings.Contains(lowerLine, "risk") ||
			strings.Contains(lowerLine, "注意") || strings.Contains(lowerLine, "警告") {
			currentSection = "risks"
			continue
		}

		// 如果是 ## 开头的标题但没有匹配到已知章节，可能是子标题
		if isMarkdownTitle {
			if currentSection == "" {
				// 如果还没有识别到章节，默认设置为详细分析
				currentSection = "analysis"
			}
			// 作为子标题，添加到当前章节（包括标题本身）
			if titleText != "" {
				switch currentSection {
				case "analysis":
					if analysisBuilder.Len() > 0 {
						analysisBuilder.WriteString("\n\n")
					}
					// 添加标题，保留原始格式
					analysisBuilder.WriteString(trimmedLine)
				case "cost":
					if costBuilder.Len() > 0 {
						costBuilder.WriteString("\n\n")
					}
					costBuilder.WriteString(trimmedLine)
				case "summary":
					if summaryBuilder.Len() > 0 {
						summaryBuilder.WriteString(" ")
					}
					summaryBuilder.WriteString(titleText)
				case "recommendations":
					// 如果标题本身是列表项格式，添加到建议中
					if matched, _ := regexp.MatchString(`^\d+[\.、]\s*`, titleText); matched {
						recommendations = append(recommendations, strings.TrimSpace(regexp.MustCompile(`^\d+[\.、]\s*`).ReplaceAllString(titleText, "")))
					} else if len(titleText) > 5 {
						recommendations = append(recommendations, titleText)
					}
				case "risks":
					// 如果标题本身是列表项格式，添加到风险中
					if matched, _ := regexp.MatchString(`^\d+[\.、]\s*`, titleText); matched {
						risks = append(risks, strings.TrimSpace(regexp.MustCompile(`^\d+[\.、]\s*`).ReplaceAllString(titleText, "")))
					} else if len(titleText) > 5 {
						risks = append(risks, titleText)
					}
				}
			}
			// 标题行已经处理，跳过后续的 switch 处理，避免重复添加
			continue
		}

		// 根据当前章节收集内容
		switch currentSection {
		case "summary":
			if summaryBuilder.Len() > 0 {
				summaryBuilder.WriteString(" ")
			}
			summaryBuilder.WriteString(trimmedLine)
		case "analysis":
			// 如果上一行是标题，不需要额外换行
			if analysisBuilder.Len() > 0 {
				lastChar := analysisBuilder.String()[analysisBuilder.Len()-1:]
				if lastChar != "\n" && !strings.HasSuffix(analysisBuilder.String(), "##") && !strings.HasSuffix(analysisBuilder.String(), "#") {
					analysisBuilder.WriteString("\n")
				}
			}
			analysisBuilder.WriteString(trimmedLine)
		case "recommendations":
			// 检测列表项（数字开头、-、*等）
			if matched, _ := regexp.MatchString(`^\d+[\.、]\s*`, trimmedLine); matched {
				// 有序列表
				recommendations = append(recommendations, strings.TrimSpace(regexp.MustCompile(`^\d+[\.、]\s*`).ReplaceAllString(trimmedLine, "")))
			} else if strings.HasPrefix(trimmedLine, "-") || strings.HasPrefix(trimmedLine, "*") || strings.HasPrefix(trimmedLine, "•") {
				// 无序列表
				recommendations = append(recommendations, strings.TrimSpace(trimmedLine[1:]))
			} else if len(trimmedLine) > 5 {
				// 普通文本也作为建议
				recommendations = append(recommendations, trimmedLine)
			}
		case "cost":
			if costBuilder.Len() > 0 {
				costBuilder.WriteString("\n")
			}
			costBuilder.WriteString(trimmedLine)
		case "risks":
			if matched, _ := regexp.MatchString(`^\d+[\.、]\s*`, trimmedLine); matched {
				risks = append(risks, strings.TrimSpace(regexp.MustCompile(`^\d+[\.、]\s*`).ReplaceAllString(trimmedLine, "")))
			} else if strings.HasPrefix(trimmedLine, "-") || strings.HasPrefix(trimmedLine, "*") || strings.HasPrefix(trimmedLine, "•") {
				risks = append(risks, strings.TrimSpace(trimmedLine[1:]))
			} else if len(trimmedLine) > 5 {
				risks = append(risks, trimmedLine)
			}
		default:
			// 如果没有明确的章节，将内容放入详细分析
			if analysisBuilder.Len() == 0 && summaryBuilder.Len() == 0 {
				// 前几行作为摘要
				if i < 3 {
					if summaryBuilder.Len() > 0 {
						summaryBuilder.WriteString(" ")
					}
					summaryBuilder.WriteString(trimmedLine)
				} else {
					// 其余作为详细分析
					if analysisBuilder.Len() > 0 {
						analysisBuilder.WriteString("\n")
					}
					analysisBuilder.WriteString(trimmedLine)
				}
			} else {
				// 有章节后，默认放入详细分析
				if analysisBuilder.Len() > 0 {
					analysisBuilder.WriteString("\n")
				}
				analysisBuilder.WriteString(trimmedLine)
			}
		}
	}

	// 构建响应
	response.Analysis = analysisBuilder.String()
	log.Printf("[LLM] 解析结果 - 详细分析长度: %d, 当前章节: %s", len(response.Analysis), currentSection)
	if response.Analysis == "" {
		log.Printf("[LLM] 警告: 详细分析为空，使用全部内容")
		response.Analysis = content // 如果没有提取到分析，使用全部内容
	}

	response.Summary = summaryBuilder.String()
	log.Printf("[LLM] 解析结果 - 摘要长度: %d", len(response.Summary))
	if response.Summary == "" {
		// 如果没有摘要，从分析中提取前100个字符（按rune截取，避免中文乱码）
		analysisRunes := []rune(response.Analysis)
		if len(analysisRunes) > 100 {
			response.Summary = string(analysisRunes[:100]) + "..."
		} else {
			response.Summary = response.Analysis
		}
	}

	if len(recommendations) > 0 {
		response.Recommendations = recommendations
		log.Printf("[LLM] 解析结果 - 建议数量: %d", len(recommendations))
	} else {
		log.Printf("[LLM] 警告: 没有提取到建议，使用默认值")
		response.Recommendations = []string{"请查看详细分析内容"}
	}

	response.CostOptimization = costBuilder.String()
	log.Printf("[LLM] 解析结果 - 成本优化长度: %d", len(response.CostOptimization))
	if response.CostOptimization == "" {
		log.Printf("[LLM] 警告: 成本优化为空，使用默认值")
		response.CostOptimization = "建议根据实际使用情况优化资源配置"
	}

	if len(risks) > 0 {
		response.Risks = risks
		log.Printf("[LLM] 解析结果 - 风险数量: %d", len(risks))
	} else {
		log.Printf("[LLM] 警告: 没有提取到风险，使用默认值")
		response.Risks = []string{"请持续监控资源使用情况"}
	}

	return &response
}

// GenerateCostOptimization 生成成本优化建议
func (c *LLMClient) GenerateCostOptimization(hostID, hostname string, predictions map[string]interface{}) (string, error) {
	if !c.config.Enabled {
		return "", fmt.Errorf("LLM is not enabled")
	}

	prompt := fmt.Sprintf(`你是一个成本优化专家。基于以下主机的容量预测，提供详细的成本优化建议：

主机ID：%s
主机名：%s
预测数据：%s

请按照以下格式提供详细的成本优化分析：

## 当前资源使用情况分析
（详细分析当前各资源的使用情况，包括CPU、内存、磁盘等）

## 优化建议
（提供具体的优化建议，例如：
- 是否可以降配（说明原因和预期效果）
- 是否有闲置资源可以释放
- 是否可以升级（说明原因和预期效果）
- 资源配置调整建议
）

## 预计节省成本
（估算优化后可以节省的成本，包括：
- 降配可节省的成本
- 释放闲置资源可节省的成本
- 其他优化措施可节省的成本
）

## 实施建议
（提供具体的实施步骤和时间安排，包括：
- 实施优先级
- 实施步骤
- 注意事项
- 回滚方案
）

请用中文回答，要具体、详细、可操作。不要使用占位符或通用性描述。`, hostID, hostname, c.formatPredictions(predictions))

	var resp *AnalysisResponse
	var err error

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek:
		resp, err = c.callOpenAICompatible(prompt)
	case ProviderClaude:
		resp, err = c.callClaude(prompt)
	case ProviderQwen:
		resp, err = c.callQwen(prompt)
	case ProviderDoubao:
		resp, err = c.callDoubao(prompt)
	case ProviderZhipu:
		resp, err = c.callZhipu(prompt)
	case ProviderCustom:
		resp, err = c.callCustom(prompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s", c.config.Provider)
	}

	if err != nil {
		return "", err
	}

	if resp == nil {
		return "", fmt.Errorf("LLM returned nil response")
	}

	// 对于成本优化，我们需要返回完整的内容，包括所有章节
	// 组合所有相关字段，因为 parseLLMResponse 可能将不同章节分散到不同字段
	var response strings.Builder

	// 组合所有相关字段，确保完整显示
	// 1. 分析字段（可能包含"当前资源使用情况分析"等章节）
	if resp.Analysis != "" {
		response.WriteString(resp.Analysis)
		response.WriteString("\n\n")
		log.Printf("[LLM] 添加 Analysis 字段，长度: %d", len(resp.Analysis))
	}

	// 2. 建议字段
	if len(resp.Recommendations) > 0 {
		if response.Len() > 0 {
			response.WriteString("\n")
		}
		response.WriteString("## 优化建议\n\n")
		for i, rec := range resp.Recommendations {
			response.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		response.WriteString("\n")
		log.Printf("[LLM] 添加 Recommendations 字段，数量: %d", len(resp.Recommendations))
	}

	// 3. 成本优化字段（可能包含"预计节省成本"等章节）
	if resp.CostOptimization != "" && resp.CostOptimization != "建议根据实际使用情况优化资源配置" {
		if response.Len() > 0 {
			response.WriteString("\n")
		}
		// 如果 CostOptimization 不包含标题，添加标题
		if !strings.Contains(resp.CostOptimization, "##") && !strings.Contains(resp.CostOptimization, "#") {
			response.WriteString("## 成本优化建议\n\n")
		}
		response.WriteString(resp.CostOptimization)
		response.WriteString("\n\n")
		log.Printf("[LLM] 添加 CostOptimization 字段，长度: %d", len(resp.CostOptimization))
	}

	// 4. 风险提示
	if len(resp.Risks) > 0 {
		if response.Len() > 0 {
			response.WriteString("\n")
		}
		response.WriteString("## 风险提示\n\n")
		for i, risk := range resp.Risks {
			response.WriteString(fmt.Sprintf("%d. %s\n", i+1, risk))
		}
		log.Printf("[LLM] 添加 Risks 字段，数量: %d", len(resp.Risks))
	}

	result := response.String()
	if result == "" {
		log.Printf("[LLM] 警告: 所有字段都为空，使用默认值")
		return "建议根据实际使用情况优化资源配置", nil
	}

	log.Printf("[LLM] 成本优化建议总长度: %d 字符", len(result))
	if len(result) > 500 {
		// 记录前500和后500字符，便于调试
		resultRunes := []rune(result)
		if len(resultRunes) > 500 {
			log.Printf("[LLM] 成本优化建议前500字符: %s", string(resultRunes[:500]))
			log.Printf("[LLM] 成本优化建议后500字符: %s", string(resultRunes[len(resultRunes)-500:]))
		}
	} else {
		log.Printf("[LLM] 成本优化建议完整内容: %s", result)
	}

	return result, nil
}

// formatPredictions 格式化预测数据为可读字符串，避免截断问题
func (c *LLMClient) formatPredictions(predictions map[string]interface{}) string {
	if len(predictions) == 0 {
		return "暂无预测数据"
	}

	jsonData, err := json.MarshalIndent(predictions, "", "  ")
	if err != nil {
		// 如果JSON序列化失败，使用简单的字符串拼接
		var parts []string
		for k, v := range predictions {
			parts = append(parts, fmt.Sprintf("%s: %v", k, v))
		}
		return strings.Join(parts, "\n")
	}

	return string(jsonData)
}

// AnalyzeAnomalyDetection 分析异常检测结果并生成总结
func (c *LLMClient) AnalyzeAnomalyDetection(hostID, hostname string, anomalies []interface{}, statistics map[string]interface{}) (string, error) {
	if !c.config.Enabled {
		return "", fmt.Errorf("LLM is not enabled")
	}

	// 构建异常检测原理说明
	detectionPrinciple := `异常检测使用以下三种算法：
1. Z-score方法（标准差方法）：检测偏离均值超过2.5个标准差的数据点
2. IQR方法（四分位距方法）：使用四分位数定义正常范围，超出[Q1-1.5×IQR, Q3+1.5×IQR]的值视为异常
3. 移动平均方法：使用滑动窗口计算局部统计值，检测相对于局部趋势的异常

异常严重程度分类：
- Critical（严重）：置信度>0.9且偏差>50%
- High（高）：置信度>0.7且偏差>30%
- Medium（中）：置信度>0.5且偏差>15%
- Low（低）：其他情况`

	// 格式化异常数据
	var anomaliesDesc strings.Builder
	if len(anomalies) == 0 {
		anomaliesDesc.WriteString("未检测到异常事件。")
	} else {
		anomaliesDesc.WriteString(fmt.Sprintf("检测到 %d 个异常事件：\n\n", len(anomalies)))
		for i, anomaly := range anomalies {
			if i >= 20 { // 最多显示20个异常
				anomaliesDesc.WriteString(fmt.Sprintf("\n... 还有 %d 个异常事件未列出\n", len(anomalies)-20))
				break
			}
			anom, _ := json.Marshal(anomaly)
			anomaliesDesc.WriteString(fmt.Sprintf("异常 %d: %s\n", i+1, string(anom)))
		}
	}

	// 格式化统计信息
	var statsDesc strings.Builder
	if statistics != nil {
		statsDesc.WriteString("异常统计信息：\n")
		if total, ok := statistics["total_anomalies"].(float64); ok {
			statsDesc.WriteString(fmt.Sprintf("- 异常总数：%.0f\n", total))
		}
		if unresolved, ok := statistics["unresolved_count"].(float64); ok {
			statsDesc.WriteString(fmt.Sprintf("- 未解决数：%.0f\n", unresolved))
		}
		if bySeverity, ok := statistics["by_severity"].(map[string]interface{}); ok {
			statsDesc.WriteString("- 按严重程度分布：\n")
			for severity, count := range bySeverity {
				if cnt, ok := count.(float64); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %.0f\n", severity, cnt))
				} else if cnt, ok := count.(int); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %d\n", severity, cnt))
				}
			}
		}
		if byType, ok := statistics["by_type"].(map[string]interface{}); ok {
			statsDesc.WriteString("- 按类型分布：\n")
			for typ, count := range byType {
				if cnt, ok := count.(float64); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %.0f\n", typ, cnt))
				} else if cnt, ok := count.(int); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %d\n", typ, cnt))
				}
			}
		}
	}

	prompt := fmt.Sprintf(`你是一个专业的运维和异常分析专家。基于以下异常检测结果，生成一份专业的分析总结报告。

## 异常检测原理

%s

## 检测结果数据

主机信息：
- 主机ID：%s
- 主机名：%s

%s

%s

请按照以下格式生成专业的分析总结报告：

## 检测总结
（用1-2段话总结异常检测的结果和主要发现）

## 异常情况分析
（详细分析检测到的异常情况，包括：
- 异常的整体概况
- 异常的类型分布和严重程度分析
- 重点关注的异常事件
- 异常的时间分布模式
）

## 风险评估
（评估异常对系统的影响，包括：
- 严重异常的潜在影响
- 系统健康度评估
- 是否需要立即处理
）

## 处理建议
（提供具体的处理建议，包括：
- 优先级排序（哪些异常需要优先处理）
- 具体的处理步骤
- 预防措施建议
- 持续监控建议
）

## 系统健康度评价
（对系统的整体健康度进行评价，包括：
- 当前系统运行状态
- 是否存在系统性风险
- 需要关注的长期趋势
）

如果未检测到异常，请说明这是正常现象，并给出持续监控的建议。

请用中文回答，要专业、详细、可操作。不要使用占位符或通用性描述。`,
		detectionPrinciple,
		hostID,
		hostname,
		anomaliesDesc.String(),
		statsDesc.String())

	var resp *AnalysisResponse
	var err error

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek:
		resp, err = c.callOpenAICompatible(prompt)
	case ProviderClaude:
		resp, err = c.callClaude(prompt)
	case ProviderQwen:
		resp, err = c.callQwen(prompt)
	case ProviderDoubao:
		resp, err = c.callDoubao(prompt)
	case ProviderZhipu:
		resp, err = c.callZhipu(prompt)
	case ProviderCustom:
		resp, err = c.callCustom(prompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s", c.config.Provider)
	}

	if err != nil {
		return "", err
	}

	if resp == nil {
		return "", fmt.Errorf("LLM returned nil response")
	}

	// 组合所有相关字段
	var response strings.Builder
	if resp.Summary != "" {
		response.WriteString(resp.Summary)
		response.WriteString("\n\n")
	}
	if resp.Analysis != "" {
		response.WriteString(resp.Analysis)
		response.WriteString("\n\n")
	}
	if len(resp.Recommendations) > 0 {
		response.WriteString("## 处理建议\n\n")
		for i, rec := range resp.Recommendations {
			response.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		response.WriteString("\n")
	}
	if resp.CostOptimization != "" {
		response.WriteString(resp.CostOptimization)
		response.WriteString("\n\n")
	}
	if len(resp.Risks) > 0 {
		response.WriteString("## 风险提示\n\n")
		for i, risk := range resp.Risks {
			response.WriteString(fmt.Sprintf("%d. %s\n", i+1, risk))
		}
	}

	result := response.String()
	if result == "" {
		// 如果没有解析到内容，使用原始响应
		if resp.Analysis != "" {
			result = resp.Analysis
		} else if resp.Summary != "" {
			result = resp.Summary
		} else {
			result = "LLM分析完成，但未能提取到具体内容。"
		}
	}

	return result, nil
}
