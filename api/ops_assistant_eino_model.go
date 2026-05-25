package api

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"monitor-backend/opsassistant"

	openai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/schema"
)

type opsAssistantEinoModel struct {
	model *openai.ChatModel
}

func newOpsAssistantEinoModel(ctx context.Context, config *LLMModelConfigInfo) (opsassistant.Model, error) {
	if config == nil || !config.Enabled {
		return nil, nil
	}

	timeout := time.Duration(config.Timeout) * time.Second
	if timeout < 300*time.Second {
		timeout = 300 * time.Second
	}
	maxTokens := config.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2000
	}
	temperature := float32(config.Temperature)
	if temperature == 0 {
		temperature = 0.2
	}

	baseURL := normalizeOpenAICompatibleBaseURL(config.Provider, config.BaseURL)
	if baseURL == "" {
		return nil, errors.New("当前模型 provider 需要配置 OpenAI-compatible base_url")
	}

	chatModel, err := openai.NewChatModel(ctx, &openai.ChatModelConfig{
		APIKey:      config.APIKey,
		BaseURL:     baseURL,
		Model:       config.Model,
		Timeout:     timeout,
		MaxTokens:   &maxTokens,
		Temperature: &temperature,
	})
	if err != nil {
		return nil, err
	}
	return &opsAssistantEinoModel{model: chatModel}, nil
}

func normalizeOpenAICompatibleBaseURL(provider, baseURL string) string {
	if strings.TrimSpace(baseURL) != "" {
		url := strings.TrimSpace(baseURL)
		return strings.TrimSuffix(url, "/chat/completions")
	}
	switch provider {
	case "openai":
		return "https://api.openai.com/v1"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	case "doubao":
		return "https://ark.cn-beijing.volces.com/api/v3"
	case "zhipu":
		return "https://open.bigmodel.cn/api/paas/v4"
	default:
		return ""
	}
}

func (m *opsAssistantEinoModel) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := m.model.Generate(ctx, []*schema.Message{
		schema.SystemMessage("你是监控系统中的只读运维助手。"),
		schema.UserMessage(prompt),
	})
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", errors.New("LLM API returned empty response")
	}
	return resp.Content, nil
}

func (m *opsAssistantEinoModel) Stream(ctx context.Context, prompt string, emit func(opsassistant.StreamEvent) error) error {
	reader, err := m.model.Stream(ctx, []*schema.Message{
		schema.SystemMessage("你是监控系统中的只读运维助手。"),
		schema.UserMessage(prompt),
	})
	if err != nil {
		return err
	}
	defer reader.Close()

	for {
		chunk, err := reader.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if chunk == nil || chunk.Content == "" {
			continue
		}
		if err := emit(opsassistant.StreamEvent{Type: opsassistant.EventContent, Content: chunk.Content}); err != nil {
			return err
		}
	}
}
