package workflow

import (
	"context"
	"encoding/json"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"monitor-backend/opsassistant/core"
)

type einoToolAdapter struct {
	tool core.Tool
}

type einoToolRunResult struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`
}

func newEinoToolAdapter(tool core.Tool) *einoToolAdapter {
	return &einoToolAdapter{tool: tool}
}

func (t *einoToolAdapter) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: t.tool.Name,
		Desc: t.tool.Description,
	}, nil
}

func (t *einoToolAdapter) InvokableRun(ctx context.Context, argumentsInJSON string, opts ...einotool.Option) (string, error) {
	var req core.ChatRequest
	if argumentsInJSON != "" {
		if err := json.Unmarshal([]byte(argumentsInJSON), &req); err != nil {
			return marshalEinoToolRunResult(einoToolRunResult{Name: t.tool.Name, Summary: t.tool.Name, Error: err.Error()}), nil
		}
	}
	result, err := t.tool.Run(ctx, req)
	if err != nil {
		return marshalEinoToolRunResult(einoToolRunResult{Name: t.tool.Name, Summary: t.tool.Name, Error: err.Error()}), nil
	}
	if result.Name == "" {
		result.Name = t.tool.Name
	}
	return marshalEinoToolRunResult(einoToolRunResult{
		Name:    result.Name,
		Summary: result.Summary,
		Content: result.Content,
	}), nil
}

func marshalEinoToolRunResult(result einoToolRunResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"error":"failed to serialize tool result"}`
	}
	return string(data)
}
