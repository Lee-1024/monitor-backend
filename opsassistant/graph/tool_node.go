package graph

import (
	"context"
	"fmt"
	"time"

	"monitor-backend/opsassistant"
)

const (
	ToolStatusRunning   = "running"
	ToolStatusCompleted = "completed"
	ToolStatusSuccess   = "success"
	ToolStatusFailed    = "failed"
)

func ExecuteToolPlan(
	ctx context.Context,
	req opsassistant.ChatRequest,
	plan opsassistant.ToolPlan,
	tools map[string]opsassistant.Tool,
	emit func(opsassistant.StreamEvent) error,
) ([]opsassistant.ToolExecutionResult, error) {
	results := make([]opsassistant.ToolExecutionResult, 0, len(plan.Calls))
	for _, call := range plan.Calls {
		tool, ok := tools[call.Tool]
		if !ok {
			result := failedToolResult(call, 0, "tool not registered")
			results = append(results, result)
			if call.Required {
				return results, fmt.Errorf("required tool %s not registered", call.Tool)
			}
			continue
		}

		if emit != nil {
			if err := emit(opsassistant.StreamEvent{
				Type:    opsassistant.EventToolCall,
				Tool:    call.Tool,
				Status:  ToolStatusRunning,
				Summary: call.Summary,
			}); err != nil {
				return results, err
			}
		}

		started := time.Now()
		toolResult, err := tool.Run(ctx, req)
		duration := time.Since(started).Milliseconds()
		if err != nil {
			result := failedToolResult(call, duration, err.Error())
			results = append(results, result)
			if emit != nil {
				if emitErr := emit(toolEventFromResult(result, ToolStatusFailed)); emitErr != nil {
					return results, emitErr
				}
			}
			if call.Required {
				return results, err
			}
			continue
		}

		name := toolResult.Name
		if name == "" {
			name = call.Tool
		}
		summary := toolResult.Summary
		if summary == "" {
			summary = call.Summary
		}
		result := opsassistant.ToolExecutionResult{
			Tool:       name,
			Summary:    summary,
			Status:     ToolStatusSuccess,
			DurationMS: duration,
			Content:    toolResult.Content,
		}
		results = append(results, result)
		if emit != nil {
			if err := emit(toolEventFromResult(result, ToolStatusCompleted)); err != nil {
				return results, err
			}
		}
	}
	return results, nil
}

func failedToolResult(call opsassistant.PlannedToolCall, duration int64, message string) opsassistant.ToolExecutionResult {
	return opsassistant.ToolExecutionResult{
		Tool:       call.Tool,
		Summary:    call.Summary,
		Status:     ToolStatusFailed,
		DurationMS: duration,
		Error:      message,
		Content:    "tool query failed: " + message,
	}
}

func toolEventFromResult(result opsassistant.ToolExecutionResult, eventStatus string) opsassistant.StreamEvent {
	summary := result.Summary
	if result.Error != "" {
		summary = summary + ": " + result.Error
	}
	return opsassistant.StreamEvent{
		Type:       opsassistant.EventToolCall,
		Tool:       result.Tool,
		Status:     eventStatus,
		Summary:    summary,
		DurationMS: result.DurationMS,
	}
}
