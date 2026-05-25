package graph

import (
	"context"
	"errors"
	"testing"

	"monitor-backend/opsassistant"
)

func TestExecuteToolPlanEmitsRunningAndCompletedEvents(t *testing.T) {
	tools := map[string]opsassistant.Tool{
		"list_agents": {
			Name: "list_agents",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				return opsassistant.ToolResult{Name: "list_agents", Summary: "listed agents", Content: "host-01 online"}, nil
			},
		},
	}
	var events []opsassistant.StreamEvent

	results, err := ExecuteToolPlan(context.Background(), opsassistant.ChatRequest{}, opsassistant.ToolPlan{
		Calls: []opsassistant.PlannedToolCall{{Tool: "list_agents", Required: true, Summary: "list agents"}},
	}, tools, func(event opsassistant.StreamEvent) error {
		events = append(events, event)
		return nil
	})

	if err != nil {
		t.Fatalf("execute plan: %v", err)
	}
	if len(results) != 1 || results[0].Status != ToolStatusSuccess {
		t.Fatalf("expected success result, got %#v", results)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %#v", events)
	}
	if events[0].Status != ToolStatusRunning || events[1].Status != ToolStatusCompleted {
		t.Fatalf("unexpected statuses: %#v", events)
	}
}

func TestExecuteToolPlanOptionalFailureDoesNotFailWorkflow(t *testing.T) {
	tools := map[string]opsassistant.Tool{
		"search_knowledge": {
			Name: "search_knowledge",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				return opsassistant.ToolResult{}, errors.New("knowledge unavailable")
			},
		},
	}

	results, err := ExecuteToolPlan(context.Background(), opsassistant.ChatRequest{}, opsassistant.ToolPlan{
		Calls: []opsassistant.PlannedToolCall{{Tool: "search_knowledge", Required: false, Summary: "search knowledge"}},
	}, tools, nil)

	if err != nil {
		t.Fatalf("optional failure should not fail workflow: %v", err)
	}
	if len(results) != 1 || results[0].Status != ToolStatusFailed {
		t.Fatalf("expected failed result, got %#v", results)
	}
}

func TestExecuteToolPlanRequiredFailureFailsWorkflow(t *testing.T) {
	tools := map[string]opsassistant.Tool{
		"get_recent_alerts": {
			Name: "get_recent_alerts",
			Run: func(ctx context.Context, req opsassistant.ChatRequest) (opsassistant.ToolResult, error) {
				return opsassistant.ToolResult{}, errors.New("alert query failed")
			},
		},
	}

	results, err := ExecuteToolPlan(context.Background(), opsassistant.ChatRequest{}, opsassistant.ToolPlan{
		Calls: []opsassistant.PlannedToolCall{{Tool: "get_recent_alerts", Required: true, Summary: "query alerts"}},
	}, tools, nil)

	if err == nil {
		t.Fatal("expected required tool failure")
	}
	if len(results) != 1 || results[0].Status != ToolStatusFailed {
		t.Fatalf("expected failed result, got %#v", results)
	}
}
