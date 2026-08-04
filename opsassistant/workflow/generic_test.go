package workflow

import (
	"context"
	"testing"

	"monitor-backend/opsassistant/core"
)

type fakeModel struct {
	answer string
}

func (m fakeModel) Complete(ctx context.Context, prompt string) (string, error) {
	return m.answer, nil
}

func (m fakeModel) Stream(ctx context.Context, prompt string, emit func(core.StreamEvent) error) error {
	return emit(core.StreamEvent{Type: core.EventContent, Content: m.answer})
}

func TestGenericWorkflowEmitsStatusToolAndReportEvents(t *testing.T) {
	runner := NewGenericRunner(fakeModel{answer: `{"title":"Report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`})
	var events []core.StreamEvent

	result, err := runner.Run(context.Background(), Input{
		Request: core.ChatRequest{Message: "show health"},
		Intent:  core.IntentResult{Intent: "global_health"},
		Tools: []core.Tool{
			{
				Name: "list_agents",
				Run: func(ctx context.Context, req core.ChatRequest) (core.ToolResult, error) {
					return core.ToolResult{Name: "list_agents", Summary: "listed agents", Content: "host online"}, nil
				},
			},
		},
	}, func(event core.StreamEvent) error {
		events = append(events, event)
		return nil
	})

	if err != nil {
		t.Fatalf("run workflow: %v", err)
	}
	if result.Report == nil {
		t.Fatal("expected report")
	}
	assertWorkflowEvent(t, events, core.EventStatus)
	assertWorkflowEvent(t, events, core.EventToolCall)
	assertWorkflowEvent(t, events, core.EventReport)
}

func TestGenericWorkflowEmitsEinoGraphNodeSequence(t *testing.T) {
	runner := NewGenericRunner(fakeModel{answer: `{"title":"Report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`})
	var events []core.StreamEvent

	_, err := runner.Run(context.Background(), Input{
		Request: core.ChatRequest{Message: "show health"},
		Intent:  core.IntentResult{Intent: "global_health"},
		Plan: core.ToolPlan{Calls: []core.PlannedToolCall{
			{Tool: "list_agents", Required: true, Summary: "list agents"},
		}},
		Tools: []core.Tool{
			{
				Name: "list_agents",
				Run: func(ctx context.Context, req core.ChatRequest) (core.ToolResult, error) {
					return core.ToolResult{Name: "list_agents", Summary: "listed agents", Content: "host online"}, nil
				},
			},
		},
		Model: fakeModel{answer: `{"title":"Report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`},
	}, func(event core.StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("run workflow: %v", err)
	}

	assertGraphNodeOrder(t, events, []string{"tool_executor", "evidence_builder", "report_generator"})
}

func TestGenericWorkflowUsesEinoCallbacksForNodeStart(t *testing.T) {
	runner := NewGenericRunner(fakeModel{answer: `{"title":"Report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`})
	var events []core.StreamEvent

	_, err := runner.Run(context.Background(), Input{
		Request: core.ChatRequest{Message: "show health"},
		Intent:  core.IntentResult{Intent: "global_health"},
		Plan: core.ToolPlan{Calls: []core.PlannedToolCall{
			{Tool: "list_agents", Required: true, Summary: "list agents"},
		}},
		Tools: []core.Tool{
			{
				Name: "list_agents",
				Run: func(ctx context.Context, req core.ChatRequest) (core.ToolResult, error) {
					return core.ToolResult{Name: "list_agents", Summary: "listed agents", Content: "host online"}, nil
				},
			},
		},
		Model: fakeModel{answer: `{"title":"Report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`},
	}, func(event core.StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("run workflow: %v", err)
	}

	assertHasGraphNodeStatus(t, events, "tool_executor", "running")
}

func assertWorkflowEvent(t *testing.T, events []core.StreamEvent, eventType string) {
	t.Helper()
	for _, event := range events {
		if event.Type == eventType {
			return
		}
	}
	t.Fatalf("expected event %s in %#v", eventType, events)
}

func assertGraphNodeOrder(t *testing.T, events []core.StreamEvent, expected []string) {
	t.Helper()
	var nodes []string
	for _, event := range events {
		if event.Type == core.EventGraphNode && event.Status == "completed" {
			nodes = append(nodes, event.Node)
		}
	}
	next := 0
	for _, node := range nodes {
		if next < len(expected) && node == expected[next] {
			next++
		}
	}
	if next != len(expected) {
		t.Fatalf("expected graph node order %v in completed nodes %v", expected, nodes)
	}
}

func assertHasGraphNodeStatus(t *testing.T, events []core.StreamEvent, node string, status string) {
	t.Helper()
	for _, event := range events {
		if event.Type == core.EventGraphNode && event.Node == node && event.Status == status {
			return
		}
	}
	t.Fatalf("expected graph node %s with status %s in %#v", node, status, events)
}
