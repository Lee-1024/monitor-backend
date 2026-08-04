package workflow

import (
	"context"
	"testing"

	"monitor-backend/opsassistant/core"
)

func TestHostPerformanceWorkflowRunsSpecialistToolPlan(t *testing.T) {
	runner := NewHostPerformanceRunner(fakeModel{answer: `{"title":"Host performance","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`})
	var calls []string

	result, err := runner.Run(context.Background(), Input{
		Request: core.ChatRequest{Message: "check host performance", HostID: "host-01"},
		Intent:  core.IntentResult{Intent: "host_performance"},
		Tools: []core.Tool{
			namedWorkflowTestTool("get_agent_detail", &calls),
			namedWorkflowTestTool("get_latest_metrics", &calls),
			namedWorkflowTestTool("get_history_metrics", &calls),
			namedWorkflowTestTool("get_recent_alerts", &calls),
			namedWorkflowTestTool("get_anomaly_events", &calls),
			namedWorkflowTestTool("search_knowledge", &calls),
		},
		Model: fakeModel{answer: `{"title":"Host performance","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`},
	}, nil)
	if err != nil {
		t.Fatalf("run host performance workflow: %v", err)
	}
	assertToolOrder(t, calls, []string{"get_agent_detail", "get_latest_metrics", "get_history_metrics", "get_recent_alerts", "get_anomaly_events", "search_knowledge"})
	if result.Report == nil || result.Report.Title != "Host performance" {
		t.Fatalf("expected structured report, got %#v", result.Report)
	}
}

func TestHostPerformanceWorkflowEmitsSpecialistGraphNode(t *testing.T) {
	runner := NewHostPerformanceRunner(fakeModel{answer: `{"title":"Host performance","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`})
	var events []core.StreamEvent

	_, err := runner.Run(context.Background(), Input{
		Request: core.ChatRequest{Message: "check host performance", HostID: "host-01"},
		Intent:  core.IntentResult{Intent: "host_performance"},
		Tools: []core.Tool{
			namedWorkflowTestTool("get_latest_metrics", nil),
			namedWorkflowTestTool("get_history_metrics", nil),
		},
		Model: fakeModel{answer: `{"title":"Host performance","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`},
	}, func(event core.StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("run host performance workflow: %v", err)
	}
	assertHasWorkflowGraphNode(t, events, "host_performance_workflow")
}

func namedWorkflowTestTool(name string, calls *[]string) core.Tool {
	return core.Tool{
		Name:        name,
		Description: name,
		Run: func(ctx context.Context, req core.ChatRequest) (core.ToolResult, error) {
			if calls != nil {
				*calls = append(*calls, name)
			}
			return core.ToolResult{Name: name, Summary: name, Content: name + " evidence"}, nil
		},
	}
}

func assertToolOrder(t *testing.T, actual []string, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("expected calls %v, got %v", expected, actual)
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Fatalf("expected calls %v, got %v", expected, actual)
		}
	}
}

func assertHasWorkflowGraphNode(t *testing.T, events []core.StreamEvent, node string) {
	t.Helper()
	for _, event := range events {
		if event.Type == core.EventGraphNode && event.Node == node {
			return
		}
	}
	t.Fatalf("expected graph node %s in %#v", node, events)
}
