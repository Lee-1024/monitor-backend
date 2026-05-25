package graph

import (
	"testing"

	"monitor-backend/opsassistant"
)

func TestPlanToolsForGlobalHealth(t *testing.T) {
	plan := PlanTools(opsassistant.IntentResult{Intent: IntentGlobalHealth}, opsassistant.ChatRequest{})

	assertPlanTools(t, plan, []string{"list_agents", "get_recent_alerts", "get_anomaly_events", "get_latest_inspection_report"})
}

func TestPlanToolsForHostPerformance(t *testing.T) {
	plan := PlanTools(opsassistant.IntentResult{Intent: IntentHostPerformance}, opsassistant.ChatRequest{HostID: "host-01"})

	assertPlanTools(t, plan, []string{"get_latest_metrics", "get_history_metrics", "get_recent_alerts", "get_anomaly_events"})
}

func TestPlanToolsSkipsHostSpecificToolsWithoutHost(t *testing.T) {
	plan := PlanTools(opsassistant.IntentResult{Intent: IntentHostPerformance}, opsassistant.ChatRequest{})

	for _, call := range plan.Calls {
		if call.Tool == "get_latest_metrics" || call.Tool == "get_history_metrics" {
			t.Fatalf("host metric tool should not be planned without host_id: %#v", plan.Calls)
		}
	}
}

func TestPlanToolsForAlertRootCauseWithHost(t *testing.T) {
	plan := PlanTools(opsassistant.IntentResult{Intent: IntentAlertRootCause}, opsassistant.ChatRequest{HostID: "host-01"})

	assertPlanTools(t, plan, []string{"get_recent_alerts", "get_history_metrics", "get_anomaly_events", "search_knowledge"})
}

func TestPlanToolsLimitsCalls(t *testing.T) {
	plan := PlanTools(opsassistant.IntentResult{Intent: IntentGlobalHealth}, opsassistant.ChatRequest{})

	if len(plan.Calls) > 8 {
		t.Fatalf("expected max 8 tool calls, got %d", len(plan.Calls))
	}
}

func assertPlanTools(t *testing.T, plan opsassistant.ToolPlan, expected []string) {
	t.Helper()
	if len(plan.Calls) != len(expected) {
		t.Fatalf("expected %d calls, got %d: %#v", len(expected), len(plan.Calls), plan.Calls)
	}
	for i, tool := range expected {
		if plan.Calls[i].Tool != tool {
			t.Fatalf("expected call %d to be %s, got %s", i, tool, plan.Calls[i].Tool)
		}
		if plan.Calls[i].Summary == "" {
			t.Fatalf("expected summary for %s", tool)
		}
	}
}
