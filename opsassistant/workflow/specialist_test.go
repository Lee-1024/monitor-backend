package workflow

import (
	"context"
	"testing"

	"monitor-backend/opsassistant/core"
)

func TestSpecialistWorkflowsRunExpectedTools(t *testing.T) {
	tests := []struct {
		name     string
		runner   Runner
		expected []string
	}{
		{
			name:     "capacity",
			runner:   NewCapacityPlanningRunner(fakeModel{answer: reportJSON("Capacity")}),
			expected: []string{"get_capacity_prediction", "get_recent_alerts", "search_knowledge"},
		},
		{
			name:     "cost",
			runner:   NewCostOptimizationRunner(fakeModel{answer: reportJSON("Cost")}),
			expected: []string{"get_cost_optimization", "get_recent_alerts", "search_knowledge"},
		},
		{
			name:     "anomaly",
			runner:   NewAnomalyAnalysisRunner(fakeModel{answer: reportJSON("Anomaly")}),
			expected: []string{"detect_anomalies", "get_history_metrics", "search_knowledge"},
		},
		{
			name:     "alert",
			runner:   NewAlertRootCauseRunner(fakeModel{answer: reportJSON("Alert")}),
			expected: []string{"get_recent_alerts", "get_history_metrics", "get_anomaly_events", "search_knowledge"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			tools := make([]core.Tool, 0, len(tt.expected))
			for _, name := range tt.expected {
				tools = append(tools, namedWorkflowTestTool(name, &calls))
			}
			_, err := tt.runner.Run(context.Background(), Input{
				Request: core.ChatRequest{Message: tt.name, HostID: "host-01"},
				Tools:   tools,
				Model:   fakeModel{answer: reportJSON(tt.name)},
			}, nil)
			if err != nil {
				t.Fatalf("run specialist workflow: %v", err)
			}
			assertToolOrder(t, calls, tt.expected)
		})
	}
}

func reportJSON(title string) string {
	return `{"title":"` + title + `","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`
}
