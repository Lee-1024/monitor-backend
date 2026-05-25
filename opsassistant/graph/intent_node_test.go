package graph

import (
	"context"
	"testing"

	"monitor-backend/opsassistant"
)

type fakeIntentModel struct {
	answer string
	prompt string
}

func (m *fakeIntentModel) Complete(ctx context.Context, prompt string) (string, error) {
	m.prompt = prompt
	return m.answer, nil
}

func (m *fakeIntentModel) Stream(ctx context.Context, prompt string, emit func(opsassistant.StreamEvent) error) error {
	return nil
}

func TestClassifyIntentUsesModelJSON(t *testing.T) {
	model := &fakeIntentModel{answer: `{"intent":"alert_root_cause","confidence":0.91,"required_context":["host_id"],"missing_context":[]}`}

	result := ClassifyIntent(context.Background(), model, opsassistant.ChatRequest{
		Message: "Analyze this alert root cause",
		HostID:  "host-01",
	})

	if result.Intent != IntentAlertRootCause {
		t.Fatalf("expected alert_root_cause, got %s", result.Intent)
	}
	if result.Confidence != 0.91 {
		t.Fatalf("expected confidence 0.91, got %f", result.Confidence)
	}
	if len(result.MissingContext) != 0 {
		t.Fatalf("expected no missing context, got %#v", result.MissingContext)
	}
	if model.prompt == "" {
		t.Fatal("expected classifier to call model")
	}
}

func TestClassifyIntentRequiresHostForHostPerformance(t *testing.T) {
	model := &fakeIntentModel{answer: `{"intent":"host_performance","confidence":0.86,"required_context":["host_id"],"missing_context":[]}`}

	result := ClassifyIntent(context.Background(), model, opsassistant.ChatRequest{
		Message: "Why is CPU high?",
	})

	if result.Intent != IntentHostPerformance {
		t.Fatalf("expected host_performance, got %s", result.Intent)
	}
	if len(result.MissingContext) != 1 || result.MissingContext[0] != "host_id" {
		t.Fatalf("expected missing host_id, got %#v", result.MissingContext)
	}
	if result.Clarification == "" {
		t.Fatal("expected clarification")
	}
}

func TestClassifyIntentFallsBackWhenModelJSONMalformed(t *testing.T) {
	model := &fakeIntentModel{answer: `not-json`}

	result := ClassifyIntent(context.Background(), model, opsassistant.ChatRequest{
		Message: "Show global health",
	})

	if result.Intent != IntentGlobalHealth {
		t.Fatalf("expected global_health fallback, got %s", result.Intent)
	}
	if result.Confidence <= 0 {
		t.Fatalf("expected fallback confidence, got %f", result.Confidence)
	}
}
