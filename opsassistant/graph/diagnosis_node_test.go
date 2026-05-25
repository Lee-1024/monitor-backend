package graph

import (
	"context"
	"strings"
	"testing"

	"monitor-backend/opsassistant"
)

func TestBuildEvidenceFromToolResults(t *testing.T) {
	evidence := BuildEvidence([]opsassistant.ToolExecutionResult{
		{Tool: "get_history_metrics", Summary: "history metrics", Status: ToolStatusSuccess, Content: "CPU peaked at 92%"},
		{Tool: "search_knowledge", Summary: "knowledge", Status: ToolStatusFailed, Error: "unavailable"},
	})

	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence items, got %#v", evidence)
	}
	if evidence[0].Source != "get_history_metrics" || !strings.Contains(evidence[0].Text, "CPU peaked") {
		t.Fatalf("unexpected first evidence: %#v", evidence[0])
	}
	if !strings.Contains(evidence[1].Text, "unavailable") {
		t.Fatalf("expected failed tool evidence, got %#v", evidence[1])
	}
}

func TestGenerateDiagnosisParsesValidReportJSON(t *testing.T) {
	model := &fakeIntentModel{answer: `{"title":"Host report","summary":"CPU is stable","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}

	result, err := GenerateDiagnosis(context.Background(), model, opsassistant.ChatRequest{Message: "check host"}, nil)
	if err != nil {
		t.Fatalf("generate diagnosis: %v", err)
	}
	if result.Report == nil {
		t.Fatal("expected structured report")
	}
	if result.Report.Title != "Host report" {
		t.Fatalf("unexpected report: %#v", result.Report)
	}
	if result.Content == "" {
		t.Fatal("expected markdown content")
	}
}

func TestGenerateDiagnosisFallsBackToMarkdownWhenJSONInvalid(t *testing.T) {
	model := &fakeIntentModel{answer: `<think>hidden reasoning</think># Report` + "\n\nSummary text"}

	result, err := GenerateDiagnosis(context.Background(), model, opsassistant.ChatRequest{Message: "check host"}, []opsassistant.Evidence{
		{Source: "get_latest_metrics", Text: "CPU is 12%"},
	})
	if err != nil {
		t.Fatalf("generate diagnosis: %v", err)
	}
	if result.Report != nil {
		t.Fatalf("expected no structured report, got %#v", result.Report)
	}
	if strings.Contains(result.Content, "<think>") || strings.Contains(result.Content, "hidden reasoning") {
		t.Fatalf("expected think block stripped, got %q", result.Content)
	}
	if !strings.Contains(result.Content, "Summary text") {
		t.Fatalf("expected fallback content, got %q", result.Content)
	}
}
