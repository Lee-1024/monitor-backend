package opsassistant

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"monitor-backend/opsassistant/knowledge"
	"monitor-backend/opsassistant/memory"
)

type fakeModel struct {
	answer string
	prompt string
}

func (m *fakeModel) Complete(ctx context.Context, prompt string) (string, error) {
	m.prompt = prompt
	return m.answer, nil
}

type fakeRetriever struct {
	docs []knowledge.Document
}

func (r fakeRetriever) Retrieve(ctx context.Context, query knowledge.Query) ([]knowledge.Document, error) {
	return r.docs, nil
}

func (m *fakeModel) Stream(ctx context.Context, prompt string, emit func(StreamEvent) error) error {
	m.prompt = prompt
	parts := []string{"diagnosis", " done"}
	if m.answer != "" {
		mid := len(m.answer) / 2
		parts = []string{m.answer[:mid], m.answer[mid:]}
	}
	for _, part := range parts {
		if err := emit(StreamEvent{Type: EventContent, Content: part}); err != nil {
			return err
		}
	}
	return nil
}

func TestAssistantReturnsConfigErrorWhenModelMissing(t *testing.T) {
	assistant := NewAssistant(nil, nil)

	_, err := assistant.Chat(context.Background(), ChatRequest{Message: "check system"})
	if err == nil {
		t.Fatal("expected missing model error")
	}
	if !strings.Contains(err.Error(), "LLM config") {
		t.Fatalf("expected config error, got %v", err)
	}
}

func TestAssistantEmitsToolEventsBeforeContent(t *testing.T) {
	model := &fakeModel{answer: "diagnosis done"}
	assistant := NewAssistant(model, []Tool{
		{
			Name:        "list_agents",
			Description: "list agents",
			Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
				return ToolResult{
					Summary: "queried 1 host",
					Content: "host-01 online",
				}, nil
			},
		},
	})

	var events []StreamEvent
	err := assistant.Stream(context.Background(), ChatRequest{Message: "show risks"}, func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(events))
	}
	if events[0].Type != EventStatus {
		t.Fatalf("expected first event to be status, got %s", events[0].Type)
	}
	toolIndex := indexOfEventType(events, EventToolCall)
	contentIndex := indexOfEventType(events, EventContent)
	if toolIndex < 0 {
		t.Fatalf("expected tool_call event in %#v", events)
	}
	if contentIndex >= 0 && toolIndex > contentIndex {
		t.Fatalf("expected tool_call before content, got %#v", events)
	}
	if events[len(events)-1].Type != EventDone {
		t.Fatalf("expected last event to be done, got %s", events[len(events)-1].Type)
	}
}

func TestAssistantSkipsHostMetricToolsWithoutHostContext(t *testing.T) {
	model := &fakeModel{answer: "diagnosis done"}
	called := false
	assistant := NewAssistant(model, []Tool{
		{
			Name:        "get_latest_metrics",
			Description: "query latest metrics",
			Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
				called = true
				return ToolResult{Name: "get_latest_metrics"}, nil
			},
		},
	})

	resp, err := assistant.Chat(context.Background(), ChatRequest{Message: "show global risk"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if called {
		t.Fatal("metric tool should not be called without host context")
	}
	if len(resp.ToolCalls) != 0 {
		t.Fatalf("expected no tool calls, got %d", len(resp.ToolCalls))
	}
}

func TestAssistantStreamEmitsGraphWorkflowEvents(t *testing.T) {
	model := &fakeModel{answer: `{"title":"Global health report","summary":"No critical risk found.","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	assistant := NewAssistant(model, []Tool{
		{
			Name:        "list_agents",
			Description: "list agents",
			Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
				return ToolResult{Name: "list_agents", Summary: "listed agents", Content: "host-01 online"}, nil
			},
		},
	})

	var events []StreamEvent
	err := assistant.Stream(context.Background(), ChatRequest{Message: "Show global health"}, func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}

	assertHasEventType(t, events, EventStatus)
	assertHasEventType(t, events, EventGraphNode)
	assertHasEventType(t, events, EventToolCall)
	assertHasEventType(t, events, EventReport)
	if events[len(events)-1].Type != EventDone {
		t.Fatalf("expected done as last event, got %#v", events[len(events)-1])
	}
}

func TestAssistantStreamEmitsContentBeforeFinalReport(t *testing.T) {
	model := &fakeModel{answer: `{"title":"Global health report","summary":"No critical risk found.","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	assistant := NewAssistant(model, nil)

	var events []StreamEvent
	err := assistant.Stream(context.Background(), ChatRequest{Message: "Show global health"}, func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}

	contentIndex := indexOfEventType(events, EventContent)
	reportIndex := indexOfEventType(events, EventReport)
	if contentIndex < 0 {
		t.Fatalf("expected streamed content before report, got %#v", events)
	}
	if reportIndex < 0 {
		t.Fatalf("expected final report event, got %#v", events)
	}
	if contentIndex > reportIndex {
		t.Fatalf("expected content before report, got %#v", events)
	}
}

func TestAssistantStreamClarifiesMissingHostContext(t *testing.T) {
	model := &fakeModel{answer: `{"intent":"host_performance","confidence":0.9,"required_context":["host_id"],"missing_context":[]}`}
	assistant := NewAssistant(model, nil)

	var events []StreamEvent
	err := assistant.Stream(context.Background(), ChatRequest{Message: "Why is CPU high?"}, func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}

	assertHasEventType(t, events, EventContent)
	for _, event := range events {
		if event.Type == EventToolCall {
			t.Fatalf("expected no tool calls when host context is missing, got %#v", events)
		}
	}
}

func TestAssistantDoesNotClarifyHostWhenHostContextSelected(t *testing.T) {
	model := &fakeModel{answer: `{"intent":"host_performance","confidence":0.9,"required_context":["host_id"],"missing_context":["host_id"]}`}
	assistant := NewAssistant(model, []Tool{
		{
			Name: "get_latest_metrics",
			Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
				if req.HostID != "master" {
					t.Fatalf("expected selected host_id to be passed, got %q", req.HostID)
				}
				return ToolResult{Name: "get_latest_metrics", Summary: "metrics queried", Content: "memory=58%"}, nil
			},
		},
	})

	var events []StreamEvent
	err := assistant.Stream(context.Background(), ChatRequest{Message: "check master host status", HostID: "master"}, func(event StreamEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}

	assertHasEventType(t, events, EventToolCall)
}

func TestHostPerformancePlanRunsHostDetailBeforeMetrics(t *testing.T) {
	model := &fakeModel{answer: `{"title":"Host report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	var calls []string
	assistant := NewAssistant(model, []Tool{
		{Name: "get_agent_detail", Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
			calls = append(calls, "get_agent_detail")
			return ToolResult{Name: "get_agent_detail", Summary: "host detail", Content: "master online"}, nil
		}},
		{Name: "get_latest_metrics", Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
			calls = append(calls, "get_latest_metrics")
			return ToolResult{Name: "get_latest_metrics", Summary: "latest metrics", Content: "cpu=10"}, nil
		}},
	})

	_, err := assistant.Chat(context.Background(), ChatRequest{Message: "check CPU status", HostID: "master"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if len(calls) < 2 {
		t.Fatalf("expected host detail and metrics calls, got %#v", calls)
	}
	if calls[0] != "get_agent_detail" || calls[1] != "get_latest_metrics" {
		t.Fatalf("unexpected host performance order: %#v", calls)
	}
}

func TestAssistantUsesSessionHostWhenRequestHostMissing(t *testing.T) {
	store := memory.NewMemoryStore()
	_ = store.Save(context.Background(), &memory.Session{
		SessionID: "ops_1",
		UserID:    1,
		Context:   memory.Context{HostID: "master"},
	})
	model := &fakeModel{answer: `{"title":"Host report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	calledHost := ""
	assistant := NewAssistant(model, []Tool{
		{
			Name: "get_latest_metrics",
			Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
				calledHost = req.HostID
				return ToolResult{Name: "get_latest_metrics", Summary: "metrics", Content: "ok"}, nil
			},
		},
	}, WithUserID(1), WithSessionStore(store))

	_, err := assistant.Chat(context.Background(), ChatRequest{SessionID: "ops_1", Message: "continue checking this host CPU"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if calledHost != "master" {
		t.Fatalf("expected session host master, got %q", calledHost)
	}
}

func TestAssistantRequestHostOverridesSessionHost(t *testing.T) {
	store := memory.NewMemoryStore()
	_ = store.Save(context.Background(), &memory.Session{
		SessionID: "ops_1",
		UserID:    1,
		Context:   memory.Context{HostID: "old-host"},
	})
	model := &fakeModel{answer: `{"title":"Host report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	calledHost := ""
	assistant := NewAssistant(model, []Tool{
		{
			Name: "get_latest_metrics",
			Run: func(ctx context.Context, req ChatRequest) (ToolResult, error) {
				calledHost = req.HostID
				return ToolResult{Name: "get_latest_metrics", Summary: "metrics", Content: "ok"}, nil
			},
		},
	}, WithUserID(1), WithSessionStore(store))

	_, err := assistant.Chat(context.Background(), ChatRequest{SessionID: "ops_1", HostID: "new-host", Message: "check selected host CPU"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if calledHost != "new-host" {
		t.Fatalf("expected request host new-host, got %q", calledHost)
	}
}

func TestAssistantPersistsUserAndAssistantMessages(t *testing.T) {
	store := memory.NewMemoryStore()
	model := &fakeModel{answer: `{"title":"Global report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	assistant := NewAssistant(model, nil, WithUserID(1), WithSessionStore(store))

	resp, err := assistant.Chat(context.Background(), ChatRequest{Message: "show global health"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	session, err := store.Get(context.Background(), 1, resp.SessionID)
	if err != nil {
		t.Fatalf("load saved session: %v", err)
	}
	if len(session.Messages) != 2 {
		t.Fatalf("expected user and assistant messages, got %#v", session.Messages)
	}
	if session.Messages[0].Role != "user" || session.Messages[1].Role != "assistant" {
		t.Fatalf("unexpected messages: %#v", session.Messages)
	}
}

func TestAssistantAddsKnowledgeEvidenceWhenRetrieverReturnsDocuments(t *testing.T) {
	model := &fakeModel{answer: `{"title":"Global report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	assistant := NewAssistant(model, nil, WithKnowledgeRetriever(fakeRetriever{docs: []knowledge.Document{
		{ID: "12", Title: "Linux memory SOP", Score: 0.9, Snippet: "check cache and process usage"},
	}}))

	_, err := assistant.Chat(context.Background(), ChatRequest{Message: "memory high", HostID: "master"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if !strings.Contains(model.prompt, "knowledge:12") {
		t.Fatalf("expected knowledge source in prompt, got %s", model.prompt)
	}
	if !strings.Contains(model.prompt, "check cache and process usage") {
		t.Fatalf("expected knowledge snippet in prompt, got %s", model.prompt)
	}
}

func TestAssistantSkipsLowScoreKnowledgeDocuments(t *testing.T) {
	model := &fakeModel{answer: `{"title":"Global report","summary":"ok","risk_level":"low","confidence":0.8,"evidence":[],"possible_causes":[],"recommendations":[],"related_entities":{}}`}
	assistant := NewAssistant(model, nil, WithKnowledgeRetriever(fakeRetriever{docs: []knowledge.Document{
		{ID: "12", Title: "Linux memory SOP", Score: 0.01, Snippet: "too weak"},
	}}))

	_, err := assistant.Chat(context.Background(), ChatRequest{Message: "memory high", HostID: "master"})
	if err != nil {
		t.Fatalf("chat failed: %v", err)
	}
	if strings.Contains(model.prompt, "knowledge:12") {
		t.Fatalf("did not expect low score knowledge in prompt: %s", model.prompt)
	}
}

func TestBuildPromptIncludesHostAndTimeContext(t *testing.T) {
	from := time.Date(2026, 5, 21, 8, 0, 0, 0, time.FixedZone("CST", 8*3600))
	to := time.Date(2026, 5, 21, 13, 0, 0, 0, time.FixedZone("CST", 8*3600))
	prompt := BuildPrompt(ChatRequest{
		Message: "why CPU is high",
		HostID:  "host-01",
		TimeRange: &TimeRange{
			From: from,
			To:   to,
		},
	}, []ToolResult{
		{Summary: "query CPU metrics", Content: "cpu=91"},
	})

	for _, expected := range []string{"host-01", "2026-05-21T08:00:00+08:00", "2026-05-21T13:00:00+08:00", "query CPU metrics", "cpu=91", "why CPU is high"} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("prompt missing %q:\n%s", expected, prompt)
		}
	}
}

func TestStreamEventSupportsGraphNodeAndReport(t *testing.T) {
	event := StreamEvent{
		Type:    EventGraphNode,
		Node:    "intent_classifier",
		Status:  "completed",
		Summary: "classified as host performance diagnosis",
		Report: &DiagnosisReport{
			Title:      "Host performance report",
			Summary:    "Current risk is low.",
			RiskLevel:  "low",
			Confidence: 0.88,
		},
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	encoded := string(payload)
	for _, expected := range []string{
		`"type":"graph_node"`,
		`"node":"intent_classifier"`,
		`"status":"completed"`,
		`"report"`,
		`"risk_level":"low"`,
	} {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("encoded event missing %s: %s", expected, encoded)
		}
	}
}

func TestExistingContentAndToolEventsRemainCompatible(t *testing.T) {
	contentPayload, err := json.Marshal(StreamEvent{Type: EventContent, Content: "hello"})
	if err != nil {
		t.Fatalf("marshal content event: %v", err)
	}
	if string(contentPayload) != `{"type":"content","content":"hello"}` {
		t.Fatalf("unexpected content event JSON: %s", string(contentPayload))
	}

	toolPayload, err := json.Marshal(StreamEvent{
		Type:    EventToolCall,
		Tool:    "get_latest_metrics",
		Summary: "query latest metrics",
	})
	if err != nil {
		t.Fatalf("marshal tool event: %v", err)
	}
	encoded := string(toolPayload)
	for _, expected := range []string{
		`"type":"tool_call"`,
		`"tool":"get_latest_metrics"`,
		`"summary":"query latest metrics"`,
	} {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("encoded tool event missing %s: %s", expected, encoded)
		}
	}
}

func assertHasEventType(t *testing.T, events []StreamEvent, eventType string) {
	t.Helper()
	for _, event := range events {
		if event.Type == eventType {
			return
		}
	}
	t.Fatalf("expected event type %s in %#v", eventType, events)
}

func indexOfEventType(events []StreamEvent, eventType string) int {
	for i, event := range events {
		if event.Type == eventType {
			return i
		}
	}
	return -1
}
