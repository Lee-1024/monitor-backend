package opsassistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"monitor-backend/opsassistant/core"
	"monitor-backend/opsassistant/knowledge"
	"monitor-backend/opsassistant/memory"
	"monitor-backend/opsassistant/workflow"
)

var ErrModelUnavailable = errors.New("LLM config is not enabled or the current model interface does not support ops assistant")

type Assistant struct {
	model        Model
	tools        []Tool
	now          func() time.Time
	sessionStore memory.Store
	userID       uint
	retriever    knowledge.Retriever
}

type AssistantOption func(*Assistant)

func WithSessionStore(store memory.Store) AssistantOption {
	return func(a *Assistant) {
		a.sessionStore = store
	}
}

func WithUserID(userID uint) AssistantOption {
	return func(a *Assistant) {
		a.userID = userID
	}
}

func WithKnowledgeRetriever(retriever knowledge.Retriever) AssistantOption {
	return func(a *Assistant) {
		a.retriever = retriever
	}
}

func NewAssistant(model Model, tools []Tool, options ...AssistantOption) *Assistant {
	assistant := &Assistant{
		model: model,
		tools: tools,
		now:   time.Now,
	}
	for _, option := range options {
		option(assistant)
	}
	return assistant
}

func (a *Assistant) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if a.model == nil {
		return nil, ErrModelUnavailable
	}
	if strings.TrimSpace(req.Message) == "" {
		return nil, fmt.Errorf("message is required")
	}

	session := a.loadSession(ctx, req)
	req = a.mergeSessionContext(req, session)
	a.appendSessionMessage(session, "user", req.Message)

	diagnosis, toolResults, err := a.runWorkflow(ctx, req, nil)
	if err != nil {
		return nil, err
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("ops_%d", a.now().UnixNano())
	}
	session.SessionID = sessionID
	a.updateSessionContext(session, req, diagnosis)
	a.appendSessionMessage(session, "assistant", diagnosis.Content)
	_ = a.saveSession(ctx, session)

	return &ChatResponse{
		SessionID: sessionID,
		Answer:    diagnosis.Content,
		ToolCalls: toolCallsFromExecutionResults(toolResults),
	}, nil
}

func (a *Assistant) Stream(ctx context.Context, req ChatRequest, emit func(StreamEvent) error) error {
	if a.model == nil {
		return ErrModelUnavailable
	}
	if strings.TrimSpace(req.Message) == "" {
		return fmt.Errorf("message is required")
	}

	session := a.loadSession(ctx, req)
	req = a.mergeSessionContext(req, session)
	a.appendSessionMessage(session, "user", req.Message)

	diagnosis, _, err := a.runWorkflow(ctx, req, emit)
	if err != nil {
		return err
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("ops_%d", a.now().UnixNano())
	}
	session.SessionID = sessionID
	a.updateSessionContext(session, req, diagnosis)
	a.appendSessionMessage(session, "assistant", diagnosis.Content)
	_ = a.saveSession(ctx, session)
	return emit(StreamEvent{Type: EventDone, SessionID: sessionID})
}

func (a *Assistant) loadSession(ctx context.Context, req ChatRequest) *memory.Session {
	userID := a.userID
	if userID == 0 {
		userID = 1
	}
	if a.sessionStore != nil && req.SessionID != "" {
		if session, err := a.sessionStore.Get(ctx, userID, req.SessionID); err == nil {
			return session
		}
	}
	now := a.now()
	return &memory.Session{
		SessionID: req.SessionID,
		UserID:    userID,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (a *Assistant) mergeSessionContext(req ChatRequest, session *memory.Session) ChatRequest {
	if session == nil {
		return req
	}
	if req.HostID == "" {
		req.HostID = session.Context.HostID
	}
	if req.TimeRange == nil && session.Context.TimeRange != nil {
		req.TimeRange = &TimeRange{From: session.Context.TimeRange.From, To: session.Context.TimeRange.To}
	}
	return req
}

func (a *Assistant) updateSessionContext(session *memory.Session, req ChatRequest, diagnosis workflowDiagnosis) {
	if session == nil {
		return
	}
	if req.HostID != "" {
		session.Context.HostID = req.HostID
	}
	if req.TimeRange != nil {
		session.Context.TimeRange = &memory.TimeRange{From: req.TimeRange.From, To: req.TimeRange.To}
	}
	if diagnosis.Report != nil {
		session.Title = diagnosis.Report.Title
	}
}

func (a *Assistant) appendSessionMessage(session *memory.Session, role string, content string) {
	if session == nil || strings.TrimSpace(content) == "" {
		return
	}
	memory.AppendMessage(session, role, content, a.now())
}

func (a *Assistant) saveSession(ctx context.Context, session *memory.Session) error {
	if a.sessionStore == nil || session == nil || session.SessionID == "" {
		return nil
	}
	return a.sessionStore.Save(ctx, session)
}

func (a *Assistant) runWorkflow(ctx context.Context, req ChatRequest, emit func(StreamEvent) error) (workflowDiagnosis, []ToolExecutionResult, error) {
	if err := emitIfPresent(emit, StreamEvent{Type: EventStatus, Content: "identifying intent..."}); err != nil {
		return workflowDiagnosis{}, nil, err
	}
	intent := a.classifyIntent(ctx, req)
	if err := emitIfPresent(emit, StreamEvent{Type: EventGraphNode, Node: "intent_classifier", Status: "completed", Summary: "intent: " + intent.Intent, Data: intent}); err != nil {
		return workflowDiagnosis{}, nil, err
	}
	if len(intent.MissingContext) > 0 {
		content := intent.Clarification
		if content == "" {
			content = "Please select a host before continuing."
		}
		if err := emitIfPresent(emit, StreamEvent{Type: EventContent, Content: content}); err != nil {
			return workflowDiagnosis{}, nil, err
		}
		return workflowDiagnosis{Content: content}, nil, nil
	}

	plan := planTools(intent, req)
	if err := emitIfPresent(emit, StreamEvent{Type: EventGraphNode, Node: "tool_planner", Status: "completed", Summary: fmt.Sprintf("planned %d read-only tools", len(plan.Calls)), Data: plan}); err != nil {
		return workflowDiagnosis{}, nil, err
	}

	result, err := workflow.NewGenericRunner(a.model).Run(ctx, workflow.Input{
		Request:  core.ChatRequest(req),
		Intent:   core.IntentResult(intent),
		Plan:     core.ToolPlan(plan),
		Tools:    coreTools(a.tools),
		Model:    a.model,
		Evidence: coreEvidence(a.retrieveKnowledgeEvidence(ctx, req, intent)),
	}, func(event core.StreamEvent) error {
		return emitIfPresent(emit, StreamEvent(event))
	})
	if err != nil {
		return workflowDiagnosis{}, toolExecutionResults(result.Tools), err
	}
	return workflowDiagnosis{Content: result.Content, Report: result.Report}, toolExecutionResults(result.Tools), nil
}

func (a *Assistant) retrieveKnowledgeEvidence(ctx context.Context, req ChatRequest, intent IntentResult) []Evidence {
	if a.retriever == nil {
		return nil
	}
	docs, err := a.retriever.Retrieve(ctx, knowledge.Query{
		Text:     req.Message,
		HostID:   req.HostID,
		Intent:   intent.Intent,
		Limit:    5,
		MinScore: 0.05,
	})
	if err != nil {
		return nil
	}
	evidence := make([]Evidence, 0, len(docs))
	for _, doc := range docs {
		if doc.Score < 0.05 {
			continue
		}
		text := doc.Snippet
		if text == "" {
			text = doc.Title
		}
		evidence = append(evidence, Evidence{
			Type:   "knowledge",
			Source: "knowledge:" + doc.ID,
			Text:   text,
		})
	}
	return evidence
}

type workflowDiagnosis struct {
	Content string
	Report  *DiagnosisReport
}

func (a *Assistant) classifyIntent(ctx context.Context, req ChatRequest) IntentResult {
	result := fallbackAssistantIntent(req)
	answer, err := a.model.Complete(ctx, BuildIntentPrompt(req))
	if err == nil {
		var parsed IntentResult
		if json.Unmarshal([]byte(extractJSON(answer)), &parsed) == nil && parsed.Intent != "" {
			result = parsed
		}
	}
	if result.Confidence <= 0 {
		result.Confidence = 0.5
	}
	if result.Intent == "" {
		result.Intent = "global_health"
	}
	if strings.TrimSpace(req.HostID) != "" {
		result.MissingContext = removeMissing(result.MissingContext, "host_id")
		if len(result.MissingContext) == 0 {
			result.Clarification = ""
		}
	}
	if result.Intent == "host_performance" && strings.TrimSpace(req.HostID) == "" {
		result.MissingContext = appendMissing(result.MissingContext, "host_id")
		result.Clarification = "Please select a host before continuing."
	}
	return result
}

func fallbackAssistantIntent(req ChatRequest) IntentResult {
	message := strings.ToLower(req.Message)
	intent := "global_health"
	if strings.Contains(message, "cpu") || strings.Contains(message, "memory") || strings.Contains(message, "disk") || strings.Contains(message, "mem") {
		intent = "host_performance"
	}
	if strings.Contains(message, "alert") || strings.Contains(message, "alarm") {
		intent = "alert_root_cause"
	}
	return IntentResult{Intent: intent, Confidence: 0.55}
}

func planTools(intent IntentResult, req ChatRequest) ToolPlan {
	hasHost := strings.TrimSpace(req.HostID) != ""
	var calls []PlannedToolCall
	switch intent.Intent {
	case "host_performance":
		if hasHost {
			calls = append(calls,
				PlannedToolCall{Tool: "get_agent_detail", Required: false, Summary: "query selected host detail"},
				PlannedToolCall{Tool: "get_latest_metrics", Required: true, Summary: "query selected host latest metrics"},
				PlannedToolCall{Tool: "get_history_metrics", Required: true, Summary: "query selected host historical metrics"},
			)
		}
		calls = append(calls,
			PlannedToolCall{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
			PlannedToolCall{Tool: "get_anomaly_events", Required: false, Summary: "query recent anomaly events"},
		)
	case "alert_root_cause":
		calls = append(calls, PlannedToolCall{Tool: "get_recent_alerts", Required: true, Summary: "query recent alerts"})
		if hasHost {
			calls = append(calls, PlannedToolCall{Tool: "get_history_metrics", Required: false, Summary: "query metrics around alert time"})
		}
		calls = append(calls,
			PlannedToolCall{Tool: "get_anomaly_events", Required: false, Summary: "query anomaly events"},
			PlannedToolCall{Tool: "search_knowledge", Required: false, Summary: "search knowledge base"},
		)
	default:
		calls = append(calls,
			PlannedToolCall{Tool: "list_agents", Required: true, Summary: "query host online status"},
			PlannedToolCall{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
			PlannedToolCall{Tool: "get_anomaly_events", Required: false, Summary: "query recent anomaly events"},
			PlannedToolCall{Tool: "get_latest_inspection_report", Required: false, Summary: "query latest inspection report"},
		)
	}
	if len(calls) > 8 {
		calls = calls[:8]
	}
	return ToolPlan{Intent: intent.Intent, Calls: calls}
}

func extractJSON(value string) string {
	start := strings.Index(value, "{")
	end := strings.LastIndex(value, "}")
	if start < 0 || end < start {
		return value
	}
	return value[start : end+1]
}

func appendMissing(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func removeMissing(values []string, value string) []string {
	filtered := make([]string, 0, len(values))
	for _, existing := range values {
		if existing != value {
			filtered = append(filtered, existing)
		}
	}
	return filtered
}

func emitIfPresent(emit func(StreamEvent) error, event StreamEvent) error {
	if emit == nil {
		return nil
	}
	return emit(event)
}

func toolCallsFromExecutionResults(results []ToolExecutionResult) []ToolCall {
	calls := make([]ToolCall, 0, len(results))
	for _, result := range results {
		calls = append(calls, ToolCall{Tool: result.Tool, Summary: result.Summary})
	}
	return calls
}

func coreTools(tools []Tool) []core.Tool {
	converted := make([]core.Tool, 0, len(tools))
	for _, tool := range tools {
		converted = append(converted, core.Tool(tool))
	}
	return converted
}

func coreEvidence(evidence []Evidence) []core.Evidence {
	converted := make([]core.Evidence, 0, len(evidence))
	for _, item := range evidence {
		converted = append(converted, core.Evidence(item))
	}
	return converted
}

func toolExecutionResults(results []core.ToolExecutionResult) []ToolExecutionResult {
	converted := make([]ToolExecutionResult, 0, len(results))
	for _, result := range results {
		converted = append(converted, ToolExecutionResult(result))
	}
	return converted
}

func shouldSkipTool(name string, req ChatRequest) bool {
	if req.HostID != "" {
		return false
	}
	switch name {
	case "get_latest_metrics", "get_history_metrics":
		return true
	default:
		return false
	}
}
