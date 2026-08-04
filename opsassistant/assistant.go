package opsassistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/callbacks"
	"github.com/cloudwego/eino/compose"

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
	runnable, err := a.compileAssistantGraph(ctx)
	if err != nil {
		return workflowDiagnosis{}, nil, err
	}
	if err := emitIfPresent(emit, StreamEvent{Type: EventStatus, Content: "identifying intent..."}); err != nil {
		return workflowDiagnosis{}, nil, err
	}
	state, err := runnable.Invoke(ctx, assistantGraphState{
		Request: req,
		Emit:    emit,
	}, compose.WithCallbacks(newAssistantTimelineCallback(emit)))
	return state.Diagnosis, state.ToolResults, err
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

type assistantGraphState struct {
	Request     ChatRequest
	Intent      IntentResult
	Plan        ToolPlan
	Diagnosis   workflowDiagnosis
	ToolResults []ToolExecutionResult
	Emit        func(StreamEvent) error
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
	if requiresAssistantHost(result.Intent) && strings.TrimSpace(req.HostID) == "" {
		result.MissingContext = appendMissing(result.MissingContext, "host_id")
		result.Clarification = "Please select a host before continuing."
	}
	return result
}

func fallbackAssistantIntent(req ChatRequest) IntentResult {
	message := strings.ToLower(req.Message)
	intent := "global_health"
	if strings.Contains(message, "capacity") || strings.Contains(message, "容量") || strings.Contains(message, "预测") || strings.Contains(message, "阈值") || strings.Contains(message, "扩容") {
		intent = "capacity_planning"
	}
	if strings.Contains(message, "cost") || strings.Contains(message, "成本") || strings.Contains(message, "降配") || strings.Contains(message, "优化") || strings.Contains(message, "rightsizing") {
		intent = "cost_optimization"
	}
	if strings.Contains(message, "performance") || strings.Contains(message, "性能分析") || strings.Contains(message, "瓶颈") {
		intent = "performance_analysis"
	}
	if intent == "global_health" && (strings.Contains(message, "cpu") || strings.Contains(message, "memory") || strings.Contains(message, "disk") || strings.Contains(message, "mem") || strings.Contains(message, "内存") || strings.Contains(message, "磁盘") || strings.Contains(message, "性能")) {
		intent = "host_performance"
	}
	if strings.Contains(message, "alert") || strings.Contains(message, "alarm") || strings.Contains(message, "告警") {
		intent = "alert_root_cause"
	}
	if strings.Contains(message, "anomaly") || strings.Contains(message, "异常") {
		intent = "anomaly_analysis"
	}
	if strings.Contains(message, "inspection") || strings.Contains(message, "巡检") {
		intent = "inspection_summary"
	}
	if strings.Contains(message, "knowledge") || strings.Contains(message, "知识") {
		intent = "knowledge_troubleshooting"
	}
	if strings.Contains(message, "log") || strings.Contains(message, "日志") {
		intent = "log_investigation"
	}
	return IntentResult{Intent: intent, Confidence: 0.55}
}

func planTools(intent IntentResult, req ChatRequest) ToolPlan {
	hasHost := strings.TrimSpace(req.HostID) != ""
	var calls []PlannedToolCall
	switch intent.Intent {
	case "capacity_planning":
		if hasHost {
			calls = append(calls, PlannedToolCall{Tool: "get_capacity_prediction", Required: true, Summary: "query capacity prediction"})
		}
		calls = append(calls,
			PlannedToolCall{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
			PlannedToolCall{Tool: "search_knowledge", Required: false, Summary: "search capacity planning knowledge"},
		)
	case "cost_optimization":
		if hasHost {
			calls = append(calls, PlannedToolCall{Tool: "get_cost_optimization", Required: true, Summary: "query resource cost optimization evidence"})
		}
		calls = append(calls,
			PlannedToolCall{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
			PlannedToolCall{Tool: "search_knowledge", Required: false, Summary: "search cost optimization knowledge"},
		)
	case "performance_analysis":
		if hasHost {
			calls = append(calls, PlannedToolCall{Tool: "get_performance_summary", Required: true, Summary: "query host performance summary"})
		}
		calls = append(calls,
			PlannedToolCall{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
			PlannedToolCall{Tool: "get_anomaly_events", Required: false, Summary: "query recent anomaly events"},
			PlannedToolCall{Tool: "search_knowledge", Required: false, Summary: "search performance troubleshooting knowledge"},
		)
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
	case "anomaly_analysis":
		if hasHost {
			calls = append(calls, PlannedToolCall{Tool: "detect_anomalies", Required: true, Summary: "query anomaly detection evidence"})
		}
		calls = append(calls,
			PlannedToolCall{Tool: "get_history_metrics", Required: false, Summary: "query metrics around anomaly time"},
			PlannedToolCall{Tool: "search_knowledge", Required: false, Summary: "search anomaly troubleshooting knowledge"},
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

func requiresAssistantHost(intent string) bool {
	switch intent {
	case "host_performance", "capacity_planning", "cost_optimization", "performance_analysis", "anomaly_analysis":
		return true
	default:
		return false
	}
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

func (a *Assistant) compileAssistantGraph(ctx context.Context) (compose.Runnable[assistantGraphState, assistantGraphState], error) {
	graph := compose.NewGraph[assistantGraphState, assistantGraphState]()
	if err := graph.AddLambdaNode("intent_classifier", compose.InvokableLambda(a.runIntentClassifierNode), compose.WithNodeName("intent_classifier")); err != nil {
		return nil, err
	}
	if err := graph.AddLambdaNode("context_guard", compose.InvokableLambda(a.runContextGuardNode), compose.WithNodeName("context_guard")); err != nil {
		return nil, err
	}
	if err := graph.AddLambdaNode("tool_planner", compose.InvokableLambda(a.runToolPlannerNode), compose.WithNodeName("tool_planner")); err != nil {
		return nil, err
	}
	if err := graph.AddLambdaNode("diagnostic_workflow", compose.InvokableLambda(a.runDiagnosticWorkflowNode), compose.WithNodeName("diagnostic_workflow")); err != nil {
		return nil, err
	}
	for _, edge := range [][2]string{
		{compose.START, "intent_classifier"},
		{"intent_classifier", "context_guard"},
		{"context_guard", "tool_planner"},
		{"tool_planner", "diagnostic_workflow"},
		{"diagnostic_workflow", compose.END},
	} {
		if err := graph.AddEdge(edge[0], edge[1]); err != nil {
			return nil, err
		}
	}
	return graph.Compile(ctx, compose.WithGraphName("ops_assistant"))
}

func (a *Assistant) runIntentClassifierNode(ctx context.Context, state assistantGraphState) (assistantGraphState, error) {
	if err := emitIfPresent(state.Emit, StreamEvent{Type: EventStatus, Content: "identifying intent..."}); err != nil {
		return state, err
	}
	state.Intent = a.classifyIntent(ctx, state.Request)
	if err := emitIfPresent(state.Emit, StreamEvent{Type: EventGraphNode, Node: "intent_classifier", Status: "completed", Summary: "intent: " + state.Intent.Intent, Data: state.Intent}); err != nil {
		return state, err
	}
	return state, nil
}

func (a *Assistant) runContextGuardNode(ctx context.Context, state assistantGraphState) (assistantGraphState, error) {
	if len(state.Intent.MissingContext) == 0 {
		return state, nil
	}
	content := state.Intent.Clarification
	if content == "" {
		content = "Please select a host before continuing."
	}
	state.Diagnosis = workflowDiagnosis{Content: content}
	if err := emitIfPresent(state.Emit, StreamEvent{Type: EventContent, Content: content}); err != nil {
		return state, err
	}
	if err := emitIfPresent(state.Emit, StreamEvent{Type: EventGraphNode, Node: "context_guard", Status: "completed", Summary: "missing context: " + strings.Join(state.Intent.MissingContext, ","), Data: state.Intent.MissingContext}); err != nil {
		return state, err
	}
	return state, nil
}

func (a *Assistant) runToolPlannerNode(ctx context.Context, state assistantGraphState) (assistantGraphState, error) {
	if len(state.Intent.MissingContext) > 0 {
		return state, nil
	}
	state.Plan = planTools(state.Intent, state.Request)
	if err := emitIfPresent(state.Emit, StreamEvent{Type: EventGraphNode, Node: "tool_planner", Status: "completed", Summary: fmt.Sprintf("planned %d read-only tools", len(state.Plan.Calls)), Data: state.Plan}); err != nil {
		return state, err
	}
	return state, nil
}

func (a *Assistant) runDiagnosticWorkflowNode(ctx context.Context, state assistantGraphState) (assistantGraphState, error) {
	if len(state.Intent.MissingContext) > 0 {
		return state, nil
	}
	runner := workflow.Runner(workflow.NewGenericRunner(a.model))
	switch state.Intent.Intent {
	case "host_performance":
		runner = workflow.NewHostPerformanceRunner(a.model)
	case "capacity_planning":
		runner = workflow.NewCapacityPlanningRunner(a.model)
	case "cost_optimization":
		runner = workflow.NewCostOptimizationRunner(a.model)
	case "anomaly_analysis":
		runner = workflow.NewAnomalyAnalysisRunner(a.model)
	case "alert_root_cause":
		runner = workflow.NewAlertRootCauseRunner(a.model)
	}
	result, err := runner.Run(ctx, workflow.Input{
		Request:  core.ChatRequest(state.Request),
		Intent:   core.IntentResult(state.Intent),
		Plan:     core.ToolPlan(state.Plan),
		Tools:    coreTools(a.tools),
		Model:    a.model,
		Evidence: coreEvidence(a.retrieveKnowledgeEvidence(ctx, state.Request, state.Intent)),
	}, func(event core.StreamEvent) error {
		return emitIfPresent(state.Emit, StreamEvent(event))
	})
	state.ToolResults = toolExecutionResults(result.Tools)
	state.Diagnosis = workflowDiagnosis{Content: result.Content, Report: result.Report}
	return state, err
}

func newAssistantTimelineCallback(emit func(StreamEvent) error) callbacks.Handler {
	graphNodes := map[string]bool{
		"intent_classifier":   true,
		"context_guard":       true,
		"tool_planner":        true,
		"diagnostic_workflow": true,
	}
	return callbacks.NewHandlerBuilder().
		OnStartFn(func(ctx context.Context, info *callbacks.RunInfo, input callbacks.CallbackInput) context.Context {
			if emit == nil || info == nil || !graphNodes[info.Name] {
				return ctx
			}
			_ = emit(StreamEvent{Type: EventGraphNode, Node: info.Name, Status: "running", Summary: info.Name + " started"})
			return ctx
		}).
		OnErrorFn(func(ctx context.Context, info *callbacks.RunInfo, err error) context.Context {
			if emit == nil || info == nil || !graphNodes[info.Name] {
				return ctx
			}
			_ = emit(StreamEvent{Type: EventGraphNode, Node: info.Name, Status: "failed", Summary: err.Error()})
			return ctx
		}).
		Build()
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
