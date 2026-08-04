package workflow

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"

	"monitor-backend/opsassistant/core"
	"monitor-backend/opsassistant/report"
)

type GenericRunner struct {
	model core.Model
}

type genericGraphState struct {
	Input    Input
	Results  []core.ToolExecutionResult
	Evidence []core.Evidence
	Result   Result
	Emit     func(core.StreamEvent) error
}

func NewGenericRunner(model core.Model) *GenericRunner {
	return &GenericRunner{model: model}
}

func (r *GenericRunner) Run(ctx context.Context, input Input, emit func(core.StreamEvent) error) (Result, error) {
	model := input.Model
	if model == nil {
		model = r.model
	}
	input.Model = model
	if err := emitIfPresent(emit, core.StreamEvent{Type: core.EventStatus, Content: "正在查询监控数据..."}); err != nil {
		return Result{}, err
	}
	plan := input.Plan
	if len(plan.Calls) == 0 {
		plan = defaultPlan(input.Intent, input.Request)
	}
	input.Plan = plan

	runnable, err := compileGenericGraph(ctx)
	if err != nil {
		return Result{}, err
	}
	state, err := runnable.Invoke(ctx, genericGraphState{
		Input: input,
		Emit:  emit,
	}, compose.WithCallbacks(newEinoTimelineCallback(emit)))
	if err != nil {
		return Result{}, err
	}
	return state.Result, nil
}

func compileGenericGraph(ctx context.Context) (compose.Runnable[genericGraphState, genericGraphState], error) {
	graph := compose.NewGraph[genericGraphState, genericGraphState]()
	if err := graph.AddLambdaNode("tool_executor", compose.InvokableLambda(runToolExecutorNode), compose.WithNodeName("tool_executor")); err != nil {
		return nil, err
	}
	if err := graph.AddLambdaNode("evidence_builder", compose.InvokableLambda(runEvidenceBuilderNode), compose.WithNodeName("evidence_builder")); err != nil {
		return nil, err
	}
	if err := graph.AddLambdaNode("report_generator", compose.InvokableLambda(runReportGeneratorNode), compose.WithNodeName("report_generator")); err != nil {
		return nil, err
	}
	for _, edge := range [][2]string{
		{compose.START, "tool_executor"},
		{"tool_executor", "evidence_builder"},
		{"evidence_builder", "report_generator"},
		{"report_generator", compose.END},
	} {
		if err := graph.AddEdge(edge[0], edge[1]); err != nil {
			return nil, err
		}
	}
	return graph.Compile(ctx, compose.WithGraphName("ops_assistant_generic"))
}

func runToolExecutorNode(ctx context.Context, state genericGraphState) (genericGraphState, error) {
	results := executePlan(ctx, state.Input.Request, state.Input.Plan, state.Input.Tools, state.Emit)
	state.Results = results
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: "tool_executor", Status: "completed", Summary: "tools executed", Data: results}); err != nil {
		return state, err
	}
	return state, nil
}

func runEvidenceBuilderNode(ctx context.Context, state genericGraphState) (genericGraphState, error) {
	evidence := append(evidenceFromResults(state.Results), state.Input.Evidence...)
	state.Evidence = evidence
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: "evidence_builder", Status: "completed", Summary: "evidence collected", Data: evidence}); err != nil {
		return state, err
	}
	return state, nil
}

func runReportGeneratorNode(ctx context.Context, state genericGraphState) (genericGraphState, error) {
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventStatus, Content: "正在生成诊断报告..."}); err != nil {
		return state, err
	}
	answer, err := generateAnswer(ctx, state.Input.Model, buildDiagnosisPrompt(state.Input.Request, state.Evidence), state.Emit)
	if err != nil {
		return state, err
	}
	content, parsed := parseReport(answer)
	state.Result = Result{Content: content, Report: parsed, Tools: state.Results}
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: "report_generator", Status: "completed", Summary: "report generated", Data: state.Result}); err != nil {
		return state, err
	}
	if parsed != nil {
		if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventReport, Report: parsed, Data: parsed}); err != nil {
			return state, err
		}
	} else if content != "" {
		if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventContent, Content: content}); err != nil {
			return state, err
		}
	}
	return state, nil
}

func executePlan(ctx context.Context, req core.ChatRequest, plan core.ToolPlan, tools []core.Tool, emit func(core.StreamEvent) error) []core.ToolExecutionResult {
	toolMap := make(map[string]core.Tool, len(tools))
	einoTools := make([]einotool.BaseTool, 0, len(tools))
	for _, tool := range tools {
		toolMap[tool.Name] = tool
		einoTools = append(einoTools, newEinoToolAdapter(tool))
	}
	results := make([]core.ToolExecutionResult, 0, len(plan.Calls))
	var toolCalls []schema.ToolCall
	reqPayload, _ := json.Marshal(req)
	for index, call := range plan.Calls {
		_, ok := toolMap[call.Tool]
		if !ok {
			continue
		}
		_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: call.Tool, Status: "running", Summary: call.Summary})
		toolCalls = append(toolCalls, schema.ToolCall{
			ID:   call.Tool,
			Type: "function",
			Function: schema.FunctionCall{
				Name:      call.Tool,
				Arguments: string(reqPayload),
			},
			Index: &index,
		})
	}
	if len(toolCalls) == 0 {
		return results
	}
	start := time.Now()
	toolNode, err := compose.NewToolNode(ctx, &compose.ToolsNodeConfig{Tools: einoTools, ExecuteSequentially: true})
	if err != nil {
		return failRunningToolCalls(plan, results, emit, time.Since(start).Milliseconds(), err.Error())
	}
	messages, err := toolNode.Invoke(ctx, schema.AssistantMessage("", toolCalls))
	duration := time.Since(start).Milliseconds()
	if err != nil {
		return failRunningToolCalls(plan, results, emit, duration, err.Error())
	}
	summaries := make(map[string]string, len(plan.Calls))
	for _, call := range plan.Calls {
		summaries[call.Tool] = call.Summary
	}
	for _, message := range messages {
		name := message.ToolName
		if name == "" {
			name = message.ToolCallID
		}
		var runResult einoToolRunResult
		if err := json.Unmarshal([]byte(message.Content), &runResult); err != nil {
			runResult = einoToolRunResult{Name: name, Summary: summaries[name], Error: err.Error(), Content: message.Content}
		}
		if runResult.Name == "" {
			runResult.Name = name
		}
		if runResult.Summary == "" {
			runResult.Summary = summaries[runResult.Name]
		}
		execResult := core.ToolExecutionResult{
			Tool:       runResult.Name,
			Summary:    runResult.Summary,
			Status:     "success",
			DurationMS: duration,
			Content:    runResult.Content,
		}
		if runResult.Error != "" {
			execResult.Status = "failed"
			execResult.Error = runResult.Error
			execResult.Content = runResult.Error
			_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: execResult.Tool, Status: "failed", Summary: execResult.Summary + ": " + runResult.Error, DurationMS: duration})
		} else {
			_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: execResult.Tool, Status: "completed", Summary: execResult.Summary, DurationMS: duration})
		}
		results = append(results, execResult)
	}
	return results
}

func failRunningToolCalls(plan core.ToolPlan, results []core.ToolExecutionResult, emit func(core.StreamEvent) error, duration int64, message string) []core.ToolExecutionResult {
	for _, call := range plan.Calls {
		result := core.ToolExecutionResult{Tool: call.Tool, Summary: call.Summary, Status: "failed", DurationMS: duration, Content: message, Error: message}
		results = append(results, result)
		_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: call.Tool, Status: "failed", Summary: call.Summary + ": " + message, DurationMS: duration})
	}
	return results
}

func evidenceFromResults(results []core.ToolExecutionResult) []core.Evidence {
	evidence := make([]core.Evidence, 0, len(results))
	for _, result := range results {
		text := strings.TrimSpace(result.Content)
		if text == "" {
			text = result.Error
		}
		evidence = append(evidence, core.Evidence{Type: "system", Source: result.Tool, Text: text})
	}
	return evidence
}

func generateAnswer(ctx context.Context, model core.Model, prompt string, emit func(core.StreamEvent) error) (string, error) {
	if emit == nil {
		return model.Complete(ctx, prompt)
	}
	var builder strings.Builder
	err := model.Stream(ctx, prompt, func(event core.StreamEvent) error {
		if event.Type == core.EventContent && event.Content != "" {
			builder.WriteString(event.Content)
		}
		return emit(event)
	})
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

func parseReport(answer string) (string, *core.DiagnosisReport) {
	cleaned := stripThink(answer)
	parsed, err := report.ParseFlexibleReport([]byte(extractJSON(cleaned)))
	if err == nil {
		return report.RenderMarkdown(parsed), &parsed
	}
	return cleaned, nil
}

func buildDiagnosisPrompt(req core.ChatRequest, evidence []core.Evidence) string {
	var builder strings.Builder
	builder.WriteString("You are an operations diagnostic assistant. Return a single JSON object only. Do not output markdown or <think> tags.\n")
	builder.WriteString("JSON fields: title, summary, risk_level(low|medium|high|critical), confidence(0-1), evidence, possible_causes, recommendations, related_entities.\n")
	builder.WriteString("Question:\n")
	builder.WriteString(req.Message)
	builder.WriteString("\n\nEvidence:\n")
	for _, item := range evidence {
		builder.WriteString("- [")
		builder.WriteString(item.Source)
		builder.WriteString("] ")
		builder.WriteString(item.Text)
		builder.WriteString("\n")
	}
	return builder.String()
}

func defaultPlan(intent core.IntentResult, req core.ChatRequest) core.ToolPlan {
	return core.ToolPlan{
		Intent: intent.Intent,
		Calls:  []core.PlannedToolCall{{Tool: "list_agents", Required: false, Summary: "query agents"}},
	}
}

func stripThink(value string) string {
	for {
		lower := strings.ToLower(value)
		start := strings.Index(lower, "<think>")
		end := strings.Index(lower, "</think>")
		if start < 0 || end < start {
			break
		}
		value = value[:start] + value[end+len("</think>"):]
	}
	return strings.TrimSpace(strings.ReplaceAll(value, "</think>", ""))
}

func extractJSON(value string) string {
	start := strings.Index(value, "{")
	end := strings.LastIndex(value, "}")
	if start < 0 || end < start {
		return value
	}
	return value[start : end+1]
}

func emitIfPresent(emit func(core.StreamEvent) error, event core.StreamEvent) error {
	if emit == nil {
		return nil
	}
	return emit(event)
}
