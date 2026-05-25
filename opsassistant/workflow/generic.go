package workflow

import (
	"context"
	"strings"
	"time"

	"monitor-backend/opsassistant/core"
	"monitor-backend/opsassistant/report"
)

type GenericRunner struct {
	model core.Model
}

func NewGenericRunner(model core.Model) *GenericRunner {
	return &GenericRunner{model: model}
}

func (r *GenericRunner) Run(ctx context.Context, input Input, emit func(core.StreamEvent) error) (Result, error) {
	model := input.Model
	if model == nil {
		model = r.model
	}
	if err := emitIfPresent(emit, core.StreamEvent{Type: core.EventStatus, Content: "正在查询监控数据..."}); err != nil {
		return Result{}, err
	}
	plan := input.Plan
	if len(plan.Calls) == 0 {
		plan = defaultPlan(input.Intent, input.Request)
	}
	results := executePlan(ctx, input.Request, plan, input.Tools, emit)
	evidence := append(evidenceFromResults(results), input.Evidence...)
	if err := emitIfPresent(emit, core.StreamEvent{Type: core.EventGraphNode, Node: "evidence_builder", Status: "completed", Summary: "evidence collected", Data: evidence}); err != nil {
		return Result{}, err
	}
	if err := emitIfPresent(emit, core.StreamEvent{Type: core.EventStatus, Content: "正在生成诊断报告..."}); err != nil {
		return Result{}, err
	}
	answer, err := generateAnswer(ctx, model, buildDiagnosisPrompt(input.Request, evidence), emit)
	if err != nil {
		return Result{}, err
	}
	content, parsed := parseReport(answer)
	result := Result{Content: content, Report: parsed, Tools: results}
	if parsed != nil {
		if err := emitIfPresent(emit, core.StreamEvent{Type: core.EventReport, Report: parsed, Data: parsed}); err != nil {
			return Result{}, err
		}
	} else if content != "" {
		if err := emitIfPresent(emit, core.StreamEvent{Type: core.EventContent, Content: content}); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func executePlan(ctx context.Context, req core.ChatRequest, plan core.ToolPlan, tools []core.Tool, emit func(core.StreamEvent) error) []core.ToolExecutionResult {
	toolMap := make(map[string]core.Tool, len(tools))
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}
	results := make([]core.ToolExecutionResult, 0, len(plan.Calls))
	for _, call := range plan.Calls {
		tool, ok := toolMap[call.Tool]
		if !ok {
			continue
		}
		_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: call.Tool, Status: "running", Summary: call.Summary})
		start := time.Now()
		result, err := tool.Run(ctx, req)
		duration := time.Since(start).Milliseconds()
		execResult := core.ToolExecutionResult{Tool: call.Tool, Summary: call.Summary, Status: "success", DurationMS: duration}
		if err != nil {
			execResult.Status = "failed"
			execResult.Error = err.Error()
			execResult.Content = err.Error()
			_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: call.Tool, Status: "failed", Summary: call.Summary + ": " + err.Error(), DurationMS: duration})
		} else {
			if result.Name != "" {
				execResult.Tool = result.Name
			}
			if result.Summary != "" {
				execResult.Summary = result.Summary
			}
			execResult.Content = result.Content
			_ = emitIfPresent(emit, core.StreamEvent{Type: core.EventToolCall, Tool: execResult.Tool, Status: "completed", Summary: execResult.Summary, DurationMS: duration})
		}
		results = append(results, execResult)
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
