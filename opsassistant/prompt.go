package opsassistant

import (
	"fmt"
	"strings"
)

func BuildPrompt(req ChatRequest, toolResults []ToolResult) string {
	var b strings.Builder
	b.WriteString("你是监控系统中的专业运维助手。请基于已查询到的监控数据回答，区分事实、推断和建议。")
	b.WriteString("不要声称已经执行任何变更操作；第一版助手只能做只读诊断和建议。")
	b.WriteString("不要输出 <think>、</think> 或任何推理过程标签，只输出给用户看的结论和依据。\n\n")

	b.WriteString("用户问题:\n")
	b.WriteString(req.Message)
	b.WriteString("\n\n")

	if req.HostID != "" || req.TimeRange != nil {
		b.WriteString("请求上下文:\n")
		if req.HostID != "" {
			b.WriteString(fmt.Sprintf("- 主机: %s\n", req.HostID))
		}
		if req.TimeRange != nil {
			b.WriteString(fmt.Sprintf("- 时间范围: %s 到 %s\n", req.TimeRange.From.Format("2006-01-02T15:04:05Z07:00"), req.TimeRange.To.Format("2006-01-02T15:04:05Z07:00")))
		}
		b.WriteString("\n")
	}

	if len(toolResults) > 0 {
		b.WriteString("已查询数据:\n")
		for _, result := range toolResults {
			b.WriteString(fmt.Sprintf("## %s\n%s\n\n", result.Summary, result.Content))
		}
	}

	b.WriteString("请用中文输出，结构包含：摘要、证据、可能原因、建议步骤、风险级别。")
	return b.String()
}

func BuildIntentPrompt(req ChatRequest) string {
	var b strings.Builder
	b.WriteString("Classify the operations question into one intent. Return JSON only.\n")
	b.WriteString("Supported intents: global_health, host_performance, alert_root_cause, anomaly_analysis, inspection_summary, knowledge_troubleshooting, log_investigation.\n")
	b.WriteString("JSON shape: {\"intent\":\"host_performance\",\"confidence\":0.8,\"required_context\":[\"host_id\"],\"missing_context\":[]}.\n")
	if req.HostID != "" {
		b.WriteString(fmt.Sprintf("Selected host_id: %s\n", req.HostID))
	}
	b.WriteString("Question:\n")
	b.WriteString(req.Message)
	return b.String()
}

func BuildDiagnosisPrompt(req ChatRequest, evidence []Evidence) string {
	var b strings.Builder
	b.WriteString("You are an operations diagnostic assistant. Return a single JSON object only. Do not output markdown or <think> tags.\n")
	b.WriteString("JSON fields: title, summary, risk_level(low|medium|high|critical), confidence(0-1), evidence, possible_causes, recommendations, related_entities.\n")
	b.WriteString("Question:\n")
	b.WriteString(req.Message)
	b.WriteString("\n\nEvidence:\n")
	for _, item := range evidence {
		b.WriteString(fmt.Sprintf("- [%s] %s\n", item.Source, item.Text))
	}
	return b.String()
}
