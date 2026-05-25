package graph

import (
	"context"
	"encoding/json"
	"strings"

	"monitor-backend/opsassistant"
)

const (
	IntentGlobalHealth             = "global_health"
	IntentHostPerformance          = "host_performance"
	IntentAlertRootCause           = "alert_root_cause"
	IntentAnomalyAnalysis          = "anomaly_analysis"
	IntentInspectionSummary        = "inspection_summary"
	IntentKnowledgeTroubleshooting = "knowledge_troubleshooting"
	IntentLogInvestigation         = "log_investigation"
)

func ClassifyIntent(ctx context.Context, model opsassistant.Model, req opsassistant.ChatRequest) opsassistant.IntentResult {
	result := fallbackIntent(req)
	if model != nil {
		answer, err := model.Complete(ctx, opsassistant.BuildIntentPrompt(req))
		if err == nil {
			var parsed opsassistant.IntentResult
			if json.Unmarshal([]byte(extractJSONObject(answer)), &parsed) == nil && parsed.Intent != "" {
				result = parsed
			}
		}
	}
	return normalizeIntentContext(result, req)
}

func normalizeIntentContext(result opsassistant.IntentResult, req opsassistant.ChatRequest) opsassistant.IntentResult {
	result.Intent = normalizeIntent(result.Intent)
	if result.Confidence <= 0 {
		result.Confidence = 0.5
	}
	if requiresHost(result.Intent) && strings.TrimSpace(req.HostID) == "" && !contains(result.MissingContext, "host_id") {
		result.MissingContext = append(result.MissingContext, "host_id")
	}
	if len(result.MissingContext) > 0 && result.Clarification == "" {
		result.Clarification = "请选择要诊断的主机后再继续。"
	}
	return result
}

func fallbackIntent(req opsassistant.ChatRequest) opsassistant.IntentResult {
	message := strings.ToLower(req.Message)
	intent := IntentGlobalHealth
	switch {
	case strings.Contains(message, "alert") || strings.Contains(message, "告警"):
		intent = IntentAlertRootCause
	case strings.Contains(message, "cpu") || strings.Contains(message, "memory") || strings.Contains(message, "disk") ||
		strings.Contains(message, "内存") || strings.Contains(message, "磁盘") || strings.Contains(message, "性能"):
		intent = IntentHostPerformance
	case strings.Contains(message, "anomaly") || strings.Contains(message, "异常"):
		intent = IntentAnomalyAnalysis
	case strings.Contains(message, "inspection") || strings.Contains(message, "巡检"):
		intent = IntentInspectionSummary
	case strings.Contains(message, "log") || strings.Contains(message, "日志"):
		intent = IntentLogInvestigation
	case strings.Contains(message, "knowledge") || strings.Contains(message, "知识"):
		intent = IntentKnowledgeTroubleshooting
	}
	return opsassistant.IntentResult{Intent: intent, Confidence: 0.55}
}

func normalizeIntent(intent string) string {
	switch intent {
	case IntentHostPerformance, IntentAlertRootCause, IntentAnomalyAnalysis, IntentInspectionSummary, IntentKnowledgeTroubleshooting, IntentLogInvestigation:
		return intent
	default:
		return IntentGlobalHealth
	}
}

func requiresHost(intent string) bool {
	switch intent {
	case IntentHostPerformance:
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func extractJSONObject(value string) string {
	value = strings.TrimSpace(value)
	start := strings.Index(value, "{")
	end := strings.LastIndex(value, "}")
	if start < 0 || end < start {
		return value
	}
	return value[start : end+1]
}
