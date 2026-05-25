package graph

import (
	"strings"

	"monitor-backend/opsassistant"
)

const maxToolCalls = 8

func PlanTools(intent opsassistant.IntentResult, req opsassistant.ChatRequest) opsassistant.ToolPlan {
	tools := toolsForIntent(intent.Intent, strings.TrimSpace(req.HostID) != "")
	if len(tools) > maxToolCalls {
		tools = tools[:maxToolCalls]
	}
	return opsassistant.ToolPlan{
		Intent: intent.Intent,
		Calls:  tools,
	}
}

func toolsForIntent(intent string, hasHost bool) []opsassistant.PlannedToolCall {
	switch intent {
	case IntentHostPerformance:
		return filterHostTools([]opsassistant.PlannedToolCall{
			toolCall("get_latest_metrics", true, "查询所选主机最新 CPU、内存、磁盘和网络指标"),
			toolCall("get_history_metrics", true, "查询所选主机历史性能趋势"),
			toolCall("get_recent_alerts", false, "查询近期相关告警"),
			toolCall("get_anomaly_events", false, "查询近期异常事件"),
		}, hasHost)
	case IntentAlertRootCause:
		return filterHostTools([]opsassistant.PlannedToolCall{
			toolCall("get_recent_alerts", true, "查询近期告警"),
			toolCall("get_history_metrics", false, "查询告警时间附近的历史指标"),
			toolCall("get_anomaly_events", false, "查询告警附近的异常事件"),
			toolCall("search_knowledge", false, "检索知识库中的处置建议"),
		}, hasHost)
	case IntentAnomalyAnalysis:
		return filterHostTools([]opsassistant.PlannedToolCall{
			toolCall("get_anomaly_events", true, "查询异常事件"),
			toolCall("get_history_metrics", false, "查询异常时间附近的指标趋势"),
			toolCall("search_knowledge", false, "检索异常分析知识"),
		}, hasHost)
	case IntentInspectionSummary:
		return []opsassistant.PlannedToolCall{
			toolCall("get_latest_inspection_report", true, "查询最新巡检报告"),
			toolCall("list_agents", false, "查询主机在线状态"),
			toolCall("get_recent_alerts", false, "查询近期告警"),
		}
	case IntentKnowledgeTroubleshooting:
		calls := []opsassistant.PlannedToolCall{
			toolCall("search_knowledge", true, "检索知识库"),
		}
		if hasHost {
			calls = append(calls, toolCall("get_latest_metrics", false, "补充当前主机最新指标"))
		}
		return calls
	case IntentLogInvestigation:
		return filterHostTools([]opsassistant.PlannedToolCall{
			toolCall("get_recent_alerts", false, "查询日志时间附近的告警"),
			toolCall("get_anomaly_events", false, "查询日志时间附近的异常事件"),
			toolCall("search_knowledge", false, "检索日志排障知识"),
		}, hasHost)
	default:
		return []opsassistant.PlannedToolCall{
			toolCall("list_agents", true, "查询主机在线状态"),
			toolCall("get_recent_alerts", false, "查询近期告警"),
			toolCall("get_anomaly_events", false, "查询近期异常事件"),
			toolCall("get_latest_inspection_report", false, "查询最新巡检报告"),
		}
	}
}

func toolCall(name string, required bool, summary string) opsassistant.PlannedToolCall {
	return opsassistant.PlannedToolCall{
		Tool:     name,
		Required: required,
		Summary:  summary,
	}
}

func filterHostTools(calls []opsassistant.PlannedToolCall, hasHost bool) []opsassistant.PlannedToolCall {
	if hasHost {
		return calls
	}
	filtered := make([]opsassistant.PlannedToolCall, 0, len(calls))
	for _, call := range calls {
		if call.Tool == "get_latest_metrics" || call.Tool == "get_history_metrics" {
			continue
		}
		filtered = append(filtered, call)
	}
	return filtered
}
