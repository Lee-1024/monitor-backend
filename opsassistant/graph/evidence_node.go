package graph

import (
	"strings"

	"monitor-backend/opsassistant"
)

func BuildEvidence(results []opsassistant.ToolExecutionResult) []opsassistant.Evidence {
	evidence := make([]opsassistant.Evidence, 0, len(results))
	for _, result := range results {
		text := strings.TrimSpace(result.Content)
		if text == "" && result.Error != "" {
			text = result.Error
		}
		if text == "" {
			text = result.Summary
		}
		evidence = append(evidence, opsassistant.Evidence{
			Type:   evidenceType(result.Tool),
			Source: result.Tool,
			Text:   limitText(text, 1200),
		})
	}
	return evidence
}

func evidenceType(tool string) string {
	switch tool {
	case "get_latest_metrics", "get_history_metrics":
		return "metric"
	case "get_recent_alerts":
		return "alert"
	case "get_anomaly_events":
		return "anomaly"
	case "search_knowledge":
		return "knowledge"
	case "get_latest_inspection_report":
		return "inspection"
	default:
		return "system"
	}
}

func limitText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
