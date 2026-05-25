package graph

import (
	"regexp"
	"strings"

	"monitor-backend/opsassistant/report"
)

var thinkBlockPattern = regexp.MustCompile(`(?is)<think>.*?</think>`)

func BuildDiagnosisResult(answer string) (DiagnosisResult, error) {
	cleaned := stripReasoning(answer)
	parsed, err := report.ParseFlexibleReport([]byte(extractJSONObject(cleaned)))
	if err == nil {
		content := report.RenderMarkdown(parsed)
		return DiagnosisResult{Content: content, Report: &parsed}, nil
	}
	return DiagnosisResult{Content: cleaned}, nil
}

func stripReasoning(value string) string {
	cleaned := thinkBlockPattern.ReplaceAllString(value, "")
	cleaned = strings.ReplaceAll(cleaned, "</think>", "")
	return strings.TrimSpace(cleaned)
}
