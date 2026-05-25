package report

import (
	"fmt"
	"strings"
)

func RenderMarkdown(report DiagnosisReport) string {
	title := strings.TrimSpace(report.Title)
	if title == "" {
		title = "Operations Diagnosis Report"
	}

	var builder strings.Builder
	builder.WriteString("# ")
	builder.WriteString(title)
	builder.WriteString("\n\n")

	if report.RiskLevel != "" {
		builder.WriteString(fmt.Sprintf("- Risk level: %s\n", report.RiskLevel))
	}
	builder.WriteString(fmt.Sprintf("- Confidence: %.2f\n\n", report.Confidence))

	if strings.TrimSpace(report.Summary) != "" {
		builder.WriteString("## Summary\n\n")
		builder.WriteString(report.Summary)
		builder.WriteString("\n\n")
	}

	if len(report.Evidence) > 0 {
		builder.WriteString("## Evidence\n\n")
		for _, item := range report.Evidence {
			builder.WriteString("- ")
			if item.Source != "" {
				builder.WriteString("[")
				builder.WriteString(item.Source)
				builder.WriteString("] ")
			}
			builder.WriteString(item.Text)
			builder.WriteString("\n")
		}
		builder.WriteString("\n")
	}

	if len(report.PossibleCauses) > 0 {
		builder.WriteString("## Possible Causes\n\n")
		for _, cause := range report.PossibleCauses {
			builder.WriteString("- ")
			builder.WriteString(cause.Cause)
			if cause.Probability != "" {
				builder.WriteString(" (")
				builder.WriteString(cause.Probability)
				builder.WriteString(")")
			}
			builder.WriteString("\n")
		}
		builder.WriteString("\n")
	}

	if len(report.Recommendations) > 0 {
		builder.WriteString("## Recommendations\n\n")
		for _, recommendation := range report.Recommendations {
			builder.WriteString("- ")
			if recommendation.Priority != "" {
				builder.WriteString("[")
				builder.WriteString(recommendation.Priority)
				builder.WriteString("] ")
			}
			builder.WriteString(recommendation.Action)
			builder.WriteString("\n")
		}
	}

	return strings.TrimSpace(builder.String())
}
