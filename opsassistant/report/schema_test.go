package report

import (
	"strings"
	"testing"
)

func TestValidateReportAcceptsValidReport(t *testing.T) {
	err := ValidateReport(DiagnosisReport{
		Title:      "Host performance report",
		Summary:    "CPU and memory are stable.",
		RiskLevel:  "low",
		Confidence: 0.82,
		Evidence: []Evidence{
			{Type: "metric", Source: "get_latest_metrics", Text: "CPU usage is 12%."},
		},
		PossibleCauses: []PossibleCause{
			{Cause: "No active pressure", Probability: "high", EvidenceRefs: []string{"get_latest_metrics"}},
		},
		Recommendations: []Recommendation{
			{Priority: "low", Action: "Continue monitoring.", Type: "monitoring"},
		},
	})
	if err != nil {
		t.Fatalf("expected valid report, got %v", err)
	}
}

func TestValidateReportRejectsInvalidRiskLevel(t *testing.T) {
	err := ValidateReport(DiagnosisReport{
		Title:      "Host performance report",
		Summary:    "CPU and memory are stable.",
		RiskLevel:  "unknown",
		Confidence: 0.82,
	})
	if err == nil {
		t.Fatal("expected invalid risk level error")
	}
	if !strings.Contains(err.Error(), "risk_level") {
		t.Fatalf("expected risk_level error, got %v", err)
	}
}

func TestValidateReportRejectsConfidenceOutOfRange(t *testing.T) {
	err := ValidateReport(DiagnosisReport{
		Title:      "Host performance report",
		Summary:    "CPU and memory are stable.",
		RiskLevel:  "medium",
		Confidence: 1.2,
	})
	if err == nil {
		t.Fatal("expected confidence range error")
	}
	if !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("expected confidence error, got %v", err)
	}
}

func TestMarkdownFallbackIncludesSummaryEvidenceAndRecommendations(t *testing.T) {
	markdown := RenderMarkdown(DiagnosisReport{
		Title:      "",
		Summary:    "Memory pressure is currently low.",
		RiskLevel:  "medium",
		Confidence: 0.71,
		Evidence: []Evidence{
			{Type: "metric", Source: "get_history_metrics", Text: "Memory peaked around 09:30."},
		},
		Recommendations: []Recommendation{
			{Priority: "high", Action: "Check processes during the peak.", Type: "investigation"},
		},
	})

	for _, expected := range []string{
		"# Operations Diagnosis Report",
		"Memory pressure is currently low.",
		"Memory peaked around 09:30.",
		"Check processes during the peak.",
		"medium",
	} {
		if !strings.Contains(markdown, expected) {
			t.Fatalf("markdown missing %q:\n%s", expected, markdown)
		}
	}
}

func TestParseFlexibleReportAcceptsModelFriendlyShape(t *testing.T) {
	payload := []byte(`{
		"title":"服务器内存状态分析",
		"summary":"服务器内存使用率58.26%，处于中等水平。",
		"risk_level":"medium",
		"confidence":0.85,
		"evidence":"当前内存状态：总量31.3GB，已用18.2GB。",
		"possible_causes":["应用程序正常运行占用的合理内存使用","历史告警阈值设置偏低"],
		"recommendations":["配置告警通知通道","考虑调整内存告警阈值至70-80%"],
		"related_entities":["server-001","zabbix_agentd"]
	}`)

	report, err := ParseFlexibleReport(payload)
	if err != nil {
		t.Fatalf("expected flexible report to parse, got %v", err)
	}
	if report.Title != "服务器内存状态分析" {
		t.Fatalf("unexpected title: %s", report.Title)
	}
	if len(report.Evidence) != 1 || !strings.Contains(report.Evidence[0].Text, "31.3GB") {
		t.Fatalf("unexpected evidence: %#v", report.Evidence)
	}
	if len(report.PossibleCauses) != 2 || report.PossibleCauses[0].Cause == "" {
		t.Fatalf("unexpected causes: %#v", report.PossibleCauses)
	}
	if len(report.Recommendations) != 2 || report.Recommendations[0].Action == "" {
		t.Fatalf("unexpected recommendations: %#v", report.Recommendations)
	}
	if len(report.RelatedEntities.Hosts) != 2 {
		t.Fatalf("unexpected related entities: %#v", report.RelatedEntities)
	}
}
