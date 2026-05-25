package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

type DiagnosisReport struct {
	Title           string           `json:"title"`
	Summary         string           `json:"summary"`
	RiskLevel       string           `json:"risk_level"`
	Confidence      float64          `json:"confidence"`
	Evidence        []Evidence       `json:"evidence"`
	PossibleCauses  []PossibleCause  `json:"possible_causes"`
	Recommendations []Recommendation `json:"recommendations"`
	RelatedEntities RelatedEntities  `json:"related_entities"`
}

type Evidence struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Text   string `json:"text"`
}

type PossibleCause struct {
	Cause        string   `json:"cause"`
	Probability  string   `json:"probability"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type Recommendation struct {
	Priority string `json:"priority"`
	Action   string `json:"action"`
	Type     string `json:"type"`
}

type RelatedEntities struct {
	Hosts          []string `json:"hosts,omitempty"`
	Alerts         []string `json:"alerts,omitempty"`
	KnowledgeItems []string `json:"knowledge_items,omitempty"`
}

func ValidateReport(report DiagnosisReport) error {
	switch report.RiskLevel {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("risk_level must be one of low, medium, high, critical")
	}
	if report.Confidence < 0 || report.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	return nil
}

func ParseFlexibleReport(payload []byte) (DiagnosisReport, error) {
	var report DiagnosisReport
	if err := json.Unmarshal(payload, &report); err == nil {
		return report, ValidateReport(report)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return DiagnosisReport{}, err
	}

	report.Title = readString(raw, "title")
	report.Summary = readString(raw, "summary")
	report.RiskLevel = readString(raw, "risk_level")
	report.Confidence = readFloat(raw, "confidence")
	report.Evidence = readEvidence(raw["evidence"])
	report.PossibleCauses = readPossibleCauses(raw["possible_causes"])
	report.Recommendations = readRecommendations(raw["recommendations"])
	report.RelatedEntities = readRelatedEntities(raw["related_entities"])

	if err := ValidateReport(report); err != nil {
		return DiagnosisReport{}, err
	}
	return report, nil
}

func readString(raw map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(raw[key], &value)
	return value
}

func readFloat(raw map[string]json.RawMessage, key string) float64 {
	var value float64
	_ = json.Unmarshal(raw[key], &value)
	return value
}

func readEvidence(raw json.RawMessage) []Evidence {
	var structured []Evidence
	if json.Unmarshal(raw, &structured) == nil {
		return structured
	}
	var text string
	if json.Unmarshal(raw, &text) == nil && strings.TrimSpace(text) != "" {
		return []Evidence{{Type: "summary", Source: "model", Text: text}}
	}
	var texts []string
	if json.Unmarshal(raw, &texts) == nil {
		evidence := make([]Evidence, 0, len(texts))
		for _, item := range texts {
			if strings.TrimSpace(item) != "" {
				evidence = append(evidence, Evidence{Type: "summary", Source: "model", Text: item})
			}
		}
		return evidence
	}
	return nil
}

func readPossibleCauses(raw json.RawMessage) []PossibleCause {
	var structured []PossibleCause
	if json.Unmarshal(raw, &structured) == nil {
		return structured
	}
	var texts []string
	if json.Unmarshal(raw, &texts) != nil {
		return nil
	}
	causes := make([]PossibleCause, 0, len(texts))
	for _, item := range texts {
		if strings.TrimSpace(item) != "" {
			causes = append(causes, PossibleCause{Cause: item, Probability: "unknown"})
		}
	}
	return causes
}

func readRecommendations(raw json.RawMessage) []Recommendation {
	var structured []Recommendation
	if json.Unmarshal(raw, &structured) == nil {
		return structured
	}
	var texts []string
	if json.Unmarshal(raw, &texts) != nil {
		return nil
	}
	recommendations := make([]Recommendation, 0, len(texts))
	for _, item := range texts {
		if strings.TrimSpace(item) != "" {
			recommendations = append(recommendations, Recommendation{Priority: "medium", Action: item, Type: "investigation"})
		}
	}
	return recommendations
}

func readRelatedEntities(raw json.RawMessage) RelatedEntities {
	var structured RelatedEntities
	if json.Unmarshal(raw, &structured) == nil {
		return structured
	}
	var items []string
	if json.Unmarshal(raw, &items) == nil {
		return RelatedEntities{Hosts: items}
	}
	return RelatedEntities{}
}
