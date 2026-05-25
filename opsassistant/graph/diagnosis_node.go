package graph

import (
	"context"

	"monitor-backend/opsassistant"
)

type DiagnosisResult struct {
	Content string
	Report  *opsassistant.DiagnosisReport
}

func GenerateDiagnosis(ctx context.Context, model opsassistant.Model, req opsassistant.ChatRequest, evidence []opsassistant.Evidence) (DiagnosisResult, error) {
	if model == nil {
		return DiagnosisResult{}, opsassistant.ErrModelUnavailable
	}
	answer, err := model.Complete(ctx, opsassistant.BuildDiagnosisPrompt(req, evidence))
	if err != nil {
		return DiagnosisResult{}, err
	}
	return BuildDiagnosisResult(answer)
}
