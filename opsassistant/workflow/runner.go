package workflow

import (
	"context"

	"monitor-backend/opsassistant/core"
)

type Runner interface {
	Run(ctx context.Context, input Input, emit func(core.StreamEvent) error) (Result, error)
}

type Input struct {
	Request  core.ChatRequest
	Intent   core.IntentResult
	Plan     core.ToolPlan
	Tools    []core.Tool
	Model    core.Model
	Evidence []core.Evidence
}

type Result struct {
	Content string
	Report  *core.DiagnosisReport
	Tools   []core.ToolExecutionResult
}
