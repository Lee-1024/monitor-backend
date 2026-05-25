package core

import (
	"context"
	"time"

	"monitor-backend/opsassistant/report"
)

const (
	EventContent     = "content"
	EventToolCall    = "tool_call"
	EventStatus      = "status"
	EventDone        = "done"
	EventError       = "error"
	EventGraphNode   = "graph_node"
	EventReportDelta = "report_delta"
	EventReport      = "report"
)

type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type ChatRequest struct {
	Message   string     `json:"message"`
	SessionID string     `json:"session_id,omitempty"`
	HostID    string     `json:"host_id,omitempty"`
	TimeRange *TimeRange `json:"time_range,omitempty"`
}

type ToolCall struct {
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
}

type ChatResponse struct {
	SessionID string     `json:"session_id"`
	Answer    string     `json:"answer"`
	ToolCalls []ToolCall `json:"tool_calls"`
}

type StreamEvent struct {
	Type       string           `json:"type"`
	Content    string           `json:"content,omitempty"`
	Tool       string           `json:"tool,omitempty"`
	Summary    string           `json:"summary,omitempty"`
	SessionID  string           `json:"session_id,omitempty"`
	Message    string           `json:"message,omitempty"`
	Node       string           `json:"node,omitempty"`
	Status     string           `json:"status,omitempty"`
	DurationMS int64            `json:"duration_ms,omitempty"`
	Section    string           `json:"section,omitempty"`
	Report     *DiagnosisReport `json:"report,omitempty"`
	Data       any              `json:"data,omitempty"`
}

type DiagnosisReport = report.DiagnosisReport
type Evidence = report.Evidence
type PossibleCause = report.PossibleCause
type Recommendation = report.Recommendation
type RelatedEntities = report.RelatedEntities

type IntentResult struct {
	Intent          string   `json:"intent"`
	Confidence      float64  `json:"confidence"`
	RequiredContext []string `json:"required_context,omitempty"`
	MissingContext  []string `json:"missing_context,omitempty"`
	Clarification   string   `json:"clarification,omitempty"`
}

type ToolPlan struct {
	Intent string            `json:"intent"`
	Calls  []PlannedToolCall `json:"calls"`
}

type PlannedToolCall struct {
	Tool     string         `json:"tool"`
	Args     map[string]any `json:"args,omitempty"`
	Required bool           `json:"required"`
	Summary  string         `json:"summary"`
}

type ToolExecutionResult struct {
	Tool       string
	Summary    string
	Status     string
	DurationMS int64
	Content    string
	Error      string
}

type GraphNodeEvent struct {
	Node    string `json:"node"`
	Status  string `json:"status"`
	Summary string `json:"summary,omitempty"`
}

type ReportDeltaEvent struct {
	Section string `json:"section"`
	Content string `json:"content"`
}

type DiagnosisContext struct {
	Request  ChatRequest
	Intent   IntentResult
	Plan     ToolPlan
	Results  []ToolExecutionResult
	Evidence []Evidence
}

type ToolResult struct {
	Name    string
	Summary string
	Content string
}

type Tool struct {
	Name        string
	Description string
	Run         func(ctx context.Context, req ChatRequest) (ToolResult, error)
}

type Model interface {
	Complete(ctx context.Context, prompt string) (string, error)
	Stream(ctx context.Context, prompt string, emit func(StreamEvent) error) error
}
