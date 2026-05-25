package opsassistant

import (
	"monitor-backend/opsassistant/core"
	"monitor-backend/opsassistant/report"
)

const (
	EventContent     = core.EventContent
	EventToolCall    = core.EventToolCall
	EventStatus      = core.EventStatus
	EventDone        = core.EventDone
	EventError       = core.EventError
	EventGraphNode   = core.EventGraphNode
	EventReportDelta = core.EventReportDelta
	EventReport      = core.EventReport
)

type TimeRange = core.TimeRange
type ChatRequest = core.ChatRequest
type ToolCall = core.ToolCall
type ChatResponse = core.ChatResponse
type StreamEvent = core.StreamEvent

type DiagnosisReport = report.DiagnosisReport
type Evidence = report.Evidence
type PossibleCause = report.PossibleCause
type Recommendation = report.Recommendation
type RelatedEntities = report.RelatedEntities

type IntentResult = core.IntentResult
type ToolPlan = core.ToolPlan
type PlannedToolCall = core.PlannedToolCall
type ToolExecutionResult = core.ToolExecutionResult
type GraphNodeEvent = core.GraphNodeEvent
type ReportDeltaEvent = core.ReportDeltaEvent
type DiagnosisContext = core.DiagnosisContext
type ToolResult = core.ToolResult
type Tool = core.Tool
type Model = core.Model
