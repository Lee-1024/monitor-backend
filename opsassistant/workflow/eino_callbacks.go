package workflow

import (
	"context"

	"github.com/cloudwego/eino/callbacks"

	"monitor-backend/opsassistant/core"
)

func newEinoTimelineCallback(emit func(core.StreamEvent) error) callbacks.Handler {
	graphNodes := map[string]bool{
		"tool_executor":    true,
		"evidence_builder": true,
		"report_generator": true,
	}
	return callbacks.NewHandlerBuilder().
		OnStartFn(func(ctx context.Context, info *callbacks.RunInfo, input callbacks.CallbackInput) context.Context {
			if emit == nil || info == nil || !graphNodes[info.Name] {
				return ctx
			}
			_ = emit(core.StreamEvent{
				Type:    core.EventGraphNode,
				Node:    info.Name,
				Status:  "running",
				Summary: info.Name + " started",
			})
			return ctx
		}).
		OnErrorFn(func(ctx context.Context, info *callbacks.RunInfo, err error) context.Context {
			if emit == nil || info == nil || !graphNodes[info.Name] {
				return ctx
			}
			_ = emit(core.StreamEvent{
				Type:    core.EventGraphNode,
				Node:    info.Name,
				Status:  "failed",
				Summary: err.Error(),
			})
			return ctx
		}).
		Build()
}
