package workflow

import (
	"context"

	"github.com/cloudwego/eino/compose"

	"monitor-backend/opsassistant/core"
)

type HostPerformanceRunner struct {
	model core.Model
}

type hostPerformanceState struct {
	Input  Input
	Result Result
	Emit   func(core.StreamEvent) error
}

func NewHostPerformanceRunner(model core.Model) *HostPerformanceRunner {
	return &HostPerformanceRunner{model: model}
}

func (r *HostPerformanceRunner) Run(ctx context.Context, input Input, emit func(core.StreamEvent) error) (Result, error) {
	model := input.Model
	if model == nil {
		model = r.model
	}
	input.Model = model
	runnable, err := r.compileGraph(ctx)
	if err != nil {
		return Result{}, err
	}
	state, err := runnable.Invoke(ctx, hostPerformanceState{
		Input: input,
		Emit:  emit,
	})
	return state.Result, err
}

func (r *HostPerformanceRunner) compileGraph(ctx context.Context) (compose.Runnable[hostPerformanceState, hostPerformanceState], error) {
	graph := compose.NewGraph[hostPerformanceState, hostPerformanceState]()
	if err := graph.AddLambdaNode("host_performance_workflow", compose.InvokableLambda(r.runSpecialistNode), compose.WithNodeName("host_performance_workflow")); err != nil {
		return nil, err
	}
	if err := graph.AddEdge(compose.START, "host_performance_workflow"); err != nil {
		return nil, err
	}
	if err := graph.AddEdge("host_performance_workflow", compose.END); err != nil {
		return nil, err
	}
	return graph.Compile(ctx, compose.WithGraphName("ops_assistant_host_performance"))
}

func (r *HostPerformanceRunner) runSpecialistNode(ctx context.Context, state hostPerformanceState) (hostPerformanceState, error) {
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: "host_performance_workflow", Status: "running", Summary: "host performance specialist started"}); err != nil {
		return state, err
	}
	state.Input.Plan = core.ToolPlan{
		Intent: "host_performance",
		Calls: []core.PlannedToolCall{
			{Tool: "get_agent_detail", Required: false, Summary: "query selected host detail"},
			{Tool: "get_latest_metrics", Required: true, Summary: "query selected host latest metrics"},
			{Tool: "get_history_metrics", Required: true, Summary: "query selected host historical metrics"},
			{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
			{Tool: "get_anomaly_events", Required: false, Summary: "query recent anomaly events"},
			{Tool: "search_knowledge", Required: false, Summary: "search performance troubleshooting knowledge"},
		},
	}
	result, err := NewGenericRunner(r.model).Run(ctx, state.Input, state.Emit)
	state.Result = result
	if err != nil {
		return state, err
	}
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: "host_performance_workflow", Status: "completed", Summary: "host performance specialist completed", Data: result}); err != nil {
		return state, err
	}
	return state, nil
}
