package workflow

import (
	"context"

	"github.com/cloudwego/eino/compose"

	"monitor-backend/opsassistant/core"
)

type SpecialistRunner struct {
	model core.Model
	name  string
	plan  core.ToolPlan
}

type specialistState struct {
	Input  Input
	Result Result
	Emit   func(core.StreamEvent) error
}

func NewCapacityPlanningRunner(model core.Model) *SpecialistRunner {
	return &SpecialistRunner{
		model: model,
		name:  "capacity_planning_workflow",
		plan: core.ToolPlan{
			Intent: "capacity_planning",
			Calls: []core.PlannedToolCall{
				{Tool: "get_capacity_prediction", Required: true, Summary: "query capacity prediction"},
				{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
				{Tool: "search_knowledge", Required: false, Summary: "search capacity planning knowledge"},
			},
		},
	}
}

func NewCostOptimizationRunner(model core.Model) *SpecialistRunner {
	return &SpecialistRunner{
		model: model,
		name:  "cost_optimization_workflow",
		plan: core.ToolPlan{
			Intent: "cost_optimization",
			Calls: []core.PlannedToolCall{
				{Tool: "get_cost_optimization", Required: true, Summary: "query resource cost optimization evidence"},
				{Tool: "get_recent_alerts", Required: false, Summary: "query recent alerts"},
				{Tool: "search_knowledge", Required: false, Summary: "search cost optimization knowledge"},
			},
		},
	}
}

func NewAnomalyAnalysisRunner(model core.Model) *SpecialistRunner {
	return &SpecialistRunner{
		model: model,
		name:  "anomaly_analysis_workflow",
		plan: core.ToolPlan{
			Intent: "anomaly_analysis",
			Calls: []core.PlannedToolCall{
				{Tool: "detect_anomalies", Required: true, Summary: "query anomaly detection evidence"},
				{Tool: "get_history_metrics", Required: false, Summary: "query metrics around anomaly time"},
				{Tool: "search_knowledge", Required: false, Summary: "search anomaly troubleshooting knowledge"},
			},
		},
	}
}

func NewAlertRootCauseRunner(model core.Model) *SpecialistRunner {
	return &SpecialistRunner{
		model: model,
		name:  "alert_root_cause_workflow",
		plan: core.ToolPlan{
			Intent: "alert_root_cause",
			Calls: []core.PlannedToolCall{
				{Tool: "get_recent_alerts", Required: true, Summary: "query recent alerts"},
				{Tool: "get_history_metrics", Required: false, Summary: "query metrics around alert time"},
				{Tool: "get_anomaly_events", Required: false, Summary: "query anomaly events"},
				{Tool: "search_knowledge", Required: false, Summary: "search knowledge base"},
			},
		},
	}
}

func (r *SpecialistRunner) Run(ctx context.Context, input Input, emit func(core.StreamEvent) error) (Result, error) {
	model := input.Model
	if model == nil {
		model = r.model
	}
	input.Model = model
	runnable, err := r.compileGraph(ctx)
	if err != nil {
		return Result{}, err
	}
	state, err := runnable.Invoke(ctx, specialistState{Input: input, Emit: emit})
	return state.Result, err
}

func (r *SpecialistRunner) compileGraph(ctx context.Context) (compose.Runnable[specialistState, specialistState], error) {
	graph := compose.NewGraph[specialistState, specialistState]()
	if err := graph.AddLambdaNode(r.name, compose.InvokableLambda(r.runNode), compose.WithNodeName(r.name)); err != nil {
		return nil, err
	}
	if err := graph.AddEdge(compose.START, r.name); err != nil {
		return nil, err
	}
	if err := graph.AddEdge(r.name, compose.END); err != nil {
		return nil, err
	}
	return graph.Compile(ctx, compose.WithGraphName("ops_assistant_"+r.name))
}

func (r *SpecialistRunner) runNode(ctx context.Context, state specialistState) (specialistState, error) {
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: r.name, Status: "running", Summary: r.name + " started"}); err != nil {
		return state, err
	}
	state.Input.Plan = r.plan
	result, err := NewGenericRunner(r.model).Run(ctx, state.Input, state.Emit)
	state.Result = result
	if err != nil {
		return state, err
	}
	if err := emitIfPresent(state.Emit, core.StreamEvent{Type: core.EventGraphNode, Node: r.name, Status: "completed", Summary: r.name + " completed", Data: result}); err != nil {
		return state, err
	}
	return state, nil
}
