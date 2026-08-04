package workflow

import (
	"context"
	"strings"
	"testing"

	einotool "github.com/cloudwego/eino/components/tool"

	"monitor-backend/opsassistant/core"
)

func TestCoreToolAdapterImplementsEinoInvokableTool(t *testing.T) {
	adapter := newEinoToolAdapter(core.Tool{
		Name:        "get_latest_metrics",
		Description: "query latest metrics",
		Run: func(ctx context.Context, req core.ChatRequest) (core.ToolResult, error) {
			if req.HostID != "host-01" {
				t.Fatalf("expected host_id from JSON arguments, got %q", req.HostID)
			}
			return core.ToolResult{Name: "get_latest_metrics", Summary: "metrics queried", Content: "cpu=42"}, nil
		},
	})
	var _ einotool.InvokableTool = adapter

	info, err := adapter.Info(context.Background())
	if err != nil {
		t.Fatalf("tool info: %v", err)
	}
	if info.Name != "get_latest_metrics" || !strings.Contains(info.Desc, "query latest metrics") {
		t.Fatalf("unexpected tool info: %#v", info)
	}

	output, err := adapter.InvokableRun(context.Background(), `{"host_id":"host-01","message":"check cpu"}`)
	if err != nil {
		t.Fatalf("invoke adapter: %v", err)
	}
	if !strings.Contains(output, `"content":"cpu=42"`) {
		t.Fatalf("expected serialized tool result, got %s", output)
	}
}
