package api

import (
	"testing"
	"time"
)

func TestActiveInspectionAgentsExcludesSoftDeletedAgents(t *testing.T) {
	deletedAt := time.Now()
	agents := []map[string]interface{}{
		{"host_id": "active-a", "deleted_at": nil},
		{"host_id": "deleted-a", "deleted_at": deletedAt},
		{"host_id": "active-b"},
	}

	active := activeInspectionAgents(agents)

	if len(active) != 2 {
		t.Fatalf("active agents = %d, want 2", len(active))
	}
	if active[0]["host_id"] != "active-a" || active[1]["host_id"] != "active-b" {
		t.Fatalf("unexpected active agents: %#v", active)
	}
}
