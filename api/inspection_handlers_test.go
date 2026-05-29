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

func TestReportIntConvertsDatabaseIntegerTypes(t *testing.T) {
	report := map[string]interface{}{
		"total_hosts":   int64(3),
		"online_hosts":  int32(2),
		"offline_hosts": uint(1),
	}

	if got := reportInt(report, "total_hosts"); got != 3 {
		t.Fatalf("total hosts = %d, want 3", got)
	}
	if got := reportInt(report, "online_hosts"); got != 2 {
		t.Fatalf("online hosts = %d, want 2", got)
	}
	if got := reportInt(report, "offline_hosts"); got != 1 {
		t.Fatalf("offline hosts = %d, want 1", got)
	}
}

func TestInspectionReportPayloadUsesFloatStatsForLLMTemplate(t *testing.T) {
	payload := inspectionReportPayload(7, map[string]interface{}{
		"total_hosts":    int64(4),
		"online_hosts":   int64(3),
		"offline_hosts":  int64(1),
		"warning_hosts":  int64(2),
		"critical_hosts": int64(1),
	})

	if got, ok := payload["total_hosts"].(float64); !ok || got != 4 {
		t.Fatalf("payload total_hosts = %#v, want float64(4)", payload["total_hosts"])
	}
	if got, ok := payload["online_hosts"].(float64); !ok || got != 3 {
		t.Fatalf("payload online_hosts = %#v, want float64(3)", payload["online_hosts"])
	}
	if got, ok := payload["critical_hosts"].(float64); !ok || got != 1 {
		t.Fatalf("payload critical_hosts = %#v, want float64(1)", payload["critical_hosts"])
	}
}

func TestConvertMapToInspectionRecordInfoConvertsServiceCountsFromInt64(t *testing.T) {
	record := convertMapToInspectionRecordInfo(map[string]interface{}{
		"service_count":   int64(5),
		"service_running": int64(3),
		"service_stopped": int64(1),
		"service_failed":  int64(1),
	})

	if record.ServiceCount != 5 {
		t.Fatalf("service count = %d, want 5", record.ServiceCount)
	}
	if record.ServiceRunning != 3 {
		t.Fatalf("service running = %d, want 3", record.ServiceRunning)
	}
	if record.ServiceStopped != 1 {
		t.Fatalf("service stopped = %d, want 1", record.ServiceStopped)
	}
	if record.ServiceFailed != 1 {
		t.Fatalf("service failed = %d, want 1", record.ServiceFailed)
	}
}
