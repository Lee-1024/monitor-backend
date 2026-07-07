package main

import (
	"testing"

	"monitor-backend/api"
)

func TestApplyAgentStatusToServiceInfosMarksOfflineHostServicesOffline(t *testing.T) {
	services := []api.ServiceInfo{
		{HostID: "host-1", Name: "nginx", Status: "running", Uptime: 120, PortAccessible: true},
		{HostID: "host-2", Name: "mysql", Status: "running", Uptime: 240, PortAccessible: true},
	}

	result := applyAgentStatusToServiceInfos(services, map[string]string{
		"host-1": "offline",
		"host-2": "online",
	})

	if result[0].Status != "offline" {
		t.Fatalf("expected host-1 service to be offline, got %q", result[0].Status)
	}
	if result[0].Uptime != 0 {
		t.Fatalf("expected offline service uptime to be reset, got %d", result[0].Uptime)
	}
	if result[0].PortAccessible {
		t.Fatal("expected offline service port to be inaccessible")
	}
	if result[1].Status != "running" {
		t.Fatalf("expected online host service to keep original status, got %q", result[1].Status)
	}
}

func TestServiceStatusesToAPIIncludesDatabaseID(t *testing.T) {
	services := []ServiceStatus{
		{ID: 42, HostID: "host-1", Name: "nginx", Status: "running"},
	}

	result := serviceStatusesToAPI(services)

	if result[0].ID != 42 {
		t.Fatalf("service id = %d, want 42", result[0].ID)
	}
}

func TestServiceStatusesToAPIDetectsMissingDatabaseID(t *testing.T) {
	services := []ServiceStatus{
		{HostID: "host-1", Name: "nginx", Status: "running"},
	}

	result := serviceStatusesToAPI(services)

	if result[0].ID != 0 {
		t.Fatalf("service id = %d, want 0 for missing database id", result[0].ID)
	}
}
