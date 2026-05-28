package alerter

import (
	"testing"
	"time"

	"monitor-backend/api"
)

func TestHostDownRuleUsesRuleDurationFromLastSeen(t *testing.T) {
	rule := api.AlertRuleInfo{ID: 1, Duration: 30}
	now := time.Now()

	if hostDownExceededDuration(rule, now.Add(-29*time.Second), now) {
		t.Fatal("host_down should not fire before the rule duration is reached")
	}

	if !hostDownExceededDuration(rule, now.Add(-30*time.Second), now) {
		t.Fatal("host_down should fire when last_seen exceeds the rule duration")
	}
}

func TestSpecialAlertStateRequiresDurationBeforeFiring(t *testing.T) {
	rule := api.AlertRuleInfo{ID: 1, Duration: 30}
	engine := NewAlertEngine(nil, nil, time.Second)
	now := time.Now()

	if engine.updateSpecialAlertState("1:host-a:service", rule, "host-a", now) {
		t.Fatal("special alert should enter pending state on first failure")
	}

	if engine.updateSpecialAlertState("1:host-a:service", rule, "host-a", now.Add(29*time.Second)) {
		t.Fatal("special alert should remain pending before duration is reached")
	}

	if !engine.updateSpecialAlertState("1:host-a:service", rule, "host-a", now.Add(30*time.Second)) {
		t.Fatal("special alert should fire after duration is reached")
	}
}

func TestGPUAvailableRequiresAtLeastOneDevice(t *testing.T) {
	cases := []struct {
		name      string
		gpu       map[string]interface{}
		available bool
	}{
		{name: "missing devices", gpu: map[string]interface{}{}, available: false},
		{name: "empty devices", gpu: map[string]interface{}{"devices": []interface{}{}}, available: false},
		{name: "device list", gpu: map[string]interface{}{"devices": []interface{}{map[string]interface{}{"index": 0}}}, available: true},
		{name: "typed device list", gpu: map[string]interface{}{"devices": []map[string]interface{}{{"index": 0}}}, available: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := &api.LatestMetrics{GPU: tc.gpu}
			if got := gpuAvailable(metrics); got != tc.available {
				t.Fatalf("expected GPU availability %v, got %v", tc.available, got)
			}
		})
	}
}

func TestGetHostsToCheckSupportsCommaSeparatedHostIDs(t *testing.T) {
	engine := NewAlertEngine(nil, nil, time.Second)
	rule := api.AlertRuleInfo{ID: 1, HostID: "host-a,host-c"}
	agents := []api.AgentInfo{
		{HostID: "host-a"},
		{HostID: "host-b"},
		{HostID: "host-c"},
	}

	hosts := engine.getHostsToCheck(rule, agents)

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].HostID != "host-a" || hosts[1].HostID != "host-c" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestGetHostsToCheckPrefersHostIDsList(t *testing.T) {
	engine := NewAlertEngine(nil, nil, time.Second)
	rule := api.AlertRuleInfo{ID: 1, HostID: "host-a", HostIDs: []string{"host-b", "host-c"}}
	agents := []api.AgentInfo{
		{HostID: "host-a"},
		{HostID: "host-b"},
		{HostID: "host-c"},
	}

	hosts := engine.getHostsToCheck(rule, agents)

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].HostID != "host-b" || hosts[1].HostID != "host-c" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}
