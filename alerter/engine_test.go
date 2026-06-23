package alerter

import (
	"errors"
	"strings"
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

func TestHostDownRecoveryRequiresStableOnlinePeriod(t *testing.T) {
	engine := NewAlertEngine(nil, nil, time.Second)
	rule := api.AlertRuleInfo{ID: 1}
	now := time.Now()

	if engine.hostDownRecoveryConfirmed(rule, "host-a", now) {
		t.Fatal("recovery should enter pending state on first online check")
	}

	if engine.hostDownRecoveryConfirmed(rule, "host-a", now.Add(defaultHostDownRecoveryConfirmDuration-time.Second)) {
		t.Fatal("recovery should remain pending before the confirmation period is reached")
	}

	if !engine.hostDownRecoveryConfirmed(rule, "host-a", now.Add(defaultHostDownRecoveryConfirmDuration)) {
		t.Fatal("recovery should be confirmed after the stable online period")
	}
}

func TestBuildAggregatedHostDownNotificationSummarizesHosts(t *testing.T) {
	now := time.Now()
	rule := api.AlertRuleInfo{
		ID:          1,
		Name:        "主机离线",
		Description: "主机长时间未上报",
		Severity:    "critical",
	}
	histories := []*api.AlertHistoryInfo{
		{ID: 1, HostID: "host-a", Hostname: "alpha", FiredAt: now, Status: "firing"},
		{ID: 2, HostID: "host-b", Hostname: "beta", FiredAt: now.Add(time.Second), Status: "firing"},
		{ID: 3, HostID: "host-c", Hostname: "", FiredAt: now.Add(2 * time.Second), Status: "firing"},
	}

	notification := buildAggregatedHostDownNotification(rule, histories, "firing", now)

	if notification.RuleID != rule.ID || notification.RuleName != rule.Name {
		t.Fatalf("unexpected rule fields: %#v", notification)
	}
	if notification.HostID != "aggregated" || notification.Hostname != "3 hosts" {
		t.Fatalf("unexpected aggregate host fields: host_id=%s hostname=%s", notification.HostID, notification.Hostname)
	}
	if notification.Status != "firing" || notification.MetricType != "host_down" {
		t.Fatalf("unexpected status fields: %#v", notification)
	}
	if notification.Message == "" ||
		!strings.Contains(notification.Message, "共 3 台主机") ||
		!strings.Contains(notification.Message, "alpha(host-a)") ||
		!strings.Contains(notification.Message, "beta(host-b)") ||
		!strings.Contains(notification.Message, "host-c") {
		t.Fatalf("unexpected aggregate message: %s", notification.Message)
	}
}

func TestHostDownRuleSkipsWhenBackendHealthIsUnhealthy(t *testing.T) {
	checker := &stubHealthChecker{err: errors.New("postgres ping failed")}
	engine := NewAlertEngine(nil, nil, time.Second)
	engine.SetHealthChecker(checker)

	engine.checkHostDownRule(api.AlertRuleInfo{ID: 1, Duration: 30}, []api.AgentInfo{
		{HostID: "host-a", LastSeen: time.Now().Add(-time.Hour)},
	})

	if checker.calls != 1 {
		t.Fatalf("health checker calls = %d, want 1", checker.calls)
	}
}

type stubHealthChecker struct {
	calls int
	err   error
}

func (s *stubHealthChecker) Healthy() error {
	s.calls++
	return s.err
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
