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

func TestHostDownRuleCreatesBackendHealthAlertDuringStartupGrace(t *testing.T) {
	storage := &backendHealthAlertStorage{}
	checker := &stubHealthChecker{status: HealthStatus{
		Healthy: false,
		Reason:  "backend startup grace period active",
		Kind:    "startup_grace",
	}}
	engine := NewAlertEngine(storage, nil, time.Second)
	engine.SetHealthChecker(checker)

	engine.checkHostDownRule(api.AlertRuleInfo{ID: 7, Name: "主机宕机", Severity: "critical", Duration: 30}, []api.AgentInfo{
		{HostID: "host-a", Hostname: "alpha", LastSeen: time.Now().Add(-time.Hour)},
	})

	if len(storage.created) != 1 {
		t.Fatalf("created alerts = %d, want 1 backend health alert", len(storage.created))
	}
	if got := storage.created[0].MetricType; got != "backend_health" {
		t.Fatalf("created metric type = %q, want backend_health", got)
	}
	if got := storage.created[0].HostID; got != backendHealthHostID {
		t.Fatalf("created host id = %q, want %q", got, backendHealthHostID)
	}
	for _, history := range storage.created {
		if history.MetricType == "host_down" {
			t.Fatal("host_down alert should not be created while backend health is gated")
		}
	}
}

type stubHealthChecker struct {
	calls  int
	err    error
	status HealthStatus
}

func (s *stubHealthChecker) Healthy() error {
	s.calls++
	return s.err
}

func (s *stubHealthChecker) Status() HealthStatus {
	s.calls++
	if s.err != nil {
		return HealthStatus{Healthy: false, Reason: s.err.Error(), Kind: "dependency"}
	}
	if s.status.Reason != "" || s.status.Kind != "" || s.status.Healthy {
		return s.status
	}
	return HealthStatus{Healthy: true}
}

type backendHealthAlertStorage struct {
	api.StorageInterface
	created []api.AlertHistoryInfo
}

func (s *backendHealthAlertStorage) ListAlertHistory(ruleID *uint, hostID string, status string, limit int) ([]api.AlertHistoryInfo, error) {
	return nil, nil
}

func (s *backendHealthAlertStorage) CreateAlertHistory(history *api.AlertHistoryInfo) (*api.AlertHistoryInfo, error) {
	history.ID = uint(len(s.created) + 1)
	s.created = append(s.created, *history)
	return history, nil
}

func (s *backendHealthAlertStorage) UpdateAlertHistory(id uint, status string, resolvedAt *time.Time) error {
	return nil
}

func (s *backendHealthAlertStorage) UpdateAlertHistoryNotifyStatus(id uint, notifyStatus string, notifyError string) error {
	return nil
}

func (s *backendHealthAlertStorage) UpdateAlertHistoryMetricValue(id uint, metricValue float64, message string) error {
	return nil
}

func (s *backendHealthAlertStorage) IsRuleSilenced(ruleID uint, hostID string) bool {
	return false
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
