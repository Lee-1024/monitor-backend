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
