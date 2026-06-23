package main

import (
	"testing"
	"time"
)

func TestBackendHealthCheckerSuppressesHostDownDuringRecoveryGrace(t *testing.T) {
	now := time.Now()
	checker := &BackendHealthChecker{
		recoveryGrace: time.Minute,
		now: func() time.Time {
			return now
		},
	}

	checker.markUnhealthy()

	if err := checker.markHealthy(); err == nil {
		t.Fatal("first healthy check after unhealthy period should start recovery grace")
	}

	now = now.Add(30 * time.Second)
	if err := checker.markHealthy(); err == nil {
		t.Fatal("health should remain gated during recovery grace")
	}

	now = now.Add(31 * time.Second)
	if err := checker.markHealthy(); err != nil {
		t.Fatalf("health should be accepted after recovery grace, got %v", err)
	}
}
