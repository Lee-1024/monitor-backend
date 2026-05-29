package main

import "testing"

func TestInfluxDBConfigAppliesSafeWriteTimeoutDefault(t *testing.T) {
	cfg := InfluxDBConfig{}

	if got := cfg.EffectiveWriteTimeoutSeconds(); got != 10 {
		t.Fatalf("write timeout seconds = %d, want 10", got)
	}
}

func TestInfluxDBConfigKeepsExplicitWriteTimeoutValue(t *testing.T) {
	cfg := InfluxDBConfig{WriteTimeoutSeconds: 15}

	if got := cfg.EffectiveWriteTimeoutSeconds(); got != 15 {
		t.Fatalf("write timeout seconds = %d, want 15", got)
	}
}
