package main

import (
	"strings"
	"testing"
)

func TestClickHouseConfigDefaults(t *testing.T) {
	cfg := ClickHouseConfig{}
	if cfg.EffectiveAddress() != "http://localhost:8123" {
		t.Fatalf("address = %q", cfg.EffectiveAddress())
	}
	if cfg.EffectiveRetentionDays() != 30 || cfg.EffectiveBatchRows() != 5000 {
		t.Fatalf("unexpected defaults: retention=%d batch=%d", cfg.EffectiveRetentionDays(), cfg.EffectiveBatchRows())
	}
}

func TestSnapshotStorageConfigDefaults(t *testing.T) {
	cfg := SnapshotStorageConfig{}
	if cfg.EffectiveRedisHistoryHours() != 24 {
		t.Fatalf("history hours = %d", cfg.EffectiveRedisHistoryHours())
	}
	if cfg.EffectiveConsumerGroup() == "" || cfg.EffectiveStreamMaxLen() <= 0 {
		t.Fatalf("invalid stream defaults: group=%q maxlen=%d", cfg.EffectiveConsumerGroup(), cfg.EffectiveStreamMaxLen())
	}
}

func TestClickHouseSchemaUsesMergeTreeAndTTL(t *testing.T) {
	statements := clickHouseSchemaStatements("monitor", 30)
	if len(statements) != 3 {
		t.Fatalf("statement count = %d, want 3", len(statements))
	}
	joined := strings.Join(statements, "\n")
	for _, want := range []string{"CREATE DATABASE IF NOT EXISTS monitor", "MergeTree", "PARTITION BY toDate(timestamp)", "TTL timestamp + INTERVAL 30 DAY", "process_snapshots", "docker_container_snapshots"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("schema missing %q", want)
		}
	}
}
