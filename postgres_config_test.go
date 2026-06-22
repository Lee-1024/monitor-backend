package main

import "testing"

func TestPostgreSQLConfigAppliesSafeConnectionPoolDefaults(t *testing.T) {
	cfg := PostgreSQLConfig{}

	if got := cfg.EffectiveMaxOpenConns(); got != 25 {
		t.Fatalf("max open conns = %d, want 25", got)
	}
	if got := cfg.EffectiveMaxIdleConns(); got != 5 {
		t.Fatalf("max idle conns = %d, want 5", got)
	}
	if got := cfg.EffectiveConnMaxLifetimeMinutes(); got != 30 {
		t.Fatalf("conn max lifetime minutes = %d, want 30", got)
	}
}

func TestPostgreSQLConfigKeepsExplicitConnectionPoolValues(t *testing.T) {
	cfg := PostgreSQLConfig{
		MaxOpenConns:           12,
		MaxIdleConns:           3,
		ConnMaxLifetimeMinutes: 7,
	}

	if got := cfg.EffectiveMaxOpenConns(); got != 12 {
		t.Fatalf("max open conns = %d, want 12", got)
	}
	if got := cfg.EffectiveMaxIdleConns(); got != 3 {
		t.Fatalf("max idle conns = %d, want 3", got)
	}
	if got := cfg.EffectiveConnMaxLifetimeMinutes(); got != 7 {
		t.Fatalf("conn max lifetime minutes = %d, want 7", got)
	}
}

func TestLoggingConfigAppliesProductionDefaults(t *testing.T) {
	cfg := LoggingConfig{}

	if got := cfg.EffectiveLevel(); got != "info" {
		t.Fatalf("log level = %s, want info", got)
	}
	if got := cfg.EffectiveGormLevel(); got != "error" {
		t.Fatalf("gorm log level = %s, want error", got)
	}
	if !cfg.EffectiveIgnoreRecordNotFound() {
		t.Fatal("gorm record-not-found logs should be ignored by default")
	}
}

func TestLoggingConfigKeepsExplicitValues(t *testing.T) {
	cfg := LoggingConfig{
		Level:                "debug",
		GormLevel:            "warn",
		IgnoreRecordNotFound: boolPtrForTest(false),
	}

	if got := cfg.EffectiveLevel(); got != "debug" {
		t.Fatalf("log level = %s, want debug", got)
	}
	if got := cfg.EffectiveGormLevel(); got != "warn" {
		t.Fatalf("gorm log level = %s, want warn", got)
	}
	if cfg.EffectiveIgnoreRecordNotFound() {
		t.Fatal("explicit ignore_record_not_found=false should be preserved")
	}
}

func boolPtrForTest(v bool) *bool {
	return &v
}
