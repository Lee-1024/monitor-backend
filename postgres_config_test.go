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
