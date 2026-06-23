package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type BackendHealthChecker struct {
	storage        *Storage
	recoveryGrace  time.Duration
	now            func() time.Time
	mu             sync.Mutex
	unhealthySince *time.Time
	recoveredAt    *time.Time
}

func NewBackendHealthChecker(storage *Storage) *BackendHealthChecker {
	return &BackendHealthChecker{
		storage:       storage,
		recoveryGrace: 2 * time.Minute,
		now:           time.Now,
	}
}

func (h *BackendHealthChecker) Healthy() error {
	if h == nil || h.storage == nil {
		return nil
	}

	if err := h.checkDependencies(); err != nil {
		h.markUnhealthy()
		return err
	}

	return h.markHealthy()
}

func (h *BackendHealthChecker) checkDependencies() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if h.storage.postgres == nil {
		return fmt.Errorf("postgres is not initialized")
	}
	sqlDB, err := h.storage.postgres.DB()
	if err != nil {
		return fmt.Errorf("postgres db handle unavailable: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres ping failed: %w", err)
	}

	if h.storage.redis != nil {
		if err := h.storage.redis.Ping(ctx).Err(); err != nil && err != redis.Nil {
			return fmt.Errorf("redis ping failed: %w", err)
		}
	}

	return nil
}

func (h *BackendHealthChecker) markUnhealthy() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	if h.unhealthySince == nil {
		h.unhealthySince = &now
	}
	h.recoveredAt = nil
}

func (h *BackendHealthChecker) markHealthy() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.unhealthySince == nil {
		return nil
	}

	now := h.now()
	if h.recoveredAt == nil {
		h.recoveredAt = &now
		return fmt.Errorf("backend recovered from dependency failure, suppressing host_down alerts during %s grace period", h.recoveryGrace)
	}

	if now.Sub(*h.recoveredAt) < h.recoveryGrace {
		return fmt.Errorf("backend recovery grace period active for %s", h.recoveryGrace-now.Sub(*h.recoveredAt))
	}

	h.unhealthySince = nil
	h.recoveredAt = nil
	return nil
}
