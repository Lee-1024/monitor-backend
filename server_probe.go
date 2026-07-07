package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	serverProbeTypeTCP       = "tcp"
	serverProbeTypeHTTP      = "http"
	serverProbeStatusUp      = "up"
	serverProbeStatusDown    = "down"
	serverProbeStatusUnknown = "unknown"

	serverProbeDefaultIntervalSeconds = 60
	serverProbeDefaultTimeoutSeconds  = 3
	serverProbeMinIntervalSeconds     = 10
	serverProbeMinTimeoutSeconds      = 1
)

type serverProbeCheckResult struct {
	Status     string
	LatencyMs  int64
	Error      string
	HTTPStatus int
	CheckedAt  time.Time
}

func normalizeServerProbeTarget(target *ServerProbeTarget) {
	target.Type = strings.ToLower(strings.TrimSpace(target.Type))
	target.Name = strings.TrimSpace(target.Name)
	target.Host = strings.TrimSpace(target.Host)
	target.URL = strings.TrimSpace(target.URL)
	if target.IntervalSeconds <= 0 {
		target.IntervalSeconds = serverProbeDefaultIntervalSeconds
	}
	if target.TimeoutSeconds <= 0 {
		target.TimeoutSeconds = serverProbeDefaultTimeoutSeconds
	}
	if target.LastStatus == "" {
		target.LastStatus = serverProbeStatusUnknown
	}
}

func validateServerProbeTarget(target *ServerProbeTarget) error {
	normalizeServerProbeTarget(target)
	if target.Name == "" {
		return errors.New("name is required")
	}
	if target.IntervalSeconds < serverProbeMinIntervalSeconds {
		return fmt.Errorf("interval_seconds must be at least %d", serverProbeMinIntervalSeconds)
	}
	if target.TimeoutSeconds < serverProbeMinTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be at least %d", serverProbeMinTimeoutSeconds)
	}
	if target.TimeoutSeconds > target.IntervalSeconds {
		return errors.New("timeout_seconds must be less than or equal to interval_seconds")
	}

	switch target.Type {
	case serverProbeTypeTCP:
		if target.Host == "" {
			return errors.New("host is required for tcp probes")
		}
		if target.Port < 1 || target.Port > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
	case serverProbeTypeHTTP:
		parsed, err := url.Parse(target.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return errors.New("valid http or https url is required")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("url must start with http:// or https://")
		}
	default:
		return errors.New("type must be tcp or http")
	}
	return nil
}

func runServerProbe(target ServerProbeTarget) serverProbeCheckResult {
	normalizeServerProbeTarget(&target)
	checkedAt := time.Now()
	start := time.Now()
	timeout := time.Duration(target.TimeoutSeconds) * time.Second

	switch target.Type {
	case serverProbeTypeTCP:
		err := probeTCP(target.Host, target.Port, timeout)
		return buildProbeResult(checkedAt, start, 0, err)
	case serverProbeTypeHTTP:
		status, err := probeHTTP(target.URL, timeout)
		return buildProbeResult(checkedAt, start, status, err)
	default:
		return buildProbeResult(checkedAt, start, 0, errors.New("unsupported probe type"))
	}
}

func buildProbeResult(checkedAt, start time.Time, httpStatus int, err error) serverProbeCheckResult {
	result := serverProbeCheckResult{
		Status:     serverProbeStatusUp,
		LatencyMs:  time.Since(start).Milliseconds(),
		HTTPStatus: httpStatus,
		CheckedAt:  checkedAt,
	}
	if err != nil {
		result.Status = serverProbeStatusDown
		result.Error = conciseProbeError(err)
	}
	return result
}

func probeTCP(host string, port int, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func probeHTTP(rawURL string, timeout time.Duration) (int, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, fmt.Errorf("http status %d", resp.StatusCode)
}

func conciseProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "tls"):
		return "tls error"
	case strings.Contains(msg, "no such host"):
		return "host not found"
	}
	return err.Error()
}

func (s *Storage) StartServerProbeWorker() {
	worker := &serverProbeWorker{
		storage:     s,
		tick:        5 * time.Second,
		concurrency: 10,
		stop:        make(chan struct{}),
	}
	go worker.run()
}

type serverProbeWorker struct {
	storage     *Storage
	tick        time.Duration
	concurrency int
	stop        chan struct{}
}

func (w *serverProbeWorker) run() {
	ticker := time.NewTicker(w.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.runDueChecks()
		case <-w.stop:
			return
		}
	}
}

func (w *serverProbeWorker) runDueChecks() {
	targets, err := w.storage.listDueServerProbeTargets(time.Now())
	if err != nil {
		log.Printf("[ServerProbe] Failed to load due targets: %v", err)
		return
	}
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, w.concurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := w.storage.recordServerProbeResult(target, runServerProbe(target)); err != nil {
				log.Printf("[ServerProbe] Failed to record target %d: %v", target.ID, err)
			}
		}()
	}
	wg.Wait()
}

func (s *Storage) listDueServerProbeTargets(now time.Time) ([]ServerProbeTarget, error) {
	var targets []ServerProbeTarget
	err := s.postgres.Where("enabled = ?", true).Find(&targets).Error
	if err != nil {
		return nil, err
	}
	due := make([]ServerProbeTarget, 0, len(targets))
	for _, target := range targets {
		normalizeServerProbeTarget(&target)
		if target.LastCheckedAt == nil || now.Sub(*target.LastCheckedAt) >= time.Duration(target.IntervalSeconds)*time.Second {
			due = append(due, target)
		}
	}
	return due, nil
}

func (s *Storage) recordServerProbeResult(target ServerProbeTarget, result serverProbeCheckResult) error {
	if result.CheckedAt.IsZero() {
		result.CheckedAt = time.Now()
	}
	tx := s.postgres.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	row := ServerProbeResult{
		TargetID:   target.ID,
		CheckedAt:  result.CheckedAt,
		Status:     result.Status,
		LatencyMs:  result.LatencyMs,
		Error:      result.Error,
		HTTPStatus: result.HTTPStatus,
	}
	if err := tx.Create(&row).Error; err != nil {
		tx.Rollback()
		return err
	}
	updates := map[string]interface{}{
		"last_status":     result.Status,
		"last_checked_at": result.CheckedAt,
		"last_error":      result.Error,
		"last_latency_ms": result.LatencyMs,
	}
	if result.Status == serverProbeStatusUp {
		updates["last_success_at"] = result.CheckedAt
	}
	if err := tx.Model(&ServerProbeTarget{}).Where("id = ?", target.ID).Updates(updates).Error; err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

func (s *Storage) cleanupOldServerProbeResults(ctx context.Context, cutoff time.Time) error {
	_, err := s.cleanupOldRowsInBatchesWithContext(ctx, "server_probe_results", "checked_at", cutoff, processSnapshotCleanupBatchSize, snapshotCleanupMaxBatchesPerRun)
	return err
}
