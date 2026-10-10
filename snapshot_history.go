package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func clickHouseString(value string) string { return strings.ReplaceAll(value, "'", "''") }

func (s *Storage) snapshotProcessHistory(ctx context.Context, hostID string, start, end time.Time) ([]ProcessSnapshot, error) {
	cutoff := time.Now().Add(-time.Duration(s.config.Snapshot.EffectiveRedisHistoryHours()) * time.Hour)
	var result []ProcessSnapshot
	if start.Before(cutoff) && s.clickhouse != nil {
		olderEnd := end
		if olderEnd.After(cutoff) {
			olderEnd = cutoff
		}
		rows, err := s.clickHouseProcessHistory(ctx, hostID, start, olderEnd)
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	if end.After(cutoff) {
		newerStart := start
		if newerStart.Before(cutoff) {
			newerStart = cutoff
		}
		rows, err := s.redisProcessHistory(ctx, hostID, newerStart, end)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 && s.clickhouse != nil {
			rows, err = s.clickHouseProcessHistory(ctx, hostID, newerStart, end)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, rows...)
	}
	return result, nil
}

func (s *Storage) snapshotDockerHistory(ctx context.Context, hostID string, start, end time.Time) ([]DockerContainerSnapshot, error) {
	cutoff := time.Now().Add(-time.Duration(s.config.Snapshot.EffectiveRedisHistoryHours()) * time.Hour)
	var result []DockerContainerSnapshot
	if start.Before(cutoff) && s.clickhouse != nil {
		olderEnd := end
		if olderEnd.After(cutoff) {
			olderEnd = cutoff
		}
		rows, err := s.clickHouseDockerHistory(ctx, hostID, start, olderEnd)
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	if end.After(cutoff) {
		newerStart := start
		if newerStart.Before(cutoff) {
			newerStart = cutoff
		}
		rows, err := s.redisDockerHistory(ctx, hostID, newerStart, end)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 && s.clickhouse != nil {
			rows, err = s.clickHouseDockerHistory(ctx, hostID, newerStart, end)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, rows...)
	}
	return result, nil
}

func (s *Storage) clickHouseProcessHistory(ctx context.Context, hostID string, start, end time.Time) ([]ProcessSnapshot, error) {
	where := fmt.Sprintf("timestamp >= fromUnixTimestamp64Milli(%d) AND timestamp <= fromUnixTimestamp64Milli(%d)", start.UnixMilli(), end.UnixMilli())
	if hostID != "" {
		where += fmt.Sprintf(" AND host_id = '%s'", clickHouseString(hostID))
	}
	q := fmt.Sprintf("SELECT toUnixTimestamp64Milli(timestamp) timestamp_ms, host_id, pid, name, user, cpu_percent, memory_percent, memory_bytes, status, command FROM %s.process_snapshots WHERE %s FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()), where)
	data, err := s.clickhouse.query(ctx, q)
	if err != nil {
		return nil, err
	}
	type row struct {
		TimestampMS int64   `json:"timestamp_ms"`
		HostID      string  `json:"host_id"`
		PID         int32   `json:"pid"`
		Name        string  `json:"name"`
		User        string  `json:"user"`
		CPU         float64 `json:"cpu_percent"`
		Memory      float64 `json:"memory_percent"`
		MemoryBytes uint64  `json:"memory_bytes"`
		Status      string  `json:"status"`
		Command     string  `json:"command"`
	}
	var out []ProcessSnapshot
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var r row
		if json.Unmarshal(scan.Bytes(), &r) == nil {
			out = append(out, ProcessSnapshot{HostID: r.HostID, Timestamp: time.UnixMilli(r.TimestampMS), PID: r.PID, Name: r.Name, User: r.User, CPUPercent: r.CPU, MemoryPercent: r.Memory, MemoryBytes: r.MemoryBytes, Status: r.Status, Command: r.Command})
		}
	}
	return out, scan.Err()
}

func (s *Storage) clickHouseDockerHistory(ctx context.Context, hostID string, start, end time.Time) ([]DockerContainerSnapshot, error) {
	where := fmt.Sprintf("timestamp >= fromUnixTimestamp64Milli(%d) AND timestamp <= fromUnixTimestamp64Milli(%d)", start.UnixMilli(), end.UnixMilli())
	if hostID != "" {
		where += fmt.Sprintf(" AND host_id = '%s'", clickHouseString(hostID))
	}
	q := fmt.Sprintf("SELECT toUnixTimestamp64Milli(timestamp) timestamp_ms, host_id, container_id, name, cpu_percent, memory_percent, memory_usage FROM %s.docker_container_snapshots WHERE %s FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()), where)
	data, err := s.clickhouse.query(ctx, q)
	if err != nil {
		return nil, err
	}
	type row struct {
		TimestampMS int64   `json:"timestamp_ms"`
		HostID      string  `json:"host_id"`
		ContainerID string  `json:"container_id"`
		Name        string  `json:"name"`
		CPU         float64 `json:"cpu_percent"`
		Memory      float64 `json:"memory_percent"`
		MemoryUsage uint64  `json:"memory_usage"`
	}
	var out []DockerContainerSnapshot
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var r row
		if json.Unmarshal(scan.Bytes(), &r) == nil {
			out = append(out, DockerContainerSnapshot{HostID: r.HostID, Timestamp: time.UnixMilli(r.TimestampMS), ContainerID: r.ContainerID, Name: r.Name, CPUPercent: r.CPU, MemoryPercent: r.Memory, MemoryUsage: r.MemoryUsage})
		}
	}
	return out, scan.Err()
}
