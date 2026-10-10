package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func clickHouseString(value string) string { return strings.ReplaceAll(value, "'", "''") }

func clickHouseNameFilter(names []string) string {
	if len(names) == 0 {
		return ""
	}
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = "'" + clickHouseString(name) + "'"
	}
	return " AND name IN (" + strings.Join(parts, ",") + ")"
}

func (s *Storage) clickHouseTopNames(ctx context.Context, table, hostID string, start, end time.Time, metric string, topN int) ([]string, error) {
	where := fmt.Sprintf("timestamp >= fromUnixTimestamp64Milli(%d) AND timestamp <= fromUnixTimestamp64Milli(%d)", start.UnixMilli(), end.UnixMilli())
	if hostID != "" {
		where += fmt.Sprintf(" AND host_id = '%s'", clickHouseString(hostID))
	}
	if metric != "memory" {
		metric = "cpu"
	}
	column := "cpu_percent"
	if metric == "memory" {
		column = "memory_percent"
	}
	q := fmt.Sprintf("SELECT name FROM %s.%s WHERE %s AND %s > 0 GROUP BY name ORDER BY max(%s) DESC, name ASC LIMIT %d FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()), table, where, column, column, topN)
	data, err := s.clickhouse.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var result []string
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var row struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(scan.Bytes(), &row) == nil && row.Name != "" {
			result = append(result, row.Name)
		}
	}
	return result, scan.Err()
}

func (s *Storage) clickHouseProcessHistoryFiltered(ctx context.Context, hostID string, start, end time.Time, names []string, metric string, limit int) ([]ProcessSnapshot, error) {
	where := fmt.Sprintf("timestamp >= fromUnixTimestamp64Milli(%d) AND timestamp <= fromUnixTimestamp64Milli(%d)", start.UnixMilli(), end.UnixMilli())
	if hostID != "" {
		where += fmt.Sprintf(" AND host_id = '%s'", clickHouseString(hostID))
	}
	where += clickHouseNameFilter(names)
	column := "cpu_percent"
	if metric == "memory" {
		column = "memory_percent"
	}
	where += " AND " + column + " > 0"
	limitSQL := ""
	if limit > 0 {
		limitSQL = fmt.Sprintf(" LIMIT %d", limit)
	}
	q := fmt.Sprintf("SELECT toUnixTimestamp64Milli(timestamp) timestamp_ms, host_id, pid, name, user, cpu_percent, memory_percent, memory_bytes, status, command FROM %s.process_snapshots WHERE %s ORDER BY timestamp ASC, name ASC%s FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()), where, limitSQL)
	data, err := s.clickhouse.query(ctx, q)
	if err != nil {
		return nil, err
	}
	return decodeClickHouseProcesses(data)
}

func (s *Storage) clickHouseDockerHistoryFiltered(ctx context.Context, hostID string, start, end time.Time, names []string, metric string, limit int) ([]DockerContainerSnapshot, error) {
	where := fmt.Sprintf("timestamp >= fromUnixTimestamp64Milli(%d) AND timestamp <= fromUnixTimestamp64Milli(%d)", start.UnixMilli(), end.UnixMilli())
	if hostID != "" {
		where += fmt.Sprintf(" AND host_id = '%s'", clickHouseString(hostID))
	}
	where += clickHouseNameFilter(names)
	column := "cpu_percent"
	if metric == "memory" {
		column = "memory_percent"
	}
	where += " AND " + column + " > 0"
	limitSQL := ""
	if limit > 0 {
		limitSQL = fmt.Sprintf(" LIMIT %d", limit)
	}
	q := fmt.Sprintf("SELECT toUnixTimestamp64Milli(timestamp) timestamp_ms, host_id, container_id, name, cpu_percent, memory_percent, memory_usage FROM %s.docker_container_snapshots WHERE %s ORDER BY timestamp ASC, name ASC%s FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()), where, limitSQL)
	data, err := s.clickhouse.query(ctx, q)
	if err != nil {
		return nil, err
	}
	return decodeClickHouseDocker(data)
}

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
		TimestampMS json.RawMessage `json:"timestamp_ms"`
		HostID      string          `json:"host_id"`
		PID         int32           `json:"pid"`
		Name        string          `json:"name"`
		User        string          `json:"user"`
		CPU         float64         `json:"cpu_percent"`
		Memory      float64         `json:"memory_percent"`
		MemoryBytes uint64          `json:"memory_bytes"`
		Status      string          `json:"status"`
		Command     string          `json:"command"`
	}
	return decodeClickHouseProcessesWithRow(data, row{})
}

func decodeClickHouseProcesses(data []byte) ([]ProcessSnapshot, error) {
	return decodeClickHouseProcessesWithRow(data, struct {
		TimestampMS json.RawMessage `json:"timestamp_ms"`
		HostID      string          `json:"host_id"`
		PID         int32           `json:"pid"`
		Name        string          `json:"name"`
		User        string          `json:"user"`
		CPU         float64         `json:"cpu_percent"`
		Memory      float64         `json:"memory_percent"`
		MemoryBytes uint64          `json:"memory_bytes"`
		Status      string          `json:"status"`
		Command     string          `json:"command"`
	}{})
}

func decodeClickHouseProcessesWithRow(data []byte, _ interface{}) ([]ProcessSnapshot, error) {
	type row struct {
		TimestampMS json.RawMessage `json:"timestamp_ms"`
		HostID      string          `json:"host_id"`
		PID         int32           `json:"pid"`
		Name        string          `json:"name"`
		User        string          `json:"user"`
		CPU         float64         `json:"cpu_percent"`
		Memory      float64         `json:"memory_percent"`
		MemoryBytes uint64          `json:"memory_bytes"`
		Status      string          `json:"status"`
		Command     string          `json:"command"`
	}
	var out []ProcessSnapshot
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var r row
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			return nil, err
		}
		ms, err := clickHouseTimestampMillis(r.TimestampMS)
		if err != nil {
			return nil, err
		}
		out = append(out, ProcessSnapshot{HostID: r.HostID, Timestamp: time.UnixMilli(ms), PID: r.PID, Name: r.Name, User: r.User, CPUPercent: r.CPU, MemoryPercent: r.Memory, MemoryBytes: r.MemoryBytes, Status: r.Status, Command: r.Command})
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
		TimestampMS json.RawMessage `json:"timestamp_ms"`
		HostID      string          `json:"host_id"`
		ContainerID string          `json:"container_id"`
		Name        string          `json:"name"`
		CPU         float64         `json:"cpu_percent"`
		Memory      float64         `json:"memory_percent"`
		MemoryUsage uint64          `json:"memory_usage"`
	}
	return decodeClickHouseDockerWithRow(data, row{})
}

func decodeClickHouseDocker(data []byte) ([]DockerContainerSnapshot, error) {
	return decodeClickHouseDockerWithRow(data, nil)
}
func decodeClickHouseDockerWithRow(data []byte, _ interface{}) ([]DockerContainerSnapshot, error) {
	type row struct {
		TimestampMS json.RawMessage `json:"timestamp_ms"`
		HostID      string          `json:"host_id"`
		ContainerID string          `json:"container_id"`
		Name        string          `json:"name"`
		CPU         float64         `json:"cpu_percent"`
		Memory      float64         `json:"memory_percent"`
		MemoryUsage uint64          `json:"memory_usage"`
	}
	var out []DockerContainerSnapshot
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var r row
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			return nil, err
		}
		ms, err := clickHouseTimestampMillis(r.TimestampMS)
		if err != nil {
			return nil, err
		}
		out = append(out, DockerContainerSnapshot{HostID: r.HostID, Timestamp: time.UnixMilli(ms), ContainerID: r.ContainerID, Name: r.Name, CPUPercent: r.CPU, MemoryPercent: r.Memory, MemoryUsage: r.MemoryUsage})
	}
	return out, scan.Err()
}

func clickHouseTimestampMillis(raw json.RawMessage) (int64, error) {
	value := strings.Trim(string(raw), `"`)
	return strconv.ParseInt(value, 10, 64)
}
