package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type clickHouseStorage struct {
	config ClickHouseConfig
	client *http.Client
}

func newClickHouseStorage(config ClickHouseConfig) *clickHouseStorage {
	return &clickHouseStorage{config: config, client: &http.Client{Timeout: time.Duration(config.EffectiveWriteTimeoutSeconds()) * time.Second}}
}

func clickHouseSchemaStatements(database string, retentionDays int) []string {
	db := sanitizeClickHouseIdentifier(database)
	return []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", db),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.process_snapshots (timestamp DateTime64(3), host_id String, pid Int32, name String, user String, cpu_percent Float64, memory_percent Float64, memory_bytes UInt64, status String, command String) ENGINE = MergeTree PARTITION BY toDate(timestamp) ORDER BY (host_id, timestamp, name) TTL toDateTime(timestamp) + INTERVAL %d DAY`, db, retentionDays),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.docker_container_snapshots (timestamp DateTime64(3), host_id String, container_id String, name String, image String, state String, status String, created_unix Int64, started_at DateTime64(3), restart_count Int32, ports String, cpu_percent Float64, memory_usage UInt64, memory_limit UInt64, memory_percent Float64, network_rx UInt64, network_tx UInt64, block_read UInt64, block_write UInt64) ENGINE = MergeTree PARTITION BY toDate(timestamp) ORDER BY (host_id, timestamp, name) TTL toDateTime(timestamp) + INTERVAL %d DAY`, db, retentionDays),
	}
}

func sanitizeClickHouseIdentifier(value string) string {
	for _, r := range value {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return "monitor"
		}
	}
	if value == "" {
		return "monitor"
	}
	return value
}

func (c *clickHouseStorage) initSchema(ctx context.Context) error {
	for _, statement := range clickHouseSchemaStatements(c.config.EffectiveDatabase(), c.config.EffectiveRetentionDays()) {
		if err := c.exec(ctx, statement, ""); err != nil {
			return err
		}
	}
	return nil
}

func (c *clickHouseStorage) exec(ctx context.Context, query, body string) error {
	_, err := c.do(ctx, query, body)
	return err
}

func (c *clickHouseStorage) query(ctx context.Context, query string) ([]byte, error) {
	return c.do(ctx, query, "")
}

func (c *clickHouseStorage) do(ctx context.Context, query, body string) ([]byte, error) {
	u, err := url.Parse(strings.TrimRight(c.config.EffectiveAddress(), "/"))
	if err != nil {
		return nil, err
	}
	params := u.Query()
	params.Set("query", query)
	if strings.HasPrefix(strings.TrimSpace(strings.ToUpper(query)), "INSERT") {
		params.Set("async_insert", "1")
		params.Set("wait_for_async_insert", "1")
	}
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if c.config.Username != "" {
		req.SetBasicAuth(c.config.Username, c.config.Password)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return io.ReadAll(resp.Body)
}
