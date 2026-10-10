package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	processSnapshotStream = "monitor:stream:process-snapshots"
	dockerSnapshotStream  = "monitor:stream:docker-snapshots"
	processHistoryPrefix  = "monitor:history:process:"
	dockerHistoryPrefix   = "monitor:history:docker:"
	processHistoryHosts   = "monitor:history:process:hosts"
	dockerHistoryHosts    = "monitor:history:docker:hosts"
)

type snapshotReport[T any] struct {
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`
	Rows      []T       `json:"rows"`
}

func (s *Storage) AppendProcessSnapshotReport(ctx context.Context, rows []ProcessSnapshot) error {
	if len(rows) == 0 {
		return nil
	}
	appendCtx, cancel := snapshotAppendContext()
	defer cancel()
	return s.appendSnapshotReport(appendCtx, processSnapshotStream, processHistoryPrefix+rows[0].HostID, processHistoryHosts, rows[0].HostID, snapshotReport[ProcessSnapshot]{rows[0].HostID, rows[0].Timestamp, rows})
}

func (s *Storage) AppendDockerSnapshotReport(ctx context.Context, rows []DockerContainerSnapshot) error {
	if len(rows) == 0 {
		return nil
	}
	appendCtx, cancel := snapshotAppendContext()
	defer cancel()
	return s.appendSnapshotReport(appendCtx, dockerSnapshotStream, dockerHistoryPrefix+rows[0].HostID, dockerHistoryHosts, rows[0].HostID, snapshotReport[DockerContainerSnapshot]{rows[0].HostID, rows[0].Timestamp, rows})
}

func snapshotAppendContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Second)
}

func (s *Storage) appendSnapshotReport(ctx context.Context, stream, historyKey, hostsKey, hostID string, report any) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	ts := time.Now()
	switch r := report.(type) {
	case snapshotReport[ProcessSnapshot]:
		ts = r.Timestamp
	case snapshotReport[DockerContainerSnapshot]:
		ts = r.Timestamp
	}
	pipe := s.redis.TxPipeline()
	// Do not trim the durable stream here: Redis can otherwise remove entries
	// that are still pending while ClickHouse is unavailable.
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"payload": payload}})
	pipe.ZAdd(ctx, historyKey, redis.Z{Score: float64(ts.UnixMilli()), Member: string(payload)})
	pipe.SAdd(ctx, hostsKey, hostID)
	cutoff := ts.Add(-time.Duration(s.config.Snapshot.EffectiveRedisHistoryHours()) * time.Hour).UnixMilli()
	pipe.ZRemRangeByScore(ctx, historyKey, "-inf", strconv.FormatInt(cutoff, 10))
	pipe.Expire(ctx, historyKey, time.Duration(s.config.Snapshot.EffectiveRedisHistoryHours()+1)*time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Storage) startSnapshotStreamConsumers() {
	ctx, cancel := context.WithCancel(context.Background())
	s.snapshotCancel = cancel
	group := s.config.Snapshot.EffectiveConsumerGroup()
	for _, stream := range []string{processSnapshotStream, dockerSnapshotStream} {
		if err := s.redis.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
			log.Printf("[SnapshotStream] create group stream=%s: %v", stream, err)
		}
	}
	s.snapshotWG.Add(2)
	go s.consumeProcessSnapshots(ctx)
	go s.consumeDockerSnapshots(ctx)
}

func (s *Storage) stopSnapshotStreamConsumers() {
	if s.snapshotCancel != nil {
		s.snapshotCancel()
		s.snapshotWG.Wait()
	}
}

func (s *Storage) consumeProcessSnapshots(ctx context.Context) {
	defer s.snapshotWG.Done()
	s.consumeSnapshotStream(ctx, processSnapshotStream, func(payloads [][]byte) error {
		var body bytes.Buffer
		for _, p := range payloads {
			var r snapshotReport[ProcessSnapshot]
			if err := json.Unmarshal(p, &r); err != nil {
				return err
			}
			for _, row := range r.Rows {
				data, err := json.Marshal(row)
				if err != nil {
					return err
				}
				body.Write(data)
				body.WriteByte('\n')
			}
		}
		q := fmt.Sprintf("INSERT INTO %s.process_snapshots SETTINGS input_format_skip_unknown_fields=1, date_time_input_format='best_effort' FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()))
		return s.clickhouse.exec(ctx, q, body.String())
	})
}

func marshalDockerSnapshotRow(row DockerContainerSnapshot) ([]byte, error) {
	// ClickHouse only stores trend fields. In particular, omit zero StartedAt
	// values: Go's year-1 zero time is outside ClickHouse DateTime64's range.
	return json.Marshal(map[string]interface{}{
		"timestamp":      row.Timestamp,
		"host_id":        row.HostID,
		"container_id":   row.ContainerID,
		"name":           row.Name,
		"image":          row.Image,
		"state":          row.State,
		"status":         row.Status,
		"created_unix":   row.CreatedUnix,
		"restart_count":  row.RestartCount,
		"ports":          row.Ports,
		"cpu_percent":    row.CPUPercent,
		"memory_usage":   row.MemoryUsage,
		"memory_limit":   row.MemoryLimit,
		"memory_percent": row.MemoryPercent,
		"network_rx":     row.NetworkRx,
		"network_tx":     row.NetworkTx,
		"block_read":     row.BlockRead,
		"block_write":    row.BlockWrite,
	})
}
func (s *Storage) consumeDockerSnapshots(ctx context.Context) {
	defer s.snapshotWG.Done()
	s.consumeSnapshotStream(ctx, dockerSnapshotStream, func(payloads [][]byte) error {
		var body bytes.Buffer
		for _, p := range payloads {
			var r snapshotReport[DockerContainerSnapshot]
			if err := json.Unmarshal(p, &r); err != nil {
				return err
			}
			for _, row := range r.Rows {
				data, err := marshalDockerSnapshotRow(row)
				if err != nil {
					return err
				}
				body.Write(data)
				body.WriteByte('\n')
			}
		}
		q := fmt.Sprintf("INSERT INTO %s.docker_container_snapshots SETTINGS input_format_skip_unknown_fields=1, date_time_input_format='best_effort' FORMAT JSONEachRow", sanitizeClickHouseIdentifier(s.config.ClickHouse.EffectiveDatabase()))
		return s.clickhouse.exec(ctx, q, body.String())
	})
}

func (s *Storage) redisProcessHistory(ctx context.Context, hostID string, start, end time.Time) ([]ProcessSnapshot, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ctx = queryCtx
	var reports []string
	hosts := []string{hostID}
	if hostID == "" {
		var err error
		hosts, err = s.redis.SMembers(ctx, processHistoryHosts).Result()
		if err != nil {
			return nil, err
		}
	}
	for _, host := range hosts {
		values, err := s.redis.ZRangeByScore(ctx, processHistoryPrefix+host, &redis.ZRangeBy{Min: strconv.FormatInt(start.UnixMilli(), 10), Max: strconv.FormatInt(end.UnixMilli(), 10)}).Result()
		if err != nil {
			return nil, err
		}
		reports = append(reports, values...)
	}
	rows := make([]ProcessSnapshot, 0)
	for _, payload := range reports {
		var report snapshotReport[ProcessSnapshot]
		if err := json.Unmarshal([]byte(payload), &report); err != nil {
			continue
		}
		rows = append(rows, report.Rows...)
	}
	return rows, nil
}

func (s *Storage) redisDockerHistory(ctx context.Context, hostID string, start, end time.Time) ([]DockerContainerSnapshot, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ctx = queryCtx
	var reports []string
	hosts := []string{hostID}
	if hostID == "" {
		var err error
		hosts, err = s.redis.SMembers(ctx, dockerHistoryHosts).Result()
		if err != nil {
			return nil, err
		}
	}
	for _, host := range hosts {
		values, err := s.redis.ZRangeByScore(ctx, dockerHistoryPrefix+host, &redis.ZRangeBy{Min: strconv.FormatInt(start.UnixMilli(), 10), Max: strconv.FormatInt(end.UnixMilli(), 10)}).Result()
		if err != nil {
			return nil, err
		}
		reports = append(reports, values...)
	}
	rows := make([]DockerContainerSnapshot, 0)
	for _, payload := range reports {
		var report snapshotReport[DockerContainerSnapshot]
		if err := json.Unmarshal([]byte(payload), &report); err != nil {
			continue
		}
		rows = append(rows, report.Rows...)
	}
	return rows, nil
}

func (s *Storage) consumeSnapshotStream(ctx context.Context, stream string, write func([][]byte) error) {
	group, consumer := s.config.Snapshot.EffectiveConsumerGroup(), s.config.Snapshot.EffectiveConsumerName()
	for ctx.Err() == nil {
		result, err := s.redis.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: consumer, Streams: []string{stream, "0"}, Count: int64(s.config.ClickHouse.EffectiveBatchRows())}).Result()
		if err == redis.Nil || (err == nil && len(result) == 0) {
			result, err = s.redis.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: consumer, Streams: []string{stream, ">"}, Count: int64(s.config.ClickHouse.EffectiveBatchRows()), Block: time.Duration(s.config.ClickHouse.EffectiveFlushIntervalSeconds()) * time.Second}).Result()
		}
		if err == redis.Nil || ctx.Err() != nil {
			continue
		}
		if err != nil {
			log.Printf("[SnapshotStream] read failed stream=%s: %v", stream, err)
			time.Sleep(2 * time.Second)
			continue
		}
		var ids []string
		var payloads [][]byte
		for _, sr := range result {
			for _, msg := range sr.Messages {
				value, ok := msg.Values["payload"]
				if !ok {
					ids = append(ids, msg.ID)
					continue
				}
				payloads = append(payloads, []byte(fmt.Sprint(value)))
				ids = append(ids, msg.ID)
			}
		}
		if len(payloads) > 0 {
			if err := write(payloads); err != nil {
				log.Printf("[SnapshotStream] ClickHouse write failed stream=%s reports=%d: %v", stream, len(payloads), err)
				time.Sleep(10 * time.Second)
				continue
			}
		}
		if len(ids) > 0 {
			if err := s.redis.XAck(ctx, stream, group, ids...).Err(); err != nil {
				log.Printf("[SnapshotStream] ack failed stream=%s: %v", stream, err)
			} else if err := s.redis.XDel(ctx, stream, ids...).Err(); err != nil {
				log.Printf("[SnapshotStream] delete acknowledged entries failed stream=%s: %v", stream, err)
			}
		}
	}
}
