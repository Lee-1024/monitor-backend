package api

import (
	"testing"
	"time"

	"monitor-backend/opsassistant/memory"
)

func TestOpsAssistantSessionContextJSONRoundTrip(t *testing.T) {
	from := time.Date(2026, 8, 4, 8, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Hour)
	ctx := memory.Context{
		HostID:     "host-01",
		HostName:   "master",
		LastIntent: "host_performance",
		TimeRange:  &memory.TimeRange{From: from, To: to},
	}

	payload := encodeOpsAssistantSessionContext(ctx)
	decoded := decodeOpsAssistantSessionContext(payload)

	if decoded.HostID != ctx.HostID || decoded.HostName != ctx.HostName || decoded.LastIntent != ctx.LastIntent {
		t.Fatalf("context did not round trip: %#v", decoded)
	}
	if decoded.TimeRange == nil || !decoded.TimeRange.From.Equal(from) || !decoded.TimeRange.To.Equal(to) {
		t.Fatalf("time range did not round trip: %#v", decoded.TimeRange)
	}
}
