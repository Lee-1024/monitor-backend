package memory

import (
	"testing"
	"time"
)

func TestMergeContextRequestHostOverridesSessionHost(t *testing.T) {
	session := &Session{
		Context: Context{
			HostID:   "old-host",
			HostName: "old-hostname",
		},
	}

	merged := MergeContext(RequestContext{
		Message: "check host",
		HostID:  "new-host",
	}, session)

	if merged.HostID != "new-host" {
		t.Fatalf("expected request host to win, got %q", merged.HostID)
	}
}

func TestMergeContextUsesSessionHostWhenRequestMissing(t *testing.T) {
	session := &Session{
		Context: Context{
			HostID: "session-host",
		},
	}

	merged := MergeContext(RequestContext{Message: "continue"}, session)

	if merged.HostID != "session-host" {
		t.Fatalf("expected session host, got %q", merged.HostID)
	}
}

func TestMergeContextRequestTimeRangeOverridesSessionTimeRange(t *testing.T) {
	sessionRange := &TimeRange{
		From: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
	}
	requestRange := &TimeRange{
		From: time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 5, 25, 1, 0, 0, 0, time.UTC),
	}
	session := &Session{Context: Context{TimeRange: sessionRange}}

	merged := MergeContext(RequestContext{
		Message:   "check range",
		TimeRange: requestRange,
	}, session)

	if merged.TimeRange == nil {
		t.Fatal("expected time range")
	}
	if !merged.TimeRange.From.Equal(requestRange.From) || !merged.TimeRange.To.Equal(requestRange.To) {
		t.Fatalf("expected request range, got %#v", merged.TimeRange)
	}
}

func TestMergeContextUsesSessionTimeRangeWhenRequestMissing(t *testing.T) {
	sessionRange := &TimeRange{
		From: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
	}
	session := &Session{Context: Context{TimeRange: sessionRange}}

	merged := MergeContext(RequestContext{Message: "continue"}, session)

	if merged.TimeRange == nil {
		t.Fatal("expected session time range")
	}
	if !merged.TimeRange.From.Equal(sessionRange.From) || !merged.TimeRange.To.Equal(sessionRange.To) {
		t.Fatalf("expected session range, got %#v", merged.TimeRange)
	}
}

func TestSessionKeepsLastSixMessages(t *testing.T) {
	session := &Session{}
	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 8; i++ {
		AppendMessage(session, "user", string(rune('a'+i)), now.Add(time.Duration(i)*time.Minute))
	}

	if len(session.Messages) != 6 {
		t.Fatalf("expected 6 messages, got %d", len(session.Messages))
	}
	if session.Messages[0].Content != "c" {
		t.Fatalf("expected first retained message to be c, got %q", session.Messages[0].Content)
	}
	if session.Messages[5].Content != "h" {
		t.Fatalf("expected last retained message to be h, got %q", session.Messages[5].Content)
	}
}
