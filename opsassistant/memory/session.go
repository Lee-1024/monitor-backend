package memory

import (
	"time"
)

const RawMessageLimit = 6

type Session struct {
	SessionID string
	UserID    uint
	Title     string
	Summary   string
	Context   Context
	Messages  []Message
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Context struct {
	HostID     string
	HostName   string
	TimeRange  *TimeRange
	LastIntent string
}

type TimeRange struct {
	From time.Time
	To   time.Time
}

type Message struct {
	Role      string
	Content   string
	CreatedAt time.Time
}

type RequestContext struct {
	Message   string
	SessionID string
	HostID    string
	TimeRange *TimeRange
}

func MergeContext(req RequestContext, session *Session) RequestContext {
	if session == nil {
		return req
	}
	merged := req
	if merged.HostID == "" {
		merged.HostID = session.Context.HostID
	}
	if merged.TimeRange == nil {
		merged.TimeRange = session.Context.TimeRange
	}
	return merged
}

func AppendMessage(session *Session, role string, content string, now time.Time) {
	if session == nil {
		return
	}
	session.Messages = append(session.Messages, Message{
		Role:      role,
		Content:   content,
		CreatedAt: now,
	})
	if len(session.Messages) > RawMessageLimit {
		session.Messages = session.Messages[len(session.Messages)-RawMessageLimit:]
	}
	session.UpdatedAt = now
}
