package memory

import (
	"context"
	"sort"
	"sync"
)

type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: map[string]Session{}}
}

func (s *MemoryStore) Get(ctx context.Context, userID uint, sessionID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok || session.UserID != userID {
		return nil, ErrSessionNotFound
	}
	return cloneSession(session), nil
}

func (s *MemoryStore) Save(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.SessionID] = *cloneSession(*session)
	return nil
}

func (s *MemoryStore) List(ctx context.Context, userID uint, limit int) ([]Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions []Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessions = append(sessions, *cloneSession(session))
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].UpdatedAt.After(sessions[j].UpdatedAt)
	})
	if limit > 0 && len(sessions) > limit {
		sessions = sessions[:limit]
	}
	return sessions, nil
}

func (s *MemoryStore) Delete(ctx context.Context, userID uint, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok || session.UserID != userID {
		return ErrSessionNotFound
	}
	delete(s.sessions, sessionID)
	return nil
}

func cloneSession(session Session) *Session {
	clone := session
	if session.Messages != nil {
		clone.Messages = append([]Message(nil), session.Messages...)
	}
	return &clone
}
