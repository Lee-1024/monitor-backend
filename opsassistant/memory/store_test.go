package memory

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeStore struct {
	sessions map[string]Session
}

func newFakeStore() *fakeStore {
	return &fakeStore{sessions: map[string]Session{}}
}

func (s *fakeStore) Get(ctx context.Context, userID uint, sessionID string) (*Session, error) {
	session, ok := s.sessions[sessionID]
	if !ok || session.UserID != userID {
		return nil, ErrSessionNotFound
	}
	return &session, nil
}

func (s *fakeStore) Save(ctx context.Context, session *Session) error {
	if session == nil {
		return errors.New("session is nil")
	}
	s.sessions[session.SessionID] = *session
	return nil
}

func (s *fakeStore) List(ctx context.Context, userID uint, limit int) ([]Session, error) {
	var sessions []Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	if limit > 0 && len(sessions) > limit {
		sessions = sessions[:limit]
	}
	return sessions, nil
}

func (s *fakeStore) Delete(ctx context.Context, userID uint, sessionID string) error {
	session, ok := s.sessions[sessionID]
	if !ok || session.UserID != userID {
		return ErrSessionNotFound
	}
	delete(s.sessions, sessionID)
	return nil
}

func TestStoreCreatesAndLoadsSession(t *testing.T) {
	store := newFakeStore()
	session := &Session{
		SessionID: "ops_1",
		UserID:    1,
		Title:     "master memory",
		Context:   Context{HostID: "master"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := store.Save(context.Background(), session); err != nil {
		t.Fatalf("save session: %v", err)
	}
	loaded, err := store.Get(context.Background(), 1, "ops_1")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if loaded.Context.HostID != "master" {
		t.Fatalf("expected host context, got %#v", loaded.Context)
	}
}

func TestStoreUpdatesContextAndMessages(t *testing.T) {
	store := newFakeStore()
	session := &Session{SessionID: "ops_1", UserID: 1}
	AppendMessage(session, "user", "check host", time.Now())
	session.Context.HostID = "master"

	if err := store.Save(context.Background(), session); err != nil {
		t.Fatalf("save session: %v", err)
	}
	loaded, err := store.Get(context.Background(), 1, "ops_1")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if len(loaded.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(loaded.Messages))
	}
	if loaded.Context.HostID != "master" {
		t.Fatalf("expected updated host, got %q", loaded.Context.HostID)
	}
}

func TestStoreListsSessionsByUser(t *testing.T) {
	store := newFakeStore()
	_ = store.Save(context.Background(), &Session{SessionID: "ops_1", UserID: 1})
	_ = store.Save(context.Background(), &Session{SessionID: "ops_2", UserID: 2})

	sessions, err := store.List(context.Background(), 1, 10)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "ops_1" {
		t.Fatalf("expected only user 1 session, got %#v", sessions)
	}
}

func TestStoreDeletesOnlyUserOwnedSession(t *testing.T) {
	store := newFakeStore()
	_ = store.Save(context.Background(), &Session{SessionID: "ops_1", UserID: 1})

	if err := store.Delete(context.Background(), 2, "ops_1"); err == nil {
		t.Fatal("expected delete by another user to fail")
	}
	if err := store.Delete(context.Background(), 1, "ops_1"); err != nil {
		t.Fatalf("delete owned session: %v", err)
	}
	if _, err := store.Get(context.Background(), 1, "ops_1"); err == nil {
		t.Fatal("expected deleted session to be missing")
	}
}
