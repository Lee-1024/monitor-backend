package memory

import (
	"context"
	"errors"
)

var ErrSessionNotFound = errors.New("ops assistant session not found")

type Store interface {
	Get(ctx context.Context, userID uint, sessionID string) (*Session, error)
	Save(ctx context.Context, session *Session) error
	List(ctx context.Context, userID uint, limit int) ([]Session, error)
	Delete(ctx context.Context, userID uint, sessionID string) error
}
