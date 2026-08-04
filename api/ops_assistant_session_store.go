package api

import (
	"context"
	"encoding/json"
	"time"

	"monitor-backend/opsassistant/memory"

	"gorm.io/gorm"
)

type opsAssistantDBSessionStore struct {
	db *gorm.DB
}

type opsAssistantSessionRow struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	SessionID string         `gorm:"size:64"`
	UserID    uint
	Title     string
	Summary   string
	Context   string
}

type opsAssistantMessageRow struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	SessionID string `gorm:"size:64"`
	UserID    uint
	Role      string `gorm:"size:32"`
	Content   string
}

func newOpsAssistantDBSessionStore(db *gorm.DB) memory.Store {
	return &opsAssistantDBSessionStore{db: db}
}

func (opsAssistantSessionRow) TableName() string {
	return "ops_assistant_sessions"
}

func (opsAssistantMessageRow) TableName() string {
	return "ops_assistant_messages"
}

func (s *opsAssistantDBSessionStore) Get(ctx context.Context, userID uint, sessionID string) (*memory.Session, error) {
	var row opsAssistantSessionRow
	if err := s.db.WithContext(ctx).Where("user_id = ? AND session_id = ?", userID, sessionID).First(&row).Error; err != nil {
		return nil, memory.ErrSessionNotFound
	}
	var messageRows []opsAssistantMessageRow
	if err := s.db.WithContext(ctx).Where("user_id = ? AND session_id = ?", userID, sessionID).Order("created_at ASC, id ASC").Find(&messageRows).Error; err != nil {
		return nil, err
	}
	session := sessionFromOpsAssistantRow(row, messageRows)
	return &session, nil
}

func (s *opsAssistantDBSessionStore) Save(ctx context.Context, session *memory.Session) error {
	if session == nil {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		row := opsAssistantSessionRow{
			SessionID: session.SessionID,
			UserID:    session.UserID,
			Title:     session.Title,
			Summary:   session.Summary,
			Context:   encodeOpsAssistantSessionContext(session.Context),
			CreatedAt: session.CreatedAt,
			UpdatedAt: session.UpdatedAt,
		}
		var existing opsAssistantSessionRow
		err := tx.Where("user_id = ? AND session_id = ?", session.UserID, session.SessionID).First(&existing).Error
		if err == nil {
			row.ID = existing.ID
			if row.CreatedAt.IsZero() {
				row.CreatedAt = existing.CreatedAt
			}
			if err := tx.Save(&row).Error; err != nil {
				return err
			}
		} else if err == gorm.ErrRecordNotFound {
			if row.CreatedAt.IsZero() {
				row.CreatedAt = time.Now()
			}
			if row.UpdatedAt.IsZero() {
				row.UpdatedAt = row.CreatedAt
			}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		} else {
			return err
		}

		if err := tx.Where("user_id = ? AND session_id = ?", session.UserID, session.SessionID).Delete(&opsAssistantMessageRow{}).Error; err != nil {
			return err
		}
		for _, message := range session.Messages {
			messageRow := opsAssistantMessageRow{
				SessionID: session.SessionID,
				UserID:    session.UserID,
				Role:      message.Role,
				Content:   message.Content,
				CreatedAt: message.CreatedAt,
			}
			if messageRow.CreatedAt.IsZero() {
				messageRow.CreatedAt = time.Now()
			}
			if err := tx.Create(&messageRow).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *opsAssistantDBSessionStore) List(ctx context.Context, userID uint, limit int) ([]memory.Session, error) {
	var rows []opsAssistantSessionRow
	query := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("updated_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&rows).Error; err != nil {
		return nil, err
	}
	sessions := make([]memory.Session, 0, len(rows))
	for _, row := range rows {
		sessions = append(sessions, sessionFromOpsAssistantRow(row, nil))
	}
	return sessions, nil
}

func (s *opsAssistantDBSessionStore) Delete(ctx context.Context, userID uint, sessionID string) error {
	result := s.db.WithContext(ctx).Where("user_id = ? AND session_id = ?", userID, sessionID).Delete(&opsAssistantSessionRow{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return memory.ErrSessionNotFound
	}
	return s.db.WithContext(ctx).Where("user_id = ? AND session_id = ?", userID, sessionID).Delete(&opsAssistantMessageRow{}).Error
}

func sessionFromOpsAssistantRow(row opsAssistantSessionRow, messageRows []opsAssistantMessageRow) memory.Session {
	session := memory.Session{
		SessionID: row.SessionID,
		UserID:    row.UserID,
		Title:     row.Title,
		Summary:   row.Summary,
		Context:   decodeOpsAssistantSessionContext(row.Context),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
	for _, messageRow := range messageRows {
		session.Messages = append(session.Messages, memory.Message{
			Role:      messageRow.Role,
			Content:   messageRow.Content,
			CreatedAt: messageRow.CreatedAt,
		})
	}
	return session
}

func encodeOpsAssistantSessionContext(ctx memory.Context) string {
	data, err := json.Marshal(ctx)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func decodeOpsAssistantSessionContext(payload string) memory.Context {
	var ctx memory.Context
	if payload == "" {
		return ctx
	}
	_ = json.Unmarshal([]byte(payload), &ctx)
	return ctx
}
