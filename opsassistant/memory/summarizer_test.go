package memory

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakeSummaryModel struct {
	answer string
	prompt string
}

func (m *fakeSummaryModel) Complete(ctx context.Context, prompt string) (string, error) {
	m.prompt = prompt
	return m.answer, nil
}

func TestSummarizerDoesNothingWhenMessagesWithinLimit(t *testing.T) {
	model := &fakeSummaryModel{answer: "summary"}
	summarizer := NewSummarizer(model)
	session := &Session{}
	for i := 0; i < RawMessageLimit; i++ {
		session.Messages = append(session.Messages, Message{Role: "user", Content: "message"})
	}

	if err := summarizer.Summarize(context.Background(), session); err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if session.Summary != "" {
		t.Fatalf("expected no summary, got %q", session.Summary)
	}
	if model.prompt != "" {
		t.Fatalf("model should not be called, got prompt %q", model.prompt)
	}
}

func TestSummarizerSummarizesOlderMessages(t *testing.T) {
	model := &fakeSummaryModel{answer: "user is investigating master memory"}
	summarizer := NewSummarizer(model)
	session := &Session{}
	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		session.Messages = append(session.Messages, Message{Role: "user", Content: string(rune('a' + i)), CreatedAt: now.Add(time.Duration(i) * time.Minute)})
	}

	if err := summarizer.Summarize(context.Background(), session); err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if session.Summary != "user is investigating master memory" {
		t.Fatalf("unexpected summary: %q", session.Summary)
	}
	if len(session.Messages) != RawMessageLimit {
		t.Fatalf("expected %d messages, got %d", RawMessageLimit, len(session.Messages))
	}
	if session.Messages[0].Content != "c" {
		t.Fatalf("expected first retained message c, got %q", session.Messages[0].Content)
	}
}

func TestSummarizerPromptForbidsSecrets(t *testing.T) {
	model := &fakeSummaryModel{answer: "summary"}
	summarizer := NewSummarizer(model)
	session := &Session{}
	for i := 0; i < 8; i++ {
		session.Messages = append(session.Messages, Message{Role: "user", Content: "message"})
	}

	if err := summarizer.Summarize(context.Background(), session); err != nil {
		t.Fatalf("summarize: %v", err)
	}
	for _, expected := range []string{"credentials", "API keys", "secrets"} {
		if !strings.Contains(model.prompt, expected) {
			t.Fatalf("prompt should mention %q, got %s", expected, model.prompt)
		}
	}
}
