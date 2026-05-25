package memory

import (
	"context"
	"strings"
)

type Summarizer struct {
	model SummaryModel
}

type SummaryModel interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

func NewSummarizer(model SummaryModel) *Summarizer {
	return &Summarizer{model: model}
}

func (s *Summarizer) Summarize(ctx context.Context, session *Session) error {
	if s == nil || s.model == nil || session == nil || len(session.Messages) <= RawMessageLimit {
		return nil
	}

	older := session.Messages[:len(session.Messages)-RawMessageLimit]
	prompt := buildSummaryPrompt(session.Summary, older)
	summary, err := s.model.Complete(ctx, prompt)
	if err != nil {
		return err
	}
	session.Summary = strings.TrimSpace(summary)
	session.Messages = session.Messages[len(session.Messages)-RawMessageLimit:]
	return nil
}

func buildSummaryPrompt(existing string, messages []Message) string {
	var builder strings.Builder
	builder.WriteString("Summarize the older operations assistant conversation for future troubleshooting context.\n")
	builder.WriteString("Do not include credentials, API keys, secrets, tokens, passwords, or provider configuration.\n")
	if strings.TrimSpace(existing) != "" {
		builder.WriteString("Existing summary:\n")
		builder.WriteString(existing)
		builder.WriteString("\n\n")
	}
	builder.WriteString("Messages:\n")
	for _, message := range messages {
		builder.WriteString(message.Role)
		builder.WriteString(": ")
		builder.WriteString(message.Content)
		builder.WriteString("\n")
	}
	return builder.String()
}
