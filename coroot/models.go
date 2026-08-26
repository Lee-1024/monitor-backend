package coroot

import (
	"net/http"
	"time"
)

type Config struct {
	Enabled        bool   `yaml:"enabled"`
	BaseURL        string `yaml:"base_url"`
	PublicBaseURL  string `yaml:"public_base_url"`
	ProjectID      string `yaml:"project_id"`
	APIKey         string `yaml:"api_key"`
	WebhookSecret  string `yaml:"webhook_secret"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	CacheEnabled   bool   `yaml:"cache_enabled"`
	VerifyTLS      bool   `yaml:"verify_tls"`
}

func (c Config) EffectiveTimeout() time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return 3 * time.Second
}

type APIError struct {
	Operation string
	Status    int
	Message   string
}

func (e *APIError) Error() string {
	if e.Status > 0 {
		return e.Operation + " failed with HTTP status " + http.StatusText(e.Status)
	}
	return e.Operation + " failed: " + e.Message
}
