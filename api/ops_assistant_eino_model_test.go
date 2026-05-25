package api

import "testing"

func TestNormalizeOpenAICompatibleBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		baseURL  string
		want     string
	}{
		{
			name:     "trims chat completions suffix",
			provider: "openai_compatible",
			baseURL:  "https://example.com/v1/chat/completions",
			want:     "https://example.com/v1",
		},
		{
			name:     "keeps compatible base url",
			provider: "openai_compatible",
			baseURL:  "https://example.com/v1",
			want:     "https://example.com/v1",
		},
		{
			name:     "deepseek default",
			provider: "deepseek",
			baseURL:  "",
			want:     "https://api.deepseek.com/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeOpenAICompatibleBaseURL(tt.provider, tt.baseURL)
			if got != tt.want {
				t.Fatalf("normalizeOpenAICompatibleBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
