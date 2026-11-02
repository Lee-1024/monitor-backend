package llm

import (
	"strings"
	"testing"
)

func TestInspectionReportPromptRequiresCompleteServiceInventory(t *testing.T) {
	client := NewLLMClient(LLMConfig{})
	prompt := client.buildInspectionReportPrompt(map[string]interface{}{
		"report": map[string]interface{}{
			"date":          "2026-11-02",
			"total_hosts":   1,
			"online_hosts":  1,
			"offline_hosts": 0,
		},
	})

	for _, phrase := range []string{
		"完整覆盖",
		"不得省略",
		"每一项",
	} {
		if !strings.Contains(prompt, phrase) {
			t.Fatalf("prompt does not require complete inventory (%q): %s", phrase, prompt)
		}
	}
}
