package llm

import (
	"strings"
	"testing"
)

func TestInspectionReportPromptDelegatesServiceInventoryToBackend(t *testing.T) {
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
		"完整服务明细由后端插入",
		"不要展开服务明细",
		"必须继续生成第六至第八章",
	} {
		if !strings.Contains(prompt, phrase) {
			t.Fatalf("prompt does not require complete inventory (%q): %s", phrase, prompt)
		}
	}
}
