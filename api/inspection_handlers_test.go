package api

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestBufferedStreamWriterDefersDoneEvent(t *testing.T) {
	var output bytes.Buffer
	writer := &bufferedStreamWriter{
		writer:     &output,
		contentBuf: &strings.Builder{},
		sseBuffer:  &strings.Builder{},
	}

	contentEvent := []byte("data: {\"content\":\"正文\",\"done\":false}\n\n")
	doneEvent := []byte("data: {\"content\":\"\",\"done\":true}\n\n")
	if _, err := writer.Write(contentEvent); err != nil {
		t.Fatalf("write content event: %v", err)
	}
	if _, err := writer.Write(doneEvent); err != nil {
		t.Fatalf("write done event: %v", err)
	}

	if !strings.Contains(output.String(), "正文") {
		t.Fatalf("content event was not forwarded: %q", output.String())
	}
	if strings.Contains(output.String(), `"done":true`) {
		t.Fatalf("done event reached client before persistence: %q", output.String())
	}
}

func TestActiveInspectionAgentsExcludesSoftDeletedAgents(t *testing.T) {
	deletedAt := time.Now()
	agents := []map[string]interface{}{
		{"host_id": "active-a", "deleted_at": nil},
		{"host_id": "deleted-a", "deleted_at": deletedAt},
		{"host_id": "active-b"},
	}

	active := activeInspectionAgents(agents)

	if len(active) != 2 {
		t.Fatalf("active agents = %d, want 2", len(active))
	}
	if active[0]["host_id"] != "active-a" || active[1]["host_id"] != "active-b" {
		t.Fatalf("unexpected active agents: %#v", active)
	}
}

func TestReportIntConvertsDatabaseIntegerTypes(t *testing.T) {
	report := map[string]interface{}{
		"total_hosts":   int64(3),
		"online_hosts":  int32(2),
		"offline_hosts": uint(1),
	}

	if got := reportInt(report, "total_hosts"); got != 3 {
		t.Fatalf("total hosts = %d, want 3", got)
	}
	if got := reportInt(report, "online_hosts"); got != 2 {
		t.Fatalf("online hosts = %d, want 2", got)
	}
	if got := reportInt(report, "offline_hosts"); got != 1 {
		t.Fatalf("offline hosts = %d, want 1", got)
	}
}

func TestInspectionReportPayloadUsesFloatStatsForLLMTemplate(t *testing.T) {
	payload := inspectionReportPayload(7, map[string]interface{}{
		"total_hosts":    int64(4),
		"online_hosts":   int64(3),
		"offline_hosts":  int64(1),
		"warning_hosts":  int64(2),
		"critical_hosts": int64(1),
	})

	if got, ok := payload["total_hosts"].(float64); !ok || got != 4 {
		t.Fatalf("payload total_hosts = %#v, want float64(4)", payload["total_hosts"])
	}
	if got, ok := payload["online_hosts"].(float64); !ok || got != 3 {
		t.Fatalf("payload online_hosts = %#v, want float64(3)", payload["online_hosts"])
	}
	if got, ok := payload["critical_hosts"].(float64); !ok || got != 1 {
		t.Fatalf("payload critical_hosts = %#v, want float64(1)", payload["critical_hosts"])
	}
}

func TestConvertMapToInspectionRecordInfoConvertsServiceCountsFromInt64(t *testing.T) {
	record := convertMapToInspectionRecordInfo(map[string]interface{}{
		"service_count":   int64(5),
		"service_running": int64(3),
		"service_stopped": int64(1),
		"service_failed":  int64(1),
	})

	if record.ServiceCount != 5 {
		t.Fatalf("service count = %d, want 5", record.ServiceCount)
	}
	if record.ServiceRunning != 3 {
		t.Fatalf("service running = %d, want 3", record.ServiceRunning)
	}
	if record.ServiceStopped != 1 {
		t.Fatalf("service stopped = %d, want 1", record.ServiceStopped)
	}
	if record.ServiceFailed != 1 {
		t.Fatalf("service failed = %d, want 1", record.ServiceFailed)
	}
}

func TestConvertMapToInspectionReportInfoConvertsTextBytes(t *testing.T) {
	report := convertMapToInspectionReportInfo(map[string]interface{}{
		"status":          []byte("completed"),
		"report_content":  []byte("# 系统巡检日报\n今日正常"),
		"summary":         []byte("今日正常"),
		"key_findings":    []byte("无异常"),
		"recommendations": []byte("持续观察"),
	})

	if report.ReportContent != "# 系统巡检日报\n今日正常" {
		t.Fatalf("report content = %q, want decoded text", report.ReportContent)
	}
	if report.Status != "completed" {
		t.Fatalf("status = %q, want completed", report.Status)
	}
	if report.Summary != "今日正常" || report.KeyFindings != "无异常" || report.Recommendations != "持续观察" {
		t.Fatalf("text fields were not decoded: %#v", report)
	}
}

func TestStripInspectionThinkingKeepsFinalReport(t *testing.T) {
	got := stripInspectionThinking("<think>internal plan</think>\n# 系统巡检日报\n正文")
	if got != "# 系统巡检日报\n正文" {
		t.Fatalf("cleaned report = %q", got)
	}
}

func TestStripInspectionThinkingDropsReasoningOnlyContent(t *testing.T) {
	if got := stripInspectionThinking("<think>internal plan</think>"); got != "" {
		t.Fatalf("reasoning-only report = %q, want empty", got)
	}
}

func TestFinalizeInspectionReportReplacesServiceSectionAndRequiresAllChapters(t *testing.T) {
	content := `# 系统巡检日报
## 一、巡检概览
概览
## 二、主机状态统计
统计
## 三、资源使用分析
分析
## 四、问题与告警
告警
## 五、服务状态
模型生成的不完整服务列表
## 六、关键发现
发现
## 七、优化建议
建议
## 八、后续行动
行动`
	serviceSection := "## 五、服务状态\n| 服务 | 状态 |\n|---|---|\n| nginx | running |"

	got, err := finalizeInspectionReport(content, serviceSection)
	if err != nil {
		t.Fatalf("finalize report: %v", err)
	}
	if !strings.Contains(got, "| nginx | running |") {
		t.Fatalf("finalized report does not contain deterministic service section: %s", got)
	}
	if strings.Contains(got, "模型生成的不完整服务列表") {
		t.Fatalf("model-generated service section was not replaced: %s", got)
	}

	if _, err := finalizeInspectionReport("# 系统巡检日报\n## 一、巡检概览", serviceSection); err == nil {
		t.Fatal("truncated report was accepted")
	}
}

func TestBuildInspectionServiceSectionIncludesEveryItem(t *testing.T) {
	section := buildInspectionServiceSection(
		[]map[string]interface{}{
			{"name": "nginx", "host_id": "web-1", "port": 80, "status": "running", "port_accessible": true},
			{"name": "postgres", "host_id": "db-1", "port": 5432, "status": "running", "port_accessible": true},
		},
		[]map[string]interface{}{
			{"name": "api", "type": "tcp", "address": "10.0.0.1:443", "last_status": "up", "last_latency_ms": int64(3), "last_error": ""},
		},
	)

	for _, expected := range []string{"nginx", "postgres", "web-1", "db-1", "10.0.0.1:443"} {
		if !strings.Contains(section, expected) {
			t.Fatalf("service section missing %q: %s", expected, section)
		}
	}
}

func TestSummarizeServerProbeTargetsCountsEnabledStatuses(t *testing.T) {
	targets := []ServerProbeTargetInfo{
		{Name: "api", Enabled: true, LastStatus: "up"},
		{Name: "db", Enabled: true, LastStatus: "down"},
		{Name: "cache", Enabled: true, LastStatus: "unknown"},
		{Name: "disabled", Enabled: false, LastStatus: "down"},
	}

	summary := summarizeServerProbeTargets(targets)

	if summary.Total != 3 {
		t.Fatalf("total = %d, want 3", summary.Total)
	}
	if summary.Up != 1 {
		t.Fatalf("up = %d, want 1", summary.Up)
	}
	if summary.Down != 1 {
		t.Fatalf("down = %d, want 1", summary.Down)
	}
	if summary.Unknown != 1 {
		t.Fatalf("unknown = %d, want 1", summary.Unknown)
	}
	if len(summary.FailedTargets) != 1 || summary.FailedTargets[0] != "db" {
		t.Fatalf("failed targets = %#v, want [db]", summary.FailedTargets)
	}
}
