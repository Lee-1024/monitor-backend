// ============================================
// 文件: api/inspection_handlers.go
// 智能巡检与日报生成相关API处理
// ============================================
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// InspectionRecordInfo 巡检记录信息
type InspectionRecordInfo struct {
	ID                 uint                   `json:"id"`
	CreatedAt          time.Time              `json:"created_at"`
	ReportID           uint                   `json:"report_id"`
	HostID             string                 `json:"host_id"`
	Hostname           string                 `json:"hostname"`
	Status             string                 `json:"status"`
	OS                 string                 `json:"os"`
	Arch               string                 `json:"arch"`
	Uptime             int64                  `json:"uptime_seconds"`
	LastSeen           time.Time              `json:"last_seen"`
	CPUUsage           float64                `json:"cpu_usage"`
	MemoryUsage        float64                `json:"memory_usage"`
	DiskUsage          float64                `json:"disk_usage"`
	Metrics            map[string]interface{} `json:"metrics"`
	Issues             []string               `json:"issues"`
	Warnings           []string               `json:"warnings"`
	Recommendations    []string               `json:"recommendations"`
	ServiceCount       int                    `json:"service_count"`
	ServiceRunning     int                    `json:"service_running"`
	ServiceStopped     int                    `json:"service_stopped"`
	ServiceFailed      int                    `json:"service_failed"`
	AnomalyCount       int                    `json:"anomaly_count"`
	AlertCount         int                    `json:"alert_count"`
	CriticalAlertCount int                    `json:"critical_alert_count"`
}

// InspectionReportInfo 巡检日报信息
type InspectionReportInfo struct {
	ID              uint                   `json:"id"`
	CreatedAt       time.Time              `json:"created_at"`
	Date            time.Time              `json:"date"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time,omitempty"`
	Status          string                 `json:"status"`
	TotalHosts      int                    `json:"total_hosts"`
	OnlineHosts     int                    `json:"online_hosts"`
	OfflineHosts    int                    `json:"offline_hosts"`
	WarningHosts    int                    `json:"warning_hosts"`
	CriticalHosts   int                    `json:"critical_hosts"`
	Summary         string                 `json:"summary"`
	ReportContent   string                 `json:"report_content"`
	KeyFindings     string                 `json:"key_findings"`
	Recommendations string                 `json:"recommendations"`
	GeneratedBy     string                 `json:"generated_by"`
	Records         []InspectionRecordInfo `json:"records,omitempty"`
}

// 执行巡检
func (s *APIServer) runInspection(c *gin.Context) {
	dateStr := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid date format, use YYYY-MM-DD",
		})
		return
	}

	// 检查是否已有当天的报告
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var existingReports []map[string]interface{}
	result := db.Table("inspection_reports").Where("date = ?", date.Format("2006-01-02")).Find(&existingReports)

	var existingReport map[string]interface{}
	hasExistingReport := false
	if result.Error == nil && len(existingReports) > 0 {
		existingReport = existingReports[0]
		hasExistingReport = true
		// 如果报告已完成，允许重新运行（覆盖）
		if status, ok := existingReport["status"].(string); ok && status == "completed" {
			log.Printf("[Inspection] Found completed report for date %s, will create new one or reuse", date.Format("2006-01-02"))
			// 可以选择删除旧报告或更新状态为running，这里我们允许继续创建新的
			// 但我们需要确保同一天只能有一个报告，所以更新现有报告
			hasExistingReport = true // 标记为存在，将在后面更新而不是创建
		} else if status, ok := existingReport["status"].(string); ok && status == "running" {
			log.Printf("[Inspection] Found running report for date %s, will reuse it", date.Format("2006-01-02"))
			hasExistingReport = true
		}
	}

	// 创建或更新报告
	reportData := map[string]interface{}{
		"date":       date,
		"start_time": time.Now(),
		"status":     "running",
		"created_at": time.Now(),
	}

	var reportID uint
	if !hasExistingReport {
		// 创建新报告
		log.Printf("[Inspection] Creating new report for date: %s", date.Format("2006-01-02"))
		if err := db.Table("inspection_reports").Create(&reportData).Error; err != nil {
			log.Printf("[Inspection] Failed to create report: %v", err)
			c.JSON(http.StatusInternalServerError, Response{
				Code:    500,
				Message: "Failed to create inspection report: " + err.Error(),
			})
			return
		}
		// 查询刚创建的记录以获取ID
		var newReports []map[string]interface{}
		if err := db.Table("inspection_reports").Where("date = ?", date.Format("2006-01-02")).Find(&newReports).Error; err == nil && len(newReports) > 0 {
			newReport := newReports[0]
			if id, ok := newReport["id"].(uint); ok {
				reportID = id
			} else if id, ok := newReport["id"].(int64); ok {
				reportID = uint(id)
			} else if id, ok := newReport["id"].(float64); ok {
				reportID = uint(id)
			}
		}
		if reportID == 0 {
			log.Printf("[Inspection] Failed to get created report ID")
			c.JSON(http.StatusInternalServerError, Response{
				Code:    500,
				Message: "Failed to get created report ID",
			})
			return
		}
		log.Printf("[Inspection] Created report with ID: %d", reportID)
	} else {
		// 更新现有报告
		if id, ok := existingReport["id"].(uint); ok {
			reportID = id
		} else if id, ok := existingReport["id"].(int64); ok {
			reportID = uint(id)
		} else if id, ok := existingReport["id"].(float64); ok {
			reportID = uint(id)
		}
		if reportID == 0 {
			log.Printf("[Inspection] Invalid report ID from existing report")
			c.JSON(http.StatusInternalServerError, Response{
				Code:    500,
				Message: "Invalid report ID",
			})
			return
		}
		log.Printf("[Inspection] Reusing existing report ID: %d", reportID)
		// 删除旧的巡检记录，以便重新生成
		db.Table("inspection_records").Where("report_id = ?", reportID).Delete(nil)
		// 更新报告状态和时间
		db.Table("inspection_reports").Where("id = ?", reportID).Updates(map[string]interface{}{
			"start_time":      time.Now(),
			"status":          "running",
			"end_time":        nil,
			"total_hosts":     0,
			"online_hosts":    0,
			"offline_hosts":   0,
			"warning_hosts":   0,
			"critical_hosts":  0,
			"summary":         "",
			"report_content":  "",
			"key_findings":    "",
			"recommendations": "",
		})
	}

	// 异步执行巡检
	go s.performInspection(reportID, date)

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Inspection started",
		Data: map[string]interface{}{
			"report_id": reportID,
			"date":      date.Format("2006-01-02"),
			"status":    "running",
		},
	})
}

// 执行巡检任务（异步）
func (s *APIServer) performInspection(reportID uint, date time.Time) {
	log.Printf("[Inspection] 开始执行巡检，ReportID: %d, Date: %s", reportID, date.Format("2006-01-02"))

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		log.Printf("[Inspection] 无法获取数据库连接")
		return
	}

	// 获取所有主机
	var agents []map[string]interface{}
	db.Table("agents").Find(&agents)

	log.Printf("[Inspection] Found %d agents to inspect", len(agents))
	totalHosts := len(agents)
	onlineHosts := 0
	offlineHosts := 0
	warningHosts := 0
	criticalHosts := 0

	// 遍历每个主机进行巡检
	for _, agent := range agents {
		hostID, _ := agent["host_id"].(string)
		hostname, _ := agent["hostname"].(string)
		status, _ := agent["status"].(string)

		log.Printf("[Inspection] Inspecting host: %s (%s), status: %s", hostID, hostname, status)

		record := s.inspectHost(hostID, hostname, status, reportID)

		// 先进行统计（无论保存是否成功）
		switch record.Status {
		case "online":
			onlineHosts++
			log.Printf("[Inspection] 统计: onlineHosts++ = %d", onlineHosts)
		case "offline":
			offlineHosts++
			log.Printf("[Inspection] 统计: offlineHosts++ = %d", offlineHosts)
		case "warning":
			warningHosts++
			onlineHosts++
			log.Printf("[Inspection] 统计: warningHosts++ = %d, onlineHosts++ = %d", warningHosts, onlineHosts)
		case "critical":
			criticalHosts++
			onlineHosts++
			log.Printf("[Inspection] 统计: criticalHosts++ = %d, onlineHosts++ = %d", criticalHosts, onlineHosts)
		default:
			log.Printf("[Inspection] 未知状态: %s, 主机: %s", record.Status, hostID)
		}

		// 序列化metrics为JSON字符串
		metricsJSON, _ := json.Marshal(record.Metrics)

		// 序列化字符串数组为JSON字符串（数据库字段类型为JSON）
		issuesJSON, _ := json.Marshal(record.Issues)
		warningsJSON, _ := json.Marshal(record.Warnings)
		recommendationsJSON, _ := json.Marshal(record.Recommendations)

		// 保存巡检记录
		recordData := map[string]interface{}{
			"report_id":            reportID,
			"host_id":              record.HostID,
			"hostname":             record.Hostname,
			"status":               record.Status,
			"os":                   record.OS,
			"arch":                 record.Arch,
			"uptime_seconds":       record.Uptime,
			"last_seen":            record.LastSeen,
			"cpu_usage":            record.CPUUsage,
			"memory_usage":         record.MemoryUsage,
			"disk_usage":           record.DiskUsage,
			"metrics":              string(metricsJSON),
			"issues":               string(issuesJSON),
			"warnings":             string(warningsJSON),
			"recommendations":      string(recommendationsJSON),
			"service_count":        record.ServiceCount,
			"service_running":      record.ServiceRunning,
			"service_stopped":      record.ServiceStopped,
			"service_failed":       record.ServiceFailed,
			"anomaly_count":        record.AnomalyCount,
			"alert_count":          record.AlertCount,
			"critical_alert_count": record.CriticalAlertCount,
			"created_at":           time.Now(),
		}

		if err := db.Table("inspection_records").Create(&recordData).Error; err != nil {
			log.Printf("[Inspection] 保存巡检记录失败，HostID: %s, Error: %v", hostID, err)
			// 即使保存失败，统计已经完成，继续下一个主机
		}
	}

	log.Printf("[Inspection] 巡检统计完成: total=%d, online=%d, offline=%d, warning=%d, critical=%d",
		totalHosts, onlineHosts, offlineHosts, warningHosts, criticalHosts)

	// 生成LLM日报
	reportContent, summary, keyFindings, recommendations := s.generateInspectionReport(reportID)

	// 更新报告
	endTime := time.Now()
	updateData := map[string]interface{}{
		"end_time":        &endTime,
		"status":          "completed",
		"total_hosts":     totalHosts,
		"online_hosts":    onlineHosts,
		"offline_hosts":   offlineHosts,
		"warning_hosts":   warningHosts,
		"critical_hosts":  criticalHosts,
		"summary":         summary,
		"report_content":  reportContent,
		"key_findings":    keyFindings,
		"recommendations": recommendations,
		"generated_by":    "LLM",
	}

	log.Printf("[Inspection] 准备更新报告 ID=%d, 统计数据: total=%d, online=%d, offline=%d, warning=%d, critical=%d",
		reportID, totalHosts, onlineHosts, offlineHosts, warningHosts, criticalHosts)

	if err := db.Table("inspection_reports").Where("id = ?", reportID).Updates(updateData).Error; err != nil {
		log.Printf("[Inspection] 更新报告失败，Error: %v", err)
		return
	}

	log.Printf("[Inspection] 巡检完成，ReportID: %d, 最终统计: total=%d, online=%d, offline=%d, warning=%d, critical=%d",
		reportID, totalHosts, onlineHosts, offlineHosts, warningHosts, criticalHosts)
}

// 巡检单个主机
func (s *APIServer) inspectHost(hostID, hostname, agentStatus string, reportID uint) InspectionRecordInfo {
	record := InspectionRecordInfo{
		HostID:          hostID,
		Hostname:        hostname,
		Status:          agentStatus,
		Issues:          []string{},
		Warnings:        []string{},
		Recommendations: []string{},
		Metrics:         make(map[string]interface{}),
	}

	if agentStatus != "online" {
		record.Status = "offline"
		return record
	}

	// 获取主机信息
	agent, err := s.storage.GetAgent(hostID)
	if err == nil && agent != nil {
		record.OS = agent.OS
		record.Arch = agent.Arch
		record.LastSeen = agent.LastSeen
		// 计算运行时长（从LastSeen到现在）
		if !agent.LastSeen.IsZero() {
			uptimeDuration := time.Since(agent.LastSeen)
			if uptimeDuration > 0 {
				record.Uptime = int64(uptimeDuration.Seconds())
			}
		}
		log.Printf("[Inspection] Host %s: OS=%s, Arch=%s, Uptime=%d", hostID, record.OS, record.Arch, record.Uptime)
	} else {
		log.Printf("[Inspection] Failed to get agent info for %s: %v", hostID, err)
	}

	// 获取最新指标
	metrics, err := s.storage.GetLatestMetrics(hostID)
	if err != nil {
		log.Printf("[Inspection] Failed to get metrics for %s: %v", hostID, err)
	} else if metrics == nil {
		log.Printf("[Inspection] Metrics is nil for %s", hostID)
	} else {
		log.Printf("[Inspection] Got metrics for %s: CPU=%v, Memory=%v, Disk=%v", hostID, metrics.CPU != nil, metrics.Memory != nil, metrics.Disk != nil)

		// 提取CPU使用率
		cpuMap := metrics.CPU
		if cpuMap != nil {
			if usage, ok := cpuMap["usage_percent"].(float64); ok {
				record.CPUUsage = usage
				log.Printf("[Inspection] Host %s CPU usage: %.2f%%", hostID, usage)
			} else {
				log.Printf("[Inspection] Host %s CPU usage_percent not found or wrong type in map: %v", hostID, cpuMap)
			}
		} else {
			log.Printf("[Inspection] Host %s CPU map is nil", hostID)
		}

		// 提取内存使用率
		memoryMap := metrics.Memory
		if memoryMap != nil {
			if usage, ok := memoryMap["used_percent"].(float64); ok {
				record.MemoryUsage = usage
				log.Printf("[Inspection] Host %s Memory usage: %.2f%%", hostID, usage)
			} else {
				log.Printf("[Inspection] Host %s Memory used_percent not found or wrong type in map: %v", hostID, memoryMap)
			}
		} else {
			log.Printf("[Inspection] Host %s Memory map is nil", hostID)
		}

		// 获取磁盘使用率（根分区）
		diskMap := metrics.Disk
		if diskMap != nil {
			// 尝试多种类型断言，因为 JSON 反序列化可能返回不同的类型
			var partitions []interface{}
			var ok bool

			if partitions, ok = diskMap["partitions"].([]interface{}); !ok {
				// 尝试 []map[string]interface{} 类型
				if partitionsMap, ok2 := diskMap["partitions"].([]map[string]interface{}); ok2 {
					// 转换为 []interface{}
					partitions = make([]interface{}, len(partitionsMap))
					for i, p := range partitionsMap {
						partitions[i] = p
					}
					ok = true
				}
			}

			if ok && partitions != nil {
				log.Printf("[Inspection] Host %s Found %d partitions", hostID, len(partitions))
				for _, part := range partitions {
					var partMap map[string]interface{}
					if pm, ok := part.(map[string]interface{}); ok {
						partMap = pm
					} else {
						continue
					}

					if mountpoint, ok := partMap["mountpoint"].(string); ok && mountpoint == "/" {
						if usage, ok := partMap["used_percent"].(float64); ok {
							record.DiskUsage = usage
							log.Printf("[Inspection] Host %s Disk usage: %.2f%%", hostID, usage)
							break
						}
					}
				}
			} else {
				log.Printf("[Inspection] Host %s Disk partitions not found or wrong type", hostID)
				if parts, exists := diskMap["partitions"]; exists {
					log.Printf("[Inspection] Host %s partitions type: %T", hostID, parts)
				}
			}
		} else {
			log.Printf("[Inspection] Host %s Disk map is nil", hostID)
		}

		// 构建详细指标
		record.Metrics["cpu"] = cpuMap
		record.Metrics["memory"] = memoryMap
		record.Metrics["disk"] = diskMap
		record.Metrics["network"] = metrics.Network
		record.Metrics["timestamp"] = metrics.Timestamp
	}

	// 获取服务状态
	services, err := s.storage.GetServiceStatus(hostID)
	if err != nil {
		log.Printf("[Inspection] Failed to get services for %s: %v", hostID, err)
	}
	record.ServiceCount = len(services)
	log.Printf("[Inspection] Host %s: %d services", hostID, record.ServiceCount)
	for _, service := range services {
		switch service.Status {
		case "running":
			record.ServiceRunning++
		case "stopped":
			record.ServiceStopped++
		case "failed":
			record.ServiceFailed++
		}
	}

	// 获取异常和告警
	anomalies, err := s.storage.GetAnomalyEvents(hostID, "", "", nil, 100)
	if err != nil {
		log.Printf("[Inspection] Failed to get anomalies for %s: %v", hostID, err)
	}
	record.AnomalyCount = len(anomalies)

	var ruleID *uint = nil
	alerts, err := s.storage.ListAlertHistory(ruleID, hostID, "", 100)
	if err != nil {
		log.Printf("[Inspection] Failed to get alerts for %s: %v", hostID, err)
	}
	record.AlertCount = len(alerts)
	for _, alert := range alerts {
		if alert.Severity == "critical" {
			record.CriticalAlertCount++
		}
	}

	log.Printf("[Inspection] Host %s summary: CPU=%.2f%%, Memory=%.2f%%, Disk=%.2f%%, Services=%d/%d/%d/%d, Alerts=%d/%d, Anomalies=%d",
		hostID, record.CPUUsage, record.MemoryUsage, record.DiskUsage,
		record.ServiceCount, record.ServiceRunning, record.ServiceStopped, record.ServiceFailed,
		record.AlertCount, record.CriticalAlertCount, record.AnomalyCount)

	// 评估状态
	record.Status = "online"
	if record.CriticalAlertCount > 0 || record.ServiceFailed > 0 {
		record.Status = "critical"
		record.Issues = append(record.Issues, fmt.Sprintf("发现 %d 个严重告警", record.CriticalAlertCount))
		if record.ServiceFailed > 0 {
			record.Issues = append(record.Issues, fmt.Sprintf("%d 个服务运行失败", record.ServiceFailed))
		}
	} else if record.AlertCount > 0 || record.CPUUsage > 80 || record.MemoryUsage > 85 || record.DiskUsage > 85 {
		record.Status = "warning"
		if record.CPUUsage > 80 {
			record.Warnings = append(record.Warnings, fmt.Sprintf("CPU使用率过高: %.1f%%", record.CPUUsage))
		}
		if record.MemoryUsage > 85 {
			record.Warnings = append(record.Warnings, fmt.Sprintf("内存使用率过高: %.1f%%", record.MemoryUsage))
		}
		if record.DiskUsage > 85 {
			record.Warnings = append(record.Warnings, fmt.Sprintf("磁盘使用率过高: %.1f%%", record.DiskUsage))
		}
	}

	// 生成建议
	if record.CPUUsage > 70 {
		record.Recommendations = append(record.Recommendations, "建议优化CPU使用，检查是否有异常进程占用CPU资源")
	}
	if record.MemoryUsage > 80 {
		record.Recommendations = append(record.Recommendations, "建议检查内存使用情况，考虑增加内存或优化应用内存占用")
	}
	if record.DiskUsage > 80 {
		record.Recommendations = append(record.Recommendations, "建议清理磁盘空间，删除不必要的文件或扩容磁盘")
	}
	if record.ServiceStopped > 0 {
		record.Recommendations = append(record.Recommendations, fmt.Sprintf("建议检查 %d 个已停止的服务是否需要启动", record.ServiceStopped))
	}

	return record
}

// 生成巡检日报（使用LLM）
func (s *APIServer) generateInspectionReport(reportID uint) (reportContent, summary, keyFindings, recommendations string) {
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		return "", "", "", ""
	}

	// 获取报告和记录
	var reports []map[string]interface{}
	if err := db.Table("inspection_reports").Where("id = ?", reportID).Find(&reports).Error; err != nil {
		log.Printf("[Inspection] 获取报告失败，ReportID: %d, Error: %v", reportID, err)
		return "", "", "", ""
	}

	if len(reports) == 0 {
		log.Printf("[Inspection] 报告不存在，ReportID: %d", reportID)
		return "", "", "", ""
	}

	report := reports[0]

	var records []map[string]interface{}
	db.Table("inspection_records").Where("report_id = ?", reportID).Find(&records)

	// 检查LLM是否可用
	llmClient := s.llmManager.GetClient()
	if llmClient == nil {
		// LLM不可用，生成简单报告
		return s.generateSimpleReport(report, records)
	}

	// 准备数据
	inspectionData := map[string]interface{}{
		"report_id":      reportID,
		"date":           report["date"],
		"total_hosts":    report["total_hosts"],
		"online_hosts":   report["online_hosts"],
		"offline_hosts":  report["offline_hosts"],
		"warning_hosts":  report["warning_hosts"],
		"critical_hosts": report["critical_hosts"],
		"records":        records,
	}

	// 通过反射调用LLM方法
	type ClientGetter interface {
		GetClient() interface{}
	}

	var actualClient interface{}
	if getter, ok := llmClient.(ClientGetter); ok {
		actualClient = getter.GetClient()
	} else {
		getClientMethod := reflect.ValueOf(llmClient).MethodByName("GetClient")
		if getClientMethod.IsValid() {
			results := getClientMethod.Call(nil)
			if len(results) > 0 {
				actualClient = results[0].Interface()
			}
		}
	}

	if actualClient == nil {
		return s.generateSimpleReport(report, records)
	}

	// 调用LLM生成报告（非流式）
	generateMethod := reflect.ValueOf(actualClient).MethodByName("GenerateInspectionReport")
	if !generateMethod.IsValid() {
		return s.generateSimpleReport(report, records)
	}

	results := generateMethod.Call([]reflect.Value{
		reflect.ValueOf(inspectionData),
	})

	if len(results) >= 5 {
		if err, ok := results[4].Interface().(error); ok && err == nil {
			if rc, ok := results[0].Interface().(string); ok {
				reportContent = rc
			}
			if s, ok := results[1].Interface().(string); ok {
				summary = s
			}
			if kf, ok := results[2].Interface().(string); ok {
				keyFindings = kf
			}
			if r, ok := results[3].Interface().(string); ok {
				recommendations = r
			}
			return
		}
	}

	return s.generateSimpleReport(report, records)
}

// 生成简单报告（LLM不可用时）
func (s *APIServer) generateSimpleReport(report map[string]interface{}, records []map[string]interface{}) (reportContent, summary, keyFindings, recommendations string) {
	totalHosts := 0
	if v, ok := report["total_hosts"].(int); ok {
		totalHosts = v
	} else if v, ok := report["total_hosts"].(float64); ok {
		totalHosts = int(v)
	}

	onlineHosts := 0
	if v, ok := report["online_hosts"].(int); ok {
		onlineHosts = v
	} else if v, ok := report["online_hosts"].(float64); ok {
		onlineHosts = int(v)
	}

	summary = fmt.Sprintf("本次巡检共检查 %d 台主机，其中 %d 台在线。", totalHosts, onlineHosts)
	keyFindings = "详细巡检数据已记录，请查看巡检记录。"
	recommendations = "建议定期执行巡检，及时发现和解决问题。"

	reportContent = fmt.Sprintf(`# 巡检日报

## 巡检概览
- 总主机数: %d
- 在线主机: %d
- 离线主机: %d

## 关键发现
%s

## 建议
%s
`, totalHosts, onlineHosts, totalHosts-onlineHosts, keyFindings, recommendations)

	return reportContent, summary, keyFindings, recommendations
}

// 获取巡检报告列表
func (s *APIServer) listInspectionReports(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	query := db.Table("inspection_reports")

	var total int64
	query.Count(&total)

	var reports []map[string]interface{}
	offset := (page - 1) * pageSize
	if err := query.Order("date DESC").Offset(offset).Limit(pageSize).Find(&reports).Error; err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get inspection reports: " + err.Error(),
		})
		return
	}

	result := make([]InspectionReportInfo, 0, len(reports))
	for _, r := range reports {
		log.Printf("[Inspection] 原始数据: %+v", r)
		info := convertMapToInspectionReportInfo(r)
		result = append(result, info)
		log.Printf("[Inspection] 转换后数据: ID=%d, total=%d, online=%d, offline=%d, warning=%d, critical=%d",
			info.ID, info.TotalHosts, info.OnlineHosts, info.OfflineHosts, info.WarningHosts, info.CriticalHosts)
	}

	responseData := map[string]interface{}{
		"items":     result,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	}
	
	// 打印实际发送的JSON数据（用于调试）
	if jsonBytes, err := json.Marshal(responseData); err == nil {
		log.Printf("[Inspection] API响应JSON: %s", string(jsonBytes))
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    responseData,
	})
}

// 获取巡检报告详情
func (s *APIServer) getInspectionReport(c *gin.Context) {
	id := c.Param("id")

	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var reports []map[string]interface{}
	if err := db.Table("inspection_reports").Where("id = ?", id).Find(&reports).Error; err != nil || len(reports) == 0 {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Inspection report not found",
		})
		return
	}

	report := reports[0]

	reportInfo := convertMapToInspectionReportInfo(report)

	// 获取记录
	var records []map[string]interface{}
	db.Table("inspection_records").Where("report_id = ?", id).Find(&records)

	reportInfo.Records = make([]InspectionRecordInfo, 0, len(records))
	for _, r := range records {
		reportInfo.Records = append(reportInfo.Records, convertMapToInspectionRecordInfo(r))
	}

	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "Success",
		Data:    reportInfo,
	})
}

// 流式生成巡检日报（SSE）
func (s *APIServer) streamInspectionReport(c *gin.Context) {
	reportIDStr := c.Param("id")
	if reportIDStr == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "report_id is required",
		})
		return
	}

	reportID, err := strconv.ParseUint(reportIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Code:    400,
			Message: "Invalid report_id",
		})
		return
	}

	// 检查LLM是否可用
	llmClient := s.llmManager.GetClient()
	if llmClient == nil {
		c.JSON(http.StatusServiceUnavailable, Response{
			Code:    503,
			Message: "LLM service not available",
		})
		return
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	// 获取报告数据
	db, ok := s.storage.GetDB().(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get database connection",
		})
		return
	}

	var reports []map[string]interface{}
	if err := db.Table("inspection_reports").Where("id = ?", reportID).Find(&reports).Error; err != nil || len(reports) == 0 {
		c.JSON(http.StatusNotFound, Response{
			Code:    404,
			Message: "Inspection report not found",
		})
		return
	}

	report := reports[0]

	var records []map[string]interface{}
	db.Table("inspection_records").Where("report_id = ?", reportID).Find(&records)

	inspectionData := map[string]interface{}{
		"report_id": reportID,
		"report":    report,
		"records":   records,
	}

	// 通过反射调用流式方法
	type ClientGetter interface {
		GetClient() interface{}
	}

	var actualClient interface{}
	if getter, ok := llmClient.(ClientGetter); ok {
		actualClient = getter.GetClient()
	} else {
		getClientMethod := reflect.ValueOf(llmClient).MethodByName("GetClient")
		if getClientMethod.IsValid() {
			results := getClientMethod.Call(nil)
			if len(results) > 0 {
				actualClient = results[0].Interface()
			}
		}
	}

	if actualClient == nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "Failed to get LLM client",
		})
		return
	}

	streamMethod := reflect.ValueOf(actualClient).MethodByName("StreamInspectionReport")
	if !streamMethod.IsValid() {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    500,
			Message: "LLM client does not support inspection report streaming",
		})
		return
	}

	// 创建缓冲Writer，用于收集完整内容并在完成后保存到数据库
	bufferWriter := &bufferedStreamWriter{
		writer:      c.Writer,
		contentBuf:  &strings.Builder{},
		sseBuffer:   &strings.Builder{},
		reportID:    uint(reportID),
		db:          db,
		chunkCount:  0,
		totalContent: 0,
	}

	log.Printf("[API] 使用流式生成巡检日报: ReportID=%d", reportID)
	results := streamMethod.Call([]reflect.Value{
		reflect.ValueOf(inspectionData),
		reflect.ValueOf(bufferWriter),
	})

	// 标记是否已经保存过，避免重复保存
	saved := false
	
	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok && err != nil {
			log.Printf("[API] 流式生成巡检日报失败: %v", err)
			errorChunk := map[string]interface{}{
				"content": "",
				"done":    true,
				"error":   err.Error(),
			}
			data, _ := json.Marshal(errorChunk)
			fmt.Fprintf(c.Writer, "data: %s\n\n", string(data))
			c.Writer.Flush()
		} else {
			// 流式输出成功完成，保存内容到数据库（只保存一次）
			if !saved {
				bufferWriter.saveToDatabase()
				saved = true
			}
		}
	} else {
		// 流式输出成功完成，保存内容到数据库（只保存一次）
		if !saved {
			bufferWriter.saveToDatabase()
			saved = true
		}
	}
}

// bufferedStreamWriter 缓冲流式写入器，同时写入响应和缓冲区
type bufferedStreamWriter struct {
	writer       io.Writer
	contentBuf   *strings.Builder
	reportID     uint
	db           *gorm.DB
	mu           sync.Mutex
	sseBuffer    *strings.Builder // 用于累积SSE消息
	chunkCount   int              // 统计处理的chunk数量
	totalContent int              // 统计累积的内容长度
}

// Write 实现io.Writer接口
func (b *bufferedStreamWriter) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 写入原始响应
	n, err = b.writer.Write(p)

	// 同时处理缓冲区（提取实际内容）
	if n > 0 {
		// 累积SSE数据
		b.sseBuffer.Write(p[:n])
		
		// 尝试解析完整的SSE消息（格式：data: {...}\n\n）
		bufferStr := b.sseBuffer.String()
		
		// 查找所有完整的SSE消息（以\n\n分隔）
		processedCount := 0
		for {
			idx := strings.Index(bufferStr, "\n\n")
			if idx == -1 {
				// 没有找到完整消息，保留在缓冲区
				break
			}
			
			// 提取完整的消息
			line := strings.TrimSpace(bufferStr[:idx])
			bufferStr = bufferStr[idx+2:] // 跳过\n\n
			processedCount++
			
			if strings.HasPrefix(line, "data: ") {
				jsonStr := strings.TrimPrefix(line, "data: ")
				jsonStr = strings.TrimSpace(jsonStr)
				var chunk map[string]interface{}
				if err := json.Unmarshal([]byte(jsonStr), &chunk); err == nil {
					done, _ := chunk["done"].(bool)
					if content, ok := chunk["content"].(string); ok && content != "" {
						b.chunkCount++
						if done {
							// 如果是done=true的chunk，说明这是完整内容
							// 比较长度，使用更长的版本（更完整）
							currentLen := b.contentBuf.Len()
							if len(content) > currentLen {
								log.Printf("[API] Chunk #%d (done=true): 收到完整内容，长度=%d > 当前累积长度=%d，使用完整内容", b.chunkCount, len(content), currentLen)
								b.contentBuf.Reset()
								b.contentBuf.WriteString(content)
								b.totalContent = len(content)
							} else {
								log.Printf("[API] Chunk #%d (done=true): 收到内容，长度=%d <= 当前累积长度=%d，保留累积内容", b.chunkCount, len(content), currentLen)
								// 保留已累积的内容，因为它更完整
							}
						} else {
							// 增量内容，正常累积
							b.contentBuf.WriteString(content)
							b.totalContent += len(content)
							currentTotal := b.contentBuf.Len()
							// 每10个chunk记录一次，避免日志过多
							if b.chunkCount%10 == 0 || len(content) > 100 {
								log.Printf("[API] Chunk #%d (done=false): 累积增量内容，长度=%d，当前总长度=%d", b.chunkCount, len(content), currentTotal)
							}
						}
					} else {
						log.Printf("[API] Chunk #%d: 没有content字段或content为空，done=%v", b.chunkCount, done)
					}
				} else {
					previewLen := 200
					if len(jsonStr) < previewLen {
						previewLen = len(jsonStr)
					}
					log.Printf("[API] 解析SSE消息JSON失败: %v, jsonStr: %s", err, jsonStr[:previewLen])
				}
			} else if line != "" {
					previewLen := 100
					if len(line) < previewLen {
						previewLen = len(line)
					}
					log.Printf("[API] 跳过非data行: %s", line[:previewLen])
			}
		}
		
		if processedCount > 0 {
			log.Printf("[API] 本次Write处理了 %d 个完整SSE消息，当前累积chunk数=%d，内容总长度=%d", processedCount, b.chunkCount, b.contentBuf.Len())
		}
		
		// 保留剩余的不完整消息
		b.sseBuffer.Reset()
		if bufferStr != "" {
			b.sseBuffer.WriteString(bufferStr)
		}
	}

	return n, err
}

// Flush 刷新输出
func (b *bufferedStreamWriter) Flush() {
	if flusher, ok := b.writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// saveToDatabase 保存完整内容到数据库
func (b *bufferedStreamWriter) saveToDatabase() {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 处理最后可能残留的SSE消息
	remainingBuffer := b.sseBuffer.String()
	if remainingBuffer != "" {
		line := strings.TrimSpace(remainingBuffer)
		if strings.HasPrefix(line, "data: ") {
			jsonStr := strings.TrimPrefix(line, "data: ")
			jsonStr = strings.TrimSpace(jsonStr)
			var chunk map[string]interface{}
			if json.Unmarshal([]byte(jsonStr), &chunk) == nil {
				done, _ := chunk["done"].(bool)
				if content, ok := chunk["content"].(string); ok && content != "" {
					if done {
						// 如果是done=true的chunk，比较长度使用更完整的版本
						currentLen := b.contentBuf.Len()
						if len(content) > currentLen {
							log.Printf("[API] 处理残留的done=true内容，长度=%d > 当前累积长度=%d，使用完整内容", len(content), currentLen)
							b.contentBuf.Reset()
							b.contentBuf.WriteString(content)
						} else {
							log.Printf("[API] 处理残留的done=true内容，长度=%d <= 当前累积长度=%d，保留累积内容", len(content), currentLen)
						}
					} else {
						// 增量内容，正常累积
						b.contentBuf.WriteString(content)
					}
				}
			}
		}
		b.sseBuffer.Reset()
	}

	fullContent := b.contentBuf.String()
	if fullContent == "" {
		log.Printf("[API] 流式输出内容为空，不保存到数据库")
		return
	}

	log.Printf("[API] ========== 保存日报内容 ==========")
	log.Printf("[API] ReportID=%d", b.reportID)
	log.Printf("[API] 处理的chunk总数: %d", b.chunkCount)
	log.Printf("[API] 累积的内容总长度: %d", b.totalContent)
	log.Printf("[API] 最终内容长度: %d", len(fullContent))
	
	// 检查内容是否包含"六"、"七"、"八"
	hasSix := strings.Contains(fullContent, "六")
	hasSeven := strings.Contains(fullContent, "七")
	hasEight := strings.Contains(fullContent, "八")
	log.Printf("[API] 内容检查: 包含'六'=%v, 包含'七'=%v, 包含'八'=%v", hasSix, hasSeven, hasEight)
	
	// 记录内容的前200个字符和后200个字符，用于调试
	previewStart := ""
	previewEnd := ""
	if len(fullContent) > 400 {
		previewStart = fullContent[:200]
		previewEnd = fullContent[len(fullContent)-200:]
	} else {
		previewStart = fullContent
		previewEnd = fullContent
	}
	log.Printf("[API] 内容预览（前200字符）: %s", previewStart)
	log.Printf("[API] 内容预览（后200字符）: %s", previewEnd)
	log.Printf("[API] ==================================")

	// 解析内容，提取summary、keyFindings、recommendations
	summary, keyFindings, recommendations := b.extractReportSections(fullContent)

	// 更新数据库
	updateData := map[string]interface{}{
		"report_content":  fullContent,
		"summary":         summary,
		"key_findings":    keyFindings,
		"recommendations": recommendations,
	}

	// 使用GORM的Updates方法保存，确保所有内容都被保存
	if err := b.db.Table("inspection_reports").Where("id = ?", b.reportID).Updates(updateData).Error; err != nil {
		log.Printf("[API] 保存日报内容到数据库失败: %v", err)
		log.Printf("[API] 尝试保存的内容长度: %d", len(fullContent))
		
		// 尝试直接使用Update单个字段
		if err2 := b.db.Table("inspection_reports").Where("id = ?", b.reportID).Update("report_content", fullContent).Error; err2 != nil {
			log.Printf("[API] 使用Update单个字段也失败: %v", err2)
			// 如果是因为内容太长，尝试截断保存
			if strings.Contains(err2.Error(), "too long") || strings.Contains(err2.Error(), "value too long") {
				maxLen := 100000 // 假设最大长度
				if len(fullContent) > maxLen {
					log.Printf("[API] 内容过长，截断到 %d 字符", maxLen)
					truncated := fullContent[:maxLen] + "\n\n[内容被截断...]"
					if err3 := b.db.Table("inspection_reports").Where("id = ?", b.reportID).Update("report_content", truncated).Error; err3 != nil {
						log.Printf("[API] 截断后保存仍然失败: %v", err3)
					} else {
						log.Printf("[API] 成功保存截断后的日报内容到数据库，ReportID=%d", b.reportID)
					}
				}
			}
		} else {
			log.Printf("[API] 使用Update单个字段成功保存，ReportID=%d", b.reportID)
			// 继续保存其他字段
			b.db.Table("inspection_reports").Where("id = ?", b.reportID).Updates(map[string]interface{}{
				"summary":         summary,
				"key_findings":    keyFindings,
				"recommendations": recommendations,
			})
		}
	} else {
		log.Printf("[API] 成功保存日报内容到数据库，ReportID=%d, 内容长度=%d", b.reportID, len(fullContent))
		// 验证保存的内容
		var savedReport map[string]interface{}
		if err := b.db.Table("inspection_reports").Where("id = ?", b.reportID).Select("report_content").First(&savedReport).Error; err == nil {
			if savedContent, ok := savedReport["report_content"].(string); ok {
				log.Printf("[API] 验证：数据库中保存的内容长度=%d", len(savedContent))
				if len(savedContent) != len(fullContent) {
					log.Printf("[API] 警告：保存的内容长度与原始内容不一致！原始=%d, 保存=%d", len(fullContent), len(savedContent))
					// 检查是否包含关键内容
					hasSix := strings.Contains(savedContent, "六")
					hasSeven := strings.Contains(savedContent, "七")
					hasEight := strings.Contains(savedContent, "八")
					log.Printf("[API] 数据库中内容检查: 包含'六'=%v, 包含'七'=%v, 包含'八'=%v", hasSix, hasSeven, hasEight)
				} else {
					log.Printf("[API] 验证通过：保存的内容长度与原始内容一致")
				}
			}
		}
	}
}

// extractReportSections 从报告内容中提取各个部分
func (b *bufferedStreamWriter) extractReportSections(content string) (summary, keyFindings, recommendations string) {
	// 尝试从Markdown格式中提取
	lines := strings.Split(content, "\n")
	var currentSection string
	var sectionContent []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "##") || strings.HasPrefix(line, "#") {
			// 保存之前的section
			if currentSection != "" && len(sectionContent) > 0 {
				content := strings.Join(sectionContent, "\n")
				switch currentSection {
				case "总结", "摘要", "Summary":
					summary = content
				case "关键发现", "发现", "Key Findings":
					keyFindings = content
				case "建议", "Recommendations":
					recommendations = content
				}
			}
			// 确定新的section
			sectionName := strings.TrimPrefix(line, "##")
			sectionName = strings.TrimPrefix(sectionName, "#")
			sectionName = strings.TrimSpace(sectionName)
			currentSection = sectionName
			sectionContent = []string{}
		} else if currentSection != "" && line != "" {
			sectionContent = append(sectionContent, line)
		}
	}

	// 保存最后一个section
	if currentSection != "" && len(sectionContent) > 0 {
		content := strings.Join(sectionContent, "\n")
		switch currentSection {
		case "总结", "摘要", "Summary":
			summary = content
		case "关键发现", "发现", "Key Findings":
			keyFindings = content
		case "建议", "Recommendations":
			recommendations = content
		}
	}

	// 如果没有提取到，使用默认值
	if summary == "" {
		summary = "巡检报告已生成，请查看详细内容。"
	}
	if keyFindings == "" {
		keyFindings = "详细巡检数据已记录，请查看巡检记录。"
	}
	if recommendations == "" {
		recommendations = "建议定期执行巡检，及时发现和解决问题。"
	}

	return summary, keyFindings, recommendations
}

// 辅助函数：转换map到InspectionReportInfo
func convertMapToInspectionReportInfo(m map[string]interface{}) InspectionReportInfo {
	info := InspectionReportInfo{}

	if v, ok := m["id"].(uint); ok {
		info.ID = v
	} else if v, ok := m["id"].(int64); ok {
		info.ID = uint(v)
	} else if v, ok := m["id"].(float64); ok {
		info.ID = uint(v)
	}

	if v, ok := m["created_at"].(time.Time); ok {
		info.CreatedAt = v
	} else if v, ok := m["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.CreatedAt = t
		}
	}

	if v, ok := m["date"].(time.Time); ok {
		info.Date = v
	} else if v, ok := m["date"].(string); ok {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			info.Date = t
		}
	}

	if v, ok := m["start_time"].(time.Time); ok {
		info.StartTime = v
	} else if v, ok := m["start_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.StartTime = t
		}
	}

	if v, ok := m["end_time"].(*time.Time); ok {
		info.EndTime = v
	} else if v, ok := m["end_time"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.EndTime = &t
		}
	}

	if v, ok := m["status"].(string); ok {
		info.Status = v
	}

	// 转换 total_hosts
	if v, ok := m["total_hosts"].(int); ok {
		info.TotalHosts = v
	} else if v, ok := m["total_hosts"].(int64); ok {
		info.TotalHosts = int(v)
	} else if v, ok := m["total_hosts"].(float64); ok {
		info.TotalHosts = int(v)
	}

	// 转换 online_hosts
	if v, ok := m["online_hosts"].(int); ok {
		info.OnlineHosts = v
	} else if v, ok := m["online_hosts"].(int64); ok {
		info.OnlineHosts = int(v)
	} else if v, ok := m["online_hosts"].(float64); ok {
		info.OnlineHosts = int(v)
	}

	// 转换 offline_hosts
	if v, ok := m["offline_hosts"].(int); ok {
		info.OfflineHosts = v
	} else if v, ok := m["offline_hosts"].(int64); ok {
		info.OfflineHosts = int(v)
	} else if v, ok := m["offline_hosts"].(float64); ok {
		info.OfflineHosts = int(v)
	}

	// 转换 warning_hosts
	if v, ok := m["warning_hosts"].(int); ok {
		info.WarningHosts = v
	} else if v, ok := m["warning_hosts"].(int64); ok {
		info.WarningHosts = int(v)
	} else if v, ok := m["warning_hosts"].(float64); ok {
		info.WarningHosts = int(v)
	}

	// 转换 critical_hosts
	if v, ok := m["critical_hosts"].(int); ok {
		info.CriticalHosts = v
	} else if v, ok := m["critical_hosts"].(int64); ok {
		info.CriticalHosts = int(v)
	} else if v, ok := m["critical_hosts"].(float64); ok {
		info.CriticalHosts = int(v)
	}

	if v, ok := m["summary"].(string); ok {
		info.Summary = v
	}

	if v, ok := m["report_content"].(string); ok {
		info.ReportContent = v
	}

	if v, ok := m["key_findings"].(string); ok {
		info.KeyFindings = v
	}

	if v, ok := m["recommendations"].(string); ok {
		info.Recommendations = v
	}

	if v, ok := m["generated_by"].(string); ok {
		info.GeneratedBy = v
	}

	return info
}

// 辅助函数：转换map到InspectionRecordInfo
func convertMapToInspectionRecordInfo(m map[string]interface{}) InspectionRecordInfo {
	info := InspectionRecordInfo{
		Issues:          []string{},
		Warnings:        []string{},
		Recommendations: []string{},
		Metrics:         make(map[string]interface{}),
	}

	if v, ok := m["id"].(uint); ok {
		info.ID = v
	} else if v, ok := m["id"].(int64); ok {
		info.ID = uint(v)
	} else if v, ok := m["id"].(float64); ok {
		info.ID = uint(v)
	}

	if v, ok := m["report_id"].(uint); ok {
		info.ReportID = v
	} else if v, ok := m["report_id"].(int64); ok {
		info.ReportID = uint(v)
	} else if v, ok := m["report_id"].(float64); ok {
		info.ReportID = uint(v)
	}

	if v, ok := m["host_id"].(string); ok {
		info.HostID = v
	}

	if v, ok := m["hostname"].(string); ok {
		info.Hostname = v
	}

	if v, ok := m["status"].(string); ok {
		info.Status = v
	}

	if v, ok := m["os"].(string); ok {
		info.OS = v
	}

	if v, ok := m["arch"].(string); ok {
		info.Arch = v
	}

	if v, ok := m["cpu_usage"].(float64); ok {
		info.CPUUsage = v
	}

	if v, ok := m["memory_usage"].(float64); ok {
		info.MemoryUsage = v
	}

	if v, ok := m["disk_usage"].(float64); ok {
		info.DiskUsage = v
	}

	if v, ok := m["metrics"].(map[string]interface{}); ok {
		info.Metrics = v
	} else if v, ok := m["metrics"].(string); ok {
		var metrics map[string]interface{}
		if err := json.Unmarshal([]byte(v), &metrics); err == nil {
			info.Metrics = metrics
		}
	}

	if v, ok := m["issues"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				info.Issues = append(info.Issues, str)
			}
		}
	}

	if v, ok := m["warnings"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				info.Warnings = append(info.Warnings, str)
			}
		}
	}

	if v, ok := m["recommendations"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				info.Recommendations = append(info.Recommendations, str)
			}
		}
	}

	if v, ok := m["service_count"].(int); ok {
		info.ServiceCount = v
	} else if v, ok := m["service_count"].(float64); ok {
		info.ServiceCount = int(v)
	}

	if v, ok := m["service_running"].(int); ok {
		info.ServiceRunning = v
	} else if v, ok := m["service_running"].(float64); ok {
		info.ServiceRunning = int(v)
	}

	if v, ok := m["service_stopped"].(int); ok {
		info.ServiceStopped = v
	} else if v, ok := m["service_stopped"].(float64); ok {
		info.ServiceStopped = int(v)
	}

	if v, ok := m["service_failed"].(int); ok {
		info.ServiceFailed = v
	} else if v, ok := m["service_failed"].(float64); ok {
		info.ServiceFailed = int(v)
	}

	if v, ok := m["anomaly_count"].(int); ok {
		info.AnomalyCount = v
	} else if v, ok := m["anomaly_count"].(float64); ok {
		info.AnomalyCount = int(v)
	}

	if v, ok := m["alert_count"].(int); ok {
		info.AlertCount = v
	} else if v, ok := m["alert_count"].(float64); ok {
		info.AlertCount = int(v)
	}

	if v, ok := m["critical_alert_count"].(int); ok {
		info.CriticalAlertCount = v
	} else if v, ok := m["critical_alert_count"].(float64); ok {
		info.CriticalAlertCount = int(v)
	}

	return info
}
