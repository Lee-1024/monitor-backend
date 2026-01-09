// ============================================
// 文件: alerter/engine.go
// ============================================
package alerter

import (
	"fmt"
	"log"
	"monitor-backend/api"
	"monitor-backend/notifier"
	"sync"
	"time"
)

// AlertEngine 告警引擎
type AlertEngine struct {
	storage       api.StorageInterface
	notifier      *notifier.NotificationManager
	checkInterval time.Duration
	running       bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
	alertStates   map[string]*AlertState // key: ruleID:hostID
	mu            sync.RWMutex
	// 告警抑制：记录每个告警的最后通知时间 key: ruleID:hostID
	lastNotifyTime map[string]time.Time
	notifyMu       sync.RWMutex
}

// AlertState 告警状态
type AlertState struct {
	RuleID      uint
	HostID      string
	Status      string // pending, firing, resolved
	StartTime   time.Time
	LastCheck   time.Time
	TriggerTime *time.Time
}

// NewAlertEngine 创建告警引擎
func NewAlertEngine(storage api.StorageInterface, notifier *notifier.NotificationManager, checkInterval time.Duration) *AlertEngine {
	return &AlertEngine{
		storage:        storage,
		notifier:       notifier,
		checkInterval:  checkInterval,
		stopChan:       make(chan struct{}),
		alertStates:    make(map[string]*AlertState),
		lastNotifyTime: make(map[string]time.Time),
	}
}

// Start 启动告警引擎
func (e *AlertEngine) Start() {
	if e.running {
		return
	}

	e.running = true
	e.wg.Add(1)
	go e.run()
	log.Println("Alert engine started")
}

// Stop 停止告警引擎
func (e *AlertEngine) Stop() {
	if !e.running {
		return
	}

	e.running = false
	close(e.stopChan)
	e.wg.Wait()
	log.Println("Alert engine stopped")
}

// run 运行告警检查循环
func (e *AlertEngine) run() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.checkInterval)
	defer ticker.Stop()

	// 立即执行一次检查
	e.checkRules()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			e.checkRules()
		}
	}
}

// checkRules 检查所有规则
func (e *AlertEngine) checkRules() {
	log.Printf("[AlertEngine] Starting rule check cycle")

	// 获取所有启用的规则
	rules, err := e.storage.ListAlertRules(boolPtr(true))
	if err != nil {
		log.Printf("[AlertEngine] Failed to list alert rules: %v", err)
		return
	}
	log.Printf("[AlertEngine] Found %d enabled alert rules", len(rules))

	// 获取所有主机（包括在线和离线）
	allAgents, _, err := e.storage.ListAgents("", 1, 1000)
	if err != nil {
		log.Printf("[AlertEngine] Failed to list agents: %v", err)
		return
	}
	log.Printf("[AlertEngine] Found %d total agents", len(allAgents))

	// 获取在线主机（用于常规指标检查）
	onlineAgents, _, err := e.storage.ListAgents("online", 1, 1000)
	if err != nil {
		log.Printf("[AlertEngine] Failed to list online agents: %v", err)
		return
	}
	log.Printf("[AlertEngine] Found %d online agents", len(onlineAgents))

	// 检查每个规则
	for _, rule := range rules {
		log.Printf("[AlertEngine] Checking rule: ID=%d, Name=%s, MetricType=%s, Enabled=%v, NotifyChannels=%v, Receivers=%v",
			rule.ID, rule.Name, rule.MetricType, rule.Enabled, rule.NotifyChannels, rule.Receivers)
		// 检查规则是否在静默期
		if rule.SilenceStart != nil && rule.SilenceEnd != nil {
			now := time.Now()
			if now.After(*rule.SilenceStart) && now.Before(*rule.SilenceEnd) {
				log.Printf("[AlertEngine] Rule %s is in silence period (start: %v, end: %v), skipping", rule.Name, rule.SilenceStart, rule.SilenceEnd)
				continue
			}
		}

		// 主机宕机告警特殊处理
		if rule.MetricType == "host_down" {
			log.Printf("[AlertEngine] Processing host_down rule: %s", rule.Name)
			e.checkHostDownRule(rule, allAgents)
			continue
		}

		// 常规指标检查（只检查在线主机）
		hostsToCheck := e.getHostsToCheck(rule, onlineAgents)
		log.Printf("[AlertEngine] Rule %s: checking %d hosts", rule.Name, len(hostsToCheck))
		for _, host := range hostsToCheck {
			e.checkRuleForHost(rule, host)
		}
	}
	log.Printf("[AlertEngine] Rule check cycle completed")
}

// checkHostDownRule 检查主机宕机规则
func (e *AlertEngine) checkHostDownRule(rule api.AlertRuleInfo, allAgents []api.AgentInfo) {
	// 获取需要检查的主机列表
	hostsToCheck := e.getHostsToCheck(rule, allAgents)

	for _, host := range hostsToCheck {
		// 检查是否被静默
		isSilenced := e.storage.IsRuleSilenced(rule.ID, host.HostID)

		// 如果被静默，直接跳过
		if isSilenced {
			continue
		}

		// 检查主机状态
		status, err := e.storage.GetAgentStatus(host.HostID)
		if err != nil {
			log.Printf("Failed to get agent status for %s: %v", host.HostID, err)
			continue
		}

		// 如果主机离线，触发告警
		if status == "offline" {
			// 检查是否已有未恢复的告警
			historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 1)
			if err != nil {
				log.Printf("Failed to list alert history for Rule=%s, Host=%s: %v", rule.Name, host.HostID, err)
			} else if len(historyList) > 0 {
				// 已存在未恢复的告警，检查是否需要抑制通知
				existingHistory := &historyList[0]

				// 双重检查：确保告警状态确实是 firing（防止并发问题）
				if existingHistory.Status != "firing" {
					log.Printf("Host down alert already resolved (ID=%d, status=%s) for Rule=%s, Host=%s, skipping notification",
						existingHistory.ID, existingHistory.Status, rule.Name, host.HostID)
					continue
				}

				// 再次从数据库查询，确保状态是最新的（防止恢复操作和检查操作并发）
				freshHistory, freshErr := e.storage.GetAlertHistory(existingHistory.ID)
				if freshErr != nil {
					log.Printf("Failed to get fresh alert history (ID=%d): %v, using cached", existingHistory.ID, freshErr)
				} else if freshHistory.Status != "firing" {
					log.Printf("Host down alert already resolved (ID=%d, status=%s) in database for Rule=%s, Host=%s, skipping notification",
						freshHistory.ID, freshHistory.Status, rule.Name, host.HostID)
					continue
				} else {
					// 使用最新的数据
					existingHistory = freshHistory
				}

				inhibitKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)

				e.notifyMu.RLock()
				lastNotify, exists := e.lastNotifyTime[inhibitKey]
				e.notifyMu.RUnlock()

				// 检查是否在抑制期内
				inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second
				if inhibitDuration > 0 {
					if exists && time.Since(lastNotify) < inhibitDuration {
						// 在抑制期内，不发送通知
						log.Printf("Host down alert notification inhibited for Rule=%s, Host=%s", rule.Name, host.HostID)
						continue
					}
				}

				// 不在抑制期内，发送通知并更新最后通知时间
				e.notifyMu.Lock()
				e.lastNotifyTime[inhibitKey] = time.Now()
				e.notifyMu.Unlock()

				// 发送通知
				go func() {
					// 再次检查告警状态，确保在发送通知时仍然是 firing
					recheckHistory, recheckErr := e.storage.GetAlertHistory(existingHistory.ID)
					if recheckErr != nil || recheckHistory == nil || recheckHistory.Status != "firing" {
						log.Printf("Host down alert already resolved before sending notification for Rule=%s, Host=%s, skipping", rule.Name, host.HostID)
						return
					}

					err := e.notifier.Send(rule.NotifyChannels, recheckHistory, rule.Receivers)
					notifyStatus := "success"
					if err != nil {
						notifyStatus = "failed"
						log.Printf("Failed to send notification: %v", err)
					}
					log.Printf("Host down notification sent for Rule=%s, Host=%s (status: %s)", rule.Name, host.HostID, notifyStatus)
				}()
				continue
			}

			// 创建新的告警历史
			now := time.Now()
			message := fmt.Sprintf("主机 %s (%s) 已宕机", host.Hostname, host.HostID)

			history := &api.AlertHistoryInfo{
				RuleID:       rule.ID,
				RuleName:     rule.Name,
				HostID:       host.HostID,
				Hostname:     host.Hostname,
				Severity:     rule.Severity,
				Status:       "firing",
				FiredAt:      now,
				MetricType:   "host_down",
				MetricValue:  0, // 主机宕机没有指标值
				Threshold:    rule.Threshold,
				Message:      message,
				Labels:       make(map[string]string),
				NotifyStatus: "pending",
			}

			// 保存告警历史
			savedHistory, err := e.storage.CreateAlertHistory(history)
			if err != nil {
				log.Printf("Failed to create alert history: %v", err)
				continue
			}

			// 检查抑制配置
			inhibitKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)
			inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second

			shouldNotify := true
			if inhibitDuration > 0 {
				e.notifyMu.RLock()
				lastNotify, exists := e.lastNotifyTime[inhibitKey]
				e.notifyMu.RUnlock()

				if exists && time.Since(lastNotify) < inhibitDuration {
					// 在抑制期内，不发送通知
					shouldNotify = false
					log.Printf("Host down alert notification inhibited for Rule=%s, Host=%s", rule.Name, host.HostID)
				}
			}

			// 发送通知
			if shouldNotify {
				// 更新最后通知时间
				e.notifyMu.Lock()
				e.lastNotifyTime[inhibitKey] = time.Now()
				e.notifyMu.Unlock()

				go func() {
					err := e.notifier.Send(rule.NotifyChannels, savedHistory, rule.Receivers)
					notifyStatus := "success"
					notifyError := ""
					if err != nil {
						notifyStatus = "failed"
						notifyError = err.Error()
						log.Printf("Failed to send notification: %v", err)
					}

					// 更新通知状态
					if updateErr := e.updateAlertHistoryNotifyStatus(savedHistory.ID, notifyStatus, notifyError); updateErr != nil {
						log.Printf("Failed to update alert history notify status: %v", updateErr)
					}
				}()
			} else {
				// 即使不发送通知，也更新状态为抑制
				if err := e.storage.UpdateAlertHistory(savedHistory.ID, "inhibited", nil); err != nil {
					log.Printf("Failed to update alert history: %v", err)
				}
			}
		} else if status == "online" {
			// 主机在线，检查是否有未恢复的告警，如果有则恢复所有未恢复的告警
			historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 100) // 获取所有未恢复的告警
			if err != nil {
				log.Printf("Failed to list alert history for Rule=%s, Host=%s: %v", rule.Name, host.HostID, err)
			} else if len(historyList) > 0 {
				now := time.Now()
				resolvedCount := 0

				log.Printf("Found %d unresolved host down alerts for Rule=%s, Host=%s, resolving them", len(historyList), rule.Name, host.HostID)

				// 恢复所有未恢复的告警
				for _, history := range historyList {
					// 再次检查告警状态，确保仍然是 firing（防止并发问题）
					if history.Status != "firing" {
						log.Printf("Host down alert already resolved (ID=%d, status=%s) for Rule=%s, Host=%s, skipping",
							history.ID, history.Status, rule.Name, host.HostID)
						continue
					}

					// 更新告警历史为已恢复
					err = e.storage.UpdateAlertHistory(history.ID, "resolved", &now)
					if err != nil {
						log.Printf("Failed to update alert history (ID=%d): %v", history.ID, err)
						continue
					}

					// 验证更新是否成功
					updatedHistory, verifyErr := e.storage.GetAlertHistory(history.ID)
					if verifyErr != nil {
						log.Printf("Failed to verify alert history update (ID=%d): %v", history.ID, verifyErr)
					} else if updatedHistory.Status != "resolved" {
						log.Printf("Warning: Alert history (ID=%d) status update failed, expected 'resolved' but got '%s'",
							history.ID, updatedHistory.Status)
						continue
					}

					resolvedCount++
					log.Printf("Host down alert resolved (ID=%d): Rule=%s, Host=%s", history.ID, rule.Name, host.HostID)

					// 只对最新的告警发送恢复通知（避免重复通知）
					if resolvedCount == 1 {
						// 清除抑制时间记录，以便下次告警可以正常发送
						inhibitKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)
						e.notifyMu.Lock()
						delete(e.lastNotifyTime, inhibitKey)
						e.notifyMu.Unlock()

						// 发送恢复通知
						history.Status = "resolved"
						history.ResolvedAt = &now
						go e.notifier.Send(rule.NotifyChannels, &history, rule.Receivers)
					}
				}

				if resolvedCount > 0 {
					log.Printf("Successfully resolved %d host down alerts for Rule=%s, Host=%s", resolvedCount, rule.Name, host.HostID)
				} else {
					log.Printf("No alerts were resolved for Rule=%s, Host=%s (all were already resolved)", rule.Name, host.HostID)
				}
			}
		}
	}
}

// getHostsToCheck 获取需要检查的主机列表
func (e *AlertEngine) getHostsToCheck(rule api.AlertRuleInfo, agents []api.AgentInfo) []api.AgentInfo {
	if rule.HostID != "" {
		// 指定了主机ID，只检查该主机
		for _, agent := range agents {
			if agent.HostID == rule.HostID {
				return []api.AgentInfo{agent}
			}
		}
		return []api.AgentInfo{}
	}
	// 未指定主机ID，检查所有主机
	return agents
}

// checkRuleForHost 检查单个规则对单个主机
func (e *AlertEngine) checkRuleForHost(rule api.AlertRuleInfo, host api.AgentInfo) {
	log.Printf("[checkRuleForHost] Starting check: Rule=%s (ID=%d), Host=%s", rule.Name, rule.ID, host.HostID)

	// 检查是否被静默
	isSilenced := e.storage.IsRuleSilenced(rule.ID, host.HostID)
	log.Printf("[checkRuleForHost] Rule=%s, Host=%s: isSilenced=%v", rule.Name, host.HostID, isSilenced)

	// 如果不再被静默，检查数据库中是否有未恢复的告警需要发送通知
	// 这包括两种情况：
	// 1. 告警引擎状态中有 firing 状态
	// 2. 告警引擎状态中没有记录，但数据库中有 firing 状态的告警（比如告警引擎重启后）
	if !isSilenced {
		log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Not silenced, checking for existing firing alerts", rule.Name, host.HostID)
		// 检查数据库中是否有未恢复的告警
		historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 1)
		if err != nil {
			log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Failed to list alert history: %v", rule.Name, host.HostID, err)
		} else {
			log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Found %d firing alerts in database", rule.Name, host.HostID, len(historyList))
			if len(historyList) > 0 {
				existingHistory := &historyList[0]
				log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Alert History ID=%d, Status=%s, NotifyStatus=%s",
					rule.Name, host.HostID, existingHistory.ID, existingHistory.Status, existingHistory.NotifyStatus)
				// 双重检查：确保告警状态确实是 firing
				if existingHistory.Status == "firing" {
					// 重新检查告警状态，确保在发送通知时仍然是 firing
					recheckHistory, recheckErr := e.storage.GetAlertHistory(existingHistory.ID)
					if recheckErr != nil {
						log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Failed to recheck alert history: %v", rule.Name, host.HostID, recheckErr)
					} else if recheckHistory == nil {
						log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Recheck returned nil history", rule.Name, host.HostID)
					} else if recheckHistory.Status != "firing" {
						log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Alert status changed to %s, skipping notification",
							rule.Name, host.HostID, recheckHistory.Status)
					} else {
						log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Alert confirmed firing, checking notification status", rule.Name, host.HostID)
						// 检查是否已经发送过通知（通过检查抑制时间）
						inhibitKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)
						inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second
						shouldNotify := true

						log.Printf("[checkRuleForHost] Rule=%s, Host=%s: InhibitDuration=%v, NotifyStatus=%s",
							rule.Name, host.HostID, inhibitDuration, recheckHistory.NotifyStatus)

						if inhibitDuration > 0 {
							e.notifyMu.RLock()
							lastNotify, exists := e.lastNotifyTime[inhibitKey]
							e.notifyMu.RUnlock()

							if exists {
								timeSinceLastNotify := time.Since(lastNotify)
								log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Last notify time: %v, Time since: %v, Inhibit duration: %v",
									rule.Name, host.HostID, lastNotify, timeSinceLastNotify, inhibitDuration)
								if timeSinceLastNotify < inhibitDuration {
									shouldNotify = false
									log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Alert notification inhibited (last notify: %v, inhibit duration: %v)",
										rule.Name, host.HostID, lastNotify, inhibitDuration)
								}
							} else {
								log.Printf("[checkRuleForHost] Rule=%s, Host=%s: No previous notification time found", rule.Name, host.HostID)
							}
						}

						// 如果告警历史中没有通知状态记录，或者通知状态是 pending，说明还没有发送过通知
						if shouldNotify && (recheckHistory.NotifyStatus == "" || recheckHistory.NotifyStatus == "pending") {
							log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Should notify, NotifyChannels=%v, Receivers=%v",
								rule.Name, host.HostID, rule.NotifyChannels, rule.Receivers)
							e.notifyMu.Lock()
							e.lastNotifyTime[inhibitKey] = time.Now()
							e.notifyMu.Unlock()

							// 发送通知
							go func() {
								log.Printf("[checkRuleForHost] Goroutine: Starting notification send for Rule=%s, Host=%s", rule.Name, host.HostID)
								// 再次检查告警状态，确保仍然是 firing
								finalCheck, finalErr := e.storage.GetAlertHistory(recheckHistory.ID)
								if finalErr != nil {
									log.Printf("[checkRuleForHost] Goroutine: Failed to get final check history: %v", finalErr)
									return
								}
								if finalCheck == nil {
									log.Printf("[checkRuleForHost] Goroutine: Final check returned nil history")
									return
								}
								if finalCheck.Status != "firing" {
									log.Printf("[checkRuleForHost] Goroutine: Alert already resolved (status=%s) before sending notification, skipping", finalCheck.Status)
									return
								}

								log.Printf("[checkRuleForHost] Goroutine: Sending notification via channels: %v", rule.NotifyChannels)
								err := e.notifier.Send(rule.NotifyChannels, finalCheck, rule.Receivers)
								notifyStatus := "success"
								notifyError := ""
								if err != nil {
									notifyStatus = "failed"
									notifyError = err.Error()
									log.Printf("[checkRuleForHost] Goroutine: Failed to send notification: %v", err)
								} else {
									log.Printf("[checkRuleForHost] Goroutine: Notification sent successfully")
								}
								// 更新通知状态（使用数据库直接更新）
								if updateErr := e.updateAlertHistoryNotifyStatus(finalCheck.ID, notifyStatus, notifyError); updateErr != nil {
									log.Printf("[checkRuleForHost] Goroutine: Failed to update alert history notify status: %v", updateErr)
								} else {
									log.Printf("[checkRuleForHost] Goroutine: Updated alert history notify status to: %s", notifyStatus)
								}
							}()
						} else {
							if !shouldNotify {
								log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Should not notify (inhibited)", rule.Name, host.HostID)
							} else {
								log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Notification already sent (NotifyStatus=%s)",
									rule.Name, host.HostID, recheckHistory.NotifyStatus)
							}
						}
					}
				} else {
					log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Alert status is not firing (status=%s), skipping",
						rule.Name, host.HostID, existingHistory.Status)
				}
			}
		}
	}

	// 如果被静默，直接返回
	if isSilenced {
		log.Printf("[checkRuleForHost] Rule=%s, Host=%s: Silenced, skipping further checks", rule.Name, host.HostID)
		return
	}

	// 更新告警引擎状态
	stateKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)
	e.mu.Lock()
	state, exists := e.alertStates[stateKey]

	// 如果状态存在但数据库中已经没有对应的 firing 告警，重置状态
	// 这可以处理规则被禁用后再启用的情况
	if exists && state.Status == "firing" {
		historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 1)
		if err != nil || len(historyList) == 0 {
			// 数据库中没有 firing 状态的告警，重置状态
			log.Printf("Resetting alert state for Rule=%s, Host=%s (no firing alert in DB)", rule.Name, host.HostID)
			state.Status = "pending"
			state.StartTime = time.Now()
			state.TriggerTime = nil
		}
	}
	e.mu.Unlock()

	// 获取最新指标
	metrics, err := e.storage.GetLatestMetrics(host.HostID)
	if err != nil {
		log.Printf("Failed to get metrics for %s: %v", host.HostID, err)
		return
	}

	// 获取指标值
	metricValue := e.getMetricValue(metrics, rule.MetricType)
	if metricValue == nil {
		return
	}

	// 检查条件
	shouldAlert := e.checkCondition(*metricValue, rule.Condition, rule.Threshold)
	if !shouldAlert {
		// 条件不满足，如果之前是告警状态，标记为已恢复
		e.handleResolved(rule, host)
		return
	}

	// 条件满足，检查持续时间
	e.mu.Lock()
	if !exists {
		// 首次触发，创建状态
		state = &AlertState{
			RuleID:    rule.ID,
			HostID:    host.HostID,
			Status:    "pending",
			StartTime: time.Now(),
			LastCheck: time.Now(),
		}
		e.alertStates[stateKey] = state
		e.mu.Unlock()
		return
	}

	// 更新检查时间
	state.LastCheck = time.Now()

	// 检查是否达到持续时间
	duration := time.Since(state.StartTime)
	if duration >= time.Duration(rule.Duration)*time.Second {
		// 达到持续时间，触发告警
		if state.Status != "firing" {
			state.Status = "firing"
			now := time.Now()
			state.TriggerTime = &now
			e.mu.Unlock()

			// 触发告警
			e.triggerAlert(rule, host, *metricValue)
			return
		} else {
			// 状态已经是 firing，检查是否需要再次发送通知（抑制时间已过）
			e.mu.Unlock()
			e.checkAndSendRepeatedNotification(rule, host)
			return
		}
	} else if state.Status == "resolved" {
		// 状态已恢复，重新开始计时
		state.Status = "pending"
		state.StartTime = time.Now()
	}
	e.mu.Unlock()
}

// getMetricValue 获取指标值
func (e *AlertEngine) getMetricValue(metrics *api.LatestMetrics, metricType string) *float64 {
	switch metricType {
	case "cpu":
		if val, ok := metrics.CPU["usage_percent"].(float64); ok {
			return &val
		}
	case "memory":
		if val, ok := metrics.Memory["used_percent"].(float64); ok {
			return &val
		}
	case "disk":
		if val, ok := metrics.Disk["used_percent"].(float64); ok {
			return &val
		}
	}
	return nil
}

// checkCondition 检查条件
func (e *AlertEngine) checkCondition(value float64, condition string, threshold float64) bool {
	switch condition {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	case "eq":
		return value == threshold
	case "neq":
		return value != threshold
	default:
		return false
	}
}

// triggerAlert 触发告警
func (e *AlertEngine) triggerAlert(rule api.AlertRuleInfo, host api.AgentInfo, metricValue float64) {
	log.Printf("Alert triggered: Rule=%s, Host=%s, Value=%.2f, Threshold=%.2f", rule.Name, host.HostID, metricValue, rule.Threshold)

	// 检查是否已有相同的未恢复告警
	historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 1)
	inhibitKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)

	var shouldNotify bool
	var existingHistory *api.AlertHistoryInfo

	if err == nil && len(historyList) > 0 {
		// 已存在未恢复的告警，更新触发时间
		existingHistory = &historyList[0]
		now := time.Now()

		// 更新告警历史的触发时间为当前时间
		if updateErr := e.storage.UpdateAlertHistoryFiredAt(existingHistory.ID, now); updateErr != nil {
			log.Printf("Failed to update alert history fired_at: %v", updateErr)
		} else {
			log.Printf("Updated alert history fired_at for Rule=%s, Host=%s to %v", rule.Name, host.HostID, now)
		}
		existingHistory.FiredAt = now

		// 检查抑制配置
		inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second
		if inhibitDuration > 0 {
			// 检查是否在抑制期内
			e.notifyMu.RLock()
			lastNotify, exists := e.lastNotifyTime[inhibitKey]
			e.notifyMu.RUnlock()

			if exists && time.Since(lastNotify) < inhibitDuration {
				// 在抑制期内，不发送通知
				shouldNotify = false
				log.Printf("Alert notification inhibited for Rule=%s, Host=%s (last notify: %v, inhibit duration: %v)",
					rule.Name, host.HostID, lastNotify, inhibitDuration)
			} else {
				// 不在抑制期内，可以发送通知
				shouldNotify = true
			}
		} else {
			// 没有配置抑制，不发送通知（因为告警已存在）
			shouldNotify = false
			log.Printf("Alert already exists for Rule=%s, Host=%s (no inhibit configured)", rule.Name, host.HostID)
		}

		// 如果应该发送通知，更新最后通知时间并发送
		if shouldNotify {
			e.notifyMu.Lock()
			e.lastNotifyTime[inhibitKey] = time.Now()
			e.notifyMu.Unlock()

			// 发送通知
			go func() {
				err := e.notifier.Send(rule.NotifyChannels, existingHistory, rule.Receivers)
				notifyStatus := "success"
				notifyError := ""
				if err != nil {
					notifyStatus = "failed"
					notifyError = err.Error()
					log.Printf("Failed to send notification: %v", err)
				}
				// 更新通知状态
				if updateErr := e.updateAlertHistoryNotifyStatus(existingHistory.ID, notifyStatus, notifyError); updateErr != nil {
					log.Printf("Failed to update alert history notify status: %v", updateErr)
				} else {
					log.Printf("Notification sent for Rule=%s, Host=%s (status: %s)", rule.Name, host.HostID, notifyStatus)
				}
			}()
		}
		return
	}

	// 检查是否有已恢复的告警历史，如果有，重新激活它而不是创建新的
	// 这样可以保持告警历史的连续性，并更新触发时间
	resolvedHistoryList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "resolved", 1)
	if err == nil && len(resolvedHistoryList) > 0 {
		// 找到最近的已恢复告警历史，重新激活它
		resolvedHistory := &resolvedHistoryList[0]
		now := time.Now()

		log.Printf("Re-activating resolved alert history (ID=%d) for Rule=%s, Host=%s", resolvedHistory.ID, rule.Name, host.HostID)

		// 更新告警历史状态为 firing，清除 resolved_at，并更新触发时间
		// 注意：先更新状态和清除 resolved_at，再更新 fired_at，确保数据一致性
		updateErr := e.storage.UpdateAlertHistory(resolvedHistory.ID, "firing", nil)
		if updateErr != nil {
			log.Printf("Failed to re-activate alert history: %v", updateErr)
			// 如果更新失败，继续创建新的告警历史
		} else {
			log.Printf("Re-activated alert history (ID=%d) status to firing, clearing resolved_at", resolvedHistory.ID)

			// 更新触发时间为当前时间（必须在状态更新之后）
			if updateErr := e.storage.UpdateAlertHistoryFiredAt(resolvedHistory.ID, now); updateErr != nil {
				log.Printf("Failed to update alert history fired_at: %v", updateErr)
			} else {
				log.Printf("Updated alert history fired_at for re-activated alert (ID=%d) to %v", resolvedHistory.ID, now)
			}

			// 更新指标值和消息
			message := fmt.Sprintf("%s指标值%.2f超过阈值%.2f", rule.MetricType, metricValue, rule.Threshold)
			if updateErr := e.storage.UpdateAlertHistoryMetricValue(resolvedHistory.ID, metricValue, message); updateErr != nil {
				log.Printf("Failed to update alert history metric value: %v", updateErr)
			}

			// 获取更新后的告警历史，验证状态和触发时间是否正确更新
			updatedHistory, err := e.storage.GetAlertHistory(resolvedHistory.ID)
			if err != nil {
				log.Printf("Failed to get updated alert history: %v", err)
				// 继续创建新的告警历史
			} else {
				// 验证状态是否正确更新为 firing
				if updatedHistory.Status != "firing" {
					log.Printf("Warning: Re-activated alert history (ID=%d) status is not firing, got: %s", resolvedHistory.ID, updatedHistory.Status)
					// 继续创建新的告警历史
				} else {
					log.Printf("Successfully re-activated alert history (ID=%d), status=%s, fired_at=%v",
						resolvedHistory.ID, updatedHistory.Status, updatedHistory.FiredAt)

					// 使用重新激活的告警历史
					// 注意：FiredAt 已经在数据库中更新，这里只是确保内存中的值一致
					existingHistory = updatedHistory
					// 确保指标值和消息是最新的
					if existingHistory.MetricValue != metricValue || existingHistory.Message != message {
						log.Printf("Updating metric value and message for re-activated alert (ID=%d)", resolvedHistory.ID)
						existingHistory.MetricValue = metricValue
						existingHistory.Message = message
					}

					// 检查抑制配置
					inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second
					if inhibitDuration > 0 {
						e.notifyMu.RLock()
						lastNotify, exists := e.lastNotifyTime[inhibitKey]
						e.notifyMu.RUnlock()

						if exists && time.Since(lastNotify) < inhibitDuration {
							shouldNotify = false
							log.Printf("Alert notification inhibited for re-activated alert (Rule=%s, Host=%s)", rule.Name, host.HostID)
						} else {
							shouldNotify = true
						}
					} else {
						shouldNotify = true // 重新激活的告警应该发送通知
					}

					// 如果应该发送通知，更新最后通知时间并发送
					if shouldNotify {
						e.notifyMu.Lock()
						e.lastNotifyTime[inhibitKey] = time.Now()
						e.notifyMu.Unlock()

						// 发送通知
						go func() {
							err := e.notifier.Send(rule.NotifyChannels, existingHistory, rule.Receivers)
							notifyStatus := "success"
							notifyError := ""
							if err != nil {
								notifyStatus = "failed"
								notifyError = err.Error()
								log.Printf("Failed to send notification for re-activated alert: %v", err)
							}
							// 更新通知状态
							if updateErr := e.updateAlertHistoryNotifyStatus(existingHistory.ID, notifyStatus, notifyError); updateErr != nil {
								log.Printf("Failed to update alert history notify status: %v", updateErr)
							} else {
								log.Printf("Notification sent for re-activated alert: Rule=%s, Host=%s (status: %s)", rule.Name, host.HostID, notifyStatus)
							}
						}()
					}
					return
				} // 关闭 else 块（updatedHistory.Status == "firing"）
			} // 关闭 else 块（GetAlertHistory 成功）
		} // 关闭 else 块（UpdateAlertHistory 成功）
	}

	// 创建新的告警历史
	now := time.Now()
	message := fmt.Sprintf("%s指标值%.2f超过阈值%.2f", rule.MetricType, metricValue, rule.Threshold)

	history := &api.AlertHistoryInfo{
		RuleID:       rule.ID,
		RuleName:     rule.Name,
		HostID:       host.HostID,
		Hostname:     host.Hostname,
		Severity:     rule.Severity,
		Status:       "firing",
		FiredAt:      now,
		MetricType:   rule.MetricType,
		MetricValue:  metricValue,
		Threshold:    rule.Threshold,
		Message:      message,
		Labels:       make(map[string]string),
		NotifyStatus: "pending",
	}

	// 保存告警历史
	savedHistory, err := e.storage.CreateAlertHistory(history)
	if err != nil {
		log.Printf("Failed to create alert history: %v", err)
		return
	}

	// 检查抑制配置（新告警总是发送通知，但记录时间用于后续抑制）
	inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second
	if inhibitDuration > 0 {
		// 更新最后通知时间
		e.notifyMu.Lock()
		e.lastNotifyTime[inhibitKey] = time.Now()
		e.notifyMu.Unlock()
	}

	// 发送通知
	go func() {
		err := e.notifier.Send(rule.NotifyChannels, savedHistory, rule.Receivers)
		notifyStatus := "success"
		notifyError := ""
		if err != nil {
			notifyStatus = "failed"
			notifyError = err.Error()
			log.Printf("Failed to send notification: %v", err)
		}

		// 更新通知状态
		if updateErr := e.updateAlertHistoryNotifyStatus(savedHistory.ID, notifyStatus, notifyError); updateErr != nil {
			log.Printf("Failed to update alert history notify status: %v", updateErr)
		}
	}()
}

// handleResolved 处理告警恢复
func (e *AlertEngine) handleResolved(rule api.AlertRuleInfo, host api.AgentInfo) {
	stateKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)
	e.mu.Lock()
	state, exists := e.alertStates[stateKey]
	e.mu.Unlock()

	if !exists || state.Status != "firing" {
		return
	}

	// 查找未恢复的告警历史
	historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 1)
	if err != nil || len(historyList) == 0 {
		return
	}

	history := historyList[0]
	now := time.Now()

	// 更新告警历史为已恢复
	err = e.storage.UpdateAlertHistory(history.ID, "resolved", &now)
	if err != nil {
		log.Printf("Failed to update alert history: %v", err)
		return
	}

	// 更新状态
	e.mu.Lock()
	state.Status = "resolved"
	state.StartTime = time.Now()
	e.mu.Unlock()

	log.Printf("Alert resolved: Rule=%s, Host=%s", rule.Name, host.HostID)

	// 发送恢复通知
	history.Status = "resolved"
	history.ResolvedAt = &now
	go e.notifier.Send(rule.NotifyChannels, &history, rule.Receivers)
}

// checkAndSendRepeatedNotification 检查并发送重复通知（当抑制时间已过时）
func (e *AlertEngine) checkAndSendRepeatedNotification(rule api.AlertRuleInfo, host api.AgentInfo) {
	inhibitKey := fmt.Sprintf("%d:%s", rule.ID, host.HostID)
	inhibitDuration := time.Duration(rule.InhibitDuration) * time.Second

	// 如果没有配置抑制，不需要重复发送
	if inhibitDuration <= 0 {
		return
	}

	// 检查是否在抑制期内
	e.notifyMu.RLock()
	lastNotify, exists := e.lastNotifyTime[inhibitKey]
	e.notifyMu.RUnlock()

	if !exists {
		// 没有记录，说明还没有发送过通知，应该发送
		// 这种情况不应该发生，因为 triggerAlert 应该已经处理了
		return
	}

	// 检查是否过了抑制时间
	if time.Since(lastNotify) >= inhibitDuration {
		// 抑制时间已过，可以再次发送通知
		log.Printf("Inhibit duration expired for Rule=%s, Host=%s, sending repeated notification", rule.Name, host.HostID)

		// 获取最新的告警历史
		historyList, err := e.storage.ListAlertHistory(&rule.ID, host.HostID, "firing", 1)
		if err != nil || len(historyList) == 0 {
			log.Printf("Failed to get alert history for repeated notification: Rule=%s, Host=%s", rule.Name, host.HostID)
			return
		}

		existingHistory := &historyList[0]

		// 更新最后通知时间
		e.notifyMu.Lock()
		e.lastNotifyTime[inhibitKey] = time.Now()
		e.notifyMu.Unlock()

		// 发送通知
		go func() {
			err := e.notifier.Send(rule.NotifyChannels, existingHistory, rule.Receivers)
			notifyStatus := "success"
			notifyError := ""
			if err != nil {
				notifyStatus = "failed"
				notifyError = err.Error()
				log.Printf("Failed to send repeated notification: %v", err)
			}
			// 更新通知状态
			if updateErr := e.updateAlertHistoryNotifyStatus(existingHistory.ID, notifyStatus, notifyError); updateErr != nil {
				log.Printf("Failed to update alert history notify status: %v", updateErr)
			} else {
				log.Printf("Repeated notification sent for Rule=%s, Host=%s (status: %s)", rule.Name, host.HostID, notifyStatus)
			}
		}()
	}
}

// updateAlertHistoryNotifyStatus 更新告警历史的通知状态
func (e *AlertEngine) updateAlertHistoryNotifyStatus(id uint, notifyStatus string, notifyError string) error {
	return e.storage.UpdateAlertHistoryNotifyStatus(id, notifyStatus, notifyError)
}

// boolPtr 返回bool指针
func boolPtr(b bool) *bool {
	return &b
}
