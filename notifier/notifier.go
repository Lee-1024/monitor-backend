// ============================================
// 文件: notifier/notifier.go
// ============================================
package notifier

import (
	"fmt"
	"log"
	"monitor-backend/api"
	"time"
)

// 导入 loader 包中的创建函数（它们在同一包中，可以直接使用）
// createEmailNotifier, createDingTalkNotifier, createWeChatNotifier, createFeishuNotifier 在 loader.go 中定义

// Notifier 通知器接口
type Notifier interface {
	Send(history *api.AlertHistoryInfo, receivers []string) error
	Type() string
}

// NotificationManager 通知管理器
type NotificationManager struct {
	notifiers map[string]Notifier
	storage   api.StorageInterface // 用于检查通知渠道是否启用
}

// NewNotificationManager 创建通知管理器
func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		notifiers: make(map[string]Notifier),
	}
}

// SetStorage 设置存储接口，用于检查通知渠道状态
func (nm *NotificationManager) SetStorage(storage api.StorageInterface) {
	nm.storage = storage
}

// Register 注册通知器
func (nm *NotificationManager) Register(notifier Notifier) {
	nm.notifiers[notifier.Type()] = notifier
}

// Send 发送通知
func (nm *NotificationManager) Send(channels []string, history *api.AlertHistoryInfo, receivers []string) error {
	log.Printf("[NotificationManager] Send called: AlertID=%d, Rule=%s, Host=%s, Channels=%v, Receivers=%v",
		history.ID, history.RuleName, history.HostID, channels, receivers)

	var errors []error
	var skippedChannels []string
	var successChannels []string

	if len(channels) == 0 {
		log.Printf("[NotificationManager] No notification channels configured for alert ID=%d", history.ID)
		return fmt.Errorf("no notification channels configured")
	}

	for _, channelType := range channels {
		log.Printf("[NotificationManager] Processing channel: %s", channelType)

		// 检查通知渠道是否启用
		channelEnabled := false
		if nm.storage != nil {
			// 获取所有启用的通知渠道
			enabledChannels, err := nm.storage.ListNotificationChannels(boolPtr(true))
			if err == nil {
				log.Printf("[NotificationManager] Found %d enabled notification channels", len(enabledChannels))
				for _, ch := range enabledChannels {
					if ch.Type == channelType {
						channelEnabled = true
						log.Printf("[NotificationManager] Channel %s is enabled (ID=%d, Name=%s)", channelType, ch.ID, ch.Name)
						break
					}
				}
				if !channelEnabled {
					log.Printf("[NotificationManager] Channel %s is not in enabled channels list", channelType)
				}
			} else {
				// 如果查询失败，记录警告但继续尝试发送（向后兼容）
				log.Printf("[NotificationManager] Warning: Failed to check notification channel status: %v, assuming enabled", err)
				// 如果查询失败，假设渠道可能启用，继续尝试
				channelEnabled = true
			}
		} else {
			// 如果没有存储接口，假设渠道启用（向后兼容）
			log.Printf("[NotificationManager] No storage interface, assuming channel %s is enabled", channelType)
			channelEnabled = true
		}

		if !channelEnabled {
			// 通知渠道未启用，跳过发送
			skippedChannels = append(skippedChannels, channelType)
			log.Printf("[NotificationManager] Skipping notification channel %s: channel is disabled", channelType)
			continue
		}

		notifier, exists := nm.notifiers[channelType]
		if !exists {
			// 通知器不存在，尝试从数据库动态加载
			log.Printf("[NotificationManager] Notifier for %s not found in cache, attempting to load from storage", channelType)
			if nm.storage != nil {
				// 尝试从数据库获取该类型的通知渠道
				channel, err := nm.storage.GetNotificationChannelByType(channelType)
				if err != nil {
					log.Printf("[NotificationManager] Failed to get notification channel by type %s: %v", channelType, err)
					skippedChannels = append(skippedChannels, channelType)
					continue
				}

				// 检查渠道是否启用
				if !channel.Enabled {
					log.Printf("[NotificationManager] Channel %s is disabled, skipping", channelType)
					skippedChannels = append(skippedChannels, channelType)
					continue
				}

				// 动态创建通知器
				var newNotifier Notifier
				switch channelType {
				case "email":
					newNotifier = createEmailNotifier(*channel)
				case "dingtalk":
					newNotifier = createDingTalkNotifier(*channel)
				case "wechat":
					newNotifier = createWeChatNotifier(*channel)
				case "feishu":
					newNotifier = createFeishuNotifier(*channel)
				default:
					log.Printf("[NotificationManager] Unknown notification channel type: %s", channelType)
					skippedChannels = append(skippedChannels, channelType)
					continue
				}

				if newNotifier == nil {
					log.Printf("[NotificationManager] Failed to create notifier for channel type %s (check configuration)", channelType)
					skippedChannels = append(skippedChannels, channelType)
					continue
				}

				// 注册并缓存通知器
				nm.notifiers[channelType] = newNotifier
				notifier = newNotifier
				log.Printf("[NotificationManager] Dynamically loaded and registered notifier for %s", channelType)
			} else {
				// 没有存储接口，无法动态加载
				skippedChannels = append(skippedChannels, channelType)
				log.Printf("[NotificationManager] Warning: Notification channel %s not found (notifier not registered). Available notifiers: %v",
					channelType, nm.getRegisteredNotifierTypes())
				continue
			}
		}

		log.Printf("[NotificationManager] Sending notification via %s notifier", channelType)
		if err := notifier.Send(history, receivers); err != nil {
			errors = append(errors, fmt.Errorf("failed to send via %s: %v", channelType, err))
			log.Printf("[NotificationManager] Failed to send notification via %s: %v", channelType, err)
		} else {
			successChannels = append(successChannels, channelType)
			log.Printf("[NotificationManager] Successfully sent notification via %s", channelType)
		}
	}

	// 如果所有渠道都被跳过，记录警告
	if len(skippedChannels) == len(channels) && len(errors) == 0 {
		log.Printf("[NotificationManager] Warning: All notification channels were skipped: %v", skippedChannels)
		return nil // 不返回错误，因为这是配置问题，不是发送失败
	}

	if len(errors) > 0 {
		log.Printf("[NotificationManager] Notification send completed with errors: %v, Success channels: %v, Skipped channels: %v",
			errors, successChannels, skippedChannels)
		return fmt.Errorf("notification errors: %v", errors)
	}

	log.Printf("[NotificationManager] Notification send completed successfully: Success channels: %v, Skipped channels: %v",
		successChannels, skippedChannels)
	return nil
}

// TestChannel 测试通知渠道
func (nm *NotificationManager) TestChannel(channel *api.NotificationChannelInfo) error {
	log.Printf("[NotificationManager] Testing channel: Type=%s, Name=%s", channel.Type, channel.Name)

	// 创建测试告警历史
	testHistory := &api.AlertHistoryInfo{
		ID:           0, // 测试通知不需要真实ID
		RuleID:       0,
		RuleName:     "测试告警",
		HostID:       "test-host",
		Hostname:     "测试主机",
		Severity:     "info",
		Status:       "firing",
		FiredAt:      time.Now(),
		MetricType:   "test",
		MetricValue:  0,
		Threshold:    0,
		Message:      "这是一条测试告警消息，用于验证通知渠道配置是否正确。",
		Labels:       make(map[string]string),
		NotifyStatus: "pending",
	}

	// 根据渠道类型创建通知器
	var notifier Notifier
	switch channel.Type {
	case "email":
		notifier = createEmailNotifier(*channel)
	case "dingtalk":
		notifier = createDingTalkNotifier(*channel)
	case "wechat":
		notifier = createWeChatNotifier(*channel)
	case "feishu":
		notifier = createFeishuNotifier(*channel)
	default:
		return fmt.Errorf("unsupported channel type: %s", channel.Type)
	}

	if notifier == nil {
		return fmt.Errorf("failed to create notifier for channel type: %s (check configuration)", channel.Type)
	}

	// 发送测试通知
	err := notifier.Send(testHistory, []string{})
	if err != nil {
		log.Printf("[NotificationManager] Test notification failed for channel %s: %v", channel.Name, err)
		return fmt.Errorf("test notification failed: %v", err)
	}

	log.Printf("[NotificationManager] Test notification sent successfully for channel %s", channel.Name)
	return nil
}

// getRegisteredNotifierTypes 获取已注册的通知器类型列表
func (nm *NotificationManager) getRegisteredNotifierTypes() []string {
	types := make([]string, 0, len(nm.notifiers))
	for t := range nm.notifiers {
		types = append(types, t)
	}
	return types
}
