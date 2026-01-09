// ============================================
// 文件: notifier/loader.go
// ============================================
package notifier

import (
	"fmt"
	"log"
	"strconv"
	"monitor-backend/api"
)

// LoadNotifiersFromStorage 从存储加载通知渠道配置并注册通知器
func LoadNotifiersFromStorage(storage api.StorageInterface, manager *NotificationManager) error {
	channels, err := storage.ListNotificationChannels(boolPtr(true)) // 只加载启用的渠道
	if err != nil {
		return fmt.Errorf("failed to list notification channels: %v", err)
	}

	if len(channels) == 0 {
		log.Printf("Warning: No enabled notification channels found")
		return nil
	}

	registeredCount := 0
	for _, channel := range channels {
		if !channel.Enabled {
			log.Printf("Skipping disabled notification channel: %s (%s)", channel.Name, channel.Type)
			continue
		}

		var notifier Notifier
		switch channel.Type {
		case "email":
			notifier = createEmailNotifier(channel)
		case "dingtalk":
			notifier = createDingTalkNotifier(channel)
		case "wechat":
			notifier = createWeChatNotifier(channel)
		case "feishu":
			notifier = createFeishuNotifier(channel)
		default:
			log.Printf("Unknown notification channel type: %s (channel: %s)", channel.Type, channel.Name)
			continue
		}

		if notifier != nil {
			manager.Register(notifier)
			registeredCount++
			log.Printf("Registered notification channel: %s (%s)", channel.Name, channel.Type)
		} else {
			log.Printf("Warning: Failed to create notifier for channel: %s (%s) - check configuration", channel.Name, channel.Type)
		}
	}

	log.Printf("Successfully registered %d notification channel(s)", registeredCount)
	return nil
}

// createEmailNotifier 创建邮件通知器
func createEmailNotifier(channel api.NotificationChannelInfo) Notifier {
	config := channel.Config
	smtpHost := config["smtp_host"]
	if smtpHost == "" {
		log.Printf("Email channel %s missing smtp_host", channel.Name)
		return nil
	}

	smtpPort := 587
	if portStr := config["smtp_port"]; portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			smtpPort = port
		}
	}

	smtpUser := config["smtp_user"]
	smtpPassword := config["smtp_password"]
	fromEmail := config["from_email"]
	fromName := config["from_name"]

	if fromEmail == "" {
		fromEmail = smtpUser
	}
	if fromName == "" {
		fromName = "监控系统"
	}

	return NewEmailNotifier(smtpHost, smtpPort, smtpUser, smtpPassword, fromEmail, fromName)
}

// createDingTalkNotifier 创建钉钉通知器
func createDingTalkNotifier(channel api.NotificationChannelInfo) Notifier {
	config := channel.Config
	webhookURL := config["webhook_url"]
	if webhookURL == "" {
		log.Printf("DingTalk channel %s missing webhook_url", channel.Name)
		return nil
	}
	return NewDingTalkNotifier(webhookURL)
}

// createWeChatNotifier 创建企业微信通知器
func createWeChatNotifier(channel api.NotificationChannelInfo) Notifier {
	config := channel.Config
	webhookURL := config["webhook_url"]
	if webhookURL == "" {
		log.Printf("WeChat channel %s missing webhook_url", channel.Name)
		return nil
	}
	return NewWeChatNotifier(webhookURL)
}

// createFeishuNotifier 创建飞书通知器
func createFeishuNotifier(channel api.NotificationChannelInfo) Notifier {
	config := channel.Config
	webhookURL := config["webhook_url"]
	if webhookURL == "" {
		log.Printf("Feishu channel %s missing webhook_url", channel.Name)
		return nil
	}
	return NewFeishuNotifier(webhookURL)
}

// boolPtr 返回bool指针
func boolPtr(b bool) *bool {
	return &b
}

