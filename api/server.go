// ============================================
// 文件: api/server.go
// ============================================
package api

import (
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type APIServer struct {
	router            *gin.Engine
	storage           StorageInterface
	config            *APIConfig
	notificationManager interface{} // NotificationManager 接口，避免循环依赖
}

type APIConfig struct {
	Port         string
	AllowOrigins []string
	AuthRequired bool // 是否要求认证
}

func NewAPIServer(storage StorageInterface, config *APIConfig, notificationManager interface{}) *APIServer {
	// 设置Gin模式
	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// CORS配置
	router.Use(cors.New(cors.Config{
		AllowOrigins:     config.AllowOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	server := &APIServer{
		router:             router,
		storage:            storage,
		config:             config,
		notificationManager: notificationManager,
	}

	server.setupRoutes()

	return server
}

func (s *APIServer) setupRoutes() {
	// 健康检查（无需认证）
	s.router.GET("/health", s.healthCheck)

	// 认证相关路由（无需认证）
	auth := s.router.Group("/api/v1/auth")
	{
		auth.POST("/register", s.register)      // 用户注册
		auth.POST("/login", s.login)           // 用户登录
		auth.POST("/refresh", s.refreshToken)  // 刷新Token
	}

	// API v1
	v1 := s.router.Group("/api/v1")
	// 根据配置决定是否需要认证
	if s.config.AuthRequired {
		v1.Use(AuthMiddleware()) // 所有v1路由都需要认证
	}
	{
		// 当前用户相关
		user := v1.Group("/user")
		{
			user.GET("/me", s.getCurrentUser)           // 获取当前用户信息
			user.PUT("/password", s.changePassword)     // 修改密码
		}

		// Agent相关
		agents := v1.Group("/agents")
		{
			agents.GET("", s.listAgents)                  // 获取Agent列表
			agents.GET("/:id", s.getAgent)                // 获取单个Agent
			agents.DELETE("/:id", s.deleteAgent)          // 删除Agent
			agents.GET("/:id/metrics", s.getAgentMetrics) // 获取Agent指标
		}

		// 指标相关
		metrics := v1.Group("/metrics")
		{
			metrics.GET("/latest", s.getLatestMetrics)       // 获取最新指标
			metrics.GET("/history", s.getHistoryMetrics)     // 获取历史指标
			metrics.GET("/aggregate", s.getAggregateMetrics) // 获取聚合指标
		}

		// 统计相关
		stats := v1.Group("/stats")
		{
			stats.GET("/overview", s.getOverview) // 获取概览
			stats.GET("/top", s.getTopMetrics)    // 获取Top指标
		}

		// 宕机分析路由
		crash := v1.Group("/crash")
		{
			crash.GET("/events", s.getCrashEvents)              // 获取宕机事件列表
			crash.GET("/events/:id", s.getCrashEventDetail)     // 获取宕机事件详情
			crash.GET("/analysis/:host_id", s.getCrashAnalysis) // 获取宕机分析
		}

		// 用户管理路由（需要管理员权限）
		users := v1.Group("/users")
		users.Use(AdminMiddleware()) // 管理员权限
		{
			users.GET("", s.listUsers)              // 获取用户列表
			users.GET("/:id", s.getUser)             // 获取单个用户
			users.POST("", s.createUser)             // 创建用户
			users.PUT("/:id", s.updateUser)          // 更新用户
			users.DELETE("/:id", s.deleteUser)       // 删除用户
			users.POST("/:id/reset-password", s.resetUserPassword) // 重置用户密码
		}

		// 进程监控路由
		processes := v1.Group("/processes")
		{
			processes.GET("", s.getProcesses)           // 获取进程列表
			processes.GET("/history", s.getProcessHistory) // 获取进程历史数据
		}

		// 日志路由
		logs := v1.Group("/logs")
		{
			logs.GET("", s.getLogs) // 获取日志列表
		}

		// 脚本执行路由
		scripts := v1.Group("/scripts")
		{
			scripts.GET("/executions", s.getScriptExecutions) // 获取脚本执行记录
		}

		// 服务状态路由
		services := v1.Group("/services")
		{
			services.GET("", s.getServiceStatus)      // 获取服务状态
		}

		// 告警规则路由
		alerts := v1.Group("/alerts")
		{
			alerts.GET("/rules", s.listAlertRules)           // 获取告警规则列表
			alerts.POST("/rules", s.createAlertRule)         // 创建告警规则
			alerts.GET("/rules/:id", s.getAlertRule)         // 获取告警规则
			alerts.PUT("/rules/:id", s.updateAlertRule)      // 更新告警规则
			alerts.DELETE("/rules/:id", s.deleteAlertRule)   // 删除告警规则

			alerts.GET("/history", s.listAlertHistory)       // 获取告警历史
			alerts.GET("/history/unread-count", s.getUnreadAlertCount) // 获取未读告警数量
			alerts.GET("/history/:id", s.getAlertHistory)    // 获取告警历史详情
			alerts.DELETE("/history/batch", s.deleteAlertHistories) // 批量删除告警历史（必须在 /history/:id 之前）
			alerts.DELETE("/history/:id", s.deleteAlertHistory) // 删除告警历史

			alerts.GET("/silences", s.listAlertSilences)     // 获取告警静默列表
			alerts.POST("/silences", s.createAlertSilence)   // 创建告警静默
			alerts.PUT("/silences/:id", s.updateAlertSilence) // 更新告警静默
			alerts.DELETE("/silences/:id", s.deleteAlertSilence) // 删除告警静默

			alerts.GET("/channels", s.listNotificationChannels)     // 获取通知渠道列表
			alerts.POST("/channels", s.createNotificationChannel)  // 创建通知渠道
			alerts.POST("/channels/test", s.testNotificationChannel) // 测试通知渠道（必须在 /channels/:id 之前）
			alerts.GET("/channels/:id", s.getNotificationChannel)  // 获取通知渠道
			alerts.PUT("/channels/:id", s.updateNotificationChannel) // 更新通知渠道
			alerts.DELETE("/channels/:id", s.deleteNotificationChannel) // 删除通知渠道
		}
	}
}

func (s *APIServer) Start() error {
	log.Printf("API Server starting on %s", s.config.Port)
	return s.router.Run(s.config.Port)
}
