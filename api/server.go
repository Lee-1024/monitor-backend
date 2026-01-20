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
	predictor         PredictorInterface // 预测器接口
	llmManager        interface{ GetClient() LLMClientInterface } // LLM管理器接口
	taskManager       *LLMTaskManager // LLM任务管理器
	anomalyDetector   interface{} // 异常检测器接口（避免循环依赖）
}

type APIConfig struct {
	Port         string
	AllowOrigins []string
	AuthRequired bool // 是否要求认证
}

func NewAPIServer(storage StorageInterface, config *APIConfig, notificationManager interface{}, predictor PredictorInterface, llmManager interface{ GetClient() LLMClientInterface }, anomalyDetector interface{}) *APIServer {
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

	// 初始化LLM任务管理器
	var taskManager *LLMTaskManager
	if redisClient := storage.GetRedis(); redisClient != nil {
		// 使用类型断言获取Redis客户端
		type RedisClient interface {
			Get(ctx interface{}, key string) interface{}
		}
		// 直接使用interface{}，在llm_task.go中处理类型转换
		taskManager = NewLLMTaskManagerFromInterface(redisClient)
	}

	server := &APIServer{
		router:             router,
		storage:            storage,
		config:             config,
		notificationManager: notificationManager,
		predictor:          predictor,
		llmManager:         llmManager,
		taskManager:        taskManager,
		anomalyDetector:    anomalyDetector,
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

		// 预测分析相关
		predictions := v1.Group("/predictions")
		{
			predictions.GET("/capacity", s.getCapacityPrediction) // 获取容量预测
			predictions.GET("/capacity/stream", s.streamCapacityAnalysis) // 流式获取容量分析（SSE）
			predictions.GET("/cost-optimization", s.getCostOptimization) // 获取成本优化建议
			predictions.GET("/cost-optimization/stream", s.streamCostOptimization) // 流式获取成本优化建议（SSE）
			predictions.GET("/task/:task_id", s.getLLMTaskStatus) // 获取LLM任务状态
		}

		// LLM模型配置相关
		llm := v1.Group("/llm")
		{
			llm.GET("/models", s.listLLMModelConfigs)           // 获取模型配置列表
			llm.POST("/models", s.createLLMModelConfig)        // 创建模型配置
			llm.POST("/models/test", s.testLLMModelConfig)      // 测试模型配置（必须在 /models/:id 之前）
			llm.POST("/models/:id/test", s.testLLMModelConfigByID) // 通过ID测试模型配置（必须在 /models/:id 之前）
			llm.POST("/models/:id/set-default", s.setDefaultLLMModelConfig) // 设置默认模型配置（必须在 /models/:id 之前）
			llm.GET("/models/:id", s.getLLMModelConfig)         // 获取模型配置
			llm.PUT("/models/:id", s.updateLLMModelConfig)      // 更新模型配置
			llm.DELETE("/models/:id", s.deleteLLMModelConfig)   // 删除模型配置
		}

		// 宕机分析路由
		crash := v1.Group("/crash")
		{
			crash.GET("/events", s.getCrashEvents)              // 获取宕机事件列表
			crash.GET("/events/:id", s.getCrashEventDetail)     // 获取宕机事件详情
			crash.DELETE("/events", s.deleteCrashEvents)        // 批量删除宕机事件
			crash.GET("/analysis/:host_id", s.getCrashAnalysis) // 获取宕机分析
		}

		// 异常检测路由
		anomalies := v1.Group("/anomalies")
		{
			anomalies.POST("/detect", s.detectAnomalies)                    // 检测异常（指标和日志）
			anomalies.GET("/detect/stream", s.streamAnomalyAnalysis)        // 流式获取异常分析（SSE）
			anomalies.GET("/events", s.getAnomalyEvents)                    // 获取异常事件列表
			anomalies.GET("/events/:id", s.getAnomalyEventDetail)          // 获取异常事件详情
			anomalies.POST("/events/:id/resolve", s.resolveAnomalyEvent)   // 标记异常事件为已解决
			anomalies.GET("/statistics", s.getAnomalyStatistics)            // 获取异常统计信息
		}

		// 性能分析路由
		performance := v1.Group("/performance")
		{
			performance.GET("/analysis/stream", s.streamPerformanceAnalysis) // 流式获取性能分析（SSE）
		}

		// 知识库路由
		knowledge := v1.Group("/knowledge")
		{
			// 故障处理知识库
			knowledge.GET("/troubleshooting", s.listTroubleshootingGuides)           // 获取故障处理知识库列表
			knowledge.GET("/troubleshooting/:id", s.getTroubleshootingGuide)          // 获取故障处理知识库详情
			knowledge.POST("/troubleshooting", s.createTroubleshootingGuide)          // 创建故障处理知识库
			knowledge.PUT("/troubleshooting/:id", s.updateTroubleshootingGuide)       // 更新故障处理知识库
			knowledge.DELETE("/troubleshooting/:id", s.deleteTroubleshootingGuide)    // 删除故障处理知识库

			// 最佳实践文档
			knowledge.GET("/best-practices", s.listBestPractices)                    // 获取最佳实践文档列表
			knowledge.GET("/best-practices/:id", s.getBestPractice)                  // 获取最佳实践文档详情
			knowledge.POST("/best-practices", s.createBestPractice)                  // 创建最佳实践文档
			knowledge.PUT("/best-practices/:id", s.updateBestPractice)               // 更新最佳实践文档
			knowledge.DELETE("/best-practices/:id", s.deleteBestPractice)            // 删除最佳实践文档

			// 故障案例库
			knowledge.GET("/case-studies", s.listCaseStudies)                        // 获取故障案例库列表
			knowledge.GET("/case-studies/:id", s.getCaseStudy)                       // 获取故障案例库详情
			knowledge.POST("/case-studies", s.createCaseStudy)                      // 创建故障案例库
			knowledge.PUT("/case-studies/:id", s.updateCaseStudy)                   // 更新故障案例库
			knowledge.DELETE("/case-studies/:id", s.deleteCaseStudy)                // 删除故障案例库

			// LLM搜索
			knowledge.GET("/search/stream", s.searchKnowledgeBase)                  // 流式搜索知识库（SSE）
		}

		// 智能巡检路由
		inspection := v1.Group("/inspection")
		{
			inspection.POST("/run", s.runInspection)                              // 执行巡检
			inspection.GET("/reports", s.listInspectionReports)                   // 获取巡检报告列表
			inspection.GET("/reports/:id", s.getInspectionReport)                 // 获取巡检报告详情
			inspection.GET("/reports/:id/stream", s.streamInspectionReport)       // 流式生成巡检日报（SSE）
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
