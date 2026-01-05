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
	router  *gin.Engine
	storage StorageInterface
	config  *APIConfig
}

type APIConfig struct {
	Port         string
	AllowOrigins []string
}

func NewAPIServer(storage StorageInterface, config *APIConfig) *APIServer {
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
		router:  router,
		storage: storage,
		config:  config,
	}

	server.setupRoutes()

	return server
}

func (s *APIServer) setupRoutes() {
	// 健康检查
	s.router.GET("/health", s.healthCheck)

	// API v1
	v1 := s.router.Group("/api/v1")
	{
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
	}
}

func (s *APIServer) Start() error {
	log.Printf("API Server starting on %s", s.config.Port)
	return s.router.Run(s.config.Port)
}
