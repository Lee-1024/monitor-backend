// ============================================
// 文件: main.go (修改，添加API服务)
// ============================================
package main

import (
	"log"
	"monitor-backend/api"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "monitor-backend/proto"

	"google.golang.org/grpc"
)

func main() {
	// 加载配置
	config := LoadConfig()

	// 初始化存储
	storage := NewStorage(config)
	defer storage.Close()

	// 创建收集服务
	collectorService := NewCollectorService(storage)

	// 启动gRPC服务器
	go func() {
		lis, err := net.Listen("tcp", config.GRPCAddr)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}

		grpcServer := grpc.NewServer()
		pb.RegisterCollectorServer(grpcServer, collectorService)

		log.Printf("gRPC server started on %s", config.GRPCAddr)

		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// 启动HTTP API服务器
	go func() {
		// 初始化JWT密钥
		api.SetJWTSecret(config.JWTSecret)

		apiConfig := &api.APIConfig{
			Port: config.HTTPAddr,
			AllowOrigins: []string{
				"http://localhost:3000",
				"http://localhost:8080",
				"http://localhost:5173", // Vite默认端口
			},
			AuthRequired: config.AuthRequired,
		}

		apiServer := api.NewAPIServer(NewStorageAdapter(storage), apiConfig)

		log.Printf("HTTP API server started on %s", config.HTTPAddr)

		if err := apiServer.Start(); err != nil {
			log.Fatalf("Failed to start API server: %v", err)
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")
	log.Println("Servers stopped")
}
