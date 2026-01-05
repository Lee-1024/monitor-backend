// ============================================
// 文件: service.go
// ============================================
package main

import (
	"context"
	"log"
	"time"

	pb "monitor-backend/proto"
)

type CollectorService struct {
	pb.UnimplementedCollectorServer
	storage *Storage
}

func NewCollectorService(storage *Storage) *CollectorService {
	return &CollectorService{
		storage: storage,
	}
}

// RegisterAgent 注册Agent
func (s *CollectorService) RegisterAgent(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("Agent registered: %s (%s)", req.HostId, req.Hostname)

	// 保存Agent信息到PostgreSQL
	agent := &Agent{
		HostID:   req.HostId,
		Hostname: req.Hostname,
		IP:       req.Ip,
		OS:       req.Os,
		Arch:     req.Arch,
		Tags:     req.Tags,
		Status:   "online",
		LastSeen: time.Now(),
	}

	if err := s.storage.SaveAgent(agent); err != nil {
		log.Printf("Failed to save agent: %v", err)
		return &pb.RegisterResponse{
			Success: false,
			Message: "Failed to register agent",
		}, err
	}

	return &pb.RegisterResponse{
		Success:         true,
		Message:         "Agent registered successfully",
		CollectInterval: 10, // 默认10秒
	}, nil
}

// ReportMetrics 接收指标数据
func (s *CollectorService) ReportMetrics(ctx context.Context, req *pb.MetricsRequest) (*pb.MetricsResponse, error) {
	log.Printf("Received metrics from: %s", req.HostId)

	// 更新Agent最后上报时间
	s.storage.UpdateAgentLastSeen(req.HostId)

	// 转换为内部格式
	metrics := &Metrics{
		HostID:    req.HostId,
		Timestamp: time.Unix(req.Timestamp, 0),
	}

	// CPU指标
	if req.Cpu != nil {
		metrics.CPU = CPUMetrics{
			UsagePercent: req.Cpu.UsagePercent,
			LoadAvg1:     req.Cpu.LoadAvg_1,
			LoadAvg5:     req.Cpu.LoadAvg_5,
			LoadAvg15:    req.Cpu.LoadAvg_15,
			CoreCount:    int(req.Cpu.CoreCount),
		}
	}

	// 内存指标
	if req.Memory != nil {
		metrics.Memory = MemoryMetrics{
			Total:       req.Memory.Total,
			Used:        req.Memory.Used,
			Free:        req.Memory.Free,
			UsedPercent: req.Memory.UsedPercent,
			Available:   req.Memory.Available,
		}
	}

	// 保存到InfluxDB
	if err := s.storage.SaveMetrics(metrics); err != nil {
		log.Printf("Failed to save metrics: %v", err)
		return &pb.MetricsResponse{
			Success: false,
			Message: "Failed to save metrics",
		}, err
	}

	return &pb.MetricsResponse{
		Success: true,
		Message: "Metrics saved successfully",
	}, nil
}

// Heartbeat 心跳处理
func (s *CollectorService) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	log.Printf("Heartbeat from: %s", req.HostId)

	// 更新Agent状态
	s.storage.UpdateAgentLastSeen(req.HostId)

	return &pb.HeartbeatResponse{
		Success:    true,
		ServerTime: time.Now().Unix(),
	}, nil
}
