// ============================================
// 文件: service.go (完整版本)
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

// RegisterAgent 注册Agent（支持重复注册，自动更新）
func (s *CollectorService) RegisterAgent(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("Agent registering: %s (%s)", req.HostId, req.Hostname)

	// 先尝试查找已存在的Agent
	var existingAgent Agent
	result := s.storage.postgres.Where("host_id = ?", req.HostId).First(&existingAgent)

	now := time.Now()

	if result.Error == nil {
		// Agent已存在，更新信息
		existingAgent.Hostname = req.Hostname
		existingAgent.IP = req.Ip
		existingAgent.OS = req.Os
		existingAgent.Arch = req.Arch
		existingAgent.Tags = req.Tags
		existingAgent.Status = "online"
		existingAgent.LastSeen = now

		if err := s.storage.postgres.Save(&existingAgent).Error; err != nil {
			log.Printf("Failed to update agent: %v", err)
			return &pb.RegisterResponse{
				Success: false,
				Message: "Failed to update agent",
			}, err
		}

		log.Printf("Agent updated: %s (%s)", req.HostId, req.Hostname)
	} else {
		// Agent不存在，创建新记录
		agent := &Agent{
			HostID:   req.HostId,
			Hostname: req.Hostname,
			IP:       req.Ip,
			OS:       req.Os,
			Arch:     req.Arch,
			Tags:     req.Tags,
			Status:   "online",
			LastSeen: now,
		}

		if err := s.storage.postgres.Create(agent).Error; err != nil {
			log.Printf("Failed to create agent: %v", err)
			return &pb.RegisterResponse{
				Success: false,
				Message: "Failed to register agent",
			}, err
		}

		log.Printf("Agent registered: %s (%s)", req.HostId, req.Hostname)
	}

	return &pb.RegisterResponse{
		Success:         true,
		Message:         "Agent registered successfully",
		CollectInterval: 10,
	}, nil
}

// ReportMetrics 接收指标数据（完整版 - 包含磁盘和网络）
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

	// 磁盘指标 - 新增
	if req.Disk != nil && len(req.Disk.Partitions) > 0 {
		metrics.Disk = DiskMetrics{
			Partitions: make([]PartitionMetrics, 0, len(req.Disk.Partitions)),
		}
		for _, p := range req.Disk.Partitions {
			metrics.Disk.Partitions = append(metrics.Disk.Partitions, PartitionMetrics{
				Device:      p.Device,
				Mountpoint:  p.Mountpoint,
				Fstype:      p.Fstype,
				Total:       p.Total,
				Used:        p.Used,
				Free:        p.Free,
				UsedPercent: p.UsedPercent,
			})
		}
		log.Printf("  Disk: %d partitions", len(metrics.Disk.Partitions))
	}

	// 网络指标 - 新增
	if req.Network != nil && len(req.Network.Interfaces) > 0 {
		metrics.Network = NetworkMetrics{
			Interfaces: make([]InterfaceMetrics, 0, len(req.Network.Interfaces)),
		}
		for _, iface := range req.Network.Interfaces {
			metrics.Network.Interfaces = append(metrics.Network.Interfaces, InterfaceMetrics{
				Name:        iface.Name,
				BytesSent:   iface.BytesSent,
				BytesRecv:   iface.BytesRecv,
				PacketsSent: iface.PacketsSent,
				PacketsRecv: iface.PacketsRecv,
				Errin:       iface.Errin,
				Errout:      iface.Errout,
			})
		}
		log.Printf("  Network: %d interfaces", len(metrics.Network.Interfaces))
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
