// ============================================
// 文件: service.go (完整版本)
// ============================================
package main

import (
	"context"
	"encoding/json"
	"fmt"
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

	if req.Gpu != nil && len(req.Gpu.Devices) > 0 {
		metrics.GPU = GPUMetrics{
			Devices: make([]GPUDeviceMetrics, 0, len(req.Gpu.Devices)),
		}
		for _, device := range req.Gpu.Devices {
			metrics.GPU.Devices = append(metrics.GPU.Devices, GPUDeviceMetrics{
				Index:              int(device.Index),
				Name:               device.Name,
				Vendor:             device.Vendor,
				Model:              device.Model,
				UUID:               device.Uuid,
				DriverVersion:      device.DriverVersion,
				UtilizationPercent: device.UtilizationPercent,
				MemoryTotal:        device.MemoryTotal,
				MemoryUsed:         device.MemoryUsed,
				MemoryUsedPercent:  device.MemoryUsedPercent,
				Temperature:        device.Temperature,
				PowerWatts:         device.PowerWatts,
				FanSpeedPercent:    device.FanSpeedPercent,
			})
		}
		log.Printf("  GPU: %d devices", len(metrics.GPU.Devices))
	}

	// 先缓存最新指标。即使 InfluxDB 暂时不可用，前端最新数据页面也能展示刚上报的数据。
	if err := s.storage.CacheLatestMetrics(req.HostId, metrics); err != nil {
		log.Printf("Failed to cache metrics for %s: %v", req.HostId, err)
	}

	// 保存到InfluxDB。时序库写入失败不再让 gRPC 上报失败，避免 agent 误判为未连上后端。
	if err := s.storage.SaveMetrics(metrics); err != nil {
		log.Printf("Failed to save metrics: %v", err)
		return &pb.MetricsResponse{
			Success: true,
			Message: "Metrics accepted, but time-series storage write failed",
		}, nil
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

// ReportProcesses 接收进程监控数据
func (s *CollectorService) ReportProcesses(ctx context.Context, req *pb.ProcessReportRequest) (*pb.MetricsResponse, error) {
	log.Printf("Received process data from: %s (%d processes)", req.HostId, len(req.Processes))

	if len(req.Processes) == 0 {
		log.Printf("Warning: Received empty process list from %s", req.HostId)
		return &pb.MetricsResponse{
			Success: true,
			Message: "No processes to save",
		}, nil
	}

	// 更新Agent最后上报时间
	s.storage.UpdateAgentLastSeen(req.HostId)

	// 保存进程快照
	timestamp := time.Unix(req.Timestamp, 0)
	snapshots := make([]ProcessSnapshot, 0, len(req.Processes))

	for _, proc := range req.Processes {
		snapshots = append(snapshots, ProcessSnapshot{
			HostID:        req.HostId,
			Timestamp:     timestamp,
			PID:           proc.Pid,
			Name:          proc.Name,
			User:          proc.User,
			CPUPercent:    proc.CpuPercent,
			MemoryPercent: proc.MemoryPercent,
			MemoryBytes:   proc.MemoryBytes,
			Status:        proc.Status,
			Command:       proc.Command,
		})
	}

	if err := s.storage.postgres.CreateInBatches(snapshots, 100).Error; err != nil {
		log.Printf("Failed to save process snapshots for host %s: %v", req.HostId, err)
		return &pb.MetricsResponse{
			Success: false,
			Message: "Failed to save process snapshots",
		}, err
	}

	log.Printf("Saved %d processes for host %s", len(snapshots), req.HostId)

	return &pb.MetricsResponse{
		Success: true,
		Message: fmt.Sprintf("Processes saved: %d", len(snapshots)),
	}, nil
}

// ReportLogs 接收日志数据
func (s *CollectorService) ReportLogs(ctx context.Context, req *pb.LogReportRequest) (*pb.MetricsResponse, error) {
	log.Printf("Received log data from: %s (%d entries)", req.HostId, len(req.Logs))

	// 更新Agent最后上报时间
	s.storage.UpdateAgentLastSeen(req.HostId)

	// 保存日志条目
	entries := make([]LogEntry, 0, len(req.Logs))
	for _, logEntry := range req.Logs {
		entries = append(entries, LogEntry{
			HostID:    req.HostId,
			Timestamp: time.Unix(logEntry.Timestamp, 0),
			Source:    logEntry.Source,
			Level:     logEntry.Level,
			Message:   logEntry.Message,
			Tags:      logEntry.Tags,
		})
	}

	if len(entries) > 0 {
		if err := s.storage.postgres.CreateInBatches(entries, 200).Error; err != nil {
			log.Printf("Failed to save log entries for host %s: %v", req.HostId, err)
			return &pb.MetricsResponse{
				Success: false,
				Message: "Failed to save log entries",
			}, err
		}
	}

	return &pb.MetricsResponse{
		Success: true,
		Message: fmt.Sprintf("Logs saved: %d", len(entries)),
	}, nil
}

// ReportScriptResult 接收脚本执行结果
func (s *CollectorService) ReportScriptResult(ctx context.Context, req *pb.ScriptResultRequest) (*pb.MetricsResponse, error) {
	log.Printf("Received script result from: %s (script: %s, success: %v)", req.HostId, req.ScriptId, req.Success)

	// 更新Agent最后上报时间
	s.storage.UpdateAgentLastSeen(req.HostId)

	// 保存脚本执行记录
	execution := &ScriptExecution{
		HostID:     req.HostId,
		ScriptID:   req.ScriptId,
		ScriptName: req.ScriptName,
		Timestamp:  time.Unix(req.Timestamp, 0),
		Success:    req.Success,
		Output:     req.Output,
		Error:      req.Error,
		ExitCode:   int(req.ExitCode),
		Duration:   req.DurationMs,
	}
	if err := s.storage.postgres.Create(execution).Error; err != nil {
		log.Printf("Failed to save script execution: %v", err)
		return &pb.MetricsResponse{
			Success: false,
			Message: "Failed to save script execution",
		}, err
	}

	return &pb.MetricsResponse{
		Success: true,
		Message: "Script result saved successfully",
	}, nil
}

// ReportServiceStatus 接收服务状态数据
func (s *CollectorService) ReportServiceStatus(ctx context.Context, req *pb.ServiceStatusRequest) (*pb.MetricsResponse, error) {
	log.Printf("Received service status from: %s (%d services)", req.HostId, len(req.Services))
	if len(req.Services) == 0 {
		return &pb.MetricsResponse{
			Success: true,
			Message: "No service status to save",
		}, nil
	}

	// 更新Agent最后上报时间
	s.storage.UpdateAgentLastSeen(req.HostId)

	// 保存服务状态
	timestamp := time.Unix(req.Timestamp, 0)
	savedCount := 0
	for _, svc := range req.Services {
		status := &ServiceStatus{
			HostID:      req.HostId,
			Timestamp:   timestamp,
			Name:        svc.Name,
			Status:      svc.Status,
			Enabled:     svc.Enabled,
			Description: svc.Description,
			Uptime:      svc.UptimeSeconds,
		}
		// 如果有端口信息，保存端口和端口检查结果
		if svc.Port > 0 {
			status.Port = int(svc.Port)
			status.PortAccessible = svc.PortAccessible
		}
		if err := s.storage.postgres.Create(status).Error; err != nil {
			log.Printf("Failed to save service status: %v", err)
			return &pb.MetricsResponse{
				Success: false,
				Message: "Failed to save service status",
			}, err
		}
		savedCount++
	}

	return &pb.MetricsResponse{
		Success: true,
		Message: fmt.Sprintf("Service status saved: %d", savedCount),
	}, nil
}

func (s *CollectorService) ReportDockerContainers(ctx context.Context, req *pb.LogReportRequest) (*pb.MetricsResponse, error) {
	log.Printf("Received docker container data from: %s (%d containers)", req.HostId, len(req.Logs))
	if len(req.Logs) == 0 {
		return &pb.MetricsResponse{Success: true, Message: "No docker containers to save"}, nil
	}

	s.storage.UpdateAgentLastSeen(req.HostId)

	snapshots := make([]DockerContainerSnapshot, 0, len(req.Logs))
	for _, entry := range req.Logs {
		var snapshot DockerContainerSnapshot
		if err := json.Unmarshal([]byte(entry.Message), &snapshot); err != nil {
			log.Printf("Failed to decode docker snapshot for host %s: %v", req.HostId, err)
			continue
		}
		snapshot.HostID = req.HostId
		if snapshot.Timestamp.IsZero() {
			snapshot.Timestamp = time.Unix(req.Timestamp, 0)
		}
		snapshots = append(snapshots, snapshot)
	}

	if len(snapshots) == 0 {
		return &pb.MetricsResponse{Success: true, Message: "No valid docker containers to save"}, nil
	}

	if err := s.storage.postgres.CreateInBatches(snapshots, 100).Error; err != nil {
		log.Printf("Failed to save docker snapshots for host %s: %v", req.HostId, err)
		return &pb.MetricsResponse{Success: false, Message: "Failed to save docker snapshots"}, err
	}

	return &pb.MetricsResponse{
		Success: true,
		Message: fmt.Sprintf("Docker containers saved: %d", len(snapshots)),
	}, nil
}
