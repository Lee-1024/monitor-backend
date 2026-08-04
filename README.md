# Monitor Backend

监控系统后端服务，负责接收 Agent 数据、存储指标和元数据、提供 HTTP API、执行告警引擎，并为前端运维助手提供基于 CloudWeGo Eino 的 AI 诊断编排。

## 当前能力

- gRPC 采集入口：接收主机注册、心跳、指标、进程、日志、服务、脚本结果、Docker 容器数据。
- HTTP API：为前端提供主机、指标、告警、日志、进程、服务、Docker、GPU、巡检、知识库、用户和 LLM 配置接口。
- 时序存储：InfluxDB 存储 CPU、内存、磁盘、网络、GPU、Docker 等指标。
- 元数据存储：PostgreSQL 存储主机、用户、告警、知识库、巡检报告、运维助手会话等。
- 缓存：Redis 可选，用于最新指标、任务状态等运行态数据。
- 告警引擎：支持阈值告警、主机宕机、服务端口、GPU 不可用、静默和多渠道通知。
- 异常检测：异常事件查询、统计、解决状态维护和 LLM 总结。
- 容量预测与成本优化：基于历史数据做资源趋势预测，并可结合 LLM 输出建议。
- 知识库与巡检：故障知识、最佳实践、案例库、巡检执行和流式巡检日报。
- 运维助手：统一承载 AI 运维分析能力，使用 Eino Graph、ToolsNode、Tool 和 callbacks 实现可观测的诊断流程。

## 运维助手与 Eino

运维助手代码位于 `opsassistant/` 和 `api/ops_assistant_*.go`。当前实现不是手写“类 Eino”流程，而是直接使用 CloudWeGo Eino：

- ChatModel：`api/ops_assistant_eino_model.go` 使用 Eino OpenAI 兼容模型组件。
- 顶层编排：`opsassistant/assistant.go` 使用 `compose.Graph` 串联意图识别、上下文保护、工具规划和诊断 workflow。
- 工具执行：`opsassistant/workflow/eino_tool.go` 将系统内只读工具适配为 Eino `tool.InvokableTool`。
- ToolsNode：`opsassistant/workflow/generic.go` 通过 Eino `compose.NewToolNode` 执行工具调用。
- workflow：通用诊断和专项诊断均通过 Eino Graph 编排。
- callbacks：Eino 节点生命周期映射为 SSE `graph_node` 时间线事件。
- 会话：`api/ops_assistant_session_store.go` 提供 DB 优先的会话存储，列表、恢复、删除接口供前端历史会话使用。

当前支持的诊断意图包括：

- `global_health`
- `host_performance`
- `capacity_planning`
- `cost_optimization`
- `alert_root_cause`
- `anomaly_analysis`
- `inspection_summary`
- `knowledge_troubleshooting`
- `log_investigation`

专项 workflow 包括主机性能、容量规划、成本优化、异常分析和告警根因分析。所有工具保持只读，不直接执行变更操作。

## 技术栈

- Go 1.21+
- Gin
- gRPC / Protobuf
- GORM
- PostgreSQL
- InfluxDB 2.x
- Redis，可选
- CloudWeGo Eino
- JWT

## 快速开始

### 依赖

- Go 1.21+
- PostgreSQL 12+
- InfluxDB 2.x
- Redis，可选

### 安装依赖

```bash
cd monitor-backend
go mod download
```

### 配置

编辑 `config.yaml`：

```yaml
grpc_addr: ":50051"
http_addr: ":8080"

postgresql:
  host: "localhost"
  port: 5433
  user: "monitor"
  password: "monitor123"
  database: "monitor"

influxdb:
  url: "http://localhost:8086"
  token: "your-token"
  org: "monitor"
  bucket: "metrics"

redis:
  addr: "localhost:6379"
  password: ""
  db: 0

jwt_secret: "change-me"
auth_required: true
```

LLM 模型配置主要通过前端 `/llm-config` 写入数据库并设置默认模型。运维助手启动时会读取默认 LLM 配置。

### 运行

```bash
go run .
```

默认端口：

- HTTP API：`http://localhost:8080`
- gRPC：`localhost:50051`

### 健康检查

```bash
curl http://localhost:8080/health
```

## 项目结构

```text
monitor-backend/
├── main.go                         # 程序入口
├── config.go                       # 配置加载
├── service.go                      # gRPC 采集服务
├── storage.go                      # PostgreSQL / InfluxDB 存储
├── storage_adapter.go              # API 存储适配
├── models.go                       # GORM 模型
├── server_probe.go                 # 服务端口探测
├── api/                            # HTTP API
│   ├── server.go                   # 路由注册
│   ├── handlers.go                 # 主机、指标、预测等处理器
│   ├── ops_assistant_handlers.go   # 运维助手接口和工具
│   ├── ops_assistant_eino_model.go # Eino ChatModel 适配
│   ├── ops_assistant_session_store.go
│   ├── knowledge_handlers.go
│   ├── inspection_handlers.go
│   └── ...
├── opsassistant/                   # Eino 运维助手核心
│   ├── assistant.go                # 顶层 Eino Graph
│   ├── workflow/                   # 通用和专项 workflow
│   ├── graph/                      # 意图、规划、证据等节点逻辑
│   ├── memory/                     # 会话模型和 Store 接口
│   ├── knowledge/                  # 知识检索
│   └── report/                     # 结构化诊断报告
├── analyzer/                       # 预测和异常检测
├── alerter/                        # 告警引擎
├── notifier/                       # 邮件、钉钉、企业微信、飞书通知
├── llm/                            # 历史 LLM 客户端能力
├── proto/                          # Protobuf 协议
├── go.mod
└── README.md
```

## 主要 API

所有业务接口默认挂在 `/api/v1` 下，除登录注册外需要 JWT：

```text
Authorization: Bearer <token>
```

### 认证与用户

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `GET /user/me`
- `GET /users`
- `POST /users`
- `PUT /users/:id`
- `DELETE /users/:id`
- `POST /users/:id/reset-password`

### 主机与指标

- `GET /agents`
- `GET /agents/:id`
- `DELETE /agents/:id`
- `GET /metrics/latest`
- `GET /metrics/history`
- `GET /metrics/aggregate`
- `GET /stats/overview`
- `GET /stats/top`

### 进程、日志、服务、Docker、GPU

- `GET /processes`
- `GET /processes/history`
- `GET /logs`
- `GET /services`
- `GET /docker/containers`
- `GET /docker/history`
- GPU 指标通过最新指标、历史指标、Top 统计等接口返回。

### 告警

- `GET /alerts/rules`
- `POST /alerts/rules`
- `PUT /alerts/rules/:id`
- `DELETE /alerts/rules/:id`
- `GET /alerts/history`
- `DELETE /alerts/history/:id`
- `DELETE /alerts/history/batch`
- `GET /alerts/silences`
- `POST /alerts/silences`
- `PUT /alerts/silences/:id`
- `DELETE /alerts/silences/:id`
- `GET /alerts/channels`
- `POST /alerts/channels`
- `POST /alerts/channels/test`
- `PUT /alerts/channels/:id`
- `DELETE /alerts/channels/:id`

### 运维助手

- `POST /ops-assistant/chat`
- `GET /ops-assistant/chat/stream`
- `GET /ops-assistant/sessions`
- `GET /ops-assistant/sessions/:id`
- `DELETE /ops-assistant/sessions/:id`

SSE 事件包含：

- `status`
- `graph_node`
- `tool_call`
- `report_delta`
- `report`
- `content`
- `done`
- `error`

### 知识库与巡检

- `GET /knowledge/troubleshooting`
- `POST /knowledge/troubleshooting`
- `PUT /knowledge/troubleshooting/:id`
- `DELETE /knowledge/troubleshooting/:id`
- `GET /knowledge/best-practices`
- `GET /knowledge/case-studies`
- `GET /knowledge/search/stream`
- `POST /inspection/run`
- `GET /inspection/reports`
- `GET /inspection/reports/:id`
- `GET /inspection/reports/:id/stream`

### LLM 配置

- `GET /llm/models`
- `POST /llm/models`
- `POST /llm/models/test`
- `POST /llm/models/:id/test`
- `POST /llm/models/:id/set-default`
- `GET /llm/models/:id`
- `PUT /llm/models/:id`
- `DELETE /llm/models/:id`

## 告警规则说明

当前支持：

- `cpu`
- `memory`
- `disk`
- `network`
- `host_down`
- `service_port`
- `gpu_unavailable`

规则支持多主机关联：

- `host_ids` 为空表示全部主机。
- 多主机关系存储在 `alert_rule_hosts`。
- 旧字段 `host_id` 保留兼容单主机规则。

特殊规则说明：

- `host_down`：按规则持续时间检查 `last_seen`。
- `service_port`：按服务端口不可访问状态触发。
- `gpu_unavailable`：最新 GPU 指标无可用设备时触发。

普通阈值类和特殊规则均遵循持续时间、抑制时间和恢复通知逻辑。

## 在线状态口径

Backend 当前默认使用 `30s` 未上报作为离线展示口径。Agent 上报指标、心跳、进程、日志、服务、Docker 等数据时都会更新 `last_seen`。

## 部署

### 构建二进制

```bash
go build -o monitor-backend
```

### Docker

```bash
cd monitor-backend
docker build -t monitor-backend:latest .
docker run -d --name monitor-backend \
  -p 50051:50051 \
  -p 8080:8080 \
  -v /opt/monitor-backend/config.yaml:/app/config.yaml \
  -e CONFIG_PATH=config.yaml \
  monitor-backend:latest
```

### systemd

```ini
[Unit]
Description=Monitor Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/monitor-backend
ExecStart=/opt/monitor-backend/monitor-backend
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 开发与验证

```bash
go test ./...
```

如果修改 Protobuf：

```bash
protoc --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  proto/collector.proto
```

## 相关文档

- [Frontend README](../monitor-frontend/README.md)
- [Agent README](../monitor-agent/README.md)
- [PREDICTION_FEATURE.md](./PREDICTION_FEATURE.md)

## 许可证

MIT license
