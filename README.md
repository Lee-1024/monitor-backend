# Monitor Backend

监控系统后端服务，提供数据存储、API接口、异常检测、智能分析和告警通知功能。

## 📋 目录

- [概述](#概述)
- [技术栈](#技术栈)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [配置说明](#配置说明)
- [API接口](#api接口)
- [开发指南](#开发指南)
- [部署](#部署)

## 🎯 概述

Monitor Backend 是监控系统的核心服务，负责：

- 接收Agent上报的监控数据
- 存储指标数据（InfluxDB）和元数据（PostgreSQL）
- 提供RESTful API接口
- 异常检测和智能分析
- 告警规则匹配和通知
- LLM集成（智能分析和报告生成）

## 🛠️ 技术栈

- **语言**: Go 1.21+
- **Web框架**: Gin
- **gRPC**: Google gRPC
- **数据库**: 
  - PostgreSQL (元数据、配置、用户)
  - InfluxDB (时序指标数据)
  - Redis (缓存，可选)
- **ORM**: GORM
- **认证**: JWT
- **其他**: 
  - LLM集成 (OpenAI/Claude/DeepSeek/Zhipu等)
  - 异常检测算法
  - 预测分析

## ✨ 功能特性

### 核心功能

- ✅ **数据接收**: gRPC接收Agent上报的监控数据
- ✅ **数据存储**: 时序数据存储到InfluxDB，元数据存储到PostgreSQL
- ✅ **RESTful API**: 提供完整的HTTP API接口
- ✅ **用户认证**: JWT认证和授权
- ✅ **异常检测**: 基于统计和机器学习的异常检测
- ✅ **智能分析**: 集成LLM的智能分析和预测
- ✅ **告警引擎**: 告警规则匹配和多渠道通知
- ✅ **知识库**: 故障处理知识库管理
- ✅ **智能巡检**: 自动化巡检和日报生成

### 详细功能

1. **主机管理**: 主机注册、查询、删除
2. **指标查询**: 实时指标、历史指标、聚合指标
3. **异常检测**: CPU/内存/磁盘异常检测，日志异常检测
4. **容量预测**: 基于历史数据的资源使用趋势预测
5. **成本优化**: LLM生成的成本优化建议
6. **性能分析**: 性能瓶颈分析和优化建议
7. **宕机分析**: 宕机事件记录和分析
8. **日志管理**: 日志收集、查询、分页
9. **进程监控**: 进程资源使用监控
10. **服务监控**: 系统服务状态监控
11. **脚本执行**: 远程脚本执行记录
12. **告警管理**: 告警规则配置和历史查询
13. **用户管理**: 用户认证、权限管理

## 🚀 快速开始

### 环境要求

- Go >= 1.21
- PostgreSQL >= 12
- InfluxDB >= 2.0
- Redis >= 6.0 (可选)

### 1. 安装依赖

```bash
go mod download
```

### 2. 配置数据库

确保PostgreSQL和InfluxDB已启动并配置正确。

### 3. 配置文件

编辑 `config.yaml`:

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

jwt_secret: "your-secret-key"
auth_required: true
```

### 4. 生成Protobuf代码

```bash
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/collector.proto
```

### 5. 运行

```bash
go run .
```

服务将在以下端口启动：
- HTTP API: `http://localhost:8080`
- gRPC: `localhost:50051`

### 6. 测试

```bash
# 健康检查
curl http://localhost:8080/health

# 获取主机列表（需要认证）
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/agents
```

## 📁 项目结构

```
monitor-backend/
├── main.go                    # 入口文件
├── config.go                  # 配置加载
├── service.go                 # gRPC服务
├── storage.go                 # 存储层（PostgreSQL + InfluxDB）
├── storage_adapter.go         # 存储适配器（实现StorageInterface）
├── models.go                  # 数据模型
│
├── api/                       # API层
│   ├── server.go              # HTTP服务器
│   ├── handlers.go             # 请求处理器
│   ├── auth.go                # 认证中间件
│   ├── auth_handlers.go       # 认证相关处理器
│   ├── user_handlers.go       # 用户管理处理器
│   ├── anomaly_handlers.go    # 异常检测处理器
│   ├── performance_handlers.go # 性能分析处理器
│   ├── inspection_handlers.go  # 巡检处理器
│   ├── knowledge_handlers.go   # 知识库处理器
│   ├── storage_interface.go   # 存储接口定义
│   ├── predictor_interface.go # 预测器接口
│   └── anomaly_interface.go   # 异常检测接口
│
├── analyzer/                  # 分析器
│   ├── predictor.go           # 预测分析
│   ├── anomaly_detector.go    # 异常检测
│   ├── adapter.go             # 适配器
│   └── anomaly_adapter.go     # 异常检测适配器
│
├── llm/                       # LLM集成
│   ├── client.go              # LLM客户端
│   ├── manager.go             # LLM管理器
│   ├── adapter.go              # LLM适配器
│   └── streaming.go           # 流式输出
│
├── notifier/                  # 通知器
│   ├── notifier.go            # 通知接口
│   ├── email.go               # 邮件通知
│   ├── dingtalk.go            # 钉钉通知
│   ├── feishu.go              # 飞书通知
│   ├── wechat.go              # 企业微信通知
│   └── loader.go              # 通知器加载
│
├── alerter/                   # 告警引擎
│   └── engine.go              # 告警规则引擎
│
├── proto/                     # Protobuf定义
│   ├── collector.proto        # 数据采集协议
│   ├── collector.pb.go        # 生成的代码
│   └── collector_grpc.pb.go   # 生成的gRPC代码
│
├── config.yaml                # 配置文件
├── go.mod                     # Go模块定义
└── go.sum                     # 依赖校验和
```

## ⚙️ 配置说明

### 配置文件: config.yaml

```yaml
# gRPC服务地址
grpc_addr: ":50051"

# HTTP服务地址
http_addr: ":8080"

# PostgreSQL配置
postgresql:
  host: "localhost"
  port: 5433
  user: "monitor"
  password: "monitor123"
  database: "monitor"

# InfluxDB配置
influxdb:
  url: "http://localhost:8086"
  token: "your-token"
  org: "monitor"
  bucket: "metrics"

# Redis配置（可选）
redis:
  addr: "localhost:6379"
  password: ""
  db: 0

# JWT配置
jwt_secret: "your-secret-key"
auth_required: true  # 是否要求认证

# LLM配置（可选）
llm:
  enabled: false
  provider: "openai"  # openai, claude, deepseek, zhipu, custom
  api_key: "your-api-key"
  base_url: ""  # 自定义API地址（用于custom provider）
  model: "gpt-3.5-turbo"
  temperature: 0.7
  max_tokens: 8000  # 默认8000，确保巡检日报等长文本生成完整
  timeout: 30
```

### 环境变量

可以通过环境变量覆盖配置：

```bash
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5433
export INFLUXDB_URL=http://localhost:8086
```

## 📡 API接口

### 认证

所有API请求（除登录外）需要在Header中携带JWT Token：

```
Authorization: Bearer <token>
```

### 主要API端点

#### 认证相关
- `POST /api/v1/auth/register` - 用户注册
- `POST /api/v1/auth/login` - 用户登录
- `POST /api/v1/auth/refresh` - 刷新Token
- `GET /api/v1/user/me` - 获取当前用户信息

#### 主机相关
- `GET /api/v1/agents` - 获取主机列表（支持分页）
- `GET /api/v1/agents/:id` - 获取主机详情
- `DELETE /api/v1/agents/:id` - 删除主机

#### 指标相关
- `GET /api/v1/metrics/latest` - 获取最新指标
- `GET /api/v1/metrics/history` - 获取历史指标
- `GET /api/v1/metrics/aggregate` - 获取聚合指标

#### 统计相关
- `GET /api/v1/stats/overview` - 获取统计概览
- `GET /api/v1/stats/top` - 获取Top指标

#### 异常检测
- `POST /api/v1/anomalies/detect` - 检测异常
- `GET /api/v1/anomalies/events` - 获取异常事件列表
- `GET /api/v1/anomalies/events/:id` - 获取异常事件详情
- `POST /api/v1/anomalies/events/:id/resolve` - 标记异常已解决
- `GET /api/v1/anomalies/statistics` - 获取异常统计
- `GET /api/v1/anomalies/detect/stream` - 流式获取异常分析（SSE）

#### 预测分析
- `GET /api/v1/predictions/capacity` - 容量预测
- `GET /api/v1/predictions/capacity/stream` - 流式获取容量分析（SSE）
- `GET /api/v1/predictions/cost-optimization` - 成本优化建议
- `GET /api/v1/predictions/cost-optimization/stream` - 流式获取成本优化建议（SSE）

#### 性能分析
- `GET /api/v1/performance/analysis/stream` - 流式获取性能分析（SSE）

#### 宕机分析
- `GET /api/v1/crash/events` - 获取宕机事件列表（支持分页）
- `GET /api/v1/crash/events/:id` - 获取宕机事件详情
- `DELETE /api/v1/crash/events` - 批量删除宕机事件
- `GET /api/v1/crash/analysis/:host_id` - 获取主机宕机分析

#### 日志相关
- `GET /api/v1/logs` - 获取日志列表（支持分页）

#### 进程监控
- `GET /api/v1/processes` - 获取进程列表
- `GET /api/v1/processes/history` - 获取进程历史数据

#### 服务监控
- `GET /api/v1/services` - 获取服务状态

#### 脚本执行
- `GET /api/v1/scripts/executions` - 获取脚本执行记录

#### 告警相关
- `GET /api/v1/alerts/rules` - 获取告警规则列表
- `POST /api/v1/alerts/rules` - 创建告警规则
- `PUT /api/v1/alerts/rules/:id` - 更新告警规则
- `DELETE /api/v1/alerts/rules/:id` - 删除告警规则
- `GET /api/v1/alerts/history` - 获取告警历史

#### 知识库
- `GET /api/v1/knowledge/troubleshooting` - 获取故障处理知识库
- `POST /api/v1/knowledge/troubleshooting` - 创建故障处理知识
- `PUT /api/v1/knowledge/troubleshooting/:id` - 更新故障处理知识
- `DELETE /api/v1/knowledge/troubleshooting/:id` - 删除故障处理知识
- `GET /api/v1/knowledge/best-practices` - 获取最佳实践文档
- `GET /api/v1/knowledge/case-studies` - 获取故障案例库
- `POST /api/v1/knowledge/search/stream` - 流式搜索知识库（SSE）

#### 智能巡检
- `POST /api/v1/inspection/run` - 执行巡检
- `GET /api/v1/inspection/reports` - 获取巡检报告列表（支持分页）
- `GET /api/v1/inspection/reports/:id` - 获取巡检报告详情
- `GET /api/v1/inspection/reports/:id/stream` - 流式生成巡检日报（SSE）

#### LLM配置
- `GET /api/v1/llm/models` - 获取LLM模型配置列表
- `POST /api/v1/llm/models` - 创建LLM模型配置
- `GET /api/v1/llm/models/:id` - 获取LLM模型配置
- `PUT /api/v1/llm/models/:id` - 更新LLM模型配置
- `DELETE /api/v1/llm/models/:id` - 删除LLM模型配置
- `POST /api/v1/llm/models/:id/set-default` - 设置默认LLM模型配置
- `POST /api/v1/llm/models/test` - 测试LLM模型配置

#### 用户管理（需要管理员权限）
- `GET /api/v1/users` - 获取用户列表
- `GET /api/v1/users/:id` - 获取用户详情
- `POST /api/v1/users` - 创建用户
- `PUT /api/v1/users/:id` - 更新用户
- `DELETE /api/v1/users/:id` - 删除用户
- `POST /api/v1/users/:id/reset-password` - 重置用户密码

详细API文档请参考 [PREDICTION_FEATURE.md](./PREDICTION_FEATURE.md)

## 💻 开发指南

### 安装依赖

```bash
go mod download
```

### 生成Protobuf代码

```bash
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/collector.proto
```

### 运行开发服务器

```bash
go run .
```

### 代码结构说明

- **api/**: HTTP API层，处理HTTP请求
- **analyzer/**: 分析器，包括异常检测和预测分析
- **llm/**: LLM集成，支持多种LLM提供商
- **notifier/**: 通知器，支持多种通知渠道
- **alerter/**: 告警引擎，处理告警规则匹配
- **storage.go**: 存储层，封装数据库操作
- **storage_adapter.go**: 存储适配器，实现StorageInterface

### 添加新功能

1. 在 `api/storage_interface.go` 中定义接口
2. 在 `storage_adapter.go` 中实现接口
3. 在 `api/handlers.go` 中添加处理器
4. 在 `api/server.go` 中注册路由

## 🚢 部署

### Docker 构建与运行

项目提供 `Dockerfile`，可用于构建 Backend 镜像。运行前需确保 PostgreSQL、InfluxDB（及可选 Redis）已就绪，并通过配置文件或挂载卷提供 `config.yaml`。

**构建镜像：**

```bash
cd monitor-backend
docker build -t monitor-backend:latest .
```

**运行容器：**

将 `config.yaml` 放在宿主机某路径（如 `/opt/monitor-backend/config.yaml`），挂载进容器并暴露 gRPC/HTTP 端口：

```bash
docker run -d --name monitor-backend \
  -p 50051:50051 -p 8080:8080 \
  -v /opt/monitor-backend/config.yaml:/app/config.yaml \
  -e CONFIG_PATH=config.yaml \
  monitor-backend:latest
```

**依赖说明：**

- **PostgreSQL**：元数据、配置、用户等，需在 `config.yaml` 中配置连接信息。
- **InfluxDB**：时序指标存储，需在 `config.yaml` 中配置 URL、Token、Org、Bucket。
- **Redis**（可选）：会话等缓存，按需在配置中启用。

若使用 Docker Compose，可将上述数据库与 Backend 同网段部署，并确保 `config.yaml` 中的主机名为 Compose 服务名（如 `postgres`、`influxdb`、`redis`）。

### 编译

```bash
go build -o monitor-backend
```

### 运行

```bash
./monitor-backend
```

### 使用systemd管理（Linux）

创建 `/etc/systemd/system/monitor-backend.service`:

```ini
[Unit]
Description=Monitor Backend Service
After=network.target postgresql.service

[Service]
Type=simple
User=monitor
WorkingDirectory=/opt/monitor-backend
ExecStart=/opt/monitor-backend/monitor-backend
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl enable monitor-backend
sudo systemctl start monitor-backend
sudo systemctl status monitor-backend
```

## 📝 依赖说明

主要依赖：

```go
require (
    github.com/gin-gonic/gin v1.9.1
    google.golang.org/grpc v1.60.0
    google.golang.org/protobuf v1.31.0
    github.com/influxdata/influxdb-client-go/v2 v2.13.0
    gorm.io/gorm v1.25.5
    gorm.io/driver/postgres v1.5.4
    github.com/redis/go-redis/v9 v9.3.0
    gopkg.in/yaml.v3 v3.0.1
    github.com/golang-jwt/jwt/v5 v5.2.0
)
```

## 🔧 故障排查

### 数据库连接失败

- 检查数据库服务是否启动
- 检查配置文件中的连接信息
- 检查数据库用户权限

### gRPC连接失败

- 检查gRPC服务是否启动
- 检查防火墙设置
- 检查Agent配置中的server_addr

### LLM功能不可用

- 检查LLM配置是否正确
- 检查API密钥是否有效
- 检查网络连接

## 📄 许可证

MIT license

## 📞 联系方式

WX:Li1024_REBOOT
