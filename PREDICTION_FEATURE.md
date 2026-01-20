# 数据分析和预测功能说明

## 功能概述

本系统新增了数据分析和预测功能，包括：
1. **容量规划与预测**：基于历史数据预测资源使用趋势
2. **扩容时间预测**：预测何时需要扩容（CPU/内存/磁盘）
3. **成本优化建议**：基于LLM的智能分析和建议

## API接口

### 1. 获取容量预测

**接口**: `GET /api/v1/predictions/capacity`

**参数**:
- `host_id` (必需): 主机ID
- `type` (可选): 资源类型，可选值：`cpu`, `memory`, `disk`，默认 `cpu`
- `days` (可选): 预测未来多少天，默认 `30`
- `threshold` (可选): 阈值（百分比），默认 `80`

**示例请求**:
```bash
curl "http://localhost:8080/api/v1/predictions/capacity?host_id=server-001&type=cpu&days=30&threshold=80"
```

**响应示例**:
```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "prediction": {
      "current_value": 45.2,
      "predicted_value": 78.5,
      "predicted_time": "2024-02-15T10:00:00Z",
      "growth_rate": 1.1,
      "days_to_threshold": 32.5,
      "trend": "increasing",
      "confidence": 0.85,
      "recommendation": "资源使用率上升，预计32.5天后将达到阈值，建议在23天内开始扩容。"
    },
    "capacity": {
      "resource_type": "cpu",
      "current_usage": 45.2,
      "threshold": 80,
      "days_to_threshold": 32.5,
      "predicted_date": "2024-02-15T10:00:00Z",
      "urgency": "medium",
      "recommendation": "中等优先级：cpu使用率预计在32.5天内达到阈值，建议制定扩容计划。"
    },
    "host": {
      "host_id": "server-001",
      "hostname": "server-001"
    },
    "llm_analysis": {
      "summary": "CPU使用率呈上升趋势...",
      "analysis": "详细分析...",
      "recommendations": ["建议1", "建议2"],
      "cost_optimization": "成本优化建议...",
      "risks": ["风险1", "风险2"]
    }
  }
}
```

### 2. 获取成本优化建议

**接口**: `GET /api/v1/predictions/cost-optimization`

**参数**:
- `host_id` (必需): 主机ID

**示例请求**:
```bash
curl "http://localhost:8080/api/v1/predictions/cost-optimization?host_id=server-001"
```

**响应示例**:
```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "host_id": "server-001",
    "hostname": "server-001",
    "recommendation": "基于当前资源使用情况，建议...",
    "predictions": {
      "cpu": {...},
      "memory": {...},
      "disk": {...}
    }
  }
}
```

## 配置说明

### LLM配置

在 `config.yaml` 中配置LLM服务：

```yaml
llm:
  enabled: true  # 是否启用LLM功能
  provider: "openai"  # openai, claude, custom
  api_key: "your-api-key"  # LLM API密钥
  base_url: ""  # 自定义API地址（可选）
  model: "gpt-3.5-turbo"  # 模型名称
  temperature: 0.7  # 温度参数
  max_tokens: 1000  # 最大token数
  timeout: 30  # 超时时间（秒）
```

### 支持的LLM提供商

1. **OpenAI**: 使用 `provider: "openai"`，需要设置 `api_key`
2. **Claude (Anthropic)**: 使用 `provider: "claude"`，需要设置 `api_key`
3. **自定义API**: 使用 `provider: "custom"`，需要设置 `base_url` 和 `api_key`（可选）

## 预测算法

系统使用线性回归算法进行预测：
- 基于历史数据计算趋势线
- 计算R²（决定系数）作为置信度
- 预测未来资源使用率
- 计算达到阈值所需时间

## 使用建议

1. **数据要求**：至少需要7天的历史数据才能进行有效预测
2. **预测周期**：建议预测周期不超过90天，超过此范围预测准确性会下降
3. **阈值设置**：根据实际业务需求设置合理的阈值（通常为70-90%）
4. **LLM功能**：LLM功能为可选，如果未启用，预测结果仍会包含基础建议

## 注意事项

1. 预测结果仅供参考，实际扩容决策应结合业务需求
2. LLM分析需要网络连接和API密钥，如果API调用失败，系统会继续返回基础预测结果
3. 预测准确性取决于历史数据的质量和数量
