// ============================================
// 文件: llm/streaming.go
// LLM流式输出支持
// ============================================
package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// StreamChunk 流式数据块
type StreamChunk struct {
	Content string `json:"content"`
	Done    bool   `json:"done"`
	Error   string `json:"error,omitempty"`
}

// StreamCapacityAnalysis 流式分析容量规划
func (c *LLMClient) StreamCapacityAnalysis(req AnalysisRequest, writer io.Writer) error {
	if !c.config.Enabled {
		return fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM Stream] 开始流式容量分析，Provider: %s, Model: %s", c.config.Provider, c.config.Model)
	prompt := c.buildCapacityAnalysisPrompt(req)
	log.Printf("[LLM Stream] 提示词长度: %d 字符", len(prompt))

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek, ProviderCustom:
		return c.streamOpenAICompatible(prompt, writer)
	case ProviderClaude:
		return c.streamClaude(prompt, writer)
	case ProviderZhipu:
		return c.streamZhipu(prompt, writer)
	default:
		// 对于不支持流式的提供商，回退到普通调用
		log.Printf("[LLM Stream] Provider %s 不支持流式输出，使用普通调用", c.config.Provider)
		response, err := c.AnalyzeCapacity(req)
		if err != nil {
			return err
		}
		// 将完整响应作为单个块发送
		chunk := StreamChunk{
			Content: formatAnalysisResponse(response),
			Done:    true,
		}
		return writeStreamChunk(writer, chunk)
	}
}

// StreamCostOptimization 流式生成成本优化建议
func (c *LLMClient) StreamCostOptimization(hostID, hostname string, predictions map[string]interface{}, writer io.Writer) error {
	if !c.config.Enabled {
		return fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM Stream] 开始流式成本优化分析，Provider: %s, Model: %s", c.config.Provider, c.config.Model)
	prompt := c.buildCostOptimizationPrompt(hostID, hostname, predictions)
	log.Printf("[LLM Stream] 提示词长度: %d 字符", len(prompt))

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek, ProviderCustom:
		return c.streamOpenAICompatible(prompt, writer)
	case ProviderClaude:
		return c.streamClaude(prompt, writer)
	case ProviderZhipu:
		return c.streamZhipu(prompt, writer)
	default:
		// 对于不支持流式的提供商，回退到普通调用
		log.Printf("[LLM Stream] Provider %s 不支持流式输出，使用普通调用", c.config.Provider)
		response, err := c.GenerateCostOptimization(hostID, hostname, predictions)
		if err != nil {
			return err
		}
		// 将完整响应作为单个块发送
		chunk := StreamChunk{
			Content: response,
			Done:    true,
		}
		return writeStreamChunk(writer, chunk)
	}
}

// buildCostOptimizationPrompt 构建成本优化提示词
func (c *LLMClient) buildCostOptimizationPrompt(hostID, hostname string, predictions map[string]interface{}) string {
	return fmt.Sprintf(`你是一个成本优化专家。基于以下主机的容量预测，提供详细的成本优化建议：

主机ID：%s
主机名：%s
预测数据：%s

请按照以下格式提供详细的成本优化分析：

## 当前资源使用情况分析
（详细分析当前各资源的使用情况，包括CPU、内存、磁盘等）

## 优化建议
（提供具体的优化建议，例如：
- 是否可以降配（说明原因和预期效果）
- 是否有闲置资源可以释放
- 是否可以升级（说明原因和预期效果）
- 资源配置调整建议
）

## 预计节省成本
（估算优化后可以节省的成本，包括：
- 降配可节省的成本
- 释放闲置资源可节省的成本
- 其他优化措施可节省的成本
）

## 实施建议
（提供具体的实施步骤和时间安排，包括：
- 实施优先级
- 实施步骤
- 注意事项
- 回滚方案
）

请用中文回答，要具体、详细、可操作。不要使用占位符或通用性描述。`, hostID, hostname, c.formatPredictions(predictions))
}

// StreamAnomalyAnalysis 流式分析异常检测结果
func (c *LLMClient) StreamAnomalyAnalysis(hostID, hostname string, anomalies []interface{}, statistics map[string]interface{}, writer io.Writer) error {
	if !c.config.Enabled {
		return fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM Stream] 开始流式异常分析，Provider: %s, Model: %s", c.config.Provider, c.config.Model)
	prompt := c.buildAnomalyAnalysisPrompt(hostID, hostname, anomalies, statistics)
	log.Printf("[LLM Stream] 提示词长度: %d 字符", len(prompt))

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek, ProviderCustom:
		return c.streamOpenAICompatible(prompt, writer)
	case ProviderClaude:
		return c.streamClaude(prompt, writer)
	case ProviderZhipu:
		return c.streamZhipu(prompt, writer)
	default:
		// 对于不支持流式的提供商，回退到普通调用
		log.Printf("[LLM Stream] Provider %s 不支持流式输出，使用普通调用", c.config.Provider)
		response, err := c.AnalyzeAnomalyDetection(hostID, hostname, anomalies, statistics)
		if err != nil {
			return err
		}
		// 将完整响应作为单个块发送
		chunk := StreamChunk{
			Content: response,
			Done:    true,
		}
		return writeStreamChunk(writer, chunk)
	}
}

// buildAnomalyAnalysisPrompt 构建异常分析提示词
func (c *LLMClient) buildAnomalyAnalysisPrompt(hostID, hostname string, anomalies []interface{}, statistics map[string]interface{}) string {
	// 构建异常检测原理说明
	detectionPrinciple := `异常检测使用以下三种算法：
1. Z-score方法（标准差方法）：检测偏离均值超过2.5个标准差的数据点
2. IQR方法（四分位距方法）：使用四分位数定义正常范围，超出[Q1-1.5×IQR, Q3+1.5×IQR]的值视为异常
3. 移动平均方法：使用滑动窗口计算局部统计值，检测相对于局部趋势的异常

异常严重程度分类：
- Critical（严重）：置信度>0.9且偏差>50%
- High（高）：置信度>0.7且偏差>30%
- Medium（中）：置信度>0.5且偏差>15%
- Low（低）：其他情况`

	// 格式化异常数据
	var anomaliesDesc strings.Builder
	if len(anomalies) == 0 {
		anomaliesDesc.WriteString("未检测到异常事件。")
	} else {
		anomaliesDesc.WriteString(fmt.Sprintf("检测到 %d 个异常事件：\n\n", len(anomalies)))
		for i, anomaly := range anomalies {
			if i >= 20 { // 最多显示20个异常
				anomaliesDesc.WriteString(fmt.Sprintf("\n... 还有 %d 个异常事件未列出\n", len(anomalies)-20))
				break
			}
			anom, _ := json.Marshal(anomaly)
			anomaliesDesc.WriteString(fmt.Sprintf("异常 %d: %s\n", i+1, string(anom)))
		}
	}

	// 格式化统计信息
	var statsDesc strings.Builder
	if statistics != nil {
		statsDesc.WriteString("异常统计信息：\n")
		if total, ok := statistics["total_anomalies"].(float64); ok {
			statsDesc.WriteString(fmt.Sprintf("- 异常总数：%.0f\n", total))
		}
		if unresolved, ok := statistics["unresolved_count"].(float64); ok {
			statsDesc.WriteString(fmt.Sprintf("- 未解决数：%.0f\n", unresolved))
		}
		if bySeverity, ok := statistics["by_severity"].(map[string]interface{}); ok {
			statsDesc.WriteString("- 按严重程度分布：\n")
			for severity, count := range bySeverity {
				if cnt, ok := count.(float64); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %.0f\n", severity, cnt))
				} else if cnt, ok := count.(int); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %d\n", severity, cnt))
				}
			}
		}
		if byType, ok := statistics["by_type"].(map[string]interface{}); ok {
			statsDesc.WriteString("- 按类型分布：\n")
			for typ, count := range byType {
				if cnt, ok := count.(float64); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %.0f\n", typ, cnt))
				} else if cnt, ok := count.(int); ok {
					statsDesc.WriteString(fmt.Sprintf("  - %s: %d\n", typ, cnt))
				}
			}
		}
	}

	return fmt.Sprintf(`你是一个专业的运维和异常分析专家。基于以下异常检测结果，生成一份专业的分析总结报告。

## 异常检测原理

%s

## 检测结果数据

主机信息：
- 主机ID：%s
- 主机名：%s

%s

%s

请按照以下格式生成专业的分析总结报告：

## 检测总结
（用1-2段话总结异常检测的结果和主要发现）

## 异常情况分析
（详细分析检测到的异常情况，包括：
- 异常的整体概况
- 异常的类型分布和严重程度分析
- 重点关注的异常事件
- 异常的时间分布模式
）

## 风险评估
（评估异常对系统的影响，包括：
- 严重异常的潜在影响
- 系统健康度评估
- 是否需要立即处理
）

## 处理建议
（提供具体的处理建议，包括：
- 优先级排序（哪些异常需要优先处理）
- 具体的处理步骤
- 预防措施建议
- 持续监控建议
）

## 系统健康度评价
（对系统的整体健康度进行评价，包括：
- 当前系统运行状态
- 是否存在系统性风险
- 需要关注的长期趋势
）

如果未检测到异常，请说明这是正常现象，并给出持续监控的建议。

请用中文回答，要专业、详细、可操作。不要使用占位符或通用性描述。`,
		detectionPrinciple,
		hostID,
		hostname,
		anomaliesDesc.String(),
		statsDesc.String())
}

// StreamPerformanceAnalysis 流式分析性能数据
func (c *LLMClient) StreamPerformanceAnalysis(hostID, hostname string, performanceData map[string]interface{}, writer io.Writer) error {
	if !c.config.Enabled {
		return fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM Stream] 开始流式性能分析，Provider: %s, Model: %s", c.config.Provider, c.config.Model)
	prompt := c.buildPerformanceAnalysisPrompt(hostID, hostname, performanceData)
	log.Printf("[LLM Stream] 提示词长度: %d 字符", len(prompt))

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek, ProviderCustom:
		return c.streamOpenAICompatible(prompt, writer)
	case ProviderClaude:
		return c.streamClaude(prompt, writer)
	case ProviderZhipu:
		return c.streamZhipu(prompt, writer)
	default:
		// 对于不支持流式的提供商，回退到普通调用
		log.Printf("[LLM Stream] Provider %s 不支持流式输出，使用普通调用", c.config.Provider)
		response, err := c.GeneratePerformanceAnalysis(hostID, hostname, performanceData)
		if err != nil {
			return err
		}
		// 将完整响应作为单个块发送
		chunk := StreamChunk{
			Content: response,
			Done:    true,
		}
		return writeStreamChunk(writer, chunk)
	}
}

// buildPerformanceAnalysisPrompt 构建性能分析提示词
func (c *LLMClient) buildPerformanceAnalysisPrompt(hostID, hostname string, performanceData map[string]interface{}) string {
	// 格式化性能数据
	var dataDesc strings.Builder
	dataDesc.WriteString(fmt.Sprintf("主机信息：\n- 主机ID：%s\n- 主机名：%s\n\n", hostID, hostname))

	// CPU数据
	if cpuData, ok := performanceData["cpu"].(map[string]interface{}); ok {
		dataDesc.WriteString("## CPU性能数据\n")
		if usage, ok := cpuData["usage_percent"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 当前使用率：%.2f%%\n", usage))
		}
		if avg, ok := cpuData["avg_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 平均使用率：%.2f%%\n", avg))
		}
		if max, ok := cpuData["max_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 最高使用率：%.2f%%\n", max))
		}
		if min, ok := cpuData["min_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 最低使用率：%.2f%%\n", min))
		}
		if cores, ok := cpuData["core_count"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- CPU核心数：%.0f\n", cores))
		}
		if load1, ok := cpuData["load_avg_1"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 1分钟负载：%.2f\n", load1))
		}
		if load5, ok := cpuData["load_avg_5"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 5分钟负载：%.2f\n", load5))
		}
		if load15, ok := cpuData["load_avg_15"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 15分钟负载：%.2f\n", load15))
		}
		dataDesc.WriteString("\n")
	}

	// 内存数据
	if memoryData, ok := performanceData["memory"].(map[string]interface{}); ok {
		dataDesc.WriteString("## 内存性能数据\n")
		if usedPercent, ok := memoryData["used_percent"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 当前使用率：%.2f%%\n", usedPercent))
		}
		if avg, ok := memoryData["avg_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 平均使用率：%.2f%%\n", avg))
		}
		if max, ok := memoryData["max_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 最高使用率：%.2f%%\n", max))
		}
		if total, ok := memoryData["total"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 总内存：%.2f GB\n", total/(1024*1024*1024)))
		}
		if used, ok := memoryData["used"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 已用内存：%.2f GB\n", used/(1024*1024*1024)))
		}
		if available, ok := memoryData["available"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 可用内存：%.2f GB\n", available/(1024*1024*1024)))
		}
		dataDesc.WriteString("\n")
	}

	// 磁盘数据
	if diskData, ok := performanceData["disk"].(map[string]interface{}); ok {
		dataDesc.WriteString("## 磁盘性能数据\n")
		if totalUsage, ok := diskData["total_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 平均使用率：%.2f%%\n", totalUsage))
		}
		if maxUsage, ok := diskData["max_usage"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 最高使用率：%.2f%%\n", maxUsage))
		}
		if partitions, ok := diskData["partitions"].([]interface{}); ok {
			dataDesc.WriteString(fmt.Sprintf("- 分区数量：%d\n", len(partitions)))
			for i, p := range partitions {
				if i >= 5 { // 最多显示5个分区
					break
				}
				if part, ok := p.(map[string]interface{}); ok {
					mountpoint := ""
					if mp, ok := part["mountpoint"].(string); ok {
						mountpoint = mp
					}
					usage := 0.0
					if u, ok := part["used_percent"].(float64); ok {
						usage = u
					}
					dataDesc.WriteString(fmt.Sprintf("  - %s: %.2f%%\n", mountpoint, usage))
				}
			}
		}
		dataDesc.WriteString("\n")
	}

	// 瓶颈信息
	if bottlenecks, ok := performanceData["bottlenecks"].([]interface{}); ok {
		dataDesc.WriteString("## 检测到的性能瓶颈\n")
		if len(bottlenecks) == 0 {
			dataDesc.WriteString("未检测到明显的性能瓶颈。\n\n")
		} else {
			for i, b := range bottlenecks {
				if i >= 10 { // 最多显示10个瓶颈
					break
				}
				if bottleneck, ok := b.(map[string]interface{}); ok {
					typ := ""
					if t, ok := bottleneck["type"].(string); ok {
						typ = t
					}
					severity := ""
					if s, ok := bottleneck["severity"].(string); ok {
						severity = s
					}
					desc := ""
					if d, ok := bottleneck["description"].(string); ok {
						desc = d
					}
					value := 0.0
					if v, ok := bottleneck["value"].(float64); ok {
						value = v
					}
					dataDesc.WriteString(fmt.Sprintf("- %s瓶颈（%s）：%s (当前值: %.2f%%)\n", typ, severity, desc, value))
				}
			}
			dataDesc.WriteString("\n")
		}
	}

	// 效率信息
	if efficiency, ok := performanceData["efficiency"].(map[string]interface{}); ok {
		dataDesc.WriteString("## 资源使用效率评估\n")
		if cpuEff, ok := efficiency["cpu"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- CPU使用效率：%.2f/100\n", cpuEff))
		}
		if memEff, ok := efficiency["memory"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 内存使用效率：%.2f/100\n", memEff))
		}
		if diskEff, ok := efficiency["disk"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 磁盘使用效率：%.2f/100\n", diskEff))
		}
		if overall, ok := efficiency["overall"].(float64); ok {
			dataDesc.WriteString(fmt.Sprintf("- 整体效率：%.2f/100\n", overall))
		}
		dataDesc.WriteString("\n")
	}

	// 时间范围
	if timeRange, ok := performanceData["time_range"].(string); ok {
		dataDesc.WriteString(fmt.Sprintf("分析时间范围：%s\n\n", timeRange))
	}

	return fmt.Sprintf(`你是一个专业的性能优化专家。基于以下主机的性能数据，生成一份详细的性能分析报告。

%s

请按照以下格式生成专业的性能分析报告：

## 性能概览
（用1-2段话总结主机的整体性能状况，包括：
- 当前系统运行状态
- 主要资源使用情况
- 整体性能评价
）

## 性能瓶颈分析
（详细分析检测到的性能瓶颈，包括：
- 瓶颈类型和严重程度
- 瓶颈产生的原因分析
- 瓶颈对系统的影响
- 瓶颈的优先级排序
- 如果没有瓶颈，说明系统运行良好
）

## 资源使用效率评估
（评估各资源的使用效率，包括：
- CPU使用效率分析（是否充分利用或过度使用）
- 内存使用效率分析（是否存在浪费或不足）
- 磁盘使用效率分析（空间利用是否合理）
- 整体资源利用效率评价
- 资源优化潜力分析
）

## 优化建议
（提供具体的性能优化建议，包括：
- 针对检测到的瓶颈的具体优化措施
- 资源使用效率提升建议
- 系统配置优化建议
- 监控和预警建议
- 实施优先级和时间安排
- 预期优化效果
）

## 长期性能趋势
（基于历史数据分析，包括：
- 性能变化趋势
- 潜在的性能风险
- 容量规划建议
- 持续优化方向
）

请用中文回答，要专业、详细、可操作。不要使用占位符或通用性描述。所有数据分析和建议都要基于提供的实际数据。`,
		dataDesc.String())
}

// GeneratePerformanceAnalysis 非流式生成性能分析（用于不支持流式的提供商）
func (c *LLMClient) GeneratePerformanceAnalysis(hostID, hostname string, performanceData map[string]interface{}) (string, error) {
	if !c.config.Enabled {
		return "", fmt.Errorf("LLM is not enabled")
	}

	// 这里可以调用非流式的LLM方法
	// 为了简化，我们返回一个提示信息
	// 注意：此方法主要用于不支持流式的提供商回退
	return "性能分析功能需要流式输出支持", nil
}

// StreamKnowledgeSearch 流式搜索知识库
func (c *LLMClient) StreamKnowledgeSearch(query, category string, writer io.Writer) error {
	if !c.config.Enabled {
		return fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM Stream] 开始流式知识库搜索，Provider: %s, Model: %s, Query: %s", c.config.Provider, c.config.Model, query)
	prompt := c.buildKnowledgeSearchPrompt(query, category)
	log.Printf("[LLM Stream] 提示词长度: %d 字符", len(prompt))

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek, ProviderCustom:
		return c.streamOpenAICompatible(prompt, writer)
	case ProviderClaude:
		return c.streamClaude(prompt, writer)
	case ProviderZhipu:
		return c.streamZhipu(prompt, writer)
	default:
		// 对于不支持流式的提供商，回退到普通调用
		log.Printf("[LLM Stream] Provider %s 不支持流式输出，使用普通调用", c.config.Provider)
		response, err := c.GenerateKnowledgeSearch(query, category)
		if err != nil {
			return err
		}
		// 将完整响应作为单个块发送
		chunk := StreamChunk{
			Content: response,
			Done:    true,
		}
		return writeStreamChunk(writer, chunk)
	}
}

// buildKnowledgeSearchPrompt 构建知识库搜索提示词
func (c *LLMClient) buildKnowledgeSearchPrompt(query, category string) string {
	categoryDesc := ""
	if category == "troubleshooting" {
		categoryDesc = "故障处理知识库"
	} else if category == "best_practice" {
		categoryDesc = "最佳实践文档"
	} else if category == "case_study" {
		categoryDesc = "故障案例库"
	} else {
		categoryDesc = "所有知识库（包括故障处理知识库、最佳实践文档、故障案例库）"
	}

	return fmt.Sprintf(`你是一个专业的运维知识库助手。用户正在搜索知识库，请根据用户的查询提供相关的知识库内容推荐和总结。

用户查询：%s
搜索范围：%s

请按照以下格式提供回答：

## 搜索结果总结
（用1-2段话总结搜索结果，说明找到了哪些相关内容，以及这些内容如何帮助用户解决问题）

## 相关知识点
（列出与查询相关的知识点，包括：
- 知识点1：简要说明
- 知识点2：简要说明
- ...
每个知识点要具体、实用）

## 推荐阅读
（推荐最相关的知识库条目，包括：
- 标题：简要说明为什么推荐，以及该条目能解决什么问题
- 标题：简要说明为什么推荐，以及该条目能解决什么问题
- ...
）

## 快速解答
（如果查询是一个具体问题，直接提供答案或解决步骤。要基于运维最佳实践，提供可操作的解决方案）

## 相关建议
（提供额外的建议，比如：
- 如果问题持续存在，应该检查哪些方面
- 如何预防类似问题
- 是否需要查看其他相关文档
）

请用中文回答，要专业、详细、可操作。如果搜索范围为空或没有相关内容，请说明并建议用户调整搜索关键词。`,
		query, categoryDesc)
}

// GenerateKnowledgeSearch 非流式生成知识库搜索（用于不支持流式的提供商）
func (c *LLMClient) GenerateKnowledgeSearch(query, category string) (string, error) {
	if !c.config.Enabled {
		return "", fmt.Errorf("LLM is not enabled")
	}

	// 这里可以调用非流式的LLM方法
	// 为了简化，我们返回一个提示信息
	// 注意：此方法主要用于不支持流式的提供商回退
	return "知识库搜索功能需要流式输出支持", nil
}

// StreamInspectionReport 流式生成巡检日报
func (c *LLMClient) StreamInspectionReport(inspectionData map[string]interface{}, writer io.Writer) error {
	if !c.config.Enabled {
		return fmt.Errorf("LLM is not enabled")
	}

	log.Printf("[LLM Stream] 开始流式生成巡检日报")
	prompt := c.buildInspectionReportPrompt(inspectionData)
	log.Printf("[LLM Stream] 提示词长度: %d 字符", len(prompt))

	switch c.config.Provider {
	case ProviderOpenAI, ProviderDeepSeek, ProviderCustom:
		return c.streamOpenAICompatible(prompt, writer)
	case ProviderClaude:
		return c.streamClaude(prompt, writer)
	case ProviderZhipu:
		return c.streamZhipu(prompt, writer)
	default:
		// 对于不支持流式的提供商，回退到普通调用
		log.Printf("[LLM Stream] Provider %s 不支持流式输出，使用普通调用", c.config.Provider)
		reportContent, summary, keyFindings, recommendations, err := c.GenerateInspectionReport(inspectionData)
		if err != nil {
			return err
		}
		// 将完整响应作为单个块发送
		content := fmt.Sprintf("%s\n\n## 总结\n%s\n\n## 关键发现\n%s\n\n## 建议\n%s", reportContent, summary, keyFindings, recommendations)
		chunk := StreamChunk{
			Content: content,
			Done:    true,
		}
		return writeStreamChunk(writer, chunk)
	}
}

// buildInspectionReportPrompt 构建巡检日报提示词
func (c *LLMClient) buildInspectionReportPrompt(inspectionData map[string]interface{}) string {
	report, _ := inspectionData["report"].(map[string]interface{})
	records, _ := inspectionData["records"].([]map[string]interface{})

	// 提取报告统计信息
	totalHosts := 0
	onlineHosts := 0
	offlineHosts := 0
	warningHosts := 0
	criticalHosts := 0

	if report != nil {
		if v, ok := report["total_hosts"].(float64); ok {
			totalHosts = int(v)
		}
		if v, ok := report["online_hosts"].(float64); ok {
			onlineHosts = int(v)
		}
		if v, ok := report["offline_hosts"].(float64); ok {
			offlineHosts = int(v)
		}
		if v, ok := report["warning_hosts"].(float64); ok {
			warningHosts = int(v)
		}
		if v, ok := report["critical_hosts"].(float64); ok {
			criticalHosts = int(v)
		}
	}

	// 格式化主机记录信息
	recordsText := ""
	for i, record := range records {
		hostname, _ := record["hostname"].(string)
		hostID, _ := record["host_id"].(string)
		status, _ := record["status"].(string)

		cpuUsage := 0.0
		memoryUsage := 0.0
		diskUsage := 0.0

		if v, ok := record["cpu_usage"].(float64); ok {
			cpuUsage = v
		}
		if v, ok := record["memory_usage"].(float64); ok {
			memoryUsage = v
		}
		if v, ok := record["disk_usage"].(float64); ok {
			diskUsage = v
		}

		issues := []string{}
		if v, ok := record["issues"].([]interface{}); ok {
			for _, item := range v {
				if str, ok := item.(string); ok {
					issues = append(issues, str)
				}
			}
		}

		warnings := []string{}
		if v, ok := record["warnings"].([]interface{}); ok {
			for _, item := range v {
				if str, ok := item.(string); ok {
					warnings = append(warnings, str)
				}
			}
		}

		recordsText += fmt.Sprintf("\n### 主机 %d: %s (%s)\n", i+1, hostname, hostID)
		recordsText += fmt.Sprintf("- 状态: %s\n", status)
		recordsText += fmt.Sprintf("- CPU使用率: %.1f%%\n", cpuUsage)
		recordsText += fmt.Sprintf("- 内存使用率: %.1f%%\n", memoryUsage)
		recordsText += fmt.Sprintf("- 磁盘使用率: %.1f%%\n", diskUsage)

		if len(issues) > 0 {
			recordsText += "- 问题:\n"
			for _, issue := range issues {
				recordsText += fmt.Sprintf("  - %s\n", issue)
			}
		}

		if len(warnings) > 0 {
			recordsText += "- 警告:\n"
			for _, warning := range warnings {
				recordsText += fmt.Sprintf("  - %s\n", warning)
			}
		}
	}

	return fmt.Sprintf(`你是一个专业的运维工程师，需要根据巡检数据生成一份详细的巡检日报。

## 巡检统计信息
- 总主机数: %d
- 在线主机: %d
- 离线主机: %d
- 告警主机: %d
- 严重告警主机: %d

## 主机巡检详情
%s

请按照以下格式生成详细的巡检日报（使用Markdown格式）：

# 系统巡检日报

## 一、巡检概览
（简要概述本次巡检的整体情况，包括巡检时间、主机数量、整体健康状况等）

## 二、主机状态统计
（详细列出在线、离线、告警、严重告警的主机数量和占比）

## 三、资源使用分析
（分析CPU、内存、磁盘的整体使用情况，识别资源紧张的主机）

## 四、问题与告警
（详细列出发现的问题、警告和严重告警，按严重程度分类）

## 五、服务状态
（统计服务运行状态，列出异常服务）

## 六、关键发现
（总结本次巡检的关键发现，包括但不限于：
- 资源使用趋势
- 潜在风险点
- 性能瓶颈
- 配置问题
等）

## 七、优化建议
（基于巡检结果，提供具体的优化建议和行动计划，包括：
- 资源优化建议
- 配置优化建议
- 安全加固建议
- 监控改进建议
等）

## 八、后续行动
（列出需要立即处理的问题和后续跟进事项）

请用中文撰写，内容要专业、详细、可操作。`,
		totalHosts, onlineHosts, offlineHosts, warningHosts, criticalHosts, recordsText)
}

// GenerateInspectionReport 非流式生成巡检日报（用于不支持流式的提供商）
func (c *LLMClient) GenerateInspectionReport(inspectionData map[string]interface{}) (reportContent, summary, keyFindings, recommendations string, err error) {
	if !c.config.Enabled {
		return "", "", "", "", fmt.Errorf("LLM is not enabled")
	}

	// 这里可以调用非流式的LLM方法
	// 为了简化，我们返回一个提示信息
	// 注意：此方法主要用于不支持流式的提供商回退
	_ = c.buildInspectionReportPrompt(inspectionData)
	return "巡检日报生成功能需要流式输出支持", "", "", "", nil
}

// streamOpenAICompatible 流式调用OpenAI兼容的API（包括OpenAI、DeepSeek、Custom）
func (c *LLMClient) streamOpenAICompatible(prompt string, writer io.Writer) error {
	url := "https://api.openai.com/v1/chat/completions"
	if c.config.Provider == ProviderDeepSeek {
		url = "https://api.deepseek.com/v1/chat/completions"
	}
	if c.config.Provider == ProviderCustom {
		// 自定义模型必须提供BaseURL
		if c.config.BaseURL == "" {
			return fmt.Errorf("custom API base_url is required for streaming")
		}
		url = strings.TrimSpace(c.config.BaseURL)
		log.Printf("[LLM Stream] 使用自定义API地址: %s", url)
	} else if c.config.BaseURL != "" {
		// OpenAI或DeepSeek也可以使用自定义BaseURL
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		if c.config.Provider == ProviderCustom {
			// 自定义模型如果没有指定model，尝试从URL推断或使用默认值
			model = "gpt-3.5-turbo" // 默认值
			log.Printf("[LLM Stream] 自定义模型未指定model，使用默认值: %s", model)
		} else {
			model = "gpt-3.5-turbo"
		}
	}

	// 对于巡检日报，需要更长的输出，确保max_tokens足够大
	maxTokens := c.config.MaxTokens
	if maxTokens == 0 || maxTokens < 4000 {
		maxTokens = 8000 // 巡检日报需要更长的输出，默认8000 tokens
		log.Printf("[LLM Stream] max_tokens配置为0或太小，使用默认值: %d", maxTokens)
	}

	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": c.config.Temperature,
		"max_tokens":  maxTokens,
		"stream":      true, // 启用流式输出
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	log.Printf("[LLM Stream] 发送流式请求到: %s, model: %s, stream: true, max_tokens: %d", url, model, maxTokens)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}

	// 流式请求不应该设置整体超时，因为数据是逐步返回的
	// 对于流式请求，我们需要一个很长的超时或者不设置超时
	// 但为了避免无限等待，设置一个合理的超时（如5分钟）
	timeout := time.Duration(c.config.Timeout) * time.Second
	if timeout == 0 || timeout < 60*time.Second {
		timeout = 300 * time.Second // 流式请求默认5分钟
	}
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[LLM Stream] 请求失败: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[LLM Stream] API错误响应: %s, body: %s", resp.Status, string(body))
		return fmt.Errorf("API error: %s, body: %s", resp.Status, string(body))
	}

	log.Printf("[LLM Stream] 开始读取流式响应，超时设置: %v", timeout)

	// 读取流式响应
	scanner := bufio.NewScanner(resp.Body)
	var accumulatedContent strings.Builder
	chunkCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// 处理多种可能的格式：
		// 1. "data: {...}" (标准格式，有空格)
		// 2. "data:{...}" (无空格格式，某些自定义API)
		// 3. 直接是JSON对象（某些API可能直接返回JSON）
		var dataStr string
		if strings.HasPrefix(line, "data: ") {
			// 标准格式：data: {...}
			dataStr = strings.TrimPrefix(line, "data: ")
		} else if strings.HasPrefix(line, "data:") {
			// 无空格格式：data:{...}
			dataStr = strings.TrimPrefix(line, "data:")
			// 去除可能的空格
			dataStr = strings.TrimSpace(dataStr)
		} else if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "event:") {
			// SSE元数据行，跳过
			continue
		} else if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
			// 直接是JSON，某些API可能直接返回JSON对象
			dataStr = line
			log.Printf("[LLM Stream] 检测到直接JSON格式: %s", line[:min(100, len(line))])
		} else {
			// 其他格式，记录但不处理
			log.Printf("[LLM Stream] 跳过未知格式行: %s", line[:min(200, len(line))])
			continue
		}

		if dataStr == "[DONE]" || dataStr == `"[DONE]"` {
			// 发送完成信号
			finalContent := accumulatedContent.String()
			log.Printf("[LLM Stream] 收到[DONE]信号，共处理 %d 个数据块，最终内容长度: %d", chunkCount, len(finalContent))

			// 检查最终内容是否完整
			hasSix := strings.Contains(finalContent, "六")
			hasSeven := strings.Contains(finalContent, "七")
			hasEight := strings.Contains(finalContent, "八")
			log.Printf("[LLM Stream] [DONE]时内容检查: 包含'六'=%v, 包含'七'=%v, 包含'八'=%v", hasSix, hasSeven, hasEight)

			chunk := StreamChunk{
				Content: finalContent,
				Done:    true,
			}
			if err := writeStreamChunk(writer, chunk); err != nil {
				// 如果是连接关闭错误，优雅退出
				if isConnectionClosed(err) {
					log.Printf("[LLM Stream] 客户端连接已关闭，停止流式输出")
					return nil
				}
				return err
			}
			log.Printf("[LLM Stream] 成功发送[DONE]信号和完整内容，长度: %d", len(finalContent))
			break
		}

		var streamData struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				Message struct {
					Content string `json:"content"` // 有些API可能在message中返回内容
				} `json:"message"`
			} `json:"choices"`
			// 兼容其他可能的格式
			Content string `json:"content"`
			Text    string `json:"text"`
		}

		if err := json.Unmarshal([]byte(dataStr), &streamData); err != nil {
			log.Printf("[LLM Stream] 解析流式数据失败: %v, data: %s", err, dataStr)
			continue
		}

		var content string
		// 优先从delta.content获取
		if len(streamData.Choices) > 0 {
			if streamData.Choices[0].Delta.Content != "" {
				content = streamData.Choices[0].Delta.Content
			} else if streamData.Choices[0].Message.Content != "" {
				// 有些API可能在message中返回完整内容
				content = streamData.Choices[0].Message.Content
			}
		}
		// 如果choices中没有内容，尝试从顶层字段获取
		if content == "" {
			if streamData.Content != "" {
				content = streamData.Content
			} else if streamData.Text != "" {
				content = streamData.Text
			}
		}

		if content != "" {
			accumulatedContent.WriteString(content)
			chunkCount++

			// 发送增量内容
			chunk := StreamChunk{
				Content: content,
				Done:    false,
			}
			if err := writeStreamChunk(writer, chunk); err != nil {
				// 如果是连接关闭错误，优雅退出
				if isConnectionClosed(err) {
					log.Printf("[LLM Stream] 客户端连接已关闭，停止流式输出")
					return nil
				}
				log.Printf("[LLM Stream] 写入流式数据块失败: %v", err)
				return err
			}
			// 每10个chunk或重要chunk记录一次详细日志
			if chunkCount%10 == 0 || len(content) > 50 {
				log.Printf("[LLM Stream] 已发送第 %d 个数据块，内容长度: %d，累积总长度: %d", chunkCount, len(content), accumulatedContent.Len())
				// 检查是否包含关键内容
				hasSix := strings.Contains(accumulatedContent.String(), "六")
				hasSeven := strings.Contains(accumulatedContent.String(), "七")
				hasEight := strings.Contains(accumulatedContent.String(), "八")
				if hasSix || hasSeven || hasEight {
					log.Printf("[LLM Stream] Chunk #%d 累积内容检查: 包含'六'=%v, 包含'七'=%v, 包含'八'=%v", chunkCount, hasSix, hasSeven, hasEight)
				}
			}
		} else {
			// 即使没有content，也记录一下，便于调试
			if chunkCount == 0 {
				log.Printf("[LLM Stream] 警告: 数据块中没有找到content字段，原始数据: %s", dataStr[:min(200, len(dataStr))])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[LLM Stream] 读取流式响应错误: %v", err)
		// 即使有错误，也尝试发送已累积的内容
		if accumulatedContent.Len() > 0 {
			chunk := StreamChunk{
				Content: accumulatedContent.String(),
				Done:    true,
			}
			writeStreamChunk(writer, chunk)
		}
		return err
	}

	finalContent := accumulatedContent.String()
	log.Printf("[LLM Stream] 流式输出完成，共处理 %d 个数据块，总长度: %d 字符", chunkCount, len(finalContent))

	// 检查最终内容是否完整
	hasSix := strings.Contains(finalContent, "六")
	hasSeven := strings.Contains(finalContent, "七")
	hasEight := strings.Contains(finalContent, "八")
	log.Printf("[LLM Stream] 最终内容检查: 包含'六'=%v, 包含'七'=%v, 包含'八'=%v", hasSix, hasSeven, hasEight)

	// 记录最后200个字符，用于调试
	if len(finalContent) > 200 {
		log.Printf("[LLM Stream] 最终内容最后200字符: %s", finalContent[len(finalContent)-200:])
	} else {
		log.Printf("[LLM Stream] 最终内容: %s", finalContent)
	}

	// 如果没有收到[DONE]信号但扫描结束了，发送完成信号
	if !strings.Contains(finalContent, "[DONE]") && len(finalContent) > 0 {
		chunk := StreamChunk{
			Content: finalContent,
			Done:    true,
		}
		if err := writeStreamChunk(writer, chunk); err != nil {
			log.Printf("[LLM Stream] 发送最终数据块失败: %v", err)
		} else {
			log.Printf("[LLM Stream] 成功发送最终数据块（done=true），长度: %d", len(finalContent))
		}
	}

	return nil
}

// streamClaude 流式调用Claude API
func (c *LLMClient) streamClaude(prompt string, writer io.Writer) error {
	// Claude API流式实现（类似OpenAI）
	// 这里需要根据Claude的实际API格式实现
	// 暂时回退到普通调用
	log.Printf("[LLM Stream] Claude流式输出暂未实现，使用普通调用")
	response, err := c.callClaude(prompt)
	if err != nil {
		return err
	}
	chunk := StreamChunk{
		Content: formatAnalysisResponse(response),
		Done:    true,
	}
	return writeStreamChunk(writer, chunk)
}

// streamZhipu 流式调用智普API
func (c *LLMClient) streamZhipu(prompt string, writer io.Writer) error {
	url := "https://open.bigmodel.cn/api/paas/v4/chat/completions"
	if c.config.BaseURL != "" {
		url = strings.TrimSpace(c.config.BaseURL)
	}

	model := c.config.Model
	if model == "" {
		model = "glm-4"
	}

	// 对于巡检日报，需要更长的输出，确保max_tokens足够大
	maxTokens := c.config.MaxTokens
	if maxTokens == 0 || maxTokens < 4000 {
		maxTokens = 8000 // 巡检日报需要更长的输出，默认8000 tokens
		log.Printf("[LLM Stream] Zhipu max_tokens配置为0或太小，使用默认值: %d", maxTokens)
	}

	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": c.config.Temperature,
		"max_tokens":  maxTokens,
		"stream":      true, // 启用流式输出
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	log.Printf("[LLM Stream] Zhipu 发送流式请求到: %s, model: %s, stream: true, max_tokens: %d", url, model, maxTokens)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	// 流式请求不应该设置整体超时，因为数据是逐步返回的
	// 对于流式请求，我们需要一个很长的超时或者不设置超时
	// 但为了避免无限等待，设置一个合理的超时（如5分钟）
	timeout := time.Duration(c.config.Timeout) * time.Second
	if timeout == 0 || timeout < 60*time.Second {
		timeout = 300 * time.Second // 流式请求默认5分钟
	}
	client := &http.Client{
		Timeout: timeout,
	}

	log.Printf("[LLM Stream] Zhipu API 发送流式请求到: %s, model: %s, stream: true", url, model)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[LLM Stream] Zhipu API 请求失败: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[LLM Stream] Zhipu API 错误响应: %s", string(body))
		return fmt.Errorf("Zhipu API error: %s, body: %s", resp.Status, string(body))
	}

	log.Printf("[LLM Stream] Zhipu API 开始读取流式响应")

	// 读取流式响应 - 使用更大的缓冲区来处理长行
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024) // 64KB 缓冲区
	scanner.Buffer(buf, 1024*1024)  // 最大1MB

	var accumulatedContent strings.Builder
	chunkCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line) // 去除首尾空白
		if line == "" {
			continue
		}

		// 处理多种可能的格式：
		// 1. "data: {...}" (标准格式，有空格)
		// 2. "data:{...}" (无空格格式，某些API)
		// 3. 直接是JSON对象（某些API可能直接返回JSON）
		var dataStr string
		if strings.HasPrefix(line, "data: ") {
			// 标准格式：data: {...}
			dataStr = strings.TrimPrefix(line, "data: ")
		} else if strings.HasPrefix(line, "data:") {
			// 无空格格式：data:{...}
			dataStr = strings.TrimPrefix(line, "data:")
			// 去除可能的空格
			dataStr = strings.TrimSpace(dataStr)
		} else if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "event:") {
			// SSE元数据行，跳过
			continue
		} else if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
			// 直接是JSON，某些API可能直接返回JSON对象
			dataStr = line
			log.Printf("[LLM Stream] Zhipu 检测到直接JSON格式: %s", line[:min(100, len(line))])
		} else {
			// 其他格式，记录但不处理
			log.Printf("[LLM Stream] Zhipu 跳过未知格式行: %s", line[:min(200, len(line))])
			continue
		}

		if dataStr == "[DONE]" || dataStr == `"[DONE]"` {
			// 发送完成信号
			log.Printf("[LLM Stream] Zhipu 收到[DONE]信号，共处理 %d 个数据块", chunkCount)
			chunk := StreamChunk{
				Content: accumulatedContent.String(),
				Done:    true,
			}
			if err := writeStreamChunk(writer, chunk); err != nil {
				// 如果是连接关闭错误，优雅退出
				if isConnectionClosed(err) {
					log.Printf("[LLM Stream] 客户端连接已关闭，停止流式输出")
					return nil
				}
				return err
			}
			break
		}

		var streamData struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"` // Zhipu特有字段
				} `json:"delta"`
				Message struct {
					Content          string `json:"content"` // 有些API可能在message中返回内容
					ReasoningContent string `json:"reasoning_content"`
				} `json:"message"`
			} `json:"choices"`
			// 兼容其他可能的格式
			Content string `json:"content"`
			Text    string `json:"text"`
		}

		if err := json.Unmarshal([]byte(dataStr), &streamData); err != nil {
			log.Printf("[LLM Stream] Zhipu 解析流式数据失败: %v, data: %s", err, dataStr[:min(200, len(dataStr))])
			// 尝试直接解析为简单格式（某些API可能使用简单格式）
			var simpleData struct {
				Content string `json:"content"`
				Text    string `json:"text"`
			}
			if err2 := json.Unmarshal([]byte(dataStr), &simpleData); err2 == nil {
				if simpleData.Content != "" || simpleData.Text != "" {
					content := simpleData.Content
					if content == "" {
						content = simpleData.Text
					}
					if content != "" {
						accumulatedContent.WriteString(content)
						chunkCount++
						chunk := StreamChunk{
							Content: content,
							Done:    false,
						}
						if err := writeStreamChunk(writer, chunk); err != nil {
							if isConnectionClosed(err) {
								log.Printf("[LLM Stream] 客户端连接已关闭，停止流式输出")
								return nil
							}
							log.Printf("[LLM Stream] Zhipu 写入流式数据块失败: %v", err)
							return err
						}
						log.Printf("[LLM Stream] Zhipu 已发送第 %d 个数据块（简单格式），内容长度: %d", chunkCount, len(content))
					}
				}
			}
			continue
		}

		var content string
		// 优先从delta.content获取（流式输出的增量内容）
		if len(streamData.Choices) > 0 {
			delta := streamData.Choices[0].Delta
			// Zhipu可能使用reasoning_content字段（推理模式，如GLM-4.5-flash）
			content = delta.Content
			if content == "" && delta.ReasoningContent != "" {
				content = delta.ReasoningContent
				log.Printf("[LLM Stream] Zhipu 使用delta.reasoning_content")
			}
			// 如果delta中没有内容，尝试从message中获取（某些API可能在message中返回完整内容）
			if content == "" {
				message := streamData.Choices[0].Message
				content = message.Content
				if content == "" && message.ReasoningContent != "" {
					content = message.ReasoningContent
					log.Printf("[LLM Stream] Zhipu 使用message.reasoning_content")
				}
			}
		}
		// 如果choices中没有内容，尝试从顶层字段获取（某些API的简单格式）
		if content == "" {
			if streamData.Content != "" {
				content = streamData.Content
				log.Printf("[LLM Stream] Zhipu 使用顶层content字段")
			} else if streamData.Text != "" {
				content = streamData.Text
				log.Printf("[LLM Stream] Zhipu 使用顶层text字段")
			}
		}

		if content != "" {
			accumulatedContent.WriteString(content)
			chunkCount++

			// 发送增量内容
			chunk := StreamChunk{
				Content: content,
				Done:    false,
			}
			if err := writeStreamChunk(writer, chunk); err != nil {
				// 如果是连接关闭错误，优雅退出
				if isConnectionClosed(err) {
					log.Printf("[LLM Stream] 客户端连接已关闭，停止流式输出")
					return nil
				}
				log.Printf("[LLM Stream] Zhipu 写入流式数据块失败: %v", err)
				return err
			}
			log.Printf("[LLM Stream] Zhipu 已发送第 %d 个数据块，内容长度: %d", chunkCount, len(content))
		} else {
			// 即使没有content，也记录一下，便于调试
			if chunkCount == 0 {
				log.Printf("[LLM Stream] Zhipu 警告: 数据块中没有找到content字段，原始数据: %s", dataStr[:min(200, len(dataStr))])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[LLM Stream] Zhipu 读取流式响应错误: %v", err)
		// 即使有错误，也尝试发送已累积的内容
		if accumulatedContent.Len() > 0 {
			chunk := StreamChunk{
				Content: accumulatedContent.String(),
				Done:    true,
			}
			writeStreamChunk(writer, chunk)
		}
		return err
	}

	log.Printf("[LLM Stream] Zhipu 流式输出完成，共处理 %d 个数据块，总长度: %d 字符", chunkCount, accumulatedContent.Len())

	// 如果没有收到[DONE]信号但扫描结束了，发送完成信号
	if accumulatedContent.Len() > 0 {
		chunk := StreamChunk{
			Content: accumulatedContent.String(),
			Done:    true,
		}
		if err := writeStreamChunk(writer, chunk); err != nil {
			log.Printf("[LLM Stream] Zhipu 发送最终数据块失败: %v", err)
		}
	}

	return nil
}

// writeStreamChunk 写入流式数据块（SSE格式）
func writeStreamChunk(writer io.Writer, chunk StreamChunk) error {
	data, err := json.Marshal(chunk)
	if err != nil {
		return err
	}

	// SSE格式: "data: {...}\n\n"
	_, err = fmt.Fprintf(writer, "data: %s\n\n", string(data))
	if err != nil {
		// 检查是否是连接关闭错误（broken pipe, connection reset等）
		if isConnectionClosed(err) {
			log.Printf("[LLM Stream] 客户端连接已关闭，停止写入")
			return nil // 不返回错误，这是正常的客户端断开
		}
		return err
	}

	// 刷新输出（如果支持）
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return nil
}

// isConnectionClosed 检查错误是否是连接关闭相关的错误
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}

	// 检查常见的连接关闭错误
	errStr := err.Error()
	if strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "write: broken pipe") {
		return true
	}

	// 检查是否是网络错误
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err != nil {
			if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
				if sysErr.Err == syscall.EPIPE || sysErr.Err == syscall.ECONNRESET {
					return true
				}
			}
		}
	}

	return false
}

// formatAnalysisResponse 格式化分析响应为文本
func formatAnalysisResponse(resp *AnalysisResponse) string {
	var result strings.Builder

	if resp.Summary != "" {
		result.WriteString("## 摘要\n\n")
		result.WriteString(resp.Summary)
		result.WriteString("\n\n")
	}

	if resp.Analysis != "" {
		result.WriteString("## 详细分析\n\n")
		result.WriteString(resp.Analysis)
		result.WriteString("\n\n")
	}

	if len(resp.Recommendations) > 0 {
		result.WriteString("## 建议\n\n")
		for i, rec := range resp.Recommendations {
			result.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		result.WriteString("\n")
	}

	if resp.CostOptimization != "" {
		result.WriteString("## 成本优化建议\n\n")
		result.WriteString(resp.CostOptimization)
		result.WriteString("\n\n")
	}

	if len(resp.Risks) > 0 {
		result.WriteString("## 风险提示\n\n")
		for i, risk := range resp.Risks {
			result.WriteString(fmt.Sprintf("%d. %s\n", i+1, risk))
		}
	}

	return result.String()
}
