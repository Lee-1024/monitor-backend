// ============================================
// 文件: config.go
// ============================================
package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GRPCAddr      string           `yaml:"grpc_addr"`
	HTTPAddr      string           `yaml:"http_addr"`
	JWTSecret     string           `yaml:"jwt_secret"`
	AuthRequired  bool             `yaml:"auth_required"` // 是否要求认证，默认true
	InfluxDB      InfluxDBConfig   `yaml:"influxdb"`
	PostgreSQL    PostgreSQLConfig `yaml:"postgresql"`
	Redis         RedisConfig      `yaml:"redis"`
	LLM           LLMConfig        `yaml:"llm"`
}

type InfluxDBConfig struct {
	URL    string `yaml:"url"`
	Token  string `yaml:"token"`
	Org    string `yaml:"org"`
	Bucket string `yaml:"bucket"`
}

type PostgreSQLConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type LLMConfig struct {
	Provider    string  `yaml:"provider"`     // openai, claude, custom
	APIKey      string  `yaml:"api_key"`
	BaseURL     string  `yaml:"base_url"`     // 自定义API地址
	Model       string  `yaml:"model"`        // 模型名称
	Temperature float64 `yaml:"temperature"`  // 温度参数
	MaxTokens   int     `yaml:"max_tokens"`   // 最大token数
	Timeout     int     `yaml:"timeout"`      // 超时时间（秒）
	Enabled     bool    `yaml:"enabled"`      // 是否启用
}

func LoadConfig() *Config {
	config := &Config{
		GRPCAddr:     ":50051",
		HTTPAddr:     ":8080",
		JWTSecret:    "your-secret-key-change-in-production",
		AuthRequired: true, // 默认需要认证
		InfluxDB: InfluxDBConfig{
			URL:    "http://localhost:8086",
			Token:  "your-token",
			Org:    "monitor",
			Bucket: "metrics",
		},
		PostgreSQL: PostgreSQLConfig{
			Host:     "localhost",
			Port:     5433,
			User:     "monitor",
			Password: "password",
			Database: "monitor",
		},
		Redis: RedisConfig{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		},
	}

	// 尝试从配置文件加载
	if data, err := os.ReadFile("config.yaml"); err == nil {
		if err := yaml.Unmarshal(data, config); err != nil {
			log.Printf("Failed to parse config: %v", err)
		}
	}

	return config
}
