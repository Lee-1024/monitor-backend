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
	GRPCAddr     string           `yaml:"grpc_addr"`
	HTTPAddr     string           `yaml:"http_addr"`
	JWTSecret    string           `yaml:"jwt_secret"`
	AuthRequired bool             `yaml:"auth_required"` // 是否要求认证，默认true
	InfluxDB     InfluxDBConfig   `yaml:"influxdb"`
	PostgreSQL   PostgreSQLConfig `yaml:"postgresql"`
	Redis        RedisConfig      `yaml:"redis"`
	Retention    RetentionConfig  `yaml:"retention"`
	Logging      LoggingConfig    `yaml:"logging"`
	LLM          LLMConfig        `yaml:"llm"`
}

type LoggingConfig struct {
	Level                string `yaml:"level"`
	GormLevel            string `yaml:"gorm_level"`
	IgnoreRecordNotFound *bool  `yaml:"ignore_record_not_found"`
}

func (c LoggingConfig) EffectiveLevel() string {
	if c.Level != "" {
		return c.Level
	}
	return "info"
}

func (c LoggingConfig) EffectiveGormLevel() string {
	if c.GormLevel != "" {
		return c.GormLevel
	}
	return "error"
}

func (c LoggingConfig) EffectiveIgnoreRecordNotFound() bool {
	if c.IgnoreRecordNotFound != nil {
		return *c.IgnoreRecordNotFound
	}
	return true
}

type InfluxDBConfig struct {
	URL                 string `yaml:"url"`
	Token               string `yaml:"token"`
	Org                 string `yaml:"org"`
	Bucket              string `yaml:"bucket"`
	WriteTimeoutSeconds int    `yaml:"write_timeout_seconds"`
}

func (c InfluxDBConfig) EffectiveWriteTimeoutSeconds() int {
	if c.WriteTimeoutSeconds > 0 {
		return c.WriteTimeoutSeconds
	}
	return 10
}

type PostgreSQLConfig struct {
	Host                   string `yaml:"host"`
	Port                   int    `yaml:"port"`
	User                   string `yaml:"user"`
	Password               string `yaml:"password"`
	Database               string `yaml:"database"`
	MaxOpenConns           int    `yaml:"max_open_conns"`
	MaxIdleConns           int    `yaml:"max_idle_conns"`
	ConnMaxLifetimeMinutes int    `yaml:"conn_max_lifetime_minutes"`
}

func (c PostgreSQLConfig) EffectiveMaxOpenConns() int {
	if c.MaxOpenConns > 0 {
		return c.MaxOpenConns
	}
	return 25
}

func (c PostgreSQLConfig) EffectiveMaxIdleConns() int {
	if c.MaxIdleConns > 0 {
		return c.MaxIdleConns
	}
	return 5
}

func (c PostgreSQLConfig) EffectiveConnMaxLifetimeMinutes() int {
	if c.ConnMaxLifetimeMinutes > 0 {
		return c.ConnMaxLifetimeMinutes
	}
	return 30
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type RetentionConfig struct {
	ProcessSnapshotDays int `yaml:"process_snapshot_days"`
	DockerSnapshotDays  int `yaml:"docker_snapshot_days"`
}

func (c RetentionConfig) EffectiveProcessSnapshotDays() int {
	if c.ProcessSnapshotDays > 0 {
		return c.ProcessSnapshotDays
	}
	return 30
}

func (c RetentionConfig) EffectiveDockerSnapshotDays() int {
	if c.DockerSnapshotDays > 0 {
		return c.DockerSnapshotDays
	}
	return 30
}

type LLMConfig struct {
	Provider    string  `yaml:"provider"` // openai, claude, custom
	APIKey      string  `yaml:"api_key"`
	BaseURL     string  `yaml:"base_url"`    // 自定义API地址
	Model       string  `yaml:"model"`       // 模型名称
	Temperature float64 `yaml:"temperature"` // 温度参数
	MaxTokens   int     `yaml:"max_tokens"`  // 最大token数
	Timeout     int     `yaml:"timeout"`     // 超时时间（秒）
	Enabled     bool    `yaml:"enabled"`     // 是否启用
}

func LoadConfig() *Config {
	config := &Config{
		GRPCAddr:     ":50051",
		HTTPAddr:     ":8083",
		JWTSecret:    "your-secret-key-change-in-production",
		AuthRequired: true, // 默认需要认证
		InfluxDB: InfluxDBConfig{
			URL:                 "http://localhost:8086",
			Token:               "your-token",
			Org:                 "monitor",
			Bucket:              "metrics",
			WriteTimeoutSeconds: 10,
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
		Retention: RetentionConfig{
			ProcessSnapshotDays: 30,
			DockerSnapshotDays:  30,
		},
	}

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}
	// 尝试从配置文件加载
	if data, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(data, config); err != nil {
			log.Printf("Failed to parse config: %v", err)
		}
	}

	return config
}
