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
	GRPCAddr   string           `yaml:"grpc_addr"`
	HTTPAddr   string           `yaml:"http_addr"`
	InfluxDB   InfluxDBConfig   `yaml:"influxdb"`
	PostgreSQL PostgreSQLConfig `yaml:"postgresql"`
	Redis      RedisConfig      `yaml:"redis"`
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

func LoadConfig() *Config {
	config := &Config{
		GRPCAddr: ":50051",
		HTTPAddr: ":8080",
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
