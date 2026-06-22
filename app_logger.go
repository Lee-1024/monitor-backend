package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	gormlogger "gorm.io/gorm/logger"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

var currentLogLevel = LevelInfo

func ConfigureLogging(config LoggingConfig) {
	currentLogLevel = parseLogLevel(config.EffectiveLevel())
	log.SetFlags(log.Ldate | log.Ltime)
}

func Debugf(format string, args ...interface{}) {
	if currentLogLevel <= LevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func Infof(format string, args ...interface{}) {
	if currentLogLevel <= LevelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

func Warnf(format string, args ...interface{}) {
	if currentLogLevel <= LevelWarn {
		log.Printf("[WARN] "+format, args...)
	}
}

func Errorf(format string, args ...interface{}) {
	if currentLogLevel <= LevelError {
		log.Printf("[ERROR] "+format, args...)
	}
}

func parseLogLevel(level string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func newGormLogger(config LoggingConfig) gormlogger.Interface {
	return gormlogger.New(
		log.New(gormLogWriter(), "", log.LstdFlags),
		gormlogger.Config{
			SlowThreshold:             500 * time.Millisecond,
			LogLevel:                  parseGormLogLevel(config.EffectiveGormLevel()),
			IgnoreRecordNotFoundError: config.EffectiveIgnoreRecordNotFound(),
			Colorful:                  false,
		},
	)
}

func gormLogWriter() io.Writer {
	return logWriterFunc(func(p []byte) (int, error) {
		message := strings.TrimSpace(string(p))
		if message == "" {
			return len(p), nil
		}
		_, err := fmt.Fprintf(os.Stderr, "[GORM] %s\n", message)
		return len(p), err
	})
}

func parseGormLogLevel(level string) gormlogger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "silent", "off":
		return gormlogger.Silent
	case "info", "debug":
		return gormlogger.Info
	case "warn", "warning":
		return gormlogger.Warn
	default:
		return gormlogger.Error
	}
}

type logWriterFunc func([]byte) (int, error)

func (f logWriterFunc) Write(p []byte) (int, error) {
	return f(p)
}
