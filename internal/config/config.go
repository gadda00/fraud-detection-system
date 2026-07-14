// Package config centralises runtime configuration. All settings are read
// from environment variables (12-factor) with sensible defaults so the
// service runs out-of-the-box in dev.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config is the resolved configuration for one process.
type Config struct {
	Environment string
	Port        string
	Version     string

	// Storage backend: "memory" (default), "redis", "postgres".
	StorageBackend string
	RedisAddr      string
	PostgresDSN    string

	// Auth.
	APIKeySecret string
	JWTSecret    string
	JWTIssuer    string
	AuthRequired bool

	// Rules engine.
	RulesPath string

	// Webhooks.
	SlackWebhookURL string

	// Tracing.
	OTLPEndpoint string

	// HTTP server timeouts.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Rate limiting.
	RateLimitPerSecond int
}

// Load reads config from the environment.
func Load() Config {
	return Config{
		Environment:        env("ENVIRONMENT", "development"),
		Port:               env("PORT", "8080"),
		Version:            env("VERSION", "2.0.0"),
		StorageBackend:     env("STORAGE_BACKEND", "memory"),
		RedisAddr:          env("REDIS_ADDR", "localhost:6379"),
		PostgresDSN:        env("POSTGRES_DSN", ""),
		APIKeySecret:       env("API_KEY_SECRET", ""),
		JWTSecret:          env("JWT_SECRET", "change-me-in-production-32-bytes-min"),
		JWTIssuer:          env("JWT_ISSUER", "fraud-detection-system"),
		AuthRequired:       envBool("AUTH_REQUIRED", false),
		RulesPath:          env("RULES_PATH", ""),
		SlackWebhookURL:    env("SLACK_WEBHOOK_URL", ""),
		OTLPEndpoint:       env("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		ReadTimeout:        envDuration("READ_TIMEOUT", 10*time.Second),
		WriteTimeout:       envDuration("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:        envDuration("IDLE_TIMEOUT", 60*time.Second),
		RateLimitPerSecond: envInt("RATE_LIMIT_PER_SECOND", 1000),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
