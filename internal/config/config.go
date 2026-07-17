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

	// DemoMode controls whether the boot-time synthetic seed/evaluate/
	// calibrate path runs. In development it defaults to true (so the API
	// is usable immediately); in production it defaults to false (so we
	// don't pollute the real store with fake data). Override with
	// DEMO_MODE=true|false. See DATA-01 in the deep review.
	DemoMode bool

	// Storage backend: "memory" (default), "redis", "postgres".
	StorageBackend string
	RedisAddr      string
	PostgresDSN    string

	// Kafka (optional).
	KafkaBrokers       []string
	KafkaInputTopic    string
	KafkaOutputTopic   string
	KafkaConsumerGroup string

	// Auth.
	APIKeySecret string
	JWTSecret    string
	JWTIssuer    string
	AuthRequired bool

	// Rules engine.
	RulesPath string

	// Webhooks / alerts.
	SlackWebhookURL string

	// Stripe (optional — for card blocking on confirmed fraud).
	StripeAPIKey string

	// Email (SMTP, optional).
	SMTPHost       string
	SMTPPort       string
	SMTPUsername   string
	SMTPPassword   string
	AlertEmailFrom string
	AlertEmailTo   string

	// SMS (Twilio, optional).
	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFromNumber string
	AlertSMSTo       string

	// Tracing.
	OTLPEndpoint string

	// Retraining pipeline.
	RetrainInterval time.Duration

	// HTTP server timeouts.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Rate limiting.
	RateLimitPerSecond int
}

// Load reads config from the environment.
func Load() Config {
	environment := env("ENVIRONMENT", "development")

	return Config{
		Environment:        environment,
		Port:               env("PORT", "8080"),
		Version:            env("VERSION", "2.1.0"),
		DemoMode:           demoModeDefault(environment),
		StorageBackend:     env("STORAGE_BACKEND", "memory"),
		RedisAddr:          env("REDIS_ADDR", "localhost:6379"),
		PostgresDSN:        env("POSTGRES_DSN", ""),
		KafkaBrokers:       envSlice("KAFKA_BROKERS"),
		KafkaInputTopic:    env("KAFKA_INPUT_TOPIC", "transactions"),
		KafkaOutputTopic:   env("KAFKA_OUTPUT_TOPIC", "fraud-alerts"),
		KafkaConsumerGroup: env("KAFKA_CONSUMER_GROUP", "fraud-detection"),
		APIKeySecret:       env("API_KEY_SECRET", ""),
		JWTSecret:          env("JWT_SECRET", "change-me-in-production-32-bytes-min"),
		JWTIssuer:          env("JWT_ISSUER", "fraud-detection-system"),
		AuthRequired:       envBool("AUTH_REQUIRED", false),
		RulesPath:          env("RULES_PATH", ""),
		SlackWebhookURL:    env("SLACK_WEBHOOK_URL", ""),
		StripeAPIKey:       env("STRIPE_API_KEY", ""),
		SMTPHost:           env("SMTP_HOST", ""),
		SMTPPort:           env("SMTP_PORT", "587"),
		SMTPUsername:       env("SMTP_USERNAME", ""),
		SMTPPassword:       env("SMTP_PASSWORD", ""),
		AlertEmailFrom:     env("ALERT_EMAIL_FROM", ""),
		AlertEmailTo:       env("ALERT_EMAIL_TO", ""),
		TwilioAccountSID:   env("TWILIO_ACCOUNT_SID", ""),
		TwilioAuthToken:    env("TWILIO_AUTH_TOKEN", ""),
		TwilioFromNumber:   env("TWILIO_FROM_NUMBER", ""),
		AlertSMSTo:         env("ALERT_SMS_TO", ""),
		OTLPEndpoint:       env("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		RetrainInterval:    envDuration("RETRAIN_INTERVAL", 24*time.Hour),
		ReadTimeout:        envDuration("READ_TIMEOUT", 10*time.Second),
		WriteTimeout:       envDuration("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:        envDuration("IDLE_TIMEOUT", 60*time.Second),
		RateLimitPerSecond: envInt("RATE_LIMIT_PER_SECOND", 1000),
	}
}

func envSlice(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	out := []string{}
	for _, s := range splitComma(v) {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
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

// demoModeDefault resolves the DemoMode flag from DEMO_MODE, falling back
// to an environment-aware default: true in development (so the API is
// usable out of the box) and false in production (so we don't pollute the
// real store with synthetic data or waste cycles on boot-time
// calibration against a fake dataset). Explicitly setting DEMO_MODE
// overrides the default in either environment.
func demoModeDefault(environment string) bool {
	if v := os.Getenv("DEMO_MODE"); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}
	return environment != "production"
}
