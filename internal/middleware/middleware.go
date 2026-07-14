// Package middleware contains gin middleware: auth, rate limiting, request
// ID, structured logging, Prometheus metrics, and CORS.
package middleware

import (
	"time"

	"github.com/gadda00/fraud-detection-system/internal/auth"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Context keys for values attached by middleware.
const (
	ContextRequestID = "request_id"
	ContextPrincipal = "principal"
)

// RequestID middleware attaches a UUID to every request, propagated via the
// X-Request-ID response header. If the client sends an X-Request-ID it is
// reused (useful for distributed tracing).
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-ID")
		if rid == "" {
			rid = uuid.NewString()
		}
		c.Set(ContextRequestID, rid)
		c.Header("X-Request-ID", rid)
		c.Next()
	}
}

// Auth middleware verifies the bearer token and attaches the Principal to
// the context. If requireAuth is false, missing tokens are allowed through
// (useful for health checks).
func Auth(verifier auth.Verifier, requireAuth bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := auth.ExtractBearer(c.GetHeader("Authorization"))
		if token == "" {
			if requireAuth {
				c.AbortWithStatusJSON(401, gin.H{"error": "missing bearer token"})
				return
			}
			c.Next()
			return
		}
		p, err := verifier.Verify(token)
		if err != nil {
			if requireAuth {
				c.AbortWithStatusJSON(401, gin.H{"error": "invalid token: " + err.Error()})
				return
			}
			c.Next()
			return
		}
		c.Set(ContextPrincipal, p)
		c.Next()
	}
}

// RequireRole aborts with 403 unless the principal has one of the allowed roles.
func RequireRole(roles ...auth.Role) gin.HandlerFunc {
	allowed := make(map[auth.Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		pRaw, ok := c.Get(ContextPrincipal)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "not authenticated"})
			return
		}
		p, ok := pRaw.(*auth.Principal)
		if !ok || !allowed[p.Role] {
			c.AbortWithStatusJSON(403, gin.H{"error": "insufficient role"})
			return
		}
		c.Next()
	}
}

// Prometheus metrics.
var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fraud_http_requests_total",
		Help: "Total HTTP requests by method, path, and status",
	}, []string{"method", "path", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fraud_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	scoringTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fraud_scoring_total",
		Help: "Total transactions scored, by severity and flagged status",
	}, []string{"severity", "flagged"})

	scoringLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "fraud_scoring_latency_microseconds",
		Help:    "Transaction scoring latency in microseconds",
		Buckets: []float64{50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000},
	})
)

// Prometheus middleware records request count and latency.
func Prometheus() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		elapsed := time.Since(start).Seconds()
		status := c.Writer.Status()
		httpRequestsTotal.WithLabelValues(c.Request.Method, c.FullPath(), statusLabel(status)).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, c.FullPath()).Observe(elapsed)
	}
}

// RecordScoring is called by the score handler to publish scoring metrics.
func RecordScoring(severity string, flagged bool, latencyUS float64) {
	scoringTotal.WithLabelValues(severity, boolStr(flagged)).Inc()
	scoringLatency.Observe(latencyUS)
}

func statusLabel(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
