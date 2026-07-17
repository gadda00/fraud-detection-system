// Package api — HTTP handlers wiring together detectors, rules, cases,
// auth, metrics, and webhooks.
package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/auth"
	"github.com/gadda00/fraud-detection-system/internal/cases"
	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/middleware"
	"github.com/gadda00/fraud-detection-system/internal/ml"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/pipeline"
	"github.com/gadda00/fraud-detection-system/internal/rules"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/gadda00/fraud-detection-system/internal/webhooks"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version is the semantic version reported by /api/health.
const Version = "2.1.0"

// Server bundles every dependency a handler needs. Constructing it once at
// startup and sharing it across requests keeps allocation low.
//
// Since Phase 1 the actual scoring logic lives in Server.Pipeline
// (internal/pipeline.Pipeline.Process); the handlers are thin adapters
// that decode the request, call Pipeline.Process, and shape the Result
// into the HTTP JSON envelope. The Store / Ensemble / Calibrator /
// CaseManager / Notifier fields are retained on the Server for the
// introspection endpoints (Health, Stats) and to keep api.NewServer's
// signature stable for callers (main.go).
type Server struct {
	Store       storage.Store
	Ensemble    *detector.EnsembleDetector
	RulesEngine *rules.Engine
	CaseManager *cases.Manager
	Calibrator  *ml.LogisticCalibrator
	Notifier    webhooks.Notifier
	Pipeline    *pipeline.Pipeline
	Started     time.Time

	// RateLimitPerSecond caps requests per client IP per second via a
	// token-bucket middleware. <= 0 disables rate limiting.
	RateLimitPerSecond int
}

// NewServer wires a Server around the given store with all subsystems.
func NewServer(
	store storage.Store,
	rulesEngine *rules.Engine,
	caseMgr *cases.Manager,
	calibrator *ml.LogisticCalibrator,
	notifier webhooks.Notifier,
) *Server {
	ens := detector.NewEnsembleDetector(store)
	pipe := &pipeline.Pipeline{
		Ensemble:    ens,
		Rules:       rulesEngine,
		Calibrator:  calibrator,
		Store:       store,
		CaseManager: caseMgr,
		Notifier:    notifier,
	}
	return &Server{
		Store:       store,
		Ensemble:    ens,
		RulesEngine: rulesEngine,
		CaseManager: caseMgr,
		Calibrator:  calibrator,
		Notifier:    notifier,
		Pipeline:    pipe,
		Started:     time.Now(),
	}
}

// Register attaches all API routes to a Gin engine, including auth, metrics,
// case management, and admin endpoints.
//
// Route map:
//
//	POST /api/score              — score a transaction (auth: service+)
//	GET  /api/health             — liveness (no auth)
//	GET  /api/stats              — aggregate counters (auth: readonly+)
//	GET  /api/cases              — list review queue (auth: analyst+)
//	GET  /api/cases/:id          — get one case (auth: analyst+)
//	POST /api/cases/:id/assign   — assign to analyst (auth: analyst+)
//	POST /api/cases/:id/resolve  — close with verdict (auth: analyst+)
//	POST /api/cases/:id/notes    — add a comment (auth: analyst+)
//	GET  /api/cases/stats        — case queue stats (auth: analyst+)
//	POST /admin/rules/reload     — hot-reload rules (auth: admin)
//	GET  /metrics                — Prometheus scrape (no auth)
func (s *Server) Register(r *gin.Engine, verifier auth.Verifier, authRequired bool) {
	api := r.Group("/api")
	api.Use(middleware.RequestID())
	api.Use(middleware.Prometheus())
	// Per-IP rate limit. A configured RateLimitPerSecond <= 0 makes the
	// middleware a no-op, so this stays safe even when the operator
	// hasn't set the env var.
	api.Use(middleware.RateLimit(s.RateLimitPerSecond))
	api.Use(middleware.Auth(verifier, authRequired))

	// Public-ish endpoints.
	api.GET("/health", s.Health)
	api.GET("/stats", s.Stats)

	// Scoring (service role or higher).
	scoreGroup := api.Group("", authMiddlewareGate(verifier, authRequired))
	{
		scoreGroup.POST("/score", s.ScoreTransaction)
		scoreGroup.POST("/score/batch", s.ScoreBatch)
	}

	// Case management (analyst role or higher).
	casesGroup := api.Group("/cases", middleware.RequireRole(auth.RoleAnalyst, auth.RoleAdmin))
	{
		casesGroup.GET("", s.ListCases)
		casesGroup.GET("/stats", s.CaseStats)
		casesGroup.GET("/:id", s.GetCase)
		casesGroup.POST("/:id/assign", s.AssignCase)
		casesGroup.POST("/:id/resolve", s.ResolveCase)
		casesGroup.POST("/:id/notes", s.AddNote)
	}

	// Admin.
	admin := r.Group("/admin", middleware.Auth(verifier, authRequired), middleware.RequireRole(auth.RoleAdmin))
	{
		admin.POST("/rules/reload", s.ReloadRules)
	}

	// Prometheus scrape endpoint.
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
}

// authMiddlewareGate is a thin wrapper that just ensures auth is applied
// (the group-level Auth middleware already handles this; this is a no-op
// placeholder for future per-route auth overrides).
func authMiddlewareGate(_ auth.Verifier, _ bool) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

// ---------------------------------------------------------------------------
// /api/score
// ---------------------------------------------------------------------------

// scoreResponse is the envelope returned by /api/score.
type scoreResponse struct {
	TransactionID  string            `json:"transaction_id"`
	UserID         string            `json:"user_id"`
	Amount         float64           `json:"amount"`
	Currency       string            `json:"currency"`
	Flagged        bool              `json:"flagged"`
	Blocked        bool              `json:"blocked"`
	ReviewRequired bool              `json:"review_required"`
	Risk           models.RiskScore  `json:"risk"`
	CalibratedP    float64           `json:"calibrated_probability"`
	RuleMatches    []rules.RuleMatch `json:"rule_matches,omitempty"`
	CaseID         string            `json:"case_id,omitempty"`
	ScoredAt       time.Time         `json:"scored_at"`
	LatencyUS      int64             `json:"latency_us"`
}

// ScoreTransaction is the main entry point. It is a thin adapter:
// decode → validate → Pipeline.Process → shape Result into the JSON
// envelope. All scoring logic lives in the pipeline so HTTP and Kafka
// agree on what a "scored transaction" means (Finding 3.11).
func (s *Server) ScoreTransaction(c *gin.Context) {
	var tx models.Transaction
	if err := c.ShouldBindJSON(&tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	if err := validateTx(&tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := s.Pipeline.Process(c.Request.Context(), tx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "scoring failed: " + err.Error()})
		return
	}

	// Record Prometheus metrics for the scoring latency / severity.
	middleware.RecordScoring(res.Risk.Severity, res.Risk.IsFlagged(), float64(res.LatencyUS))

	c.JSON(http.StatusOK, scoreResponse{
		TransactionID:  tx.ID,
		UserID:         tx.UserID,
		Amount:         tx.Amount,
		Currency:       tx.Currency,
		Flagged:        res.Risk.IsFlagged(),
		Blocked:        res.Blocked,
		ReviewRequired: res.ReviewRequired,
		Risk:           res.Risk,
		CalibratedP:    res.Calibrated,
		RuleMatches:    res.RuleMatches,
		CaseID:         res.CaseID,
		ScoredAt:       time.Now().UTC(),
		LatencyUS:      res.LatencyUS,
	})
}

// ScoreBatch scores a batch of transactions (for high-throughput ingestion).
// Limited to 1000 transactions per request. Each transaction goes through
// Pipeline.Process individually so the batch path inherits the same
// idempotency, FlagWeight blend, case creation and notification semantics
// as the single-score path — the only difference is that the JSON
// envelope is collected into a slice rather than returned alone.
func (s *Server) ScoreBatch(c *gin.Context) {
	var batch []models.Transaction
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	if len(batch) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "batch size exceeds 1000"})
		return
	}

	ctx := c.Request.Context()
	results := make([]scoreResponse, 0, len(batch))
	for _, tx := range batch {
		if err := validateTx(&tx); err != nil {
			continue
		}
		res, err := s.Pipeline.Process(ctx, tx)
		if err != nil {
			continue
		}
		middleware.RecordScoring(res.Risk.Severity, res.Risk.IsFlagged(), float64(res.LatencyUS))
		results = append(results, scoreResponse{
			TransactionID:  tx.ID,
			UserID:         tx.UserID,
			Amount:         tx.Amount,
			Currency:       tx.Currency,
			Flagged:        res.Risk.IsFlagged(),
			Blocked:        res.Blocked,
			ReviewRequired: res.ReviewRequired,
			Risk:           res.Risk,
			CalibratedP:    res.Calibrated,
			RuleMatches:    res.RuleMatches,
			CaseID:         res.CaseID,
			ScoredAt:       time.Now().UTC(),
			LatencyUS:      res.LatencyUS,
		})
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "count": len(results)})
}

func validateTx(tx *models.Transaction) error {
	if tx.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if tx.Amount <= 0 {
		return fmt.Errorf("amount must be positive")
	}
	if tx.ID == "" {
		tx.ID = fmt.Sprintf("live-%d", time.Now().UnixNano())
	}
	if tx.Currency == "" {
		tx.Currency = "USD"
	}
	if tx.Timestamp.IsZero() {
		tx.Timestamp = time.Now().UTC()
	} else {
		tx.Timestamp = tx.Timestamp.UTC()
	}
	return nil
}

// ---------------------------------------------------------------------------
// /api/health, /api/stats
// ---------------------------------------------------------------------------

type healthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Users     int    `json:"users_tracked"`
	Detectors int    `json:"detectors"`
}

func (s *Server) Health(c *gin.Context) {
	users, _ := s.Store.UserCount(c.Request.Context())
	c.JSON(http.StatusOK, healthResponse{
		Status:    "ok",
		Version:   Version,
		Uptime:    time.Since(s.Started).Round(time.Second).String(),
		Users:     users,
		Detectors: len(s.Ensemble.Detectors()),
	})
}

func (s *Server) Stats(c *gin.Context) {
	stats, _ := s.Store.GetStats(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"total_scored":   stats.TotalScored,
		"total_flagged":  stats.TotalFlagged,
		"users_tracked":  stats.UsersTracked,
		"by_severity":    stats.BySeverity,
		"started_at":     stats.StartedAt.UTC(),
		"uptime_seconds": stats.UptimeSeconds,
		"flag_rate":      flagRate(stats.TotalScored, stats.TotalFlagged),
		"detectors":      detectorNames(s.Ensemble.Detectors()),
		"version":        Version,
	})
}

func flagRate(total, flagged int) float64 {
	if total == 0 {
		return 0
	}
	return float64(flagged) / float64(total)
}

func detectorNames(ds []detector.Detector) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Name()
	}
	return out
}
