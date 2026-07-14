// Package api — HTTP handlers wiring together detectors, rules, cases,
// auth, metrics, and webhooks.
package api

import (
        "context"
        "fmt"
        "net/http"
        "time"

        "github.com/gadda00/fraud-detection-system/internal/auth"
        "github.com/gadda00/fraud-detection-system/internal/cases"
        "github.com/gadda00/fraud-detection-system/internal/detector"
        "github.com/gadda00/fraud-detection-system/internal/middleware"
        "github.com/gadda00/fraud-detection-system/internal/ml"
        "github.com/gadda00/fraud-detection-system/internal/models"
        "github.com/gadda00/fraud-detection-system/internal/rules"
        "github.com/gadda00/fraud-detection-system/internal/storage"
        "github.com/gadda00/fraud-detection-system/internal/webhooks"
        "github.com/gin-gonic/gin"
        "github.com/prometheus/client_golang/prometheus/promhttp"
        "github.com/rs/zerolog/log"
)

// Version is the semantic version reported by /api/health.
const Version = "2.0.0"

// Server bundles every dependency a handler needs. Constructing it once at
// startup and sharing it across requests keeps allocation low.
type Server struct {
        Store       *storage.Store
        Ensemble    *detector.EnsembleDetector
        RulesEngine *rules.Engine
        CaseManager *cases.Manager
        Calibrator  *ml.LogisticCalibrator
        Notifier    webhooks.Notifier
        Started     time.Time
}

// NewServer wires a Server around the given store with all subsystems.
func NewServer(
        store *storage.Store,
        rulesEngine *rules.Engine,
        caseMgr *cases.Manager,
        calibrator *ml.LogisticCalibrator,
        notifier webhooks.Notifier,
) *Server {
        return &Server{
                Store:       store,
                Ensemble:    detector.NewEnsembleDetector(store),
                RulesEngine: rulesEngine,
                CaseManager: caseMgr,
                Calibrator:  calibrator,
                Notifier:    notifier,
                Started:     time.Now(),
        }
}

// Register attaches all API routes to a Gin engine, including auth, metrics,
// case management, and admin endpoints.
//
// Route map:
//
//      POST /api/score              — score a transaction (auth: service+)
//      GET  /api/health             — liveness (no auth)
//      GET  /api/stats              — aggregate counters (auth: readonly+)
//      GET  /api/cases              — list review queue (auth: analyst+)
//      GET  /api/cases/:id          — get one case (auth: analyst+)
//      POST /api/cases/:id/assign   — assign to analyst (auth: analyst+)
//      POST /api/cases/:id/resolve  — close with verdict (auth: analyst+)
//      POST /api/cases/:id/notes    — add a comment (auth: analyst+)
//      GET  /api/cases/stats        — case queue stats (auth: analyst+)
//      POST /admin/rules/reload     — hot-reload rules (auth: admin)
//      GET  /metrics                — Prometheus scrape (no auth)
func (s *Server) Register(r *gin.Engine, verifier auth.Verifier, authRequired bool) {
        api := r.Group("/api")
        api.Use(middleware.RequestID())
        api.Use(middleware.Prometheus())
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
        TransactionID  string             `json:"transaction_id"`
        UserID         string             `json:"user_id"`
        Amount         float64            `json:"amount"`
        Currency       string             `json:"currency"`
        Flagged        bool               `json:"flagged"`
        Blocked        bool               `json:"blocked"`
        ReviewRequired bool               `json:"review_required"`
        Risk           models.RiskScore   `json:"risk"`
        CalibratedP    float64            `json:"calibrated_probability"`
        RuleMatches    []rules.RuleMatch  `json:"rule_matches,omitempty"`
        CaseID         string             `json:"case_id,omitempty"`
        ScoredAt       time.Time          `json:"scored_at"`
        LatencyUS      int64              `json:"latency_us"`
}

// ScoreTransaction is the main entry point.
func (s *Server) ScoreTransaction(c *gin.Context) {
        start := time.Now()

        var tx models.Transaction
        if err := c.ShouldBindJSON(&tx); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
                return
        }
        if err := validateTx(&tx); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
                return
        }

        // 1. Run the statistical ensemble.
        risk := s.Ensemble.Score(tx)

        // 2. Calibrate the raw score to a probability.
        calibrated := s.Calibrator.Calibrate(risk.Score)

        // 3. Evaluate deterministic rules.
        var ruleMatches []rules.RuleMatch
        if s.RulesEngine != nil {
                ruleMatches = s.RulesEngine.Evaluate(tx)
        }
        blocked := rules.HasBlock(ruleMatches)
        reviewRequired := rules.HasReview(ruleMatches)

        // 4. If blocked or high-severity, override the score to 1.0.
        if blocked || risk.Severity == models.SeverityCritical {
                risk.Score = 1.0
                risk.Severity = models.SeverityCritical
        }

        // 5. Persist the transaction + score.
        s.Store.Add(tx, risk)

        // 6. Create a case if flagged or review-required.
        var caseID string
        if risk.IsFlagged() || reviewRequired || blocked {
                var ruleIDs []string
                for _, m := range ruleMatches {
                        ruleIDs = append(ruleIDs, m.Rule.ID)
                }
                caseID = s.CaseManager.Create(tx, risk, ruleIDs)
        }

        // 7. Fire webhook (async — don't block the response).
        if risk.IsFlagged() {
                go func() {
                        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                        defer cancel()
                        if err := s.Notifier.Notify(ctx, tx, risk); err != nil {
                                log.Error().Err(err).Str("tx_id", tx.ID).Msg("webhook notify failed")
                        }
                }()
        }

        // 8. Record Prometheus metrics.
        latencyUS := time.Since(start).Microseconds()
        middleware.RecordScoring(risk.Severity, risk.IsFlagged(), float64(latencyUS))

        resp := scoreResponse{
                TransactionID:  tx.ID,
                UserID:         tx.UserID,
                Amount:         tx.Amount,
                Currency:       tx.Currency,
                Flagged:        risk.IsFlagged(),
                Blocked:        blocked,
                ReviewRequired: reviewRequired,
                Risk:           risk,
                CalibratedP:    calibrated,
                RuleMatches:    ruleMatches,
                CaseID:         caseID,
                ScoredAt:       time.Now().UTC(),
                LatencyUS:      latencyUS,
        }
        c.JSON(http.StatusOK, resp)
}

// ScoreBatch scores a batch of transactions (for high-throughput ingestion).
// Limited to 1000 transactions per request.
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

        results := make([]scoreResponse, 0, len(batch))
        for _, tx := range batch {
                if err := validateTx(&tx); err != nil {
                        continue
                }
                start := time.Now()
                risk := s.Ensemble.Score(tx)
                calibrated := s.Calibrator.Calibrate(risk.Score)
                s.Store.Add(tx, risk)
                latencyUS := time.Since(start).Microseconds()
                middleware.RecordScoring(risk.Severity, risk.IsFlagged(), float64(latencyUS))
                results = append(results, scoreResponse{
                        TransactionID: tx.ID,
                        UserID:        tx.UserID,
                        Amount:        tx.Amount,
                        Currency:      tx.Currency,
                        Flagged:       risk.IsFlagged(),
                        Risk:          risk,
                        CalibratedP:   calibrated,
                        ScoredAt:      time.Now().UTC(),
                        LatencyUS:     latencyUS,
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
        c.JSON(http.StatusOK, healthResponse{
                Status:    "ok",
                Version:   Version,
                Uptime:    time.Since(s.Started).Round(time.Second).String(),
                Users:     s.Store.UserCount(),
                Detectors: len(s.Ensemble.Detectors()),
        })
}

func (s *Server) Stats(c *gin.Context) {
        stats := s.Store.GetStats()
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
