// HTTP handlers for the fraud-detection API.
//
// The Server type owns the shared store and ensemble detector and exposes
// three endpoints via Gin: /api/score, /api/health and /api/stats.

package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/gin-gonic/gin"
)

// Version is the semantic version reported by /api/health. Bumped on
// releases.
const Version = "1.0.0"

// Server bundles the dependencies every handler needs. Constructing it
// once at startup and sharing it across requests keeps allocation low —
// important when the target throughput is tens of thousands of TPS.
type Server struct {
	Store    *storage.Store
	Ensemble *detector.EnsembleDetector
	Started  time.Time
}

// NewServer wires a Server around the given store. The ensemble is built
// from the same store so detectors read live history.
func NewServer(store *storage.Store) *Server {
	return &Server{
		Store:    store,
		Ensemble: detector.NewEnsembleDetector(store),
		Started:  time.Now(),
	}
}

// Register attaches the API routes to a Gin engine. Centralising routing
// here keeps main.go tiny and makes the handler set trivially testable.
func (s *Server) Register(r *gin.Engine) {
	api := r.Group("/api")
	{
		api.POST("/score", s.ScoreTransaction)
		api.GET("/health", s.Health)
		api.GET("/stats", s.Stats)
	}
}

// scoreResponse is the envelope returned by /api/score. It echoes back
// identifying fields so callers can correlate the result with their own
// logs without re-parsing the request.
type scoreResponse struct {
	TransactionID string           `json:"transaction_id"`
	UserID        string           `json:"user_id"`
	Amount        float64          `json:"amount"`
	Currency      string           `json:"currency"`
	Flagged       bool             `json:"flagged"`
	Risk          models.RiskScore `json:"risk"`
	ScoredAt      time.Time        `json:"scored_at"`
	LatencyUS     int64            `json:"latency_us"`
}

// ScoreTransaction is the main entry point: it validates an inbound
// transaction, runs the ensemble detector, persists the result, and
// returns the risk score.
//
//	curl -X POST localhost:8080/api/score \
//	  -H 'Content-Type: application/json' \
//	  -d '{"user_id":"u1","amount":5000,"currency":"USD","merchant":"Amazon","category":"shopping"}'
func (s *Server) ScoreTransaction(c *gin.Context) {
	start := time.Now()

	var tx models.Transaction
	if err := c.ShouldBindJSON(&tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}

	// ---- validation --------------------------------------------------
	if tx.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}
	if tx.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount must be positive"})
		return
	}
	// Sensible defaults so callers can post a minimal payload.
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

	// ---- scoring -----------------------------------------------------
	risk := s.Ensemble.Score(tx)

	// ---- persistence -------------------------------------------------
	// Add AFTER scoring so the transaction is never part of its own
	// baseline (the detectors read GetUserHistory, which does not yet
	// include tx).
	s.Store.Add(tx, risk)

	resp := scoreResponse{
		TransactionID: tx.ID,
		UserID:        tx.UserID,
		Amount:        tx.Amount,
		Currency:      tx.Currency,
		Flagged:       risk.IsFlagged(),
		Risk:          risk,
		ScoredAt:      time.Now().UTC(),
		LatencyUS:     time.Since(start).Microseconds(),
	}
	c.JSON(http.StatusOK, resp)
}

// healthResponse is the body of /api/health.
type healthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Users     int    `json:"users_tracked"`
	Detectors int    `json:"detectors"`
}

// Health reports liveness and basic runtime info. Load balancers and
// orchestrators (k8s liveness probes) should poll this.
func (s *Server) Health(c *gin.Context) {
	c.JSON(http.StatusOK, healthResponse{
		Status:    "ok",
		Version:   Version,
		Uptime:    time.Since(s.Started).Round(time.Second).String(),
		Users:     s.Store.UserCount(),
		Detectors: len(s.Ensemble.Detectors()),
	})
}

// Stats returns the aggregate detection counters maintained by the store.
// Useful for dashboards and for proving the service is actually doing
// work.
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

// flagRate computes the fraction of scored transactions that were
// flagged, guarding against divide-by-zero on a cold store.
func flagRate(total, flagged int) float64 {
	if total == 0 {
		return 0
	}
	return float64(flagged) / float64(total)
}

// detectorNames returns the names of the sub-detectors for display in
// /api/stats.
func detectorNames(ds []detector.Detector) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Name()
	}
	return out
}
