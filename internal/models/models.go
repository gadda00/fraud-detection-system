// Package models defines the core data structures used across the fraud
// detection system: transactions entering the pipeline and the risk scores
// that come out of it.
package models

import "time"

// Transaction represents a single financial event submitted for scoring.
// All fields are intentionally simple value types so the struct can be
// safely passed by value between goroutines without explicit locking.
type Transaction struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Amount    float64   `json:"amount"`
	Currency  string    `json:"currency"`
	Merchant  string    `json:"merchant"`
	Category  string    `json:"category"`
	Timestamp time.Time `json:"timestamp"`
	Country   string    `json:"country"`
	DeviceID  string    `json:"device_id"`
}

// RiskScore is the output of the detection pipeline for one transaction.
//
//   - Score is the ensemble probability of fraud in the range [0, 1].
//   - Severity is a human-readable bucket derived from Score
//     (low / medium / high / critical).
//   - Reasons is a free-form list explaining *why* the score is what it is.
//   - Detectors lists which individual detectors contributed to the score.
type RiskScore struct {
	Score     float64  `json:"score"`     // 0-1, probability of fraud
	Severity  string   `json:"severity"`  // low, medium, high, critical
	Reasons   []string `json:"reasons"`   // why flagged
	Detectors []string `json:"detectors"` // which detectors fired
}

// Severity thresholds. A transaction is considered suspicious once its
// ensemble score crosses the medium boundary.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"

	// Flagged is true for anything at or above medium severity.
	ThresholdFlagged = 0.5
)

// SeverityFromScore maps a continuous score onto one of the four discrete
// severity buckets. Keeping this logic in one place ensures the API,
// storage layer and tests all agree on what "high risk" means.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 0.85:
		return SeverityCritical
	case score >= 0.7:
		return SeverityHigh
	case score >= 0.5:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// IsFlagged reports whether the score should raise an alert.
func (r RiskScore) IsFlagged() bool {
	return r.Score >= ThresholdFlagged
}
