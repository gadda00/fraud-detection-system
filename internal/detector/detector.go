// Package detector implements the fraud-scoring engines.
//
// Each detector implements the Detector interface and produces a
// models.RiskScore for a single transaction. Detectors consult the
// storage.Store for the user's recent history, so they must be constructed
// with a shared store instance.
//
// Three independent detectors are provided:
//
//   - ZScoreDetector  — flags amounts more than N standard deviations
//     above the user's historical mean *for the same category*. Computing
//     the baseline per (user, category) is what keeps the false-positive
//     rate low: a $600 airline ticket is compared to past travel, not to
//     the user's $5 subscriptions.
//   - IQRDetector     — flags amounts outside the Tukey fence
//     [Q1 - 1.5*IQR, Q3 + 1.5*IQR], again computed per (user, category).
//   - VelocityDetector — flags users submitting more than N transactions
//     inside a rolling M-minute window.
//
// EnsembleDetector runs all three and fuses their outputs with a weighted
// vote. Because the weights sum to 1.0 and every sub-score lives in
// [0, 1], the ensemble score is guaranteed to stay in [0, 1] without any
// extra normalisation.
package detector

import (
	"fmt"
	"sort"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"gonum.org/v1/gonum/stat"
)

// Detector is the contract every fraud detector satisfies. Score must be
// safe to call concurrently from many goroutines; implementations achieve
// this by only reading from the shared, lock-protected storage.Store.
type Detector interface {
	// Name returns a short, stable identifier ("zscore", "iqr", ...).
	// It is used to populate RiskScore.Detectors and for logging.
	Name() string

	// Score evaluates a single transaction and returns a risk score in
	// the range [0, 1] together with human-readable reasons.
	Score(tx models.Transaction) models.RiskScore
}

// minHistory is the smallest number of same-category historical
// transactions a detector needs before it will venture an opinion. Below
// this the statistical estimators are too noisy to be meaningful, so the
// detector abstains (returns a zero / low score). Five points gives a
// stable enough mean / IQR to keep the false-positive rate low while the
// seed data supplies ~6 per (user, category).
const minHistory = 5

// clean returns a "no anomaly" risk score.
func clean() models.RiskScore {
	return models.RiskScore{
		Score:     0,
		Severity:  models.SeverityLow,
		Reasons:   nil,
		Detectors: nil,
	}
}

// ---------------------------------------------------------------------------
// ZScoreDetector
// ---------------------------------------------------------------------------

// ZScoreDetector flags transactions whose amount sits more than Threshold
// standard deviations above the user's historical mean *for the same
// category*. Per-category baselines are essential: without them a user's
// amount distribution is multi-modal (a $5 subscription next to a $500
// flight) and every large-but-legitimate purchase looks like an outlier.
// Only the upper tail is interesting for fraud — an unusually *small*
// charge is rarely fraud, so negative z-scores are ignored.
type ZScoreDetector struct {
	store     *storage.Store
	threshold float64 // sigma multiplier that triggers a flag (default 3.0)
}

// NewZScoreDetector builds a detector with the conventional 3σ threshold.
func NewZScoreDetector(store *storage.Store) *ZScoreDetector {
	return &ZScoreDetector{store: store, threshold: 3.0}
}

// Name implements Detector.
func (d *ZScoreDetector) Name() string { return "zscore" }

// Score implements Detector.
func (d *ZScoreDetector) Score(tx models.Transaction) models.RiskScore {
	hist := d.store.GetUserHistory(tx.UserID)

	// Baseline is per (user, category): see the ZScoreDetector doc comment
	// for why this matters.
	amounts := amountsOfCategory(hist, tx.Category)
	if len(amounts) < minHistory {
		return clean()
	}
	mean := stat.Mean(amounts, nil)
	std := stat.StdDev(amounts, nil)

	// If there is no spread, every transaction is "normal" by definition.
	if std == 0 {
		return clean()
	}

	z := (tx.Amount - mean) / std
	if z <= d.threshold {
		return clean()
	}

	// Map z onto [0.5, 1.0]: at the threshold the score is 0.5 (just
	// flagged) and it climbs by 0.2 for every extra σ. This keeps the
	// score monotonic in anomaly size while staying bounded.
	score := 0.5 + (z-d.threshold)*0.2
	if score > 1.0 {
		score = 1.0
	}

	return models.RiskScore{
		Score:     score,
		Severity:  models.SeverityFromScore(score),
		Reasons:   []string{fmt.Sprintf("amount %.2f is %.2fσ above user mean %.2f for category %q (σ=%.2f)", tx.Amount, z, mean, tx.Category, std)},
		Detectors: []string{d.Name()},
	}
}

// ---------------------------------------------------------------------------
// IQRDetector
// ---------------------------------------------------------------------------

// IQRDetector applies the Tukey fence rule: an amount is an outlier if it
// falls outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR]. As with ZScoreDetector the
// fence is computed per (user, category) so that cross-category spend
// differences are not mistaken for fraud. The upper fence is the primary
// fraud signal; the lower fence is down-weighted because small charges
// are more likely benign "card testing" than large theft.
type IQRDetector struct {
	store      *storage.Store
	multiplier float64 // IQR multiplier, default 1.5 (Tukey's 1.5)
}

// NewIQRDetector builds a detector with Tukey's standard 1.5 multiplier.
func NewIQRDetector(store *storage.Store) *IQRDetector {
	return &IQRDetector{store: store, multiplier: 1.5}
}

// Name implements Detector.
func (d *IQRDetector) Name() string { return "iqr" }

// Score implements Detector.
func (d *IQRDetector) Score(tx models.Transaction) models.RiskScore {
	hist := d.store.GetUserHistory(tx.UserID)

	// Baseline is per (user, category); stat.Quantile requires ascending input.
	amounts := amountsOfCategory(hist, tx.Category)
	if len(amounts) < minHistory {
		return clean()
	}
	sort.Float64s(amounts)

	q1 := stat.Quantile(0.25, stat.LinInterp, amounts, nil)
	q3 := stat.Quantile(0.75, stat.LinInterp, amounts, nil)
	iqr := q3 - q1

	// A zero IQR means the middle 50% of amounts are identical; the
	// fence collapses to a single point and the rule is meaningless.
	if iqr == 0 {
		return clean()
	}

	upper := q3 + d.multiplier*iqr
	lower := q1 - d.multiplier*iqr

	switch {
	case tx.Amount > upper:
		// Above the upper fence: how many IQRs past, mapped onto
		// [0.5, 1.0]. Two IQRs past the fence saturates at 1.0.
		distance := (tx.Amount - upper) / iqr
		score := 0.5 + 0.25*distance
		if score > 1.0 {
			score = 1.0
		}
		return models.RiskScore{
			Score:    score,
			Severity: models.SeverityFromScore(score),
			Reasons: []string{
				fmt.Sprintf("amount %.2f exceeds upper Tukey fence %.2f (Q1=%.2f Q3=%.2f IQR=%.2f)", tx.Amount, upper, q1, q3, iqr),
			},
			Detectors: []string{d.Name()},
		}

	case tx.Amount < lower:
		// Below the lower fence: possible card-testing pattern. Lower
		// weight than the upper case because tiny charges are ambiguous.
		distance := (lower - tx.Amount) / iqr
		score := 0.4 + 0.15*distance
		if score > 0.9 {
			score = 0.9
		}
		return models.RiskScore{
			Score:    score,
			Severity: models.SeverityFromScore(score),
			Reasons: []string{
				fmt.Sprintf("amount %.2f below lower Tukey fence %.2f (possible card testing)", tx.Amount, lower),
			},
			Detectors: []string{d.Name()},
		}

	default:
		return clean()
	}
}

// ---------------------------------------------------------------------------
// VelocityDetector
// ---------------------------------------------------------------------------

// VelocityDetector flags users who submit more than MaxTransactions
// transactions within a rolling Window ending at the scored transaction's
// timestamp. Rapid-fire transactions are a classic fraud signature
// (stolen card being drained before the bank blocks it).
type VelocityDetector struct {
	store *storage.Store
	// Window is the look-back duration (e.g. 5 minutes).
	Window time.Duration
	// MaxTransactions is the number of transactions permitted inside
	// Window before the detector starts flagging.
	MaxTransactions int
}

// NewVelocityDetector builds a detector with sensible defaults:
// 4 transactions per 5 minutes. Four charges in five minutes is already
// unusual for a legitimate user, so this is where the detector starts
// paying attention while keeping false positives low (the seed data
// spreads normal spend over days, so honest users essentially never hit
// this rate).
func NewVelocityDetector(store *storage.Store) *VelocityDetector {
	return &VelocityDetector{
		store:           store,
		Window:          5 * time.Minute,
		MaxTransactions: 4,
	}
}

// Name implements Detector.
func (d *VelocityDetector) Name() string { return "velocity" }

// Score implements Detector.
func (d *VelocityDetector) Score(tx models.Transaction) models.RiskScore {
	hist := d.store.GetUserHistory(tx.UserID)
	if len(hist) == 0 {
		return clean()
	}

	cutoff := tx.Timestamp.Add(-d.Window)
	count := 0
	for _, h := range hist {
		// Count transactions inside the window and at or before the
		// transaction being scored (history never contains tx itself).
		if !h.Timestamp.Before(cutoff) && !h.Timestamp.After(tx.Timestamp) {
			count++
		}
	}

	if count <= d.MaxTransactions {
		return clean()
	}

	// Each transaction beyond the allowance adds 0.1 to the score,
	// starting from 0.5 the moment the threshold is crossed. Five
	// excess transactions saturate at 1.0.
	excess := count - d.MaxTransactions
	score := 0.5 + 0.1*float64(excess)
	if score > 1.0 {
		score = 1.0
	}

	return models.RiskScore{
		Score:    score,
		Severity: models.SeverityFromScore(score),
		Reasons: []string{
			fmt.Sprintf("velocity breach: %d transactions in last %s (limit %d)", count, d.Window, d.MaxTransactions),
		},
		Detectors: []string{d.Name()},
	}
}

// ---------------------------------------------------------------------------
// EnsembleDetector
// ---------------------------------------------------------------------------

// EnsembleDetector fuses the outputs of several detectors with a weighted
// vote. Weights must be non-negative; they are normalised internally so
// the caller does not have to be precise.
type EnsembleDetector struct {
	detectors []Detector
	weights   []float64
}

// NewEnsembleDetector builds the default ensemble used in production:
// Z-Score (40%), IQR (35%) and Velocity (25%). The weighting favours the
// two amount-based detectors, which carry the strongest signal for the
// fraud patterns this system targets, while still letting velocity break
// ties and catch rapid-fire attacks.
func NewEnsembleDetector(store *storage.Store) *EnsembleDetector {
	return &EnsembleDetector{
		detectors: []Detector{
			NewZScoreDetector(store),
			NewIQRDetector(store),
			NewVelocityDetector(store),
		},
		weights: []float64{0.40, 0.35, 0.25},
	}
}

// Name implements Detector.
func (d *EnsembleDetector) Name() string { return "ensemble" }

// Detectors returns the underlying sub-detectors. Exposed so callers
// (e.g. tests or a debug endpoint) can introspect the ensemble.
func (d *EnsembleDetector) Detectors() []Detector { return d.detectors }

// Score implements Detector. It runs every sub-detector and fuses the
// outputs by weighted voting: only detectors that actually fire
// (score > 0) participate in the average, so a single strong signal can
// still raise an alert. This is the standard "weighted average of active
// voters" fusion rule — abstaining detectors neither inflate nor dilute
// the score.
//
// Concretely: ensemble_score = Σ(w_i · s_i) / Σ(w_i) over firing
// detectors. If no detector fires, the score is 0 (low risk).
func (d *EnsembleDetector) Score(tx models.Transaction) models.RiskScore {
	var (
		weightedSum float64
		weightSum   float64
		reasons     []string
		fired       []string
	)

	for i, det := range d.detectors {
		rs := det.Score(tx)
		if rs.Score <= 0 {
			continue // detector abstains
		}
		weightedSum += rs.Score * d.weights[i]
		weightSum += d.weights[i]
		fired = append(fired, det.Name())
		if len(rs.Reasons) > 0 {
			reasons = append(reasons, rs.Reasons...)
		}
	}

	var combined float64
	if weightSum > 0 {
		combined = weightedSum / weightSum
	}
	// Clamp against floating-point drift.
	if combined > 1.0 {
		combined = 1.0
	}
	if combined < 0 {
		combined = 0
	}

	if len(reasons) == 0 {
		reasons = []string{"no anomalies detected"}
	}

	return models.RiskScore{
		Score:     combined,
		Severity:  models.SeverityFromScore(combined),
		Reasons:   reasons,
		Detectors: fired,
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// amountsOfCategory extracts the Amount field of every transaction in
// hist whose Category matches category, returning a fresh []float64 that
// the caller may sort or mutate freely.
func amountsOfCategory(hist []models.Transaction, category string) []float64 {
	out := make([]float64, 0, len(hist))
	for _, h := range hist {
		if h.Category == category {
			out = append(out, h.Amount)
		}
	}
	return out
}
