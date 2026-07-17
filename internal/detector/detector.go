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
// EnsembleDetector runs all three (plus geo, device, merchant and
// behavioural detectors) and fuses their outputs with an always-voting
// log-odds combiner. See EnsembleDetector.Score for the fusion rule.
package detector

import (
	"context"
	"fmt"
	"math"
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

// minHistory is the size at which the per-user baseline is considered
// fully trusted. Below this the detectors blend the user's statistics
// with the population baseline (cold-start shrinkage, Finding 3.8)
// rather than abstaining — the blend weight is alpha = n / minHistory,
// so a brand-new user (n=0) gets the pure population baseline and a
// user with minHistory transactions gets the pure user baseline.
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
//
// Cold-start shrinkage (Finding 3.8): when the user has fewer than
// minHistory same-category transactions, the baseline is blended with the
// population-wide mean / std for that category:
//
//	alpha        = min(1.0, n / minHistory)
//	blendedMean  = alpha*userMean + (1-alpha)*popMean
//	blendedStd   = alpha*userStd  + (1-alpha)*popStd
//
// A brand-new user (n=0) is therefore scored against the population
// baseline rather than abstaining — no more cliff at 5 transactions. If
// the population has no data either, the detector abstains.
type ZScoreDetector struct {
	store     storage.Store
	threshold float64 // sigma multiplier that triggers a flag (default 3.0)
}

// NewZScoreDetector builds a detector with the conventional 3σ threshold.
func NewZScoreDetector(store storage.Store) *ZScoreDetector {
	return &ZScoreDetector{store: store, threshold: 3.0}
}

// Name implements Detector.
func (d *ZScoreDetector) Name() string { return "zscore" }

// Score implements Detector.
func (d *ZScoreDetector) Score(tx models.Transaction) models.RiskScore {
	ctx := context.Background()
	hist, _ := d.store.GetUserHistory(ctx, tx.UserID)

	// Baseline is per (user, category): see the ZScoreDetector doc comment
	// for why this matters.
	amounts := amountsOfCategory(hist, tx.Category)
	n := len(amounts)

	// Population baseline (across ALL users) — used for cold-start
	// shrinkage. If we have neither user nor population data we must
	// abstain.
	popMean, popStd := d.store.GlobalCategoryStats(ctx, tx.Category)
	if n < minHistory && popStd == 0 {
		// No user baseline and no population baseline — nothing to say.
		return clean()
	}

	// Blend user statistics with the population baseline.
	alpha := float64(n) / float64(minHistory)
	if alpha > 1.0 {
		alpha = 1.0
	}

	var userMean, userStd float64
	if n > 0 {
		userMean = stat.Mean(amounts, nil)
		userStd = stat.StdDev(amounts, nil)
	}
	blendedMean := alpha*userMean + (1-alpha)*popMean
	blendedStd := alpha*userStd + (1-alpha)*popStd

	// If there is no spread, every transaction is "normal" by definition.
	if blendedStd == 0 {
		return clean()
	}

	z := (tx.Amount - blendedMean) / blendedStd
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
		Reasons:   []string{fmt.Sprintf("amount %.2f is %.2fσ above blended mean %.2f for category %q (σ=%.2f, n=%d, α=%.2f)", tx.Amount, z, blendedMean, tx.Category, blendedStd, n, alpha)},
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
//
// Cold-start shrinkage (Finding 3.8): the per-user Q1 / Q3 are blended
// with the population Q1 / Q3 using the same alpha = n / minHistory
// schedule as ZScoreDetector. A brand-new user is scored against the
// population Tukey fence rather than abstaining.
type IQRDetector struct {
	store      storage.Store
	multiplier float64 // IQR multiplier, default 1.5 (Tukey's 1.5)
}

// NewIQRDetector builds a detector with Tukey's standard 1.5 multiplier.
func NewIQRDetector(store storage.Store) *IQRDetector {
	return &IQRDetector{store: store, multiplier: 1.5}
}

// Name implements Detector.
func (d *IQRDetector) Name() string { return "iqr" }

// Score implements Detector.
func (d *IQRDetector) Score(tx models.Transaction) models.RiskScore {
	ctx := context.Background()
	hist, _ := d.store.GetUserHistory(ctx, tx.UserID)

	amounts := amountsOfCategory(hist, tx.Category)
	n := len(amounts)

	// Population quartiles (across ALL users) — used for cold-start
	// shrinkage.
	popQ1, popQ3 := d.store.GlobalCategoryQuartiles(ctx, tx.Category)
	if n < minHistory && popQ1 == 0 && popQ3 == 0 {
		// No baseline at all — abstain.
		return clean()
	}

	alpha := float64(n) / float64(minHistory)
	if alpha > 1.0 {
		alpha = 1.0
	}

	var userQ1, userQ3 float64
	if n > 0 {
		sorted := append([]float64(nil), amounts...)
		sort.Float64s(sorted)
		userQ1 = stat.Quantile(0.25, stat.LinInterp, sorted, nil)
		userQ3 = stat.Quantile(0.75, stat.LinInterp, sorted, nil)
	}
	blendedQ1 := alpha*userQ1 + (1-alpha)*popQ1
	blendedQ3 := alpha*userQ3 + (1-alpha)*popQ3
	iqr := blendedQ3 - blendedQ1

	// A zero IQR means the middle 50% of amounts are identical; the
	// fence collapses to a single point and the rule is meaningless.
	if iqr == 0 {
		return clean()
	}

	upper := blendedQ3 + d.multiplier*iqr
	lower := blendedQ1 - d.multiplier*iqr

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
				fmt.Sprintf("amount %.2f exceeds upper Tukey fence %.2f (Q1=%.2f Q3=%.2f IQR=%.2f, n=%d, α=%.2f)", tx.Amount, upper, blendedQ1, blendedQ3, iqr, n, alpha),
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
	store storage.Store
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
func NewVelocityDetector(store storage.Store) *VelocityDetector {
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
	ctx := context.Background()
	hist, _ := d.store.GetUserHistory(ctx, tx.UserID)
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

// EnsembleDetector fuses the outputs of several detectors with an
// always-voting log-odds combiner (Finding 3.7). Weights must be
// non-negative; they are normalised internally so the caller does not
// have to be precise.
//
// The fusion rule:
//
//	For each detector i:
//	  if it fired (score s_i > 0):   logit_i = ln(s_i / (1 - s_i))
//	  if it abstained (score == 0):  logit_i = ln(0.1 / 0.9) ≈ -2.197
//	                                     (weak evidence of innocence)
//	combined_logit = Σ(w_i · logit_i) / Σ(w_i)
//	combined       = 1 / (1 + exp(-combined_logit))
//
// Unlike the previous "weighted average of active voters only" rule,
// abstaining detectors now contribute a small negative log-odds. This
// means a single weak detector firing alone pulls the score up only
// slightly (its positive logit is diluted by the abstainers' negative
// logits) instead of jumping to its own internal score. The combiner is
// also well-defined when no detector fires: the all-abstain case yields
// combined_logit ≈ -2.197 → combined ≈ 0.1, which the pipeline then
// treats as "low" via SeverityFromScore.
type EnsembleDetector struct {
	detectors []Detector
	weights   []float64
}

// NewEnsembleDetector builds the default ensemble used in production.
//
// Seven detectors contribute to the final score:
//
//   - Z-Score (20%) — amount anomaly vs per-category baseline
//   - IQR (17%) — Tukey-fence amount outlier, per-category
//   - Velocity (12%) — rapid-fire transaction bursts
//   - Geo Distance (12%) — cross-border distance from home country
//   - Device Fingerprint (10%) — new / rarely-seen device
//   - Merchant Risk (15%) — curated high-risk merchant registry
//   - Behavioral Anomaly (14%) — off-hours / unusual time-of-week
//
// Weights sum to 1.00. The amount-based detectors still carry the most
// weight (37% combined) because they have the strongest individual signal,
// but the geo, device, merchant, and behavioural detectors add compound
// signal that catches fraud the amount detectors miss (e.g. a stolen card
// used in a new country for a "normal" amount at a high-risk merchant).
func NewEnsembleDetector(store storage.Store) *EnsembleDetector {
	return &EnsembleDetector{
		detectors: []Detector{
			NewZScoreDetector(store),
			NewIQRDetector(store),
			NewVelocityDetector(store),
			NewGeoDistanceDetector(store),
			NewDeviceFingerprintDetector(store),
			NewMerchantRiskDetector(store),
			NewBehavioralAnomalyDetector(store),
		},
		weights: []float64{0.20, 0.17, 0.12, 0.12, 0.10, 0.15, 0.14},
	}
}

// Name implements Detector.
func (d *EnsembleDetector) Name() string { return "ensemble" }

// Detectors returns the underlying sub-detectors. Exposed so callers
// (e.g. tests or a debug endpoint) can introspect the ensemble.
func (d *EnsembleDetector) Detectors() []Detector { return d.detectors }

// abstainLogit is the log-odds an abstaining detector contributes: a
// weak "evidence of innocence" prior of p=0.1 → logit = ln(0.1/0.9).
// Chosen to be small enough that a single firing detector can still
// raise the score, but large enough that a lone firing on an otherwise
// quiet ensemble doesn't saturate.
const abstainLogit = -2.1972245773362196 // ln(0.1 / 0.9)

// scoreToLogit converts a per-detector score in (0, 1) to log-odds.
// Scores of exactly 0 are treated as abstentions by the caller (the
// ensemble assigns abstainLogit rather than calling this). Scores very
// close to 0 or 1 are clamped to avoid ±Inf.
func scoreToLogit(s float64) float64 {
	switch {
	case s <= 1e-6:
		s = 1e-6
	case s >= 1-1e-6:
		s = 1 - 1e-6
	}
	return math.Log(s / (1 - s))
}

// Score implements Detector. See EnsembleDetector's doc comment for the
// fusion rule. Every detector contributes — abstainers push the score
// down, firers push it up. Reasons from firing detectors are aggregated.
func (d *EnsembleDetector) Score(tx models.Transaction) models.RiskScore {
	var (
		weightedLogit float64
		weightSum     float64
		reasons       []string
		fired         []string
	)

	for i, det := range d.detectors {
		w := d.weights[i]
		if w <= 0 {
			continue
		}
		rs := det.Score(tx)
		weightSum += w
		if rs.Score <= 0 {
			// Abstention: weak evidence of innocence.
			weightedLogit += w * abstainLogit
			continue
		}
		weightedLogit += w * scoreToLogit(rs.Score)
		fired = append(fired, det.Name())
		if len(rs.Reasons) > 0 {
			reasons = append(reasons, rs.Reasons...)
		}
	}

	var combined float64
	if weightSum > 0 {
		combinedLogit := weightedLogit / weightSum
		combined = 1.0 / (1.0 + math.Exp(-combinedLogit))
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
