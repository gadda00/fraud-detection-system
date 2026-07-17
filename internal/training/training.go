// Package training implements the offline model retraining pipeline.
//
// The calibrator (logistic regression on top of the ensemble's raw score)
// needs to be periodically refitted as new labelled data arrives — analysts
// confirm or clear cases, and that feedback should feed back into the model.
//
// The pipeline runs as a background goroutine on a configurable schedule
// (default: nightly at 2 AM). It:
//
//  1. Pulls all resolved cases from the case manager.
//  2. Re-runs each case's transaction through the ensemble to get a fresh
//     raw score.
//  3. Pairs the raw score with the analyst's verdict (confirmed fraud vs
//     false positive).
//  4. Fits a new logistic calibrator on the pairs.
//  5. Hot-swaps the calibrator in a thread-safe way.
//
// The pipeline also computes a confusion matrix on the training data and
// logs recall / precision / F1 so you can watch the model improve (or
// regress) over time.
package training

import (
	"context"
	"sync"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/cases"
	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/ml"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/rs/zerolog/log"
)

// Pipeline runs the nightly retraining job.
type Pipeline struct {
	mu          sync.Mutex
	calibrator  *ml.LogisticCalibrator
	ensemble    *detector.EnsembleDetector
	store       storage.Store
	caseManager *cases.Manager
	schedule    time.Duration
}

// NewPipeline builds a retraining pipeline. The calibrator is the live
// one (hot-swapped in place after each retrain). The ensemble + store are
// used to re-score historical transactions. The case manager provides the
// analyst labels.
func NewPipeline(
	calibrator *ml.LogisticCalibrator,
	ensemble *detector.EnsembleDetector,
	store storage.Store,
	caseManager *cases.Manager,
	schedule time.Duration,
) *Pipeline {
	if schedule == 0 {
		schedule = 24 * time.Hour
	}
	return &Pipeline{
		calibrator:  calibrator,
		ensemble:    ensemble,
		store:       store,
		caseManager: caseManager,
		schedule:    schedule,
	}
}

// Start runs the retraining loop in a background goroutine. The first
// retrain happens after `schedule`; subsequent retrains run on the same
// cadence. Call Stop() to cancel.
func (p *Pipeline) Start(ctx context.Context) {
	log.Info().Dur("schedule", p.schedule).Msg("retraining pipeline started")

	go func() {
		ticker := time.NewTicker(p.schedule)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("retraining pipeline stopping")
				return
			case <-ticker.C:
				if err := p.Retrain(ctx); err != nil {
					log.Error().Err(err).Msg("retraining pipeline failed")
				}
			}
		}
	}()
}

// Retrain runs one retraining cycle. It is also exported so it can be
// triggered manually via an admin API endpoint.
//
// The cycle:
//  1. Pull all resolved cases (confirmed fraud + false positives).
//  2. For each case, reconstruct the transaction from the case record and
//     re-score it through the ensemble.
//  3. Fit a new calibrator on the (raw_score, label) pairs.
//  4. Hot-swap the calibrator.
//  5. Log the before/after confusion-matrix metrics.
func (p *Pipeline) Retrain(ctx context.Context) error {
	start := time.Now()

	// Gather resolved cases.
	allCases := p.caseManager.List("")
	var pairs []ml.LabelledPair
	var tp, fp, fn, tn int

	for _, c := range allCases {
		if c.Status != cases.StatusConfirmed && c.Status != cases.StatusFalsePositive {
			continue
		}
		// Reconstruct the transaction from the case record.
		tx := models.Transaction{
			ID:       c.TransactionID,
			UserID:   c.UserID,
			Amount:   c.Amount,
			Currency: c.Currency,
			Merchant: c.Merchant,
			Category: c.Category,
			Country:  c.Country,
		}

		// Re-score using the ensemble (this is the raw score, pre-calibration).
		risk := p.ensemble.Score(tx)
		label := c.Status == cases.StatusConfirmed
		pairs = append(pairs, ml.LabelledPair{Score: risk.Score, Label: label})

		// Confusion matrix on the raw (pre-calibration) score.
		flagged := risk.IsFlagged()
		switch {
		case label && flagged:
			tp++
		case label && !flagged:
			fn++
		case !label && flagged:
			fp++
		default:
			tn++
		}
	}

	if len(pairs) == 0 {
		log.Info().Msg("retraining skipped — no resolved cases yet")
		return nil
	}

	// Fit a new calibrator.
	newCal := ml.NewLogisticCalibrator()
	newCal.Fit(pairs, 500, 0.1)
	a, b := newCal.Coefficients()

	// Hot-swap.
	p.mu.Lock()
	// Copy the fitted coefficients into the live calibrator.
	liveA, liveB := p.calibrator.Coefficients()
	_ = liveA
	_ = liveB
	// Re-fit the live calibrator with the same pairs (avoids exposing
	// internal setter methods).
	p.calibrator.Fit(pairs, 500, 0.1)
	p.mu.Unlock()

	// Compute metrics.
	var recall, precision, f1 float64
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	log.Info().
		Int("cases", len(pairs)).
		Int("tp", tp).Int("fp", fp).Int("fn", fn).Int("tn", tn).
		Float64("recall", recall).
		Float64("precision", precision).
		Float64("f1", f1).
		Float64("a", a).Float64("b", b).
		Dur("duration", time.Since(start)).
		Msg("retraining complete — calibrator updated")

	return nil
}

// CalibratorCoefficients returns the current calibrator's (a, b) — useful
// for an admin endpoint that exposes the model state.
func (p *Pipeline) CalibratorCoefficients() (a, b float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calibrator.Coefficients()
}
