// Package pipeline implements the unified scoring pipeline.
//
// Before Phase 1 the scoring logic lived in three places: the HTTP
// ScoreTransaction handler, the ScoreBatch handler (a trimmed copy), and
// the Kafka processMessage function (another trimmed copy). Each had its
// own slightly different ordering of the score → calibrate → rules →
// persist → case → notify steps, and only the HTTP path applied the
// FlagWeight blend and block/critical override (Finding 3.11). The
// Pipeline struct collapses all three into a single Process method that
// every entry point (HTTP, Kafka, future gRPC) calls.
//
// Pipeline.Process also enforces idempotency (Finding 3.14): a duplicate
// transaction ID is short-circuited via Store.SeenBefore rather than
// re-scored and re-persisted.
package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/cases"
	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/ml"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/rules"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/gadda00/fraud-detection-system/internal/webhooks"
	"github.com/rs/zerolog/log"
)

// Pipeline fuses the ensemble, rules engine, calibrator, persistence
// layer, case manager and notifier into a single Process entry point.
// Every ingestion path (HTTP /api/score, Kafka transactions topic, future
// gRPC) goes through this struct so the scoring logic is defined exactly
// once.
type Pipeline struct {
	Ensemble    *detector.EnsembleDetector
	Rules       *rules.Engine // may be nil — rules are optional
	Calibrator  *ml.LogisticCalibrator
	Store       storage.Store
	CaseManager *cases.Manager
	Notifier    webhooks.Notifier
}

// Result is the structured outcome of scoring one transaction. The HTTP
// layer re-shapes it into its JSON envelope; the Kafka layer into its
// alert message. Both transformations are pure formatting — no business
// logic leaks out of the pipeline.
type Result struct {
	Risk           models.RiskScore
	Calibrated     float64
	RuleMatches    []rules.RuleMatch
	CaseID         string
	Blocked        bool
	ReviewRequired bool
	LatencyUS      int64
}

// notifyTimeout caps how long the async webhook notification is allowed
// to run. The pipeline fires it in its own goroutine so it never blocks
// the response, but we still bound the goroutine's lifetime so a
// misbehaving webhook endpoint can't leak goroutines.
const notifyTimeout = 5 * time.Second

// Process scores a single transaction end-to-end. Steps (in order):
//
//  1. Idempotency check — if the transaction ID has been seen before,
//     return a synthetic "duplicate" result without re-scoring.
//  2. Run the statistical ensemble.
//  3. Calibrate the raw score to a probability.
//  4. Evaluate deterministic rules (if Rules is non-nil).
//  5. Blend rule-based FlagWeight into the ensemble score.
//  6. Apply block / critical override (forces score=1.0).
//  7. Persist via Store.Add.
//  8. Create a case if flagged / review-required / blocked.
//  9. Fire the notifier asynchronously if flagged.
//  10. Return the Result.
//
// The method never returns a non-nil error for scoring-related failures
// (the detectors are best-effort); it only returns an error if the
// context is cancelled before scoring completes. Callers should treat a
// non-nil error as "transaction not scored, do not commit offsets / do
// not ack".
func (p *Pipeline) Process(ctx context.Context, tx models.Transaction) (Result, error) {
	start := time.Now()

	// 1. Idempotency — short-circuit duplicates (Finding 3.14).
	if p.Store != nil && p.Store.SeenBefore(ctx, tx.ID) {
		return Result{
			Risk: models.RiskScore{
				Score:    0,
				Severity: models.SeverityLow,
				Reasons:  []string{"duplicate transaction — already scored"},
			},
			LatencyUS: time.Since(start).Microseconds(),
		}, nil
	}

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	// 2. Run the statistical ensemble.
	risk := p.Ensemble.Score(tx)

	// 3. Calibrate the raw score to a probability.
	var calibrated float64
	if p.Calibrator != nil {
		calibrated = p.Calibrator.Calibrate(risk.Score)
	}

	// 4. Evaluate deterministic rules.
	var ruleMatches []rules.RuleMatch
	if p.Rules != nil {
		ruleMatches = p.Rules.Evaluate(tx)
	}
	blocked := rules.HasBlock(ruleMatches)
	reviewRequired := rules.HasReview(ruleMatches)

	// 5. Blend rule-based flag weights into the ensemble score.
	//
	// Each rule with Action=flag contributes its weight; the sum is
	// capped at 1.0 by FlagWeight. We blend multiplicatively into the
	// ensemble score via the standard "score = score + w*(1-score)"
	// update — this raises the score proportionally to the remaining
	// headroom to 1.0, so a strong ensemble score (0.9) is nudged less
	// than a weak one (0.2). This happens *before* the block/critical
	// override below so a hard-block still forces 1.0.
	if flagWeight := rules.FlagWeight(ruleMatches); flagWeight > 0 {
		risk.Score = risk.Score + flagWeight*(1-risk.Score)
		if risk.Score > 1.0 {
			risk.Score = 1.0
		}
		risk.Severity = models.SeverityFromScore(risk.Score)
		risk.Reasons = append(risk.Reasons, fmt.Sprintf("rule-based flag weight %.2f applied", flagWeight))
	}

	// 6. If blocked or high-severity, override the score to 1.0.
	if blocked || risk.Severity == models.SeverityCritical {
		risk.Score = 1.0
		risk.Severity = models.SeverityCritical
	}

	// 7. Persist the transaction + score.
	if p.Store != nil {
		if err := p.Store.Add(ctx, tx, risk); err != nil {
			log.Error().Err(err).Str("tx_id", tx.ID).Msg("pipeline: store.Add failed")
			// Persistence failure is non-fatal for the response — we
			// still return the score so the caller can act on it. The
			// transaction will simply not appear in future baselines,
			// which is the correct degradation for an in-memory store
			// under memory pressure.
		}
	}

	// 8. Create a case if flagged or review-required.
	var caseID string
	if risk.IsFlagged() || reviewRequired || blocked {
		var ruleIDs []string
		for _, m := range ruleMatches {
			ruleIDs = append(ruleIDs, m.Rule.ID)
		}
		if p.CaseManager != nil {
			caseID = p.CaseManager.Create(tx, risk, ruleIDs)
		}
	}

	// 9. Fire webhook (async — don't block the response).
	if risk.IsFlagged() && p.Notifier != nil {
		notifier := p.Notifier
		go func() {
			nctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
			defer cancel()
			if err := notifier.Notify(nctx, tx, risk); err != nil {
				log.Error().Err(err).Str("tx_id", tx.ID).Msg("webhook notify failed")
			}
		}()
	}

	return Result{
		Risk:           risk,
		Calibrated:     calibrated,
		RuleMatches:    ruleMatches,
		CaseID:         caseID,
		Blocked:        blocked,
		ReviewRequired: reviewRequired,
		LatencyUS:      time.Since(start).Microseconds(),
	}, nil
}
