package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/cases"
	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/ml"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/rules"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/gadda00/fraud-detection-system/internal/webhooks"
)

// newTestPipeline wires a Pipeline against a fresh in-memory store with
// no rules and a noop notifier. The store is pre-seeded with a small
// realistic baseline so the ensemble has something to compare against.
func newTestPipeline(t *testing.T) (*Pipeline, *storage.MemStore) {
	t.Helper()
	store := storage.New()
	// Seed enough user history that the amount detectors don't abstain.
	for i := 0; i < 6; i++ {
		_ = store.Seed(context.Background(), models.Transaction{
			ID:        "seed-u1-shopping",
			UserID:    "u1",
			Amount:    30 + float64(i),
			Category:  "shopping",
			Country:   "US",
			DeviceID:  "dev-1",
			Timestamp: time.Now().Add(-time.Duration(6-i) * time.Hour),
		})
	}
	pipe := &Pipeline{
		Ensemble:    detector.NewEnsembleDetector(store),
		Calibrator:  ml.NewLogisticCalibrator(),
		Store:       store,
		CaseManager: cases.NewManager(),
		Notifier:    webhooks.NoopNotifier{},
	}
	return pipe, store
}

// TestProcess_DuplicateShortCircuits verifies the idempotency check
// (Finding 3.14): a second call with the same tx.ID returns a synthetic
// "duplicate" result and does NOT re-score, re-persist, or create
// another case.
func TestProcess_DuplicateShortCircuits(t *testing.T) {
	pipe, store := newTestPipeline(t)
	ctx := context.Background()
	tx := models.Transaction{
		ID:        "tx-dup-1",
		UserID:    "u1",
		Amount:    5000, // large enough to be flagged on the first pass
		Category:  "shopping",
		Country:   "US",
		DeviceID:  "dev-1",
		Timestamp: time.Now(),
	}

	first, err := pipe.Process(ctx, tx)
	if err != nil {
		t.Fatalf("first Process: %v", err)
	}
	_ = first // we only care that the call succeeded and persisted the ID

	scoredBefore, _ := store.GetStats(ctx)
	casesBefore := len(pipe.CaseManager.List(""))

	// Second call with the SAME tx.ID must short-circuit.
	second, err := pipe.Process(ctx, tx)
	if err != nil {
		t.Fatalf("second Process: %v", err)
	}
	if second.Risk.Score != 0 {
		t.Fatalf("duplicate should short-circuit to score=0, got %v", second.Risk.Score)
	}
	if len(second.Risk.Reasons) == 0 || second.Risk.Reasons[0] != "duplicate transaction — already scored" {
		t.Fatalf("duplicate reason missing, got %v", second.Risk.Reasons)
	}

	// Verify nothing was re-scored or re-cased.
	scoredAfter, _ := store.GetStats(ctx)
	if scoredAfter.TotalScored != scoredBefore.TotalScored {
		t.Fatalf("duplicate should not bump TotalScored: before=%d after=%d",
			scoredBefore.TotalScored, scoredAfter.TotalScored)
	}
	casesAfter := len(pipe.CaseManager.List(""))
	if casesAfter != casesBefore {
		t.Fatalf("duplicate should not create a new case: before=%d after=%d",
			casesBefore, casesAfter)
	}
}

// TestProcess_BlockRuleForcesMaxScore verifies that an Action=block rule
// forces the score to 1.0 and sets Blocked=true on the result, even when
// the ensemble score would have been low.
func TestProcess_BlockRuleForcesMaxScore(t *testing.T) {
	pipe, store := newTestPipeline(t)
	pipe.Rules = rules.NewEngineFromRules([]rules.Rule{
		{
			ID:          "block_high_value",
			Description: "Block transactions >= $10000",
			Match:       rules.Match{AmountMin: 10000},
			Action:      rules.ActionBlock,
			Weight:      1.0,
		},
	})

	tx := models.Transaction{
		ID:        "tx-block-1",
		UserID:    "u1",
		Amount:    15000,
		Category:  "shopping",
		Country:   "US",
		DeviceID:  "dev-1",
		Timestamp: time.Now(),
	}
	res, err := pipe.Process(context.Background(), tx)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Blocked {
		t.Fatal("expected Blocked=true for block-rule match")
	}
	if res.Risk.Score != 1.0 {
		t.Fatalf("expected score=1.0 for block rule, got %v", res.Risk.Score)
	}
	if res.Risk.Severity != models.SeverityCritical {
		t.Fatalf("expected critical severity, got %v", res.Risk.Severity)
	}
	if res.CaseID == "" {
		t.Fatal("expected a case to be created for a blocked transaction")
	}
	_ = store // silence unused warning if assertions grow
}

// TestProcess_FlagWeightBlendsEnsembleScore verifies the FlagWeight
// blend: with a low ensemble score and a rule with Action=flag
// weight=0.5, the final score is pushed up by the headroom-aware
// formula score += w*(1-score). The block/critical override is NOT
// triggered, so the final score should land between the ensemble score
// and 1.0, and the reason list should mention the flag weight.
//
// Two fresh pipelines are used (one for baseline, one for the flag
// case) so the Store.Add inside the first Process call doesn't pollute
// the baseline of the second.
func TestProcess_FlagWeightBlendsEnsembleScore(t *testing.T) {
	basePipe, _ := newTestPipeline(t)

	// A transaction the ensemble scores LOW: in-profile amount, home
	// country, trusted device, no high-risk merchant.
	baseTx := models.Transaction{
		ID:        "tx-baseline",
		UserID:    "u1",
		Amount:    32,
		Category:  "shopping",
		Country:   "US",
		DeviceID:  "dev-1",
		Timestamp: time.Now(),
	}
	baseline, err := basePipe.Process(context.Background(), baseTx)
	if err != nil {
		t.Fatalf("baseline Process: %v", err)
	}
	if baseline.Risk.Score >= 0.5 {
		t.Fatalf("test setup invariant failed: expected baseline ensemble score <0.5, got %v", baseline.Risk.Score)
	}

	// A fresh pipeline so the Store.Add doesn't change the baseline the
	// flag call is scored against. Same seed data, plus the FlagWeight
	// rule. The rule matches a benign merchant substring ("acme") so
	// the ensemble's own MerchantRiskDetector doesn't fire — we want
	// the FlagWeight blend to be the ONLY difference between baseline
	// and flag.
	flagPipe, _ := newTestPipeline(t)
	flagPipe.Rules = rules.NewEngineFromRules([]rules.Rule{
		{
			ID:          "flag_acme",
			Description: "Flag Acme merchant",
			Match:       rules.Match{Merchants: []string{"acme"}},
			Action:      rules.ActionFlag,
			Weight:      0.5,
		},
	})
	flagTx := baseTx
	flagTx.ID = "tx-flag"
	flagTx.Merchant = "AcmeTestMerchant" // not in the high-risk registry
	res, err := flagPipe.Process(context.Background(), flagTx)
	if err != nil {
		t.Fatalf("flag Process: %v", err)
	}

	// Expected: score = baseline + 0.5*(1-baseline) = 0.5 + 0.5*baseline.
	// The two pipelines have identical seed data and the ensemble sees
	// the same per-user history for both calls (the only difference
	// between baseTx and flagTx is the ID + Merchant, neither of which
	// influences the ensemble's amount/geo/device/velocity/behavioral
	// detectors, and the merchant isn't in the risk registry).
	expected := baseline.Risk.Score + 0.5*(1-baseline.Risk.Score)
	if !approxEqual(res.Risk.Score, expected, 1e-6) {
		t.Fatalf("FlagWeight blend: expected ~%.6f, got %.6f (baseline=%.6f)",
			expected, res.Risk.Score, baseline.Risk.Score)
	}

	// The reason list should record that the flag weight was applied.
	found := false
	for _, r := range res.Risk.Reasons {
		if r == "rule-based flag weight 0.50 applied" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 'rule-based flag weight 0.50 applied' reason, got %v", res.Risk.Reasons)
	}
}

// TestProcess_DuplicateDoesNotBlock verifies that a legitimate first
// score and then a duplicate returns a non-flagged duplicate result even
// when the first call had IsFlagged()=true.
func TestProcess_DuplicateDoesNotBlock(t *testing.T) {
	pipe, _ := newTestPipeline(t)
	pipe.Rules = rules.NewEngineFromRules([]rules.Rule{
		{
			ID:          "block_high_value",
			Description: "Block >= $10000",
			Match:       rules.Match{AmountMin: 10000},
			Action:      rules.ActionBlock,
		},
	})
	tx := models.Transaction{
		ID:        "tx-block-dup",
		UserID:    "u1",
		Amount:    12000,
		Category:  "shopping",
		Country:   "US",
		DeviceID:  "dev-1",
		Timestamp: time.Now(),
	}
	if _, err := pipe.Process(context.Background(), tx); err != nil {
		t.Fatalf("first Process: %v", err)
	}
	dup, err := pipe.Process(context.Background(), tx)
	if err != nil {
		t.Fatalf("duplicate Process: %v", err)
	}
	if dup.Blocked {
		t.Fatal("duplicate result should not be Blocked")
	}
	if dup.CaseID != "" {
		t.Fatalf("duplicate result should not create a case, got %q", dup.CaseID)
	}
}

func approxEqual(a, b, tol float64) bool {
	if a-b > tol || b-a > tol {
		return false
	}
	return true
}
