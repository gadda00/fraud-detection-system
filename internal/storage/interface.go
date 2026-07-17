// Package storage — Store interface.
//
// The Store interface is the contract every storage backend must satisfy
// to be usable by the detection pipeline. Today only the in-memory MemStore
// (see storage.go) satisfies it; the Redis and Postgres backends will be
// migrated in Phase 2 (see the Phase 0 worklog, "Built, not yet wired").
//
// The interface deliberately carries a context.Context on every method:
// the in-memory implementation ignores it, but a future Postgres or Redis
// implementation needs it for cancellation / timeouts on every network
// round-trip. Having it on the interface from day one means the call sites
// (Pipeline, detectors, handlers) don't have to change again when the
// production backends are wired in.
//
// Two methods go beyond the historical "history + stats" surface:
//
//   - SeenBefore(ctx, txID) — idempotency check. The pipeline uses it to
//     short-circuit duplicate transaction IDs without re-scoring. This is
//     the fix for Finding 3.14.
//   - GlobalCategoryStats(ctx, category) — population-level mean / std
//     used by the cold-start shrinkage in the Z-Score and IQR detectors
//     (Finding 3.8). Without it, brand-new users fall off a "5 history
//     minimum" cliff and every detector abstains.
package storage

import (
	"context"

	"github.com/gadda00/fraud-detection-system/internal/models"
)

// Store is the contract the detection pipeline depends on. The in-memory
// MemStore satisfies it; Redis and Postgres will be migrated in Phase 2.
type Store interface {
	// Add records a transaction + its risk score against the user's
	// history and bumps the aggregate counters. Implementations should
	// also mark the transaction ID as seen so a subsequent SeenBefore
	// call returns true.
	Add(ctx context.Context, tx models.Transaction, score models.RiskScore) error

	// Seed inserts a transaction into history *without* touching the
	// aggregate scoring counters. Used by the seed-data loader so the
	// detectors have a baseline the moment the first live request
	// arrives, without polluting /api/stats with 1000 fake "scored"
	// events.
	Seed(ctx context.Context, tx models.Transaction) error

	// GetUserHistory returns a defensive copy of the user's transaction
	// history (oldest first). Callers may mutate the returned slice
	// freely.
	GetUserHistory(ctx context.Context, userID string) ([]models.Transaction, error)

	// GetStats returns a snapshot of the aggregate counters.
	GetStats(ctx context.Context) (Stats, error)

	// UserCount returns the number of users currently tracked.
	UserCount(ctx context.Context) (int, error)

	// SeenBefore reports whether a transaction with the given ID has
	// already been recorded (via Add or Seed). Used by the pipeline for
	// idempotency: a duplicate transaction ID is short-circuited to a
	// cached zero-risk result rather than re-scored and re-persisted.
	SeenBefore(ctx context.Context, txID string) bool

	// GlobalCategoryStats returns the population-level mean and standard
	// deviation of transaction amounts for the given category across
	// *all* users. Used by the cold-start shrinkage in the Z-Score
	// detector so a brand-new user (no per-user history yet) is scored
	// against the population baseline rather than abstaining.
	// If the population has fewer than two transactions in the category
	// both returns are 0 (and the caller is expected to abstain).
	GlobalCategoryStats(ctx context.Context, category string) (mean, std float64)

	// GlobalCategoryQuartiles returns the population-level first and
	// third quartiles (Q1, Q3) of transaction amounts for the given
	// category across *all* users. Used by the IQR detector's
	// cold-start shrinkage — the same role GlobalCategoryStats plays
	// for the Z-Score detector. Returns (0, 0) when the population has
	// fewer than four transactions in the category (quantiles are too
	// noisy below that).
	GlobalCategoryQuartiles(ctx context.Context, category string) (q1, q3 float64)
}
