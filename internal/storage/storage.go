// Package storage provides an in-memory, thread-safe store of per-user
// transaction history. It is the single source of truth that detectors
// consult when computing baselines (mean, std-dev, IQR, velocity).
//
// The store is intentionally bounded: only the most recent
// maxHistoryPerUser transactions are retained per user. This keeps memory
// predictable under load and means baselines naturally reflect recent
// behaviour rather than a user's entire lifetime history.
package storage

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"gonum.org/v1/gonum/stat"
)

// maxHistoryPerUser caps how many transactions we remember per user.
// 100 is large enough to give the statistical detectors a stable
// baseline, but small enough that memory stays bounded at scale.
const maxHistoryPerUser = 100

// Stats summarises everything the store has observed since startup. It is
// surfaced through the /api/stats endpoint.
type Stats struct {
	TotalScored   int            `json:"total_scored"`
	TotalFlagged  int            `json:"total_flagged"`
	UsersTracked  int            `json:"users_tracked"`
	BySeverity    map[string]int `json:"by_severity"`
	StartedAt     time.Time      `json:"started_at"`
	UptimeSeconds int64          `json:"uptime_seconds"`
}

// MemStore is the in-memory implementation of the Store interface. It is
// safe for concurrent use by many goroutines. All public methods take a
// write or read lock as appropriate; the context.Context parameters are
// accepted to satisfy the Store interface but are otherwise unused
// (there is no I/O to cancel).
//
// The concrete type is MemStore (not Store) so the interface name Store
// is unambiguous in call sites — every consumer depends on the Store
// interface, only main.go and tests instantiate the concrete MemStore
// via New().
type MemStore struct {
	mu sync.RWMutex

	// history maps userID -> chronological slice of transactions
	// (oldest first, newest last).
	history map[string][]models.Transaction

	// seenIDs records every transaction ID ever passed to Add or Seed,
	// so SeenBefore can short-circuit duplicates (Finding 3.14,
	// idempotency). It grows unbounded across the process lifetime,
	// which is acceptable for an in-memory dev store; the Postgres
	// backend uses the transactions table's primary key for the same
	// check.
	seenIDs map[string]bool

	// Running aggregate counters, updated atomically with Add.
	totalScored  int
	totalFlagged int
	bySeverity   map[string]int

	startedAt time.Time
}

// New returns an empty, ready-to-use MemStore.
func New() *MemStore {
	return &MemStore{
		history:    make(map[string][]models.Transaction),
		seenIDs:    make(map[string]bool),
		bySeverity: make(map[string]int),
		startedAt:  time.Now(),
	}
}

// compile-time assertion that *MemStore satisfies Store.
var _ Store = (*MemStore)(nil)

// Add records a transaction against the user's history and bumps the
// aggregate counters. If the user's ring buffer is full the oldest entry
// is dropped. The transaction's ID is marked as seen for idempotency.
func (s *MemStore) Add(ctx context.Context, tx models.Transaction, score models.RiskScore) error {
	_ = ctx // in-memory: no I/O to cancel

	s.mu.Lock()
	defer s.mu.Unlock()

	s.appendLocked(tx)
	if tx.ID != "" {
		s.seenIDs[tx.ID] = true
	}

	s.totalScored++
	if score.IsFlagged() {
		s.totalFlagged++
	}
	sev := score.Severity
	if sev == "" {
		sev = models.SeverityFromScore(score.Score)
	}
	s.bySeverity[sev]++
	return nil
}

// Seed inserts a transaction into history *without* touching the aggregate
// scoring counters. It is used by the seed-data loader so that the
// detectors have a realistic baseline the moment the first live request
// arrives, without polluting /api/stats with 1000 fake "scored" events.
// The transaction's ID is still marked as seen — seed transactions are
// real history and must not be re-scored if a duplicate arrives.
func (s *MemStore) Seed(ctx context.Context, tx models.Transaction) error {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	s.appendLocked(tx)
	if tx.ID != "" {
		s.seenIDs[tx.ID] = true
	}
	return nil
}

// appendLocked is the shared body of Add and Seed: it appends tx to the
// user's ring buffer and trims to maxHistoryPerUser. Caller must hold
// s.mu.
func (s *MemStore) appendLocked(tx models.Transaction) {
	hist := s.history[tx.UserID]
	hist = append(hist, tx)
	if len(hist) > maxHistoryPerUser {
		// Drop the oldest entries to keep the slice bounded. Copying the
		// tail avoids retaining the underlying array forever.
		hist = append([]models.Transaction(nil), hist[len(hist)-maxHistoryPerUser:]...)
	}
	s.history[tx.UserID] = hist
}

// GetUserHistory returns a defensive copy of the user's transaction
// history (oldest first). Callers may mutate the returned slice freely.
func (s *MemStore) GetUserHistory(ctx context.Context, userID string) ([]models.Transaction, error) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()

	hist, ok := s.history[userID]
	if !ok {
		return nil, nil
	}
	// Copy so detectors can sort/slice without racing a future Add.
	out := make([]models.Transaction, len(hist))
	copy(out, hist)
	return out, nil
}

// GetStats returns a snapshot of the aggregate counters. The maps inside
// the returned struct are fresh copies, so callers cannot mutate the
// store's internal state through them.
func (s *MemStore) GetStats(ctx context.Context) (Stats, error) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()

	bySev := make(map[string]int, len(s.bySeverity))
	for k, v := range s.bySeverity {
		bySev[k] = v
	}

	return Stats{
		TotalScored:   s.totalScored,
		TotalFlagged:  s.totalFlagged,
		UsersTracked:  len(s.history),
		BySeverity:    bySev,
		StartedAt:     s.startedAt,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
	}, nil
}

// UserCount returns the number of users currently tracked. Useful for
// smoke tests.
func (s *MemStore) UserCount(ctx context.Context) (int, error) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.history), nil
}

// SeenBefore reports whether a transaction with the given ID has been
// recorded via Add or Seed. Used by the pipeline for idempotency.
func (s *MemStore) SeenBefore(ctx context.Context, txID string) bool {
	_ = ctx

	if txID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seenIDs[txID]
}

// GlobalCategoryStats returns the population-level mean and standard
// deviation of transaction amounts for the given category, computed
// across every user's history. Used by the Z-Score detector for
// cold-start shrinkage (Finding 3.8): a brand-new user with no
// per-category history is scored against the population baseline rather
// than abstaining.
//
// If the population has fewer than two transactions in the category the
// std-dev is meaningless, so both returns are zero (and the caller is
// expected to abstain).
func (s *MemStore) GlobalCategoryStats(ctx context.Context, category string) (mean, std float64) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()

	var amounts []float64
	for _, hist := range s.history {
		for _, h := range hist {
			if h.Category == category {
				amounts = append(amounts, h.Amount)
			}
		}
	}
	if len(amounts) < 2 {
		return 0, 0
	}
	mean = stat.Mean(amounts, nil)
	std = stat.StdDev(amounts, nil)
	if math.IsNaN(mean) || math.IsNaN(std) {
		return 0, 0
	}
	return mean, std
}

// GlobalCategoryQuartiles returns the population-level first and third
// quartiles of transaction amounts for the given category, computed
// across every user's history. Used by the IQR detector for cold-start
// shrinkage.
//
// Returns (0, 0) when the population has fewer than four transactions
// in the category — below that the quantile estimates are too noisy.
func (s *MemStore) GlobalCategoryQuartiles(ctx context.Context, category string) (q1, q3 float64) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()

	var amounts []float64
	for _, hist := range s.history {
		for _, h := range hist {
			if h.Category == category {
				amounts = append(amounts, h.Amount)
			}
		}
	}
	if len(amounts) < 4 {
		return 0, 0
	}
	sort.Float64s(amounts)
	q1 = stat.Quantile(0.25, stat.LinInterp, amounts, nil)
	q3 = stat.Quantile(0.75, stat.LinInterp, amounts, nil)
	if math.IsNaN(q1) || math.IsNaN(q3) {
		return 0, 0
	}
	return q1, q3
}
