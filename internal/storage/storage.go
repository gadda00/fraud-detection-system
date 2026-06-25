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
	"sync"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
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

// Store is safe for concurrent use by many goroutines. All public methods
// take either a read or write lock as appropriate.
type Store struct {
	mu sync.RWMutex

	// history maps userID -> chronological slice of transactions
	// (oldest first, newest last).
	history map[string][]models.Transaction

	// Running aggregate counters, updated atomically with Add.
	totalScored  int
	totalFlagged int
	bySeverity   map[string]int

	startedAt time.Time
}

// New returns an empty, ready-to-use store.
func New() *Store {
	return &Store{
		history:    make(map[string][]models.Transaction),
		bySeverity: make(map[string]int),
		startedAt:  time.Now(),
	}
}

// Add records a transaction against the user's history and bumps the
// aggregate counters. If the user's ring buffer is full the oldest entry
// is dropped.
func (s *Store) Add(tx models.Transaction, score models.RiskScore) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hist := s.history[tx.UserID]
	hist = append(hist, tx)
	if len(hist) > maxHistoryPerUser {
		// Drop the oldest entries to keep the slice bounded. Copying the
		// tail avoids retaining the underlying array forever.
		hist = append([]models.Transaction(nil), hist[len(hist)-maxHistoryPerUser:]...)
	}
	s.history[tx.UserID] = hist

	s.totalScored++
	if score.IsFlagged() {
		s.totalFlagged++
	}
	sev := score.Severity
	if sev == "" {
		sev = models.SeverityFromScore(score.Score)
	}
	s.bySeverity[sev]++
}

// Seed inserts a transaction into history *without* touching the aggregate
// scoring counters. It is used by the seed-data loader so that the
// detectors have a realistic baseline the moment the first live request
// arrives, without polluting /api/stats with 1000 fake "scored" events.
func (s *Store) Seed(tx models.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hist := s.history[tx.UserID]
	hist = append(hist, tx)
	if len(hist) > maxHistoryPerUser {
		hist = append([]models.Transaction(nil), hist[len(hist)-maxHistoryPerUser:]...)
	}
	s.history[tx.UserID] = hist
}

// GetUserHistory returns a defensive copy of the user's transaction
// history (oldest first). Callers may mutate the returned slice freely.
func (s *Store) GetUserHistory(userID string) []models.Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hist, ok := s.history[userID]
	if !ok {
		return nil
	}
	// Copy so detectors can sort/slice without racing a future Add.
	out := make([]models.Transaction, len(hist))
	copy(out, hist)
	return out
}

// GetStats returns a snapshot of the aggregate counters. The maps inside
// the returned struct are fresh copies, so callers cannot mutate the
// store's internal state through them.
func (s *Store) GetStats() Stats {
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
	}
}

// UserCount returns the number of users currently tracked. Useful for
// smoke tests.
func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.history)
}
