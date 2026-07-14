// Package storage — Postgres-backed persistent store.
//
// PostgresStore persists per-user transaction history in a `transactions`
// table. Unlike the in-memory Store (which is lost on restart) and Redis
// (which is volatile unless AOF is enabled), Postgres is the durable,
// queryable, ACID-compliant backend suitable for regulated finance.
//
// The schema is intentionally simple — one row per transaction with a
// composite index on (user_id, timestamp) for the history scans that the
// detectors perform. For very-high-throughput deployments, consider
// partitioning by user_id hash or by time range.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxHistoryPerUserPostgres mirrors the in-memory cap.
const maxHistoryPerUserPostgres = 100

// PostgresStore persists transactions and aggregate stats to Postgres.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore opens a connection pool to dsn and runs the schema
// migration (CREATE TABLE IF NOT EXISTS). The pool is sized for 20
// concurrent connections by default; tune via the DSN's pool_max_conns.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres migrate: %w", err)
	}
	return s, nil
}

// Close releases the connection pool.
func (p *PostgresStore) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// migrate creates the tables and indexes if they don't exist. Idempotent.
func (p *PostgresStore) migrate(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS transactions (
    id           TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    amount       DOUBLE PRECISION NOT NULL,
    currency     TEXT NOT NULL DEFAULT 'USD',
    merchant     TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    device_id    TEXT NOT NULL DEFAULT '',
    timestamp    TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_transactions_user_ts ON transactions (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_user_category ON transactions (user_id, category);

CREATE TABLE IF NOT EXISTS fraud_stats (
    key           TEXT PRIMARY KEY,
    int_value     BIGINT,
    text_value    TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fraud_severity_counts (
    severity      TEXT PRIMARY KEY,
    count         BIGINT NOT NULL DEFAULT 0
);
`)
	return err
}

// Add records a transaction and bumps the aggregate counters in a single
// transaction. The history is capped at maxHistoryPerUserPostgres per user
// (older rows are deleted to keep the table from growing unbounded).
func (p *PostgresStore) Add(ctx context.Context, tx models.Transaction, score models.RiskScore) error {
	dbTx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = dbTx.Rollback(ctx) }() // safe to call after commit

	if _, err := dbTx.Exec(ctx,
		"INSERT INTO transactions (id, user_id, amount, currency, merchant, category, country, device_id, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		tx.ID, tx.UserID, tx.Amount, tx.Currency, tx.Merchant, tx.Category, tx.Country, tx.DeviceID, tx.Timestamp); err != nil {
		return fmt.Errorf("insert tx: %w", err)
	}

	if _, err := dbTx.Exec(ctx,
		"INSERT INTO fraud_stats (key, int_value, updated_at) VALUES ('total_scored', 1, NOW()) ON CONFLICT (key) DO UPDATE SET int_value = fraud_stats.int_value + 1, updated_at = NOW()"); err != nil {
		return fmt.Errorf("incr total_scored: %w", err)
	}

	if score.IsFlagged() {
		if _, err := dbTx.Exec(ctx,
			"INSERT INTO fraud_stats (key, int_value, updated_at) VALUES ('total_flagged', 1, NOW()) ON CONFLICT (key) DO UPDATE SET int_value = fraud_stats.int_value + 1, updated_at = NOW()"); err != nil {
			return fmt.Errorf("incr total_flagged: %w", err)
		}
	}

	sev := score.Severity
	if sev == "" {
		sev = models.SeverityFromScore(score.Score)
	}
	if _, err := dbTx.Exec(ctx,
		"INSERT INTO fraud_severity_counts (severity, count) VALUES ($1, 1) ON CONFLICT (severity) DO UPDATE SET count = fraud_severity_counts.count + 1", sev); err != nil {
		return fmt.Errorf("incr severity: %w", err)
	}

	// Cap history per user (delete oldest beyond the cap).
	if _, err := dbTx.Exec(ctx,
		"DELETE FROM transactions WHERE user_id = $1 AND id NOT IN (SELECT id FROM transactions WHERE user_id = $1 ORDER BY timestamp DESC LIMIT $2)",
		tx.UserID, maxHistoryPerUserPostgres); err != nil {
		return fmt.Errorf("cap history: %w", err)
	}

	return dbTx.Commit(ctx)
}

// Seed inserts a transaction without touching the aggregate counters.
func (p *PostgresStore) Seed(ctx context.Context, tx models.Transaction) error {
	_, err := p.pool.Exec(ctx,
		"INSERT INTO transactions (id, user_id, amount, currency, merchant, category, country, device_id, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
		tx.ID, tx.UserID, tx.Amount, tx.Currency, tx.Merchant, tx.Category, tx.Country, tx.DeviceID, tx.Timestamp)
	return err
}

// GetUserHistory returns up to the last maxHistoryPerUserPostgres
// transactions for the user, oldest first (to match the in-memory Store).
func (p *PostgresStore) GetUserHistory(ctx context.Context, userID string) ([]models.Transaction, error) {
	rows, err := p.pool.Query(ctx,
		"SELECT id, user_id, amount, currency, merchant, category, country, device_id, timestamp FROM transactions WHERE user_id = $1 ORDER BY timestamp DESC LIMIT $2",
		userID, maxHistoryPerUserPostgres)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Transaction
	for rows.Next() {
		var tx models.Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Amount, &tx.Currency, &tx.Merchant, &tx.Category, &tx.Country, &tx.DeviceID, &tx.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, tx)
	}
	// Reverse to oldest-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// GetStats reads the aggregate counters. UserCount is approximate (DISTINCT
// user_id over the transactions table — for very large tables, consider a
// separate users table or a materialized view).
func (p *PostgresStore) GetStats(ctx context.Context) (Stats, error) {
	var total, flagged int
	// tolerate missing rows (cold start) — pgx returns ErrNoRows
	_ = p.pool.QueryRow(ctx, "SELECT int_value FROM fraud_stats WHERE key = 'total_scored'").Scan(&total)
	_ = p.pool.QueryRow(ctx, "SELECT int_value FROM fraud_stats WHERE key = 'total_flagged'").Scan(&flagged)

	var users int
	_ = p.pool.QueryRow(ctx, "SELECT COUNT(DISTINCT user_id) FROM transactions").Scan(&users)

	rows, err := p.pool.Query(ctx, "SELECT severity, count FROM fraud_severity_counts")
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close()
	bySev := make(map[string]int)
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return Stats{}, err
		}
		bySev[sev] = n
	}

	return Stats{
		TotalScored:   total,
		TotalFlagged:  flagged,
		UsersTracked:  users,
		BySeverity:    bySev,
		StartedAt:     time.Now(), // not persisted; caller may override
		UptimeSeconds: 0,
	}, nil
}

// UserCount returns the approximate number of tracked users.
func (p *PostgresStore) UserCount(ctx context.Context) int {
	var n int
	_ = p.pool.QueryRow(ctx, "SELECT COUNT(DISTINCT user_id) FROM transactions").Scan(&n)
	return n
}

// MarshalJSON helper for stats (not used internally but handy for admin endpoints).
func (p *PostgresStore) StatsJSON(ctx context.Context) ([]byte, error) {
	s, err := p.GetStats(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}
