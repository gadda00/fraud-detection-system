// Redis-backed implementation of the history store.
//
// This file is part of package storage alongside the in-memory Store.
// The in-memory Store is what the skeleton actually wires up (it needs no
// external dependencies, which keeps the demo self-contained), but a
// production deployment would swap it for RedisStore so that history
// survives restarts and can be shared across horizontally-scaled replicas.
//
// RedisStore is fully implemented and unit-compilable but is not
// instantiated by main.go by default. To use it, construct one with
// NewRedisStore and pass it to the detectors instead of storage.New().
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/redis/go-redis/v9"
)

// maxHistoryPerUserRedis mirrors the in-memory cap so both backends
// present the same baseline window to the detectors.
const maxHistoryPerUserRedis = 100

// RedisStore persists per-user transaction history in Redis lists. Each
// user gets two keys: a list of recent transactions (capped at
// maxHistoryPerUserRedis) and a small hash of aggregate counters used by
// GetStats.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore returns a RedisStore connected to addr (e.g.
// "localhost:6379"). It pings Redis eagerly so misconfiguration fails
// fast at startup rather than on the first request.
func NewRedisStore(addr string) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		DB:           0,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     20,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping %s: %w", addr, err)
	}
	return &RedisStore{client: client}, nil
}

// Close releases the connection pool.
func (r *RedisStore) Close() error { return r.client.Close() }

// userHistoryKey is the Redis list key holding a user's recent txs.
func userHistoryKey(userID string) string { return "fraud:hist:" + userID }

// Add appends tx to the user's history, trims the list to the cap, and
// bumps the aggregate counters in a single pipelined round-trip.
func (r *RedisStore) Add(ctx context.Context, tx models.Transaction, score models.RiskScore) error {
	payload, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx: %w", err)
	}

	key := userHistoryKey(tx.UserID)
	pipe := r.client.TxPipeline()
	pipe.RPush(ctx, key, payload)
	pipe.LTrim(ctx, key, -maxHistoryPerUserRedis, -1)
	pipe.Incr(ctx, "fraud:stats:total_scored")
	if score.IsFlagged() {
		pipe.Incr(ctx, "fraud:stats:total_flagged")
	}
	sev := score.Severity
	if sev == "" {
		sev = models.SeverityFromScore(score.Score)
	}
	pipe.HIncrBy(ctx, "fraud:stats:by_severity", sev, 1)
	_, err = pipe.Exec(ctx)
	return err
}

// Seed is the non-scoring variant of Add: it records the transaction
// without touching the aggregate counters. Used by the seed-data loader.
func (r *RedisStore) Seed(ctx context.Context, tx models.Transaction) error {
	payload, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx: %w", err)
	}
	key := userHistoryKey(tx.UserID)
	pipe := r.client.TxPipeline()
	pipe.RPush(ctx, key, payload)
	pipe.LTrim(ctx, key, -maxHistoryPerUserRedis, -1)
	_, err = pipe.Exec(ctx)
	return err
}

// GetUserHistory returns up to the last maxHistoryPerUserRedis
// transactions for the user, oldest first (to match the in-memory Store).
func (r *RedisStore) GetUserHistory(ctx context.Context, userID string) ([]models.Transaction, error) {
	raw, err := r.client.LRange(ctx, userHistoryKey(userID), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]models.Transaction, 0, len(raw))
	for _, item := range raw {
		var tx models.Transaction
		if err := json.Unmarshal([]byte(item), &tx); err != nil {
			return nil, fmt.Errorf("unmarshal tx: %w", err)
		}
		out = append(out, tx)
	}
	return out, nil
}

// GetStats reads the aggregate counters back from Redis. Missing keys
// are treated as zero, which is the correct behaviour for a fresh
// instance.
func (r *RedisStore) GetStats(ctx context.Context) (Stats, error) {
	total, err := r.client.Get(ctx, "fraud:stats:total_scored").Int()
	if err != nil && err != redis.Nil {
		return Stats{}, err
	}
	flagged, err := r.client.Get(ctx, "fraud:stats:total_flagged").Int()
	if err != nil && err != redis.Nil {
		return Stats{}, err
	}
	users, err := r.client.DBSize(ctx).Result()
	if err != nil {
		return Stats{}, err
	}
	sevMap, err := r.client.HGetAll(ctx, "fraud:stats:by_severity").Result()
	if err != nil {
		return Stats{}, err
	}
	bySev := make(map[string]int, len(sevMap))
	for k, v := range sevMap {
		if n, perr := strconv.Atoi(v); perr == nil {
			bySev[k] = n
		}
	}
	return Stats{
		TotalScored:   total,
		TotalFlagged:  flagged,
		UsersTracked:  int(users), // approximate: DBSize is a coarse proxy
		BySeverity:    bySev,
		StartedAt:     time.Now(), // not persisted; caller may override
		UptimeSeconds: 0,
	}, nil
}
