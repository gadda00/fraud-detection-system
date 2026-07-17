package detector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

// bg is a background context reused by every benchmark in this file.
var bg = context.Background()

// BenchmarkEnsemble_Score measures the per-transaction scoring latency.
// The target is < 1ms per transaction (we typically see 50-300µs).
func BenchmarkEnsemble_Score(b *testing.B) {
	store := storage.New()
	// Seed 100 transactions to give the detectors a realistic baseline.
	for i := 0; i < 100; i++ {
		_ = store.Seed(bg, models.Transaction{
			UserID:    "u1",
			Amount:    30 + float64(i%20),
			Category:  "shopping",
			Country:   "US",
			DeviceID:  "dev-1",
			Timestamp: time.Now().Add(-time.Duration(100-i) * time.Minute),
		})
	}
	ens := NewEnsembleDetector(store)

	tx := models.Transaction{
		UserID:    "u1",
		Amount:    45,
		Category:  "shopping",
		Country:   "US",
		DeviceID:  "dev-1",
		Merchant:  "Amazon",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ens.Score(tx)
	}
}

// BenchmarkEnsemble_ScoreParallel runs the scorer from multiple goroutines
// to measure throughput under concurrent load.
func BenchmarkEnsemble_ScoreParallel(b *testing.B) {
	store := storage.New()
	for i := 0; i < 100; i++ {
		_ = store.Seed(bg, models.Transaction{
			UserID:    "u1",
			Amount:    30 + float64(i%20),
			Category:  "shopping",
			Country:   "US",
			DeviceID:  "dev-1",
			Timestamp: time.Now().Add(-time.Duration(100-i) * time.Minute),
		})
	}
	ens := NewEnsembleDetector(store)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		tx := models.Transaction{
			UserID:    "u1",
			Amount:    45,
			Category:  "shopping",
			Country:   "US",
			DeviceID:  "dev-1",
			Merchant:  "Amazon",
			Timestamp: time.Now(),
		}
		for pb.Next() {
			ens.Score(tx)
		}
	})
}

// BenchmarkStore_Add measures the write path (Add + GetUserHistory).
func BenchmarkStore_Add(b *testing.B) {
	store := storage.New()
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: time.Now()}
	risk := models.RiskScore{Score: 0.1, Severity: "low"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = store.Add(bg, tx, risk)
	}
}

// BenchmarkStore_GetUserHistory measures the read path.
func BenchmarkStore_GetUserHistory(b *testing.B) {
	store := storage.New()
	for i := 0; i < 100; i++ {
		_ = store.Seed(bg, models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: time.Now()})
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = store.GetUserHistory(bg, "u1")
	}
}

// BenchmarkEnsemble_MultiUser simulates a realistic mix of transactions
// across many users, measuring throughput in transactions/sec.
func BenchmarkEnsemble_MultiUser(b *testing.B) {
	store := storage.New()
	// Seed 50 users with 20 transactions each = 1000 total.
	for u := 0; u < 50; u++ {
		userID := fmt.Sprintf("u%d", u)
		for i := 0; i < 20; i++ {
			_ = store.Seed(bg, models.Transaction{
				UserID:    userID,
				Amount:    30 + float64(i%20),
				Category:  "shopping",
				Country:   "US",
				DeviceID:  "dev-1",
				Timestamp: time.Now().Add(-time.Duration(20-i) * time.Hour),
			})
		}
	}
	ens := NewEnsembleDetector(store)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		userID := fmt.Sprintf("u%d", i%50)
		tx := models.Transaction{
			UserID:    userID,
			Amount:    30 + float64(i%20),
			Category:  "shopping",
			Country:   "US",
			DeviceID:  "dev-1",
			Merchant:  "Amazon",
			Timestamp: time.Now(),
		}
		ens.Score(tx)
	}
}
