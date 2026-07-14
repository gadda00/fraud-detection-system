package detector

import (
	"testing"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

// ----- ZScoreDetector -----

func TestZScore_AbstainsOnShortHistory(t *testing.T) {
	store := storage.New()
	d := NewZScoreDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 100, Category: "shopping", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score != 0 {
		t.Fatalf("expected abstain (score=0) on short history, got %v", rs.Score)
	}
}

func TestZScore_FlagsHighAmount(t *testing.T) {
	store := storage.New()
	// Seed 6 normal shopping transactions with some variance so std > 0.
	for _, a := range []float64{28, 30, 32, 29, 31, 30} {
		store.Seed(models.Transaction{UserID: "u1", Amount: a, Category: "shopping", Timestamp: time.Now()})
	}
	d := NewZScoreDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 500, Category: "shopping", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score < 0.5 {
		t.Fatalf("expected flag on 500 vs mean ~30, got score %v", rs.Score)
	}
	if rs.Severity != models.SeverityCritical && rs.Severity != models.SeverityHigh {
		t.Fatalf("expected high/critical severity, got %v", rs.Severity)
	}
}

func TestZScore_DoesNotFlagNormalAmount(t *testing.T) {
	store := storage.New()
	for i := 0; i < 6; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: time.Now()})
	}
	d := NewZScoreDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 32, Category: "shopping", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score != 0 {
		t.Fatalf("expected no flag on normal amount, got %v", rs.Score)
	}
}

func TestZScore_PerCategoryBaseline(t *testing.T) {
	store := storage.New()
	// 6 small shopping + 6 large travel with variance.
	for i := 0; i < 6; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30 + float64(i), Category: "shopping", Timestamp: time.Now()})
		store.Seed(models.Transaction{UserID: "u1", Amount: 500 + float64(i), Category: "travel", Timestamp: time.Now()})
	}
	d := NewZScoreDetector(store)
	// A travel amount within the normal travel range should not flag.
	tx := models.Transaction{UserID: "u1", Amount: 502, Category: "travel", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score != 0 {
		t.Fatalf("per-category baseline failed: travel amount flagged, score %v", rs.Score)
	}
}

// ----- IQRDetector -----

func TestIQR_FlagsUpperOutlier(t *testing.T) {
	store := storage.New()
	for _, a := range []float64{10, 12, 14, 15, 16, 18, 20, 22, 25} {
		store.Seed(models.Transaction{UserID: "u1", Amount: a, Category: "dining", Timestamp: time.Now()})
	}
	d := NewIQRDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 100, Category: "dining", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score < 0.5 {
		t.Fatalf("expected IQR flag on 100 vs Q3 ~22, got %v", rs.Score)
	}
}

func TestIQR_AbstainsOnShortHistory(t *testing.T) {
	store := storage.New()
	d := NewIQRDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 100, Category: "dining", Timestamp: time.Now()}
	if rs := d.Score(tx); rs.Score != 0 {
		t.Fatalf("expected abstain, got %v", rs.Score)
	}
}

// ----- VelocityDetector -----

func TestVelocity_FlagsRapidBurst(t *testing.T) {
	store := storage.New()
	now := time.Now()
	// 6 transactions in the last 3 minutes — exceeds the 4-in-5-min default.
	for i := 0; i < 6; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: now.Add(-time.Duration(30-i) * time.Second)})
	}
	d := NewVelocityDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: now}
	rs := d.Score(tx)
	if rs.Score < 0.5 {
		t.Fatalf("expected velocity flag on 6-in-3min, got %v", rs.Score)
	}
}

func TestVelocity_DoesNotFlagNormalCadence(t *testing.T) {
	store := storage.New()
	now := time.Now()
	// 4 transactions spread over a day — normal cadence.
	for i := 0; i < 4; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: now.Add(-time.Duration(24-i) * time.Hour)})
	}
	d := NewVelocityDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: now}
	if rs := d.Score(tx); rs.Score != 0 {
		t.Fatalf("expected no flag on normal cadence, got %v", rs.Score)
	}
}

// ----- GeoDistanceDetector -----

func TestGeoDistance_FlagsFarCountry(t *testing.T) {
	store := storage.New()
	// Seed history in the US.
	for i := 0; i < 5; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Country: "US", Timestamp: time.Now()})
	}
	d := NewGeoDistanceDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Country: "RU", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score < 0.5 {
		t.Fatalf("expected geo flag on US→RU, got %v", rs.Score)
	}
}

func TestGeoDistance_DoesNotFlagHomeCountry(t *testing.T) {
	store := storage.New()
	for i := 0; i < 5; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Country: "US", Timestamp: time.Now()})
	}
	d := NewGeoDistanceDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Country: "US", Timestamp: time.Now()}
	if rs := d.Score(tx); rs.Score != 0 {
		t.Fatalf("expected no flag for home country, got %v", rs.Score)
	}
}

// ----- DeviceFingerprintDetector -----

func TestDevice_NewDeviceFlagged(t *testing.T) {
	store := storage.New()
	// History with dev-1.
	for i := 0; i < 5; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", DeviceID: "dev-1", Timestamp: time.Now()})
	}
	d := NewDeviceFingerprintDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", DeviceID: "dev-2", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score == 0 {
		t.Fatalf("expected new device to be flagged, got 0")
	}
}

func TestDevice_TrustedDeviceNotFlagged(t *testing.T) {
	store := storage.New()
	// 5 transactions with dev-1 — above the trusted threshold of 2.
	for i := 0; i < 5; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", DeviceID: "dev-1", Timestamp: time.Now()})
	}
	d := NewDeviceFingerprintDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", DeviceID: "dev-1", Timestamp: time.Now()}
	if rs := d.Score(tx); rs.Score != 0 {
		t.Fatalf("expected trusted device not flagged, got %v", rs.Score)
	}
}

// ----- MerchantRiskDetector -----

func TestMerchant_HighRiskFlagged(t *testing.T) {
	store := storage.New()
	d := NewMerchantRiskDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 100, Merchant: "CryptoExchange-X", Timestamp: time.Now()}
	rs := d.Score(tx)
	if rs.Score < 0.8 {
		t.Fatalf("expected high-risk merchant to score >=0.8, got %v", rs.Score)
	}
}

func TestMerchant_NormalMerchantNotFlagged(t *testing.T) {
	store := storage.New()
	d := NewMerchantRiskDetector(store)
	tx := models.Transaction{UserID: "u1", Amount: 100, Merchant: "Amazon", Timestamp: time.Now()}
	if rs := d.Score(tx); rs.Score != 0 {
		t.Fatalf("expected Amazon not flagged, got %v", rs.Score)
	}
}

// ----- BehavioralAnomalyDetector -----

func TestBehavioral_QuietHoursFlagged(t *testing.T) {
	store := storage.New()
	// Seed history all during business hours (9am-5pm UTC).
	for i := 0; i < 10; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: time.Date(2026, 1, 1+i, 12, 0, 0, 0, time.UTC)})
	}
	d := NewBehavioralAnomalyDetector(store)
	// Score a transaction at 3am.
	tx := models.Transaction{UserID: "u1", Amount: 30, Category: "shopping", Timestamp: time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC)}
	rs := d.Score(tx)
	if rs.Score == 0 {
		t.Fatalf("expected 3am transaction to be flagged, got 0")
	}
}

// ----- EnsembleDetector -----

func TestEnsemble_CombinesDetectors(t *testing.T) {
	store := storage.New()
	// Seed normal US shopping history with variance.
	for i := 0; i < 6; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30 + float64(i), Category: "shopping", Country: "US", DeviceID: "dev-1", Timestamp: time.Now().Add(-time.Duration(6-i) * time.Hour)})
	}
	ens := NewEnsembleDetector(store)
	// A high-amount transaction in a new country from a new device at a high-risk merchant.
	tx := models.Transaction{
		UserID: "u1", Amount: 5000, Category: "shopping", Country: "RU",
		DeviceID: "dev-unknown", Merchant: "CryptoExchange-X", Timestamp: time.Now(),
	}
	rs := ens.Score(tx)
	if rs.Score < 0.6 {
		t.Fatalf("expected ensemble to combine signals into a high score, got %v", rs.Score)
	}
	if len(rs.Detectors) < 3 {
		t.Fatalf("expected at least 3 detectors to fire, got %v", rs.Detectors)
	}
}

func TestEnsemble_NormalTransactionLowRisk(t *testing.T) {
	store := storage.New()
	for i := 0; i < 6; i++ {
		store.Seed(models.Transaction{UserID: "u1", Amount: 30 + float64(i), Category: "shopping", Country: "US", DeviceID: "dev-1", Timestamp: time.Now().Add(-time.Duration(6-i) * time.Hour)})
	}
	ens := NewEnsembleDetector(store)
	tx := models.Transaction{
		UserID: "u1", Amount: 32, Category: "shopping", Country: "US",
		DeviceID: "dev-1", Merchant: "Amazon", Timestamp: time.Now(),
	}
	rs := ens.Score(tx)
	if rs.Score > 0.4 {
		t.Fatalf("expected normal transaction to score low, got %v", rs.Score)
	}
}
