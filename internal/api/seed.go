// Package api groups the HTTP-facing code: request handlers, seed-data
// generation and the offline evaluation harness used to sanity-check the
// detectors at startup.
package api

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

// SeedData is the result of GenerateSeedData: a slice of transactions
// together with the subset that is known to be fraudulent. The fraud
// labels let the evaluation harness compute recall / precision.
type SeedData struct {
	Transactions []models.Transaction
	FraudIDs     map[string]bool
}

// IsFraud reports whether a transaction id belongs to the labelled fraud set.
func (s SeedData) IsFraud(id string) bool { return s.FraudIDs[id] }

// categoryProfile describes the normal spending envelope for a category.
type categoryProfile struct {
	min       float64
	max       float64
	merchants []string
}

// categoryProfiles is a small, hand-curated catalogue that gives the
// generated data a realistic shape: groceries cluster low, travel spans
// wide, subscriptions are tiny and recurring, etc.
var categoryProfiles = map[string]categoryProfile{
	"groceries":     {10, 150, []string{"Whole Foods", "Trader Joe's", "Safeway", "Kroger", "Aldi"}},
	"dining":        {12, 90, []string{"Starbucks", "Chipotle", "McDonald's", "Olive Garden", "Domino's"}},
	"gas":           {20, 75, []string{"Shell", "Chevron", "Exxon", "BP", "Mobil"}},
	"entertainment": {10, 65, []string{"Netflix", "Spotify", "AMC", "Steam", "Disney+"}},
	"shopping":      {20, 320, []string{"Amazon", "Target", "Walmart", "eBay", "Best Buy"}},
	"transport":     {6, 55, []string{"Uber", "Lyft", "Metro Transit", "Bird", "Parking"}},
	"utilities":     {35, 220, []string{"Verizon", "AT&T", "PG&E", "Comcast", "Duke Energy"}},
	"subscriptions": {5, 35, []string{"Adobe", "iCloud", "Google One", "NYT", "Dropbox"}},
	"health":        {20, 260, []string{"CVS", "Walgreens", "Kaiser", "LabCorp", "BrightSmile Dental"}},
	"travel":        {60, 600, []string{"Delta", "Marriott", "Airbnb", "Expedia", "Hertz"}},
}

// allCategories is the ordered list used to pick user preferences.
var allCategories = []string{
	"groceries", "dining", "gas", "entertainment", "shopping",
	"transport", "utilities", "subscriptions", "health", "travel",
}

// userProfile captures the spending personality of a single user. Keeping
// per-user multipliers and category preferences is what makes the seeded
// baselines realistic: user "u7" might be a big spender on travel while
// "u19" mostly buys groceries.
type userProfile struct {
	id              string
	homeCountry     string
	preferred       []string
	spendMultiplier float64
}

// GenerateSeedData builds a deterministic, realistic dataset of 1000
// transactions across 50 users: 950 normal and 50 fraudulent. Determinism
// comes from a fixed PRNG seed, so two runs produce the same data — useful
// for reproducible demos and tests.
//
// Fraud is split into two patterns the detectors are designed to catch:
//
//   - High-amount fraud (35): a single charge 6–20× the user's normal
//     mean. Caught by both ZScore and IQR detectors.
//   - Velocity fraud (15): a rapid burst of small charges inside the
//     5-minute velocity window. Caught by the Velocity detector (the
//     first few in the burst look normal, which is the honest, realistic
//     behaviour).
func GenerateSeedData() SeedData {
	// Fixed seed => reproducible dataset.
	rng := rand.New(rand.NewSource(42))
	now := time.Now().UTC()

	users := generateUsers(50, rng)
	normal := generateNormal(users, 950, rng, now)

	highAmountFraud, fraudA := generateHighAmountFraud(users, normal, 35, rng, now)
	velocityFraud, fraudB := generateVelocityFraud(users, 15, rng, now)

	all := append(append(normal, highAmountFraud...), velocityFraud...)

	fraudIDs := make(map[string]bool, len(fraudA)+len(fraudB))
	for _, id := range fraudA {
		fraudIDs[id] = true
	}
	for _, id := range fraudB {
		fraudIDs[id] = true
	}

	// Stable ordering by timestamp so the evaluation harness can replay
	// the stream chronologically.
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.Before(all[j].Timestamp)
	})

	return SeedData{Transactions: all, FraudIDs: fraudIDs}
}

// generateUsers builds n user profiles with random country, category
// preferences and spend multipliers.
func generateUsers(n int, rng *rand.Rand) []userProfile {
	countries := []string{"US", "US", "US", "US", "UK", "DE", "KE", "CA", "NG", "IN"}
	users := make([]userProfile, n)
	for i := 0; i < n; i++ {
		// Each user prefers exactly 3 categories. With ~19 normal
		// transactions per user that gives ~6 per category — enough for
		// the per-category detectors to build a stable baseline while
		// keeping the spend pattern focused and realistic.
		k := 3
		pref := make([]string, k)
		perm := rng.Perm(len(allCategories))
		for j := 0; j < k; j++ {
			pref[j] = allCategories[perm[j]]
		}
		users[i] = userProfile{
			id:              fmt.Sprintf("u%d", i+1),
			homeCountry:     countries[rng.Intn(len(countries))],
			preferred:       pref,
			spendMultiplier: 0.7 + rng.Float64()*0.9, // 0.7 – 1.6
		}
	}
	return users
}

// generateNormal produces count realistic, in-profile transactions.
//
// Transactions are allocated *evenly* across every (user, category) pair
// rather than purely at random. This guarantees each user has a usable
// per-category baseline (the detectors abstain below minHistory=5), which
// is what makes the seeded data a fair test of the amount-based
// detectors. Any remainder after the even allocation is sprinkled
// randomly so the total lands exactly on count.
func generateNormal(users []userProfile, count int, rng *rand.Rand, now time.Time) []models.Transaction {
	out := make([]models.Transaction, 0, count)
	week := 7 * 24 * time.Hour
	idCounter := 0

	// makeTx is the single place a normal transaction is constructed.
	makeTx := func(u userProfile, cat string) models.Transaction {
		prof := categoryProfiles[cat]
		merchant := prof.merchants[rng.Intn(len(prof.merchants))]
		amount := lerp(prof.min, prof.max, rng.Float64()) * u.spendMultiplier
		amount = float64(int(amount*100)) / 100 // round to 2 decimals
		idCounter++
		return models.Transaction{
			ID:        fmt.Sprintf("tx-%04d", idCounter),
			UserID:    u.id,
			Amount:    amount,
			Currency:  "USD",
			Merchant:  merchant,
			Category:  cat,
			Timestamp: now.Add(-time.Duration(rng.Int63n(int64(week)))),
			Country:   u.homeCountry,
			DeviceID:  fmt.Sprintf("dev-%s-%d", u.id, rng.Intn(3)+1),
		}
	}

	// First pass: a fixed base of 6 transactions per (user, category).
	// 50 users × 3 categories × 6 = 900.
	const basePerSlot = 6
	for _, u := range users {
		for _, cat := range u.preferred {
			for j := 0; j < basePerSlot; j++ {
				out = append(out, makeTx(u, cat))
			}
		}
	}

	// Second pass: sprinkle the remainder randomly so the total is
	// exactly count.
	for len(out) < count {
		u := users[rng.Intn(len(users))]
		cat := u.preferred[rng.Intn(len(u.preferred))]
		out = append(out, makeTx(u, cat))
	}

	return out
}

// generateHighAmountFraud produces count single-charge frauds whose
// amount is 6–20× the targeted user's normal mean *for the same
// category*. Anchoring the fraud to a category the user actually uses —
// and to that category's own baseline — is what lets the per-category
// detectors catch it while leaving legitimate cross-category spend alone.
// Returns the transactions and the list of their IDs (for labelling).
func generateHighAmountFraud(users []userProfile, normal []models.Transaction, count int, rng *rand.Rand, now time.Time) ([]models.Transaction, []string) {
	// Pre-compute per-(user, category) mean and count of normal amounts so
	// we can anchor each fraud to a realistic baseline.
	type ucKey struct{ user, category string }
	sumByUC := make(map[ucKey]float64)
	cntByUC := make(map[ucKey]int)
	for _, tx := range normal {
		k := ucKey{tx.UserID, tx.Category}
		sumByUC[k] += tx.Amount
		cntByUC[k]++
	}
	meanFor := func(user, category string) (float64, bool) {
		c := cntByUC[ucKey{user, category}]
		if c == 0 {
			return 0, false
		}
		return sumByUC[ucKey{user, category}] / float64(c), true
	}

	out := make([]models.Transaction, 0, count)
	ids := make([]string, 0, count)
	// Occasionally use an "unusual" merchant to mimic a compromised card
	// being used at a merchant the victim never visits.
	unusualMerchants := []string{"LuxuryWatches.io", "CryptoExchange-X", "OffshoreBets", "GoldBullion24", "WireTransferHub"}

	for i := 0; i < count; i++ {
		u := users[rng.Intn(len(users))]

		// Pick one of the user's preferred categories that has a real
		// baseline, so the fraud is anomalous *within* that category.
		cat := ""
		var mean float64
		for _, p := range rng.Perm(len(u.preferred)) {
			c := u.preferred[p]
			if m, ok := meanFor(u.id, c); ok && m > 0 {
				cat = c
				mean = m
				break
			}
		}
		if cat == "" {
			// Fallback: no in-category history (rare); use a flat baseline.
			cat = u.preferred[0]
			mean = 100
		}

		multiplier := 6.0 + rng.Float64()*14.0 // 6× – 20× the category mean
		amount := mean * multiplier
		if amount < 500 {
			amount = 500 + rng.Float64()*2000
		}
		amount = float64(int(amount*100)) / 100

		prof := categoryProfiles[cat]
		var merchant string
		if rng.Intn(3) == 0 {
			merchant = unusualMerchants[rng.Intn(len(unusualMerchants))]
		} else {
			merchant = prof.merchants[rng.Intn(len(prof.merchants))]
		}

		id := fmt.Sprintf("fraud-h-%02d", i+1)
		out = append(out, models.Transaction{
			ID:        id,
			UserID:    u.id,
			Amount:    amount,
			Currency:  "USD",
			Merchant:  merchant,
			Category:  cat,
			Timestamp: now.Add(-time.Duration(rng.Int63n(int64(24 * time.Hour)))),
			Country:   pickUnusualCountry(u.homeCountry, rng),
			DeviceID:  fmt.Sprintf("dev-unknown-%d", rng.Intn(50)),
		})
		ids = append(ids, id)
	}
	return out, ids
}

// generateVelocityFraud produces count transactions forming a single
// rapid burst (all within a few minutes) for one randomly chosen user.
// Amounts are kept in-profile so that only the Velocity detector fires —
// this isolates the velocity signal in the evaluation.
func generateVelocityFraud(users []userProfile, count int, rng *rand.Rand, now time.Time) ([]models.Transaction, []string) {
	u := users[rng.Intn(len(users))]
	cat := u.preferred[rng.Intn(len(u.preferred))]
	prof := categoryProfiles[cat]

	out := make([]models.Transaction, 0, count)
	ids := make([]string, 0, count)
	// Burst starts ~3 minutes ago, one charge every 10–25 seconds.
	start := now.Add(-3 * time.Minute)
	for i := 0; i < count; i++ {
		amount := lerp(prof.min, prof.max, rng.Float64()) * u.spendMultiplier
		amount = float64(int(amount*100)) / 100
		id := fmt.Sprintf("fraud-v-%02d", i+1)
		out = append(out, models.Transaction{
			ID:        id,
			UserID:    u.id,
			Amount:    amount,
			Currency:  "USD",
			Merchant:  prof.merchants[rng.Intn(len(prof.merchants))],
			Category:  cat,
			Timestamp: start.Add(time.Duration(i) * (10*time.Second + time.Duration(rng.Intn(15))*time.Second)),
			Country:   u.homeCountry,
			DeviceID:  fmt.Sprintf("dev-%s-burst", u.id),
		})
		ids = append(ids, id)
	}
	return out, ids
}

// SeedStore loads every transaction in data into store's history via the
// non-scoring Seed method, so /api/stats is not polluted by 1000 fake
// "scored" events. Returns the number of transactions loaded.
func SeedStore(store storage.Store, data SeedData) int {
	ctx := context.Background()
	for _, tx := range data.Transactions {
		_ = store.Seed(ctx, tx)
	}
	return len(data.Transactions)
}

// ---------------------------------------------------------------------------
// Offline evaluation harness
// ---------------------------------------------------------------------------

// EvalMetrics holds the confusion-matrix counts and derived metrics for an
// offline run of a detector over a labelled dataset.
type EvalMetrics struct {
	Total     int     `json:"total"`
	Fraud     int     `json:"fraud"`
	Normal    int     `json:"normal"`
	TruePos   int     `json:"true_positives"`  // fraud correctly flagged
	FalseNeg  int     `json:"false_negatives"` // fraud missed
	TrueNeg   int     `json:"true_negatives"`  // normal correctly cleared
	FalsePos  int     `json:"false_positives"` // normal wrongly flagged
	Recall    float64 `json:"recall"`          // TP / (TP + FN)
	Precision float64 `json:"precision"`       // TP / (TP + FP)
	F1        float64 `json:"f1"`
	FPR       float64 `json:"false_positive_rate"` // FP / (FP + TN)
}

// Evaluate replays data chronologically through d, scoring each
// transaction against the history that preceded it (no leakage), and
// returns confusion-matrix metrics. The store passed in must be the same
// one bound to d; it is seeded transaction-by-transaction as the replay
// proceeds so each score reflects only past behaviour.
//
// This is the same regime a live system operates under, which makes the
// metrics a fair predictor of production behaviour.
func Evaluate(d detector.Detector, store storage.Store, data SeedData) EvalMetrics {
	ctx := context.Background()
	// data.Transactions is already sorted chronologically by GenerateSeedData.
	m := EvalMetrics{}
	for _, tx := range data.Transactions {
		rs := d.Score(tx)
		flagged := rs.IsFlagged()
		isFraud := data.IsFraud(tx.ID)

		m.Total++
		switch {
		case isFraud && flagged:
			m.TruePos++
		case isFraud && !flagged:
			m.FalseNeg++
		case !isFraud && flagged:
			m.FalsePos++
		default:
			m.TrueNeg++
		}

		// Add to baseline AFTER scoring so the current tx is never in
		// its own history.
		_ = store.Seed(ctx, tx)
	}

	m.Fraud = m.TruePos + m.FalseNeg
	m.Normal = m.TrueNeg + m.FalsePos

	if m.Fraud > 0 {
		m.Recall = float64(m.TruePos) / float64(m.Fraud)
	}
	if m.TruePos+m.FalsePos > 0 {
		m.Precision = float64(m.TruePos) / float64(m.TruePos+m.FalsePos)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	if m.Normal > 0 {
		m.FPR = float64(m.FalsePos) / float64(m.Normal)
	}
	return m
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// lerp returns the linear interpolation between a and b at parameter t.
func lerp(a, b, t float64) float64 { return a + (b-a)*t }

// pickUnusualCountry returns a country different from home, simulating a
// cross-border fraud attempt.
func pickUnusualCountry(home string, rng *rand.Rand) string {
	candidates := []string{"RU", "NG", "VN", "BR", "TR", "ID", "UA", "MM"}
	for _, c := range candidates {
		if c != home {
			// 50% of the time return an unusual country.
			if rng.Intn(2) == 0 {
				return c
			}
		}
	}
	return home
}
