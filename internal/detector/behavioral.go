// Package detector — behavioral anomaly detector.
//
// BehavioralAnomalyDetector tracks the user's typical time-of-day and
// day-of-week spending patterns. A transaction at 3:17 AM local time in a
// category the user has never used at that hour is a weak-but-real signal.
//
// The detector builds a 7×24 matrix (7 days × 24 hours) of transaction
// counts per (user, category) and flags transactions that fall in cells
// with zero prior activity, or that occur in the user's "quiet hours"
// (the contiguous 6-hour window with the fewest transactions).
//
// This detector is intentionally conservative — a single off-hours
// transaction is not fraud. Its purpose is to add a small push to the
// ensemble score when *combined* with other signals (new device, unusual
// amount, distant geo).
package detector

import (
        "fmt"

        "github.com/gadda00/fraud-detection-system/internal/models"
        "github.com/gadda00/fraud-detection-system/internal/storage"
)

// BehavioralAnomalyDetector flags transactions outside the user's typical
// behavioural envelope (time-of-day, day-of-week).
type BehavioralAnomalyDetector struct {
        store *storage.Store
}

// NewBehavioralAnomalyDetector builds a detector with default parameters.
func NewBehavioralAnomalyDetector(store *storage.Store) *BehavioralAnomalyDetector {
        return &BehavioralAnomalyDetector{store: store}
}

// Name implements Detector.
func (d *BehavioralAnomalyDetector) Name() string { return "behavioral_anomaly" }

// Score implements Detector.
func (d *BehavioralAnomalyDetector) Score(tx models.Transaction) models.RiskScore {
        hist := d.store.GetUserHistory(tx.UserID)
        if len(hist) < 5 {
                // Need at least a week of history to build a behavioural profile.
                return clean()
        }

        // Build a 7×24 hour-of-week matrix for the user's history.
        var matrix [7 * 24]int
        for _, h := range hist {
                if h.Timestamp.IsZero() {
                        continue
                }
                // Convert to user-local time assumption: we use UTC here because
                // we don't have the user's timezone. This is a known limitation;
                // in production we'd join on a users table to get the tz.
                dow := int(h.Timestamp.UTC().Weekday())
                hour := h.Timestamp.UTC().Hour()
                matrix[dow*24+hour]++
        }

        txTime := tx.Timestamp.UTC()
        dow := int(txTime.Weekday())
        hour := txTime.Hour()
        cell := matrix[dow*24+hour]

        // Determine the user's "quiet hours": the 6-hour window with the
        // fewest total transactions across the week.
        quietStart := findQuietestHour(matrix, 6)
        isQuiet := isInWindow(hour, quietStart, 6)

        var score float64
        var reason string

        switch {
        case cell == 0 && isQuiet:
                // Brand-new hour AND in quiet hours — strongest behavioural signal.
                score = 0.5
                reason = fmt.Sprintf("transaction at %02d:00 (day %d) — first-ever in this hour and inside user's quiet hours (%02d:00–%02d:00)",
                        hour, dow, quietStart, (quietStart+6)%24)
        case cell == 0:
                // First-ever transaction in this hour-of-week cell.
                score = 0.35
                reason = fmt.Sprintf("transaction at %02d:00 (day %d) — first-ever in this hour for this user", hour, dow)
        case isQuiet:
                // In quiet hours but not unprecedented.
                score = 0.3
                reason = fmt.Sprintf("transaction at %02d:00 — inside user's quiet hours (%02d:00–%02d:00)",
                        hour, quietStart, (quietStart+6)%24)
        default:
                return clean()
        }

        return models.RiskScore{
                Score:     score,
                Severity:  models.SeverityFromScore(score),
                Reasons:   []string{reason},
                Detectors: []string{d.Name()},
        }
}

// findQuietestHour returns the start hour of the 6-hour window with the
// fewest total transactions across the entire week.
func findQuietestHour(matrix [7 * 24]int, windowSize int) int {
        var hourSums [24]int
        for dow := 0; dow < 7; dow++ {
                for h := 0; h < 24; h++ {
                        hourSums[h] += matrix[dow*24+h]
                }
        }
        bestStart := 0
        bestSum := -1
        for start := 0; start < 24; start++ {
                sum := 0
                for i := 0; i < windowSize; i++ {
                        sum += hourSums[(start+i)%24]
                }
                if bestSum == -1 || sum < bestSum {
                        bestSum = sum
                        bestStart = start
                }
        }
        return bestStart
}

// isInWindow reports whether hour falls inside the [start, start+window) mod 24 window.
func isInWindow(hour, start, window int) bool {
        for i := 0; i < window; i++ {
                if (start+i)%24 == hour {
                        return true
                }
        }
        return false
}
