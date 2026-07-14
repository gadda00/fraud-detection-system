// Package detector — device fingerprint detector.
//
// DeviceFingerprintDetector flags transactions from a device the user has
// never used before, especially when combined with a high amount or an
// unusual geo. "New device" alone is a weak signal (users get new phones),
// but "new device + amount anomaly + new geo" is a strong one — which is
// exactly the kind of multi-signal pattern the ensemble fuses together.
//
// The detector tracks the set of device IDs the user has used in their
// recent history. A device that has appeared at least `trustedThreshold`
// times is considered "trusted"; a brand-new device starts at score 0.4 and
// ramps up if other risk factors compound.
package detector

import (
	"fmt"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

// DeviceFingerprintDetector flags transactions from devices the user has
// not used before (or has used very rarely).
type DeviceFingerprintDetector struct {
	store *storage.Store
	// TrustedThreshold is the number of times a device must have appeared
	// in history before it is considered trusted.
	TrustedThreshold int
}

// NewDeviceFingerprintDetector builds a detector with a threshold of 2
// (a device seen at least twice in the last 100 transactions is trusted).
func NewDeviceFingerprintDetector(store *storage.Store) *DeviceFingerprintDetector {
	return &DeviceFingerprintDetector{
		store:            store,
		TrustedThreshold: 2,
	}
}

// Name implements Detector.
func (d *DeviceFingerprintDetector) Name() string { return "device_fingerprint" }

// Score implements Detector.
func (d *DeviceFingerprintDetector) Score(tx models.Transaction) models.RiskScore {
	if tx.DeviceID == "" {
		// No device fingerprint supplied — abstain rather than penalise.
		return clean()
	}

	hist := d.store.GetUserHistory(tx.UserID)
	if len(hist) == 0 {
		// Brand-new user — can't say whether the device is novel.
		return clean()
	}

	count := 0
	for _, h := range hist {
		if h.DeviceID == tx.DeviceID {
			count++
		}
	}

	if count >= d.TrustedThreshold {
		return clean()
	}

	// Brand-new device (count == 0) or rarely-seen device (count == 1).
	// The score is intentionally modest — 0.4 for a totally new device —
	// because a new device alone is not fraud. The ensemble will only fire
	// if other detectors (geo, amount) also raise concerns.
	var score float64
	switch count {
	case 0:
		score = 0.4
	case 1:
		score = 0.3
	default:
		return clean()
	}

	reason := fmt.Sprintf("new device %q (seen %d time(s) in history)", tx.DeviceID, count)
	return models.RiskScore{
		Score:     score,
		Severity:  models.SeverityFromScore(score),
		Reasons:   []string{reason},
		Detectors: []string{d.Name()},
	}
}
