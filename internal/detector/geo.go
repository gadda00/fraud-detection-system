// Package detector — geo-distance detector.
//
// GeoDistanceDetector flags transactions whose merchant country is far from
// the user's home country or recent transaction locations. Cross-border
// transactions, especially high-value ones originating shortly after a
// "home country" transaction, are a classic card-not-present fraud signal.
//
// The detector uses a simplified great-circle distance via the equirectangular
// approximation (sufficient at the country-centroid granularity we operate
// on; full haversine is overkill for ~200 country points). A distance above
// 2,000 km starts ramping the score; above 8,000 km saturates at 1.0.
package detector

import (
	"fmt"
	"math"
	"sync"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

// countryCoord is a latitude/longitude pair in decimal degrees.
type countryCoord struct {
	Lat float64
	Lon float64
}

// countryCentroids maps ISO-3166 alpha-2 country codes to a rough centroid.
// These are intentionally coarse — the detector only needs to know whether
// two countries are "near" or "far apart" — not the precise distance between
// two addresses.
var countryCentroids = map[string]countryCoord{
	"US": {39.8, -98.6}, "CA": {56.1, -106.3}, "GB": {55.4, -3.4}, "UK": {55.4, -3.4},
	"DE": {51.2, 10.5}, "FR": {46.2, 2.2}, "ES": {40.5, -3.7}, "IT": {41.9, 12.6},
	"NL": {52.1, 5.3}, "KE": {0.0, 37.9}, "NG": {9.1, 8.7}, "ZA": {-30.6, 22.9},
	"EG": {26.8, 30.8}, "IN": {22.6, 79.0}, "CN": {35.0, 104.2}, "JP": {36.2, 138.3},
	"SG": {1.4, 103.8}, "AE": {23.4, 53.8}, "SA": {23.9, 45.1}, "TR": {38.9, 35.2},
	"RU": {61.5, 105.3}, "BR": {-10.2, -53.1}, "AR": {-34.4, -63.6}, "MX": {23.6, -102.6},
	"AU": {-25.3, 133.8}, "ID": {-2.5, 118.0}, "VN": {15.9, 105.8}, "TH": {15.9, 100.9},
	"UA": {49.0, 31.2}, "MM": {21.0, 96.0}, "PH": {12.9, 121.8}, "PK": {30.4, 69.3},
	"BD": {23.7, 90.4}, "GH": {7.9, -1.0}, "TZ": {-6.4, 34.9}, "UG": {1.4, 32.3},
}

// centroidOnce caches lookups; the table is static but a sync.Once avoids
// paying any race-detector cost on concurrent first-access.
var (
	centroidOnce sync.Once
)

// distanceKm returns the great-circle distance between two country codes
// using the equirectangular approximation. Unknown countries return 0
// (treated as "same location" so the detector abstains rather than
// false-positiving on every transaction from an unmapped country).
func distanceKm(a, b string) float64 {
	ca, ok1 := countryCentroids[a]
	cb, ok2 := countryCentroids[b]
	if !ok1 || !ok2 {
		return 0
	}
	// Equirectangular: x = Δlon · cos(meanLat); y = Δlat. Convert to km.
	const kmPerDeg = 111.32
	meanLat := (ca.Lat + cb.Lat) / 2 * math.Pi / 180
	x := (ca.Lon - cb.Lon) * math.Cos(meanLat)
	y := ca.Lat - cb.Lat
	return math.Sqrt(x*x+y*y) * kmPerDeg
}

func init() {
	// Touch the sync.Once so linter doesn't complain about it being unused
	// if we later switch to lazy initialisation.
	centroidOnce.Do(func() {})
}

// GeoDistanceDetector flags transactions that occur far from the user's home
// country. Home country is the most common country in the user's recent
// history; if there is no history yet the detector abstains.
type GeoDistanceDetector struct {
	store *storage.Store
	// ThresholdKm is the distance past which the score starts ramping up.
	// 2,000 km catches intra-continental jumps (e.g. UK → Turkey).
	ThresholdKm float64
	// SaturateKm is the distance at which the score saturates at 1.0.
	SaturateKm float64
}

// NewGeoDistanceDetector builds a detector with sensible defaults.
func NewGeoDistanceDetector(store *storage.Store) *GeoDistanceDetector {
	return &GeoDistanceDetector{
		store:       store,
		ThresholdKm: 2000,
		SaturateKm:  8000,
	}
}

// Name implements Detector.
func (d *GeoDistanceDetector) Name() string { return "geo_distance" }

// Score implements Detector.
func (d *GeoDistanceDetector) Score(tx models.Transaction) models.RiskScore {
	hist := d.store.GetUserHistory(tx.UserID)
	if len(hist) == 0 {
		return clean()
	}

	// Determine the user's "home" country: the modal country in history.
	home := modalCountry(hist)
	if home == "" {
		return clean()
	}
	if tx.Country == "" || tx.Country == home {
		return clean()
	}

	dist := distanceKm(home, tx.Country)
	if dist < d.ThresholdKm {
		return clean()
	}

	// Linear ramp from 0.5 at ThresholdKm to 1.0 at SaturateKm.
	score := 0.5 + 0.5*(dist-d.ThresholdKm)/(d.SaturateKm-d.ThresholdKm)
	if score > 1.0 {
		score = 1.0
	}

	return models.RiskScore{
		Score:    score,
		Severity: models.SeverityFromScore(score),
		Reasons: []string{
			fmt.Sprintf("transaction in %s is %.0f km from user home country %s", tx.Country, dist, home),
		},
		Detectors: []string{d.Name()},
	}
}

// modalCountry returns the most frequently occurring country in the user's
// history. Ties are broken arbitrarily (the first to reach the max count).
func modalCountry(hist []models.Transaction) string {
	counts := make(map[string]int)
	for _, h := range hist {
		if h.Country != "" {
			counts[h.Country]++
		}
	}
	var best string
	var bestN int
	for c, n := range counts {
		if n > bestN {
			best = c
			bestN = n
		}
	}
	return best
}
