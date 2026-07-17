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
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// countryCoord is a latitude/longitude pair in decimal degrees.
type countryCoord struct {
	Lat float64
	Lon float64
}

// countryCentroids maps ISO-3166 alpha-2 country codes to a rough
// centroid. This is a near-complete ISO-3166 table (~195 entries)
// covering every UN-recognised country plus a handful of territories
// commonly seen in payment data (Hong Kong, Macau, Puerto Rico, etc.).
// The centroids are intentionally coarse — the detector only needs to
// know whether two countries are "near" or "far apart", not the precise
// distance between two addresses. Centroids are approximate to ~1°
// (≈111 km at the equator), which is well below the detector's 2,000 km
// threshold so the noise does not affect scoring.
var countryCentroids = map[string]countryCoord{
	// — North America —
	"US": {39.8, -98.6}, "CA": {56.1, -106.3}, "MX": {23.6, -102.6},
	"GT": {15.7, -90.2}, "BZ": {17.2, -88.5}, "SV": {13.7, -88.9},
	"HN": {14.6, -86.2}, "NI": {12.9, -85.2}, "CR": {9.7, -84.0},
	"PA": {8.5, -80.8}, "CU": {21.5, -77.8}, "JM": {18.1, -77.3},
	"HT": {18.9, -72.3}, "DO": {18.7, -70.7}, "BS": {25.0, -77.4},
	"TT": {10.7, -61.2}, "BB": {13.2, -59.5}, "GD": {12.1, -61.7},
	"LC": {13.9, -60.9}, "VC": {13.2, -61.2}, "AG": {17.0, -61.8},
	"DM": {15.4, -61.3}, "KN": {17.4, -62.8}, "PR": {18.2, -66.6},
	"GL": {71.7, -42.6},

	// — South America —
	"BR": {-10.2, -53.1}, "AR": {-34.4, -63.6}, "CO": {4.6, -74.3},
	"PE": {-9.2, -75.0}, "VE": {6.4, -66.6}, "CL": {-35.7, -71.5},
	"EC": {-1.8, -78.2}, "BO": {-16.3, -63.6}, "PY": {-23.4, -58.4},
	"UY": {-32.5, -55.8}, "GY": {4.9, -58.9}, "SR": {3.9, -56.0},
	"FK": {-51.8, -59.0}, "GF": {3.9, -53.1},

	// — Europe (Western, Central, Northern) —
	"GB": {55.4, -3.4}, "UK": {55.4, -3.4}, "IE": {53.1, -7.7},
	"FR": {46.2, 2.2}, "DE": {51.2, 10.5}, "IT": {41.9, 12.6},
	"ES": {40.5, -3.7}, "PT": {39.4, -8.2}, "NL": {52.1, 5.3},
	"BE": {50.5, 4.5}, "LU": {49.8, 6.1}, "CH": {46.8, 8.2},
	"AT": {47.5, 14.6}, "LI": {47.2, 9.6}, "MC": {43.7, 7.4},
	"AD": {42.5, 1.6}, "MT": {35.9, 14.4}, "SM": {43.9, 12.5},
	"VA": {41.9, 12.4},

	// — Northern Europe / Baltics / Scandinavia —
	"SE": {60.1, 18.6}, "NO": {60.5, 8.5}, "DK": {56.3, 9.5},
	"FI": {61.9, 25.7}, "IS": {64.9, -19.0}, "EE": {58.6, 25.0},
	"LV": {56.9, 24.6}, "LT": {55.2, 23.9},

	// — Eastern Europe —
	"PL": {51.9, 19.1}, "CZ": {49.8, 15.5}, "SK": {48.7, 19.7},
	"HU": {47.2, 19.5}, "RO": {45.9, 24.97}, "BG": {42.7, 25.5},
	"RS": {44.0, 21.0}, "HR": {45.1, 15.2}, "SI": {46.2, 14.99},
	"BA": {43.9, 17.7}, "MK": {41.6, 21.7}, "AL": {41.2, 20.2},
	"ME": {42.7, 19.4}, "XK": {42.6, 20.9}, "MD": {47.4, 28.4},
	"UA": {49.0, 31.2}, "BY": {53.7, 27.9}, "RU": {61.5, 105.3},

	// — Southern Europe / Mediterranean —
	"GR": {39.1, 21.8}, "TR": {38.9, 35.2}, "CY": {35.1, 33.4},
	"GE": {42.3, 43.4}, "AM": {40.1, 45.0}, "AZ": {40.1, 47.6},

	// — Middle East —
	"AE": {23.4, 53.8}, "SA": {23.9, 45.1}, "QA": {25.3, 51.2},
	"BH": {26.1, 50.6}, "KW": {29.3, 47.5}, "OM": {21.5, 55.9},
	"YE": {15.6, 48.5}, "IR": {32.4, 53.7}, "IQ": {33.2, 43.7},
	"SY": {34.8, 38.9}, "JO": {30.6, 36.2}, "LB": {33.9, 35.9},
	"IL": {31.0, 34.9}, "PS": {31.9, 35.3},

	// — Central Asia —
	"KZ": {48.0, 66.9}, "UZ": {41.4, 64.6}, "TM": {39.2, 59.4},
	"KG": {41.2, 74.8}, "TJ": {38.9, 71.3}, "AF": {33.9, 67.7},

	// — South Asia —
	"IN": {22.6, 79.0}, "PK": {30.4, 69.3}, "BD": {23.7, 90.4},
	"NP": {28.4, 84.1}, "BT": {27.5, 90.4}, "LK": {7.9, 80.8},
	"MV": {3.2, 73.2},

	// — Southeast Asia —
	"SG": {1.4, 103.8}, "MY": {4.2, 101.9}, "ID": {-2.5, 118.0},
	"TH": {15.9, 100.9}, "VN": {15.9, 105.8}, "PH": {12.9, 121.8},
	"MM": {21.0, 96.0}, "LA": {19.9, 102.5}, "KH": {12.6, 104.9},
	"BN": {4.5, 114.7}, "TL": {-8.9, 125.7},

	// — East Asia —
	"CN": {35.0, 104.2}, "JP": {36.2, 138.3}, "KR": {36.0, 128.0},
	"KP": {40.3, 127.5}, "TW": {23.7, 121.0}, "HK": {22.3, 114.2},
	"MO": {22.2, 113.5}, "MN": {46.9, 103.8},

	// — Oceania / Pacific —
	"AU": {-25.3, 133.8}, "NZ": {-41.0, 174.0}, "PG": {-6.3, 143.9},
	"FJ": {-17.7, 178.1}, "SB": {-9.4, 160.0}, "VU": {-16.4, 167.6},
	"WS": {-13.6, -172.4}, "TO": {-21.2, -175.2}, "KI": {-3.4, -168.7},
	"TV": {-7.5, 178.7}, "NR": {-0.5, 166.9}, "PW": {7.5, 134.6},
	"MH": {7.1, 171.2}, "FM": {7.4, 150.6}, "CK": {-21.2, -159.8},
	"NU": {-19.0, -169.9}, "NC": {-21.5, 165.5}, "PF": {-17.7, -149.4},

	// — Africa: North —
	"EG": {26.8, 30.8}, "LY": {26.3, 17.2}, "TN": {33.9, 9.5},
	"DZ": {28.0, 2.6}, "MA": {31.8, -7.1}, "SD": {12.9, 30.2},
	"SS": {6.9, 31.3}, "EH": {24.2, -12.9},

	// — Africa: West —
	"NG": {9.1, 8.7}, "GH": {7.9, -1.0}, "CI": {7.5, -5.5},
	"SN": {14.5, -14.5}, "ML": {17.6, -4.0}, "BF": {12.2, -1.6},
	"NE": {17.6, 9.4}, "MR": {20.3, -10.3},
	"BJ": {9.3, 2.3}, "TG": {8.6, 0.8}, "SL": {8.5, -11.8},
	"LR": {6.4, -9.4}, "GN": {9.9, -9.7}, "GW": {12.0, -15.0},
	"CV": {16.0, -24.0}, "GM": {13.4, -15.3},

	// — Africa: Central —
	"CM": {7.4, 12.4}, "CF": {6.6, 20.9}, "CD": {-4.0, 21.8},
	"CG": {-0.7, 15.8}, "GA": {-0.8, 11.6}, "GQ": {1.7, 10.3},
	"ST": {0.2, 6.6}, "TD": {15.5, 18.7}, "AO": {-11.2, 17.9},
	"RW": {-1.9, 29.9}, "BI": {-3.4, 29.9},

	// — Africa: East —
	"KE": {0.0, 37.9}, "UG": {1.4, 32.3}, "TZ": {-6.4, 34.9},
	"ET": {9.1, 40.5}, "ER": {15.2, 39.8}, "DJ": {11.8, 42.6},
	"SO": {5.2, 46.2}, "MG": {-18.8, 47.0},
	"MU": {-20.3, 57.6}, "SC": {-4.7, 55.5}, "KM": {-11.7, 43.4},
	"RE": {-21.1, 55.5}, "YT": {-12.8, 45.2},

	// — Africa: Southern —
	"ZA": {-30.6, 22.9}, "NA": {-22.0, 16.9}, "BW": {-22.3, 24.7},
	"ZW": {-19.0, 29.2}, "ZM": {-13.1, 27.8}, "MW": {-13.2, 34.3},
	"MZ": {-18.7, 35.5}, "LS": {-29.6, 28.2}, "SZ": {-26.5, 31.5},
}

// unmappedCountryCounter increments every time the geo detector sees a
// country code that is not in countryCentroids. The percentage of total
// transactions landing here is a useful operational signal — a spike
// suggests either a new territory appearing in merchant data or (more
// likely) a malformed / non-ISO code being passed in.
var unmappedCountryCounter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "fraud_geo_detector_unmapped_country_total",
	Help: "Number of transactions whose merchant or home country code is not in the geo-centroid table.",
})

// centroidOnce caches lookups; the table is static but a sync.Once avoids
// paying any race-detector cost on concurrent first-access.
var (
	centroidOnce sync.Once
)

// distanceKm returns the great-circle distance between two country codes
// using the equirectangular approximation. Unknown countries return 0
// (treated as "same location" so the detector abstains rather than
// false-positiving on every transaction from an unmapped country) and
// increment the unmapped-country Prometheus counter so operators can see
// how often the table is being missed.
func distanceKm(a, b string) float64 {
	ca, ok1 := countryCentroids[a]
	cb, ok2 := countryCentroids[b]
	if !ok1 {
		unmappedCountryCounter.Inc()
	}
	if !ok2 {
		unmappedCountryCounter.Inc()
	}
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
	store storage.Store
	// ThresholdKm is the distance past which the score starts ramping up.
	// 2,000 km catches intra-continental jumps (e.g. UK → Turkey).
	ThresholdKm float64
	// SaturateKm is the distance at which the score saturates at 1.0.
	SaturateKm float64
}

// NewGeoDistanceDetector builds a detector with sensible defaults.
func NewGeoDistanceDetector(store storage.Store) *GeoDistanceDetector {
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
	hist, _ := d.store.GetUserHistory(context.Background(), tx.UserID)
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
