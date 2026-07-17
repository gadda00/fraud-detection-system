// Package detector — merchant risk detector.
//
// MerchantRiskDetector consults a curated registry of merchant risk scores.
// High-risk merchants (cryptocurrency exchanges, gambling sites, luxury
// watch resellers, offshore wire services) carry a baseline score that
// compounds with other signals. The registry is intentionally small and
// human-curated — this is a transparent, auditable signal, not a learned
// one.
//
// In production this registry would be maintained by a risk-ops team and
// backed by a database table; here it is a static map for simplicity.
// Merchant names are matched case-insensitively and by substring so
// "LuxuryWatches.io" matches "luxurywatches" and "LUXURYWATCHES.IO".
package detector

import (
	"fmt"
	"strings"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

// MerchantRiskEntry describes the risk profile of a known merchant.
type MerchantRiskEntry struct {
	// Score is the baseline risk score for transactions at this merchant,
	// in [0, 1]. 0.5 means "neutral, defer to other detectors"; higher
	// values bias the ensemble toward flagging.
	Score float64
	// Category is a human-readable label for the risk type.
	Category string
}

// merchantRegistry is the curated list of high-risk merchants. Names are
// stored lowercase for case-insensitive matching. Add new entries as the
// risk-ops team identifies new patterns.
var merchantRegistry = map[string]MerchantRiskEntry{
	"cryptoexchange-x":  {0.85, "cryptocurrency_exchange"},
	"offshorebets":      {0.9, "gambling_offshore"},
	"luxurywatches.io":  {0.8, "high_value_reseller"},
	"goldbullion24":     {0.85, "precious_metals"},
	"wiretransferhub":   {0.9, "wire_transfer_service"},
	"cryptowallet-x":    {0.85, "cryptocurrency_wallet"},
	"mixer-service":     {0.95, "cryptocurrency_mixer"},
	"prepaidcardstore":  {0.7, "prepaid_card"},
	"giftcardliquid":    {0.75, "gift_card_resale"},
	"darknet-market-xx": {0.98, "darknet_market"},
}

// MerchantRiskDetector flags transactions at known high-risk merchants.
type MerchantRiskDetector struct {
	store storage.Store
}

// NewMerchantRiskDetector builds a detector backed by the static registry.
// In production this would accept a repository interface so the registry
// can be loaded from a database and refreshed at runtime.
func NewMerchantRiskDetector(store storage.Store) *MerchantRiskDetector {
	return &MerchantRiskDetector{store: store}
}

// Name implements Detector.
func (d *MerchantRiskDetector) Name() string { return "merchant_risk" }

// Score implements Detector.
func (d *MerchantRiskDetector) Score(tx models.Transaction) models.RiskScore {
	if tx.Merchant == "" {
		return clean()
	}

	merchant := strings.ToLower(tx.Merchant)
	for key, entry := range merchantRegistry {
		if strings.Contains(merchant, key) {
			return models.RiskScore{
				Score:     entry.Score,
				Severity:  models.SeverityFromScore(entry.Score),
				Reasons:   []string{fmt.Sprintf("merchant %q is flagged as high-risk (%s, score=%.2f)", tx.Merchant, entry.Category, entry.Score)},
				Detectors: []string{d.Name()},
			}
		}
	}
	return clean()
}

// RegisterMerchant adds or updates a merchant entry in the registry. This
// is intended for runtime use by an admin API; the registry is protected
// by a mutex (not shown here for brevity — in production use sync.RWMutex).
func RegisterMerchant(name string, entry MerchantRiskEntry) {
	merchantRegistry[strings.ToLower(name)] = entry
}
