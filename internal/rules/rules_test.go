package rules

import (
	"testing"

	"github.com/gadda00/fraud-detection-system/internal/models"
)

func TestEngine_BlockRule(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "high_value_offshore",
			Description: "Block transactions > $10k to offshore havens",
			Match:       Match{AmountMin: 10000, Countries: []string{"KY", "VG", "BZ", "PA"}},
			Action:      ActionBlock,
			Weight:      1.0,
		},
	})

	tx := models.Transaction{UserID: "u1", Amount: 15000, Country: "KY"}
	matches := engine.Evaluate(tx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if !HasBlock(matches) {
		t.Fatal("expected HasBlock=true")
	}
}

func TestEngine_ReviewRule(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "high_value_review",
			Description: "Review transactions > $5k",
			Match:       Match{AmountMin: 5000},
			Action:      ActionReview,
		},
	})

	tx := models.Transaction{UserID: "u1", Amount: 6000}
	matches := engine.Evaluate(tx)
	if !HasReview(matches) {
		t.Fatal("expected HasReview=true")
	}
}

func TestEngine_FlagRule(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "unusual_merchant",
			Description: "Flag known risky merchant",
			Match:       Match{Merchants: []string{"cryptoexchange"}},
			Action:      ActionFlag,
			Weight:      0.5,
		},
	})

	tx := models.Transaction{UserID: "u1", Amount: 100, Merchant: "CryptoExchange-X"}
	matches := engine.Evaluate(tx)
	if w := FlagWeight(matches); w != 0.5 {
		t.Fatalf("expected flag weight 0.5, got %v", w)
	}
}

func TestEngine_NoMatch(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "high_value_block",
			Description: "Block transactions > $10k",
			Match:       Match{AmountMin: 10000},
			Action:      ActionBlock,
		},
	})

	tx := models.Transaction{UserID: "u1", Amount: 100}
	matches := engine.Evaluate(tx)
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestEngine_MerchantSubstringCaseInsensitive(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "crypto",
			Description: "Flag crypto",
			Match:       Match{Merchants: []string{"cryptoexchange"}},
			Action:      ActionFlag,
			Weight:      0.5,
		},
	})

	cases := []string{"CryptoExchange-X", "CRYPTOEXCHANGE.io", "cryptoexchange-xyz"}
	for _, m := range cases {
		tx := models.Transaction{UserID: "u1", Amount: 100, Merchant: m}
		matches := engine.Evaluate(tx)
		if len(matches) != 1 {
			t.Fatalf("expected merchant %q to match, got %d matches", m, len(matches))
		}
	}
}

func TestEngine_CategoryAndCountryMatch(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "travel_high_value_risk_country",
			Description: "Flag high-value travel to risky countries",
			Match:       Match{AmountMin: 1000, Categories: []string{"travel"}, Countries: []string{"RU", "NG"}},
			Action:      ActionFlag,
			Weight:      0.7,
		},
	})

	// Match: travel + $1500 + RU.
	tx := models.Transaction{UserID: "u1", Amount: 1500, Category: "travel", Country: "RU"}
	if matches := engine.Evaluate(tx); len(matches) != 1 {
		t.Fatalf("expected match for travel+RU+$1500, got %d", len(matches))
	}

	// No match: wrong category.
	tx = models.Transaction{UserID: "u1", Amount: 1500, Category: "shopping", Country: "RU"}
	if matches := engine.Evaluate(tx); len(matches) != 0 {
		t.Fatalf("expected no match for shopping, got %d", len(matches))
	}

	// No match: wrong country.
	tx = models.Transaction{UserID: "u1", Amount: 1500, Category: "travel", Country: "US"}
	if matches := engine.Evaluate(tx); len(matches) != 0 {
		t.Fatalf("expected no match for US, got %d", len(matches))
	}
}

func TestEngine_ExcludeCountries(t *testing.T) {
	engine := NewEngineFromRules([]Rule{
		{
			ID:          "non_us_high_value",
			Description: "Flag high-value transactions outside US",
			Match:       Match{AmountMin: 1000, ExcludeCountries: []string{"US"}},
			Action:      ActionFlag,
			Weight:      0.6,
		},
	})

	// US transaction — should not match.
	tx := models.Transaction{UserID: "u1", Amount: 2000, Country: "US"}
	if matches := engine.Evaluate(tx); len(matches) != 0 {
		t.Fatalf("expected no match for US, got %d", len(matches))
	}

	// Non-US transaction — should match.
	tx = models.Transaction{UserID: "u1", Amount: 2000, Country: "GB"}
	if matches := engine.Evaluate(tx); len(matches) != 1 {
		t.Fatalf("expected match for GB, got %d", len(matches))
	}
}
