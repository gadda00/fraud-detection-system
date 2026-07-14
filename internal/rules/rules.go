// Package rules implements a configurable rules engine that runs alongside
// the statistical detectors. Rules are deterministic, human-authored
// policies — "block any transaction above $10,000 from country X" — that
// can either hard-block a transaction, force it into review, or contribute
// to the ensemble score.
//
// Rules are loaded from a JSON config file at startup and can be hot-reloaded
// via an admin API. See Config for the file format.
package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gadda00/fraud-detection-system/internal/models"
)

// Action is the consequence of a matched rule.
type Action string

const (
	ActionBlock  Action = "block"  // Hard-block the transaction (return 1.0 + block flag)
	ActionReview Action = "review" // Force into manual review queue
	ActionFlag   Action = "flag"   // Add weight to the ensemble score
)

// Match describes the conditions under which a rule fires. All non-zero
// fields must match for the rule to fire (logical AND).
type Match struct {
	AmountMin        float64  `json:"amount_min,omitempty"`
	AmountMax        float64  `json:"amount_max,omitempty"`
	Countries        []string `json:"countries,omitempty"`
	ExcludeCountries []string `json:"exclude_countries,omitempty"`
	Merchants        []string `json:"merchants,omitempty"`
	Categories       []string `json:"categories,omitempty"`
	DeviceIDs        []string `json:"device_ids,omitempty"`
	UserIDs          []string `json:"user_ids,omitempty"`
}

// Rule is a single deterministic policy.
type Rule struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Match       Match   `json:"match"`
	Action      Action  `json:"action"`
	Weight      float64 `json:"weight"`
}

// Config is the top-level rules file format.
type Config struct {
	Rules []Rule `json:"rules"`
}

// Engine evaluates rules against a transaction.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine loads rules from a JSON file. Missing file = no rules (permissive).
func NewEngine(path string) (*Engine, error) {
	e := &Engine{}
	if path == "" {
		return e, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return e, nil
		}
		return nil, fmt.Errorf("read rules %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	e.rules = cfg.Rules
	return e, nil
}

// NewEngineFromRules builds an engine from an in-memory rule slice.
func NewEngineFromRules(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Reload re-reads the rules file. Safe to call concurrently with Evaluate.
func (e *Engine) Reload(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = cfg.Rules
	return nil
}

// RuleMatch is the result of evaluating one rule against a transaction.
type RuleMatch struct {
	Rule   Rule    `json:"rule"`
	Action Action  `json:"action"`
	Weight float64 `json:"weight,omitempty"`
	Reason string  `json:"reason"`
}

// Evaluate runs all rules against tx and returns the matches that fired.
func (e *Engine) Evaluate(tx models.Transaction) []RuleMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []RuleMatch
	for _, r := range e.rules {
		if matchesRule(tx, r.Match) {
			matches = append(matches, RuleMatch{
				Rule:   r,
				Action: r.Action,
				Weight: r.Weight,
				Reason: r.Description,
			})
		}
	}
	return matches
}

func matchesRule(tx models.Transaction, m Match) bool {
	if m.AmountMin > 0 && tx.Amount < m.AmountMin {
		return false
	}
	if m.AmountMax > 0 && tx.Amount > m.AmountMax {
		return false
	}
	if len(m.Countries) > 0 && !contains(m.Countries, tx.Country) {
		return false
	}
	if len(m.ExcludeCountries) > 0 && contains(m.ExcludeCountries, tx.Country) {
		return false
	}
	if len(m.Merchants) > 0 && !containsAnySubstring(m.Merchants, tx.Merchant) {
		return false
	}
	if len(m.Categories) > 0 && !contains(m.Categories, tx.Category) {
		return false
	}
	if len(m.DeviceIDs) > 0 && !contains(m.DeviceIDs, tx.DeviceID) {
		return false
	}
	if len(m.UserIDs) > 0 && !contains(m.UserIDs, tx.UserID) {
		return false
	}
	return true
}

func contains(slice []string, s string) bool {
	for _, x := range slice {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func containsAnySubstring(substrings []string, s string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// HasBlock reports whether any matched rule has Action=block.
func HasBlock(matches []RuleMatch) bool {
	for _, m := range matches {
		if m.Action == ActionBlock {
			return true
		}
	}
	return false
}

// HasReview reports whether any matched rule has Action=review.
func HasReview(matches []RuleMatch) bool {
	for _, m := range matches {
		if m.Action == ActionReview {
			return true
		}
	}
	return false
}

// FlagWeight sums the weights of all Action=flag matches, capped at 1.0.
func FlagWeight(matches []RuleMatch) float64 {
	var sum float64
	for _, m := range matches {
		if m.Action == ActionFlag {
			sum += m.Weight
		}
	}
	if sum > 1.0 {
		sum = 1.0
	}
	return sum
}
