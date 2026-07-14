// Package cases implements the analyst-facing case management system.
//
// When a transaction is flagged (either by the ensemble or by a rule with
// Action=review), a Case is created and placed in the review queue. Analysts
// can then:
//
//   - Confirm fraud (block the card, reverse the transaction)
//   - Mark as false positive (feed back into model retraining)
//   - Escalate to a senior analyst
//   - Request more information from the customer
//
// Cases are persisted to the storage layer (Postgres in production, in-memory
// in dev) and exposed via the /api/cases endpoints.
package cases

import (
	"sync"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
)

// Status is the lifecycle state of a case.
type Status string

const (
	StatusOpen          Status = "open"           // Awaiting analyst review
	StatusInReview      Status = "in_review"      // Analyst has picked it up
	StatusConfirmed     Status = "confirmed"      // Analyst confirmed fraud
	StatusFalsePositive Status = "false_positive" // Analyst cleared
	StatusEscalated     Status = "escalated"      // Sent to senior analyst
	StatusAutoResolved  Status = "auto_resolved"  // Closed by rule (e.g. block)
)

// Priority is how urgently a case needs human attention.
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

// Case is the central artefact of the analyst workflow.
type Case struct {
	ID            string     `json:"id"`
	TransactionID string     `json:"transaction_id"`
	UserID        string     `json:"user_id"`
	Amount        float64    `json:"amount"`
	Currency      string     `json:"currency"`
	Merchant      string     `json:"merchant"`
	Category      string     `json:"category"`
	Country       string     `json:"country"`
	RiskScore     float64    `json:"risk_score"`
	Severity      string     `json:"severity"`
	Reasons       []string   `json:"reasons"`
	Detectors     []string   `json:"detectors"`
	RuleMatches   []string   `json:"rule_matches,omitempty"`
	Status        Status     `json:"status"`
	Priority      Priority   `json:"priority"`
	AssignedTo    string     `json:"assigned_to,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
	Notes         []Note     `json:"notes,omitempty"`
}

// Note is an analyst comment on a case.
type Note struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// Manager owns the case lifecycle. In production this would be backed by
// Postgres; here it uses an in-memory map protected by a mutex.
type Manager struct {
	mu    sync.RWMutex
	cases map[string]*Case
}

// NewManager creates an empty case manager.
func NewManager() *Manager {
	return &Manager{cases: make(map[string]*Case)}
}

// Create opens a new case for a flagged transaction. Returns the case ID.
func (m *Manager) Create(tx models.Transaction, risk models.RiskScore, ruleMatches []string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := "case-" + tx.ID
	now := time.Now().UTC()
	c := &Case{
		ID:            id,
		TransactionID: tx.ID,
		UserID:        tx.UserID,
		Amount:        tx.Amount,
		Currency:      tx.Currency,
		Merchant:      tx.Merchant,
		Category:      tx.Category,
		Country:       tx.Country,
		RiskScore:     risk.Score,
		Severity:      risk.Severity,
		Reasons:       risk.Reasons,
		Detectors:     risk.Detectors,
		RuleMatches:   ruleMatches,
		Status:        StatusOpen,
		Priority:      priorityFromSeverity(risk.Severity),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	m.cases[id] = c
	return id
}

// Get returns a case by ID.
func (m *Manager) Get(id string) (*Case, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.cases[id]
	return c, ok
}

// List returns cases filtered by status. Pass "" for all statuses.
func (m *Manager) List(status Status) []*Case {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Case
	for _, c := range m.cases {
		if status == "" || c.Status == status {
			out = append(out, c)
		}
	}
	return out
}

// Assign marks a case as in-review by an analyst.
func (m *Manager) Assign(id, analyst string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cases[id]
	if !ok {
		return errCaseNotFound
	}
	c.Status = StatusInReview
	c.AssignedTo = analyst
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// Resolve closes a case with the given final status.
func (m *Manager) Resolve(id string, status Status, analyst, note string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cases[id]
	if !ok {
		return errCaseNotFound
	}
	now := time.Now().UTC()
	c.Status = status
	c.AssignedTo = analyst
	c.ResolvedAt = &now
	c.UpdatedAt = now
	if note != "" {
		c.Notes = append(c.Notes, Note{
			ID:        noteID(),
			Author:    analyst,
			Text:      note,
			CreatedAt: now,
		})
	}
	return nil
}

// AddNote adds a comment to a case without changing its status.
func (m *Manager) AddNote(id, author, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cases[id]
	if !ok {
		return errCaseNotFound
	}
	c.Notes = append(c.Notes, Note{
		ID:        noteID(),
		Author:    author,
		Text:      text,
		CreatedAt: time.Now().UTC(),
	})
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// Stats summarises the case queue.
type Stats struct {
	Total          int              `json:"total"`
	ByStatus       map[Status]int   `json:"by_status"`
	ByPriority     map[Priority]int `json:"by_priority"`
	ConfirmedFraud int              `json:"confirmed_fraud"`
	FalsePositives int              `json:"false_positives"`
}

// Stats returns aggregate counts for dashboards.
func (m *Manager) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Stats{
		ByStatus:   make(map[Status]int),
		ByPriority: make(map[Priority]int),
	}
	for _, c := range m.cases {
		s.Total++
		s.ByStatus[c.Status]++
		s.ByPriority[c.Priority]++
		if c.Status == StatusConfirmed {
			s.ConfirmedFraud++
		}
		if c.Status == StatusFalsePositive {
			s.FalsePositives++
		}
	}
	return s
}

func priorityFromSeverity(sev string) Priority {
	switch sev {
	case models.SeverityCritical:
		return PriorityCritical
	case models.SeverityHigh:
		return PriorityHigh
	case models.SeverityMedium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

func noteID() string {
	return "note-" + time.Now().UTC().Format("20060102-150405.000000")
}
