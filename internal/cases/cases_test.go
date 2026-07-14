package cases

import (
        "testing"

        "github.com/gadda00/fraud-detection-system/internal/models"
)

func TestManager_CreateAndGet(t *testing.T) {
        mgr := NewManager()
        tx := models.Transaction{ID: "tx-1", UserID: "u1", Amount: 5000, Currency: "USD", Merchant: "Amazon", Category: "shopping", Country: "US"}
        risk := models.RiskScore{Score: 0.9, Severity: models.SeverityCritical, Reasons: []string{"test"}, Detectors: []string{"zscore"}}

        id := mgr.Create(tx, risk, nil)
        if id == "" {
                t.Fatal("expected non-empty case ID")
        }

        cs, ok := mgr.Get(id)
        if !ok {
                t.Fatalf("case %s not found", id)
        }
        if cs.TransactionID != "tx-1" {
                t.Fatalf("expected tx_id=tx-1, got %s", cs.TransactionID)
        }
        if cs.Status != StatusOpen {
                t.Fatalf("expected status=open, got %s", cs.Status)
        }
        if cs.Priority != PriorityCritical {
                t.Fatalf("expected priority=critical, got %s", cs.Priority)
        }
}

func TestManager_AssignAndResolve(t *testing.T) {
        mgr := NewManager()
        tx := models.Transaction{ID: "tx-1", UserID: "u1", Amount: 5000}
        risk := models.RiskScore{Score: 0.8, Severity: models.SeverityHigh}
        id := mgr.Create(tx, risk, nil)

        if err := mgr.Assign(id, "analyst1"); err != nil {
                t.Fatalf("assign failed: %v", err)
        }
        cs, _ := mgr.Get(id)
        if cs.Status != StatusInReview || cs.AssignedTo != "analyst1" {
                t.Fatalf("expected in_review/analyst1, got %s/%s", cs.Status, cs.AssignedTo)
        }

        if err := mgr.Resolve(id, StatusConfirmed, "analyst1", "confirmed fraud"); err != nil {
                t.Fatalf("resolve failed: %v", err)
        }
        cs, _ = mgr.Get(id)
        if cs.Status != StatusConfirmed {
                t.Fatalf("expected confirmed, got %s", cs.Status)
        }
        if cs.ResolvedAt == nil {
                t.Fatal("expected resolved_at to be set")
        }
        if len(cs.Notes) != 1 || cs.Notes[0].Text != "confirmed fraud" {
                t.Fatalf("expected 1 note 'confirmed fraud', got %+v", cs.Notes)
        }
}

func TestManager_ListByStatus(t *testing.T) {
        mgr := NewManager()
        tx1 := models.Transaction{ID: "tx-1", UserID: "u1", Amount: 100}
        tx2 := models.Transaction{ID: "tx-2", UserID: "u2", Amount: 200}
        risk := models.RiskScore{Score: 0.8, Severity: models.SeverityHigh}
        id1 := mgr.Create(tx1, risk, nil)
        id2 := mgr.Create(tx2, risk, nil)

        if err := mgr.Resolve(id1, StatusConfirmed, "a1", ""); err != nil {
                t.Fatalf("resolve 1: %v", err)
        }
        if err := mgr.Resolve(id2, StatusFalsePositive, "a1", ""); err != nil {
                t.Fatalf("resolve 2: %v", err)
        }

        open := mgr.List(StatusOpen)
        if len(open) != 0 {
                t.Fatalf("expected 0 open, got %d", len(open))
        }
        confirmed := mgr.List(StatusConfirmed)
        if len(confirmed) != 1 {
                t.Fatalf("expected 1 confirmed, got %d", len(confirmed))
        }
        fp := mgr.List(StatusFalsePositive)
        if len(fp) != 1 {
                t.Fatalf("expected 1 false_positive, got %d", len(fp))
        }
}

func TestManager_Stats(t *testing.T) {
        mgr := NewManager()
        tx := models.Transaction{ID: "tx-1", UserID: "u1", Amount: 100}
        risk := models.RiskScore{Score: 0.9, Severity: models.SeverityCritical}
        id := mgr.Create(tx, risk, nil)
        if err := mgr.Resolve(id, StatusConfirmed, "a1", ""); err != nil {
                t.Fatalf("resolve: %v", err)
        }

        s := mgr.Stats()
        if s.Total != 1 {
                t.Fatalf("expected total=1, got %d", s.Total)
        }
        if s.ConfirmedFraud != 1 {
                t.Fatalf("expected confirmed=1, got %d", s.ConfirmedFraud)
        }
        if s.ByStatus[StatusConfirmed] != 1 {
                t.Fatalf("expected by_status[confirmed]=1, got %d", s.ByStatus[StatusConfirmed])
        }
}

func TestManager_AddNote(t *testing.T) {
        mgr := NewManager()
        tx := models.Transaction{ID: "tx-1", UserID: "u1", Amount: 100}
        risk := models.RiskScore{Score: 0.5, Severity: models.SeverityMedium}
        id := mgr.Create(tx, risk, nil)

        if err := mgr.AddNote(id, "analyst1", "investigating"); err != nil {
                t.Fatalf("add note failed: %v", err)
        }
        cs, _ := mgr.Get(id)
        if len(cs.Notes) != 1 {
                t.Fatalf("expected 1 note, got %d", len(cs.Notes))
        }
}

func TestManager_GetNonexistent(t *testing.T) {
        mgr := NewManager()
        if _, ok := mgr.Get("nonexistent"); ok {
                t.Fatal("expected not found")
        }
}
