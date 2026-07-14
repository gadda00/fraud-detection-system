package api

import (
	"net/http"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/cases"
	"github.com/gadda00/fraud-detection-system/internal/middleware"
	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// /api/cases endpoints
// ---------------------------------------------------------------------------

// listCasesResponse wraps the cases list with pagination metadata.
type listCasesResponse struct {
	Cases []*cases.Case `json:"cases"`
	Total int           `json:"total"`
}

// ListCases returns cases filtered by ?status= (open, in_review, confirmed, false_positive, escalated).
// Without a status filter, returns all cases.
func (s *Server) ListCases(c *gin.Context) {
	status := cases.Status(c.Query("status"))
	all := s.CaseManager.List(status)
	c.JSON(http.StatusOK, listCasesResponse{
		Cases: all,
		Total: len(all),
	})
}

// GetCase returns a single case by ID.
func (s *Server) GetCase(c *gin.Context) {
	id := c.Param("id")
	cs, ok := s.CaseManager.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	c.JSON(http.StatusOK, cs)
}

// assignRequest is the body of POST /api/cases/:id/assign.
type assignRequest struct {
	Analyst string `json:"analyst"`
}

// AssignCase marks a case as in-review by an analyst.
func (s *Server) AssignCase(c *gin.Context) {
	id := c.Param("id")
	var body assignRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	if body.Analyst == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "analyst is required"})
		return
	}
	if err := s.CaseManager.Assign(id, body.Analyst); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "assigned", "assigned_to": body.Analyst})
}

// resolveRequest is the body of POST /api/cases/:id/resolve.
type resolveRequest struct {
	Status cases.Status `json:"status"`
	Note   string       `json:"note"`
}

// ResolveCase closes a case with a final verdict.
func (s *Server) ResolveCase(c *gin.Context) {
	id := c.Param("id")
	var body resolveRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	if body.Status != cases.StatusConfirmed && body.Status != cases.StatusFalsePositive && body.Status != cases.StatusEscalated {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be confirmed, false_positive, or escalated"})
		return
	}

	p, _ := c.Get(middleware.ContextPrincipal)
	analyst := "system"
	if princ, ok := p.(*principalAlias); ok {
		analyst = princ.ID
	}

	if err := s.CaseManager.Resolve(id, body.Status, analyst, body.Note); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": body.Status, "resolved_at": time.Now().UTC()})
}

// noteRequest is the body of POST /api/cases/:id/notes.
type noteRequest struct {
	Text string `json:"text"`
}

// AddNote adds a comment to a case.
func (s *Server) AddNote(c *gin.Context) {
	id := c.Param("id")
	var body noteRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	if body.Text == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "text is required"})
		return
	}

	p, _ := c.Get(middleware.ContextPrincipal)
	author := "system"
	if princ, ok := p.(*principalAlias); ok {
		author = princ.ID
	}

	if err := s.CaseManager.AddNote(id, author, body.Text); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"status": "note added"})
}

// CaseStats returns aggregate counts for the case queue.
func (s *Server) CaseStats(c *gin.Context) {
	c.JSON(http.StatusOK, s.CaseManager.Stats())
}
