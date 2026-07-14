package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// reloadRulesRequest is the body of POST /admin/rules/reload.
type reloadRulesRequest struct {
	Path string `json:"path"`
}

// ReloadRules hot-reloads the rules engine from a JSON file.
func (s *Server) ReloadRules(c *gin.Context) {
	var body reloadRulesRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	if s.RulesEngine == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rules engine is not configured"})
		return
	}
	if err := s.RulesEngine.Reload(body.Path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "reloaded"})
}
