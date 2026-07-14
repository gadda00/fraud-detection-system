// Package webhooks delivers real-time alerts when high-severity transactions
// are flagged. Currently supports Slack incoming webhooks; email and Stripe
// block actions can be added behind the same Notifier interface.
package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/rs/zerolog/log"
)

// Notifier sends an alert about a flagged transaction.
type Notifier interface {
	Notify(ctx context.Context, tx models.Transaction, risk models.RiskScore) error
}

// NoopNotifier does nothing (used when no webhooks are configured).
type NoopNotifier struct{}

func (NoopNotifier) Notify(context.Context, models.Transaction, models.RiskScore) error { return nil }

// SlackNotifier posts to a Slack incoming webhook.
type SlackNotifier struct {
	WebhookURL string
	Client     *http.Client
}

// NewSlackNotifier builds a notifier. If webhookURL is empty, returns NoopNotifier.
func NewSlackNotifier(webhookURL string) Notifier {
	if webhookURL == "" {
		return NoopNotifier{}
	}
	return &SlackNotifier{
		WebhookURL: webhookURL,
		Client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// Notify implements Notifier.
func (s *SlackNotifier) Notify(ctx context.Context, tx models.Transaction, risk models.RiskScore) error {
	if risk.Severity != models.SeverityHigh && risk.Severity != models.SeverityCritical {
		return nil // only alert on high/critical
	}

	color := "#ff0000" // red
	if risk.Severity == models.SeverityHigh {
		color = "#ff9900" // orange
	}

	message := map[string]interface{}{
		"username":   "Fraud Sentinel",
		"icon_emoji": ":rotating_light:",
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("🚨 %s severity fraud alert — %s", risk.Severity, tx.ID),
				"fields": []map[string]string{
					{"title": "User", "value": tx.UserID, "short": "true"},
					{"title": "Amount", "value": fmt.Sprintf("%.2f %s", tx.Amount, tx.Currency), "short": "true"},
					{"title": "Merchant", "value": tx.Merchant, "short": "true"},
					{"title": "Country", "value": tx.Country, "short": "true"},
					{"title": "Category", "value": tx.Category, "short": "true"},
					{"title": "Score", "value": fmt.Sprintf("%.3f", risk.Score), "short": "true"},
					{"title": "Detectors", "value": fmt.Sprintf("%v", risk.Detectors), "short": "false"},
					{"title": "Reasons", "value": fmt.Sprintf("%v", risk.Reasons), "short": "false"},
				},
				"ts": time.Now().Unix(),
			},
		},
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("slack webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}

	log.Info().
		Str("tx_id", tx.ID).
		Str("severity", risk.Severity).
		Msg("slack alert sent")
	return nil
}
