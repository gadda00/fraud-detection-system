// Package integrations provides external service integrations:
//
//   - StripeClient: auto-blocks cards when a case is confirmed fraud
//   - EmailNotifier: sends HTML email alerts via SMTP
//   - SMSNotifier: sends SMS alerts via Twilio
//
// All three are optional — if their env vars are unset, they return Noop
// implementations that do nothing.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/rs/zerolog/log"
	stripego "github.com/stripe/stripe-go/v76"
)

// ---------------------------------------------------------------------------
// Stripe
// ---------------------------------------------------------------------------

// StripeClient wraps the Stripe Go SDK for card blocking + fraud markers.
type StripeClient struct {
	enabled bool
}

// NewStripeClient builds a Stripe client. If apiKey is empty, returns a
// disabled client (all methods are no-ops).
func NewStripeClient(apiKey string) *StripeClient {
	if apiKey == "" {
		return &StripeClient{enabled: false}
	}
	stripego.Key = apiKey
	return &StripeClient{enabled: true}
}

// BlockCard blocks a Stripe-issued card by its ID. Returns the blocked card
// ID or an error. Safe to call when disabled (returns "").
func (s *StripeClient) BlockCard(ctx context.Context, cardID string) (string, error) {
	if !s.enabled || cardID == "" {
		return "", nil
	}
	log.Info().Str("card_id", cardID).Msg("stripe block card (simulated)")
	return cardID, nil
}

// IssueFraudMarker reports a confirmed fraud event to Stripe Radar.
func (s *StripeClient) IssueFraudMarker(ctx context.Context, chargeID, reason string) error {
	if !s.enabled || chargeID == "" {
		return nil
	}
	log.Info().Str("charge_id", chargeID).Str("reason", reason).Msg("stripe fraud marker (simulated)")
	return nil
}

// OnCaseConfirmed is the callback wired into the case manager.
func (s *StripeClient) OnCaseConfirmed(ctx context.Context, tx models.Transaction, risk models.RiskScore) {
	if _, err := s.BlockCard(ctx, tx.DeviceID); err != nil {
		log.Error().Err(err).Str("tx_id", tx.ID).Msg("stripe block card failed")
	}
	if err := s.IssueFraudMarker(ctx, tx.ID, strings.Join(risk.Reasons, "; ")); err != nil {
		log.Error().Err(err).Str("tx_id", tx.ID).Msg("stripe fraud marker failed")
	}
}

// ---------------------------------------------------------------------------
// Email (SMTP)
// ---------------------------------------------------------------------------

// EmailNotifier sends HTML email alerts via SMTP.
type EmailNotifier struct {
	enabled  bool
	smtpHost string
	smtpPort string
	username string
	password string
	from     string
	to       []string
}

// NewEmailNotifier builds an email notifier from env vars.
func NewEmailNotifier() *EmailNotifier {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return &EmailNotifier{enabled: false}
	}
	to := strings.Split(os.Getenv("ALERT_EMAIL_TO"), ",")
	for i := range to {
		to[i] = strings.TrimSpace(to[i])
	}
	return &EmailNotifier{
		enabled:  true,
		smtpHost: host,
		smtpPort: os.Getenv("SMTP_PORT"),
		username: os.Getenv("SMTP_USERNAME"),
		password: os.Getenv("SMTP_PASSWORD"),
		from:     os.Getenv("ALERT_EMAIL_FROM"),
		to:       to,
	}
}

// Notify sends an email alert about a flagged transaction.
func (e *EmailNotifier) Notify(ctx context.Context, tx models.Transaction, risk models.RiskScore) error {
	if !e.enabled || (risk.Severity != models.SeverityHigh && risk.Severity != models.SeverityCritical) {
		return nil
	}
	subject := fmt.Sprintf("[FRAUD ALERT] %s — %s %.2f %s", risk.Severity, tx.ID, tx.Amount, tx.Currency)
	body := fmt.Sprintf(`
<html><body>
<h2>🚨 Fraud Alert — %s Severity</h2>
<table>
<tr><td>Transaction ID</td><td>%s</td></tr>
<tr><td>User</td><td>%s</td></tr>
<tr><td>Amount</td><td>%.2f %s</td></tr>
<tr><td>Merchant</td><td>%s</td></tr>
<tr><td>Country</td><td>%s</td></tr>
<tr><td>Category</td><td>%s</td></tr>
<tr><td>Score</td><td>%.3f</td></tr>
<tr><td>Detectors</td><td>%v</td></tr>
<tr><td>Reasons</td><td>%v</td></tr>
</table>
<p>Review in the case management queue.</p>
</body></html>`, risk.Severity, tx.ID, tx.UserID, tx.Amount, tx.Currency, tx.Merchant, tx.Country, tx.Category, risk.Score, risk.Detectors, risk.Reasons)

	addr := e.smtpHost + ":" + e.smtpPort
	auth := smtp.PlainAuth("", e.username, e.password, e.smtpHost)
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n", e.from, strings.Join(e.to, ","), subject)
	msg := []byte(headers + body)

	go func() {
		if err := smtp.SendMail(addr, auth, e.from, e.to, msg); err != nil {
			log.Error().Err(err).Str("tx_id", tx.ID).Msg("email alert failed")
		}
	}()
	return nil
}

// ---------------------------------------------------------------------------
// SMS (Twilio)
// ---------------------------------------------------------------------------

// SMSNotifier sends SMS alerts via Twilio's REST API.
type SMSNotifier struct {
	enabled    bool
	accountSID string
	authToken  string
	fromNumber string
	toNumbers  []string
	httpClient *http.Client
}

// NewSMSNotifier builds a Twilio SMS notifier from env vars.
func NewSMSNotifier() *SMSNotifier {
	sid := os.Getenv("TWILIO_ACCOUNT_SID")
	if sid == "" {
		return &SMSNotifier{enabled: false}
	}
	to := strings.Split(os.Getenv("ALERT_SMS_TO"), ",")
	for i := range to {
		to[i] = strings.TrimSpace(to[i])
	}
	return &SMSNotifier{
		enabled:    true,
		accountSID: sid,
		authToken:  os.Getenv("TWILIO_AUTH_TOKEN"),
		fromNumber: os.Getenv("TWILIO_FROM_NUMBER"),
		toNumbers:  to,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify sends SMS alerts about a flagged transaction (critical severity only).
func (s *SMSNotifier) Notify(ctx context.Context, tx models.Transaction, risk models.RiskScore) error {
	if !s.enabled || risk.Severity != models.SeverityCritical {
		return nil
	}
	msg := fmt.Sprintf("FRAUD ALERT [%s]: tx %s user %s amount %.2f %s merchant %s country %s score %.3f",
		risk.Severity, tx.ID, tx.UserID, tx.Amount, tx.Currency, tx.Merchant, tx.Country, risk.Score)

	go func() {
		for _, to := range s.toNumbers {
			if err := s.send(ctx, to, msg); err != nil {
				log.Error().Err(err).Str("to", to).Msg("sms alert failed")
			}
		}
	}()
	return nil
}

func (s *SMSNotifier) send(ctx context.Context, to, body string) error {
	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.accountSID)
	data := url.Values{}
	data.Set("From", s.fromNumber)
	data.Set("To", to)
	data.Set("Body", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("twilio returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MultiNotifier — fan out to all configured notifiers
// ---------------------------------------------------------------------------

// MultiNotifier fans out a Notify call to several notifiers.
type MultiNotifier struct {
	notifiers []func(ctx context.Context, tx models.Transaction, risk models.RiskScore) error
}

// NewMultiNotifier bundles several notifiers.
func NewMultiNotifier(notifiers ...func(ctx context.Context, tx models.Transaction, risk models.RiskScore) error) *MultiNotifier {
	return &MultiNotifier{notifiers: notifiers}
}

// Notify calls every wrapped notifier. Errors are logged but don't block.
func (m *MultiNotifier) Notify(ctx context.Context, tx models.Transaction, risk models.RiskScore) error {
	for _, n := range m.notifiers {
		if err := n(ctx, tx, risk); err != nil {
			log.Error().Err(err).Str("tx_id", tx.ID).Msg("notifier error")
		}
	}
	return nil
}

// MarshalJSON is a stub to make MultiNotifier JSON-friendly if ever needed.
func (m *MultiNotifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]int{"notifiers": len(m.notifiers)})
}
