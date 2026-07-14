// Package kafka provides a Kafka consumer that ingests transactions from a
// `transactions` topic and scores them in real time.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/middleware"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/gadda00/fraud-detection-system/internal/webhooks"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/kafka-go"
)

// Config holds the Kafka consumer + producer settings.
type Config struct {
	Brokers        []string
	InputTopic     string
	OutputTopic    string
	ConsumerGroup  string
	CommitInterval time.Duration
}

// Consumer runs the Kafka → score → produce loop.
type Consumer struct {
	cfg      Config
	store    *storage.Store
	ensemble *detector.EnsembleDetector
	notifier webhooks.Notifier
	reader   *kafka.Reader
	writer   *kafka.Writer
}

// NewConsumer builds a Kafka consumer. Call Start() to begin consuming.
func NewConsumer(cfg Config, store *storage.Store, ensemble *detector.EnsembleDetector, notifier webhooks.Notifier) *Consumer {
	if cfg.InputTopic == "" {
		cfg.InputTopic = "transactions"
	}
	if cfg.OutputTopic == "" {
		cfg.OutputTopic = "fraud-alerts"
	}
	if cfg.ConsumerGroup == "" {
		cfg.ConsumerGroup = "fraud-detection"
	}
	if cfg.CommitInterval == 0 {
		cfg.CommitInterval = 5 * time.Second
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        cfg.Brokers,
		Topic:          cfg.InputTopic,
		GroupID:        cfg.ConsumerGroup,
		CommitInterval: cfg.CommitInterval,
		MinBytes:       1,
		MaxBytes:       10e6,
	})
	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.OutputTopic,
		Balancer:     &kafka.LeastBytes{},
		BatchTimeout: 10 * time.Millisecond,
	}

	return &Consumer{
		cfg:      cfg,
		store:    store,
		ensemble: ensemble,
		notifier: notifier,
		reader:   reader,
		writer:   writer,
	}
}

// Start begins consuming in a background goroutine.
func (c *Consumer) Start(ctx context.Context) {
	log.Info().
		Strs("brokers", c.cfg.Brokers).
		Str("input_topic", c.cfg.InputTopic).
		Str("output_topic", c.cfg.OutputTopic).
		Str("consumer_group", c.cfg.ConsumerGroup).
		Msg("kafka consumer starting")

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("kafka consumer stopping")
				return
			default:
				msg, err := c.reader.ReadMessage(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Error().Err(err).Msg("kafka read message")
					continue
				}
				c.processMessage(ctx, msg)
			}
		}
	}()
}

// AlertMessage is the JSON published to the fraud-alerts output topic.
type AlertMessage struct {
	TransactionID string           `json:"transaction_id"`
	UserID        string           `json:"user_id"`
	Amount        float64          `json:"amount"`
	Currency      string           `json:"currency"`
	Flagged       bool             `json:"flagged"`
	Risk          models.RiskScore `json:"risk"`
	ScoredAt      time.Time        `json:"scored_at"`
	LatencyUS     int64            `json:"latency_us"`
}

func (c *Consumer) processMessage(ctx context.Context, msg kafka.Message) {
	start := time.Now()

	var tx models.Transaction
	if err := json.Unmarshal(msg.Value, &tx); err != nil {
		log.Error().Err(err).Bytes("raw", msg.Value).Msg("kafka unmarshal transaction")
		return
	}
	if tx.ID == "" {
		tx.ID = fmt.Sprintf("kafka-%d-%s", msg.Offset, msg.Topic)
	}
	if tx.Timestamp.IsZero() {
		tx.Timestamp = time.Now().UTC()
	}

	risk := c.ensemble.Score(tx)
	c.store.Add(tx, risk)
	middleware.RecordScoring(risk.Severity, risk.IsFlagged(), float64(time.Since(start).Microseconds()))

	if risk.IsFlagged() {
		alert := AlertMessage{
			TransactionID: tx.ID,
			UserID:        tx.UserID,
			Amount:        tx.Amount,
			Currency:      tx.Currency,
			Flagged:       risk.IsFlagged(),
			Risk:          risk,
			ScoredAt:      time.Now().UTC(),
			LatencyUS:     time.Since(start).Microseconds(),
		}
		payload, _ := json.Marshal(alert)
		if err := c.writer.WriteMessages(ctx, kafka.Message{Value: payload}); err != nil {
			log.Error().Err(err).Str("tx_id", tx.ID).Msg("kafka publish alert")
		}

		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := c.notifier.Notify(notifyCtx, tx, risk); err != nil {
				log.Error().Err(err).Str("tx_id", tx.ID).Msg("kafka webhook notify")
			}
		}()
	}

	log.Debug().
		Str("tx_id", tx.ID).
		Str("user_id", tx.UserID).
		Float64("score", risk.Score).
		Str("severity", risk.Severity).
		Int64("latency_us", time.Since(start).Microseconds()).
		Msg("kafka scored")
}

// Close gracefully shuts down the reader and writer.
func (c *Consumer) Close() error {
	if err := c.reader.Close(); err != nil {
		return fmt.Errorf("kafka reader close: %w", err)
	}
	if err := c.writer.Close(); err != nil {
		return fmt.Errorf("kafka writer close: %w", err)
	}
	return nil
}
