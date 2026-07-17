// Package kafka provides a Kafka consumer that ingests transactions from a
// `transactions` topic and scores them in real time via the unified
// pipeline (internal/pipeline.Pipeline). The pipeline is shared with the
// HTTP path so both ingestion routes apply the same idempotency,
// FlagWeight blend, case-creation and notification semantics (Finding
// 3.11).
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gadda00/fraud-detection-system/internal/middleware"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/pipeline"
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

// Consumer runs the Kafka → score → produce loop. Since Phase 1 the
// scoring work is delegated to a *pipeline.Pipeline; the consumer no
// longer holds a Store / Ensemble / Notifier directly — those all live
// inside the pipeline.
type Consumer struct {
	cfg      Config
	pipeline *pipeline.Pipeline
	reader   *kafka.Reader
	writer   *kafka.Writer
}

// NewConsumer builds a Kafka consumer. Call Start() to begin consuming.
func NewConsumer(cfg Config, pipe *pipeline.Pipeline) *Consumer {
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
		pipeline: pipe,
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

// processMessage is the per-message handler. It decodes the transaction,
// runs it through the pipeline, records Prometheus metrics, and — if the
// transaction was flagged — publishes an AlertMessage to the output
// topic. The webhook notification, case creation and persistence all
// happen inside Pipeline.Process so this function stays a thin adapter.
func (c *Consumer) processMessage(ctx context.Context, msg kafka.Message) {
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

	res, err := c.pipeline.Process(ctx, tx)
	if err != nil {
		log.Error().Err(err).Str("tx_id", tx.ID).Msg("kafka pipeline process")
		return
	}

	middleware.RecordScoring(res.Risk.Severity, res.Risk.IsFlagged(), float64(res.LatencyUS))

	if res.Risk.IsFlagged() {
		alert := AlertMessage{
			TransactionID: tx.ID,
			UserID:        tx.UserID,
			Amount:        tx.Amount,
			Currency:      tx.Currency,
			Flagged:       res.Risk.IsFlagged(),
			Risk:          res.Risk,
			ScoredAt:      time.Now().UTC(),
			LatencyUS:     res.LatencyUS,
		}
		payload, _ := json.Marshal(alert)
		if err := c.writer.WriteMessages(ctx, kafka.Message{Value: payload}); err != nil {
			log.Error().Err(err).Str("tx_id", tx.ID).Msg("kafka publish alert")
		}
	}

	log.Debug().
		Str("tx_id", tx.ID).
		Str("user_id", tx.UserID).
		Float64("score", res.Risk.Score).
		Str("severity", res.Risk.Severity).
		Int64("latency_us", res.LatencyUS).
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
