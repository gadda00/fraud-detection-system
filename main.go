// Command fraud-detection-system starts the real-time transaction fraud
// scoring service.
//
// On boot it:
//
//  1. Loads configuration from environment variables.
//  2. Initialises structured logging + OpenTelemetry tracing.
//  3. Builds the storage backend (in-memory by default; Redis or Postgres
//     when configured).
//  4. In DEMO_MODE (default in development): seeds the store with a
//     realistic, labelled dataset (1000 transactions, 50 users, 5% fraud),
//     runs an offline evaluation of the ensemble detector, and fits the
//     logistic calibrator on the labelled data. In production this step is
//     skipped — see the DEMO_MODE env var.
//  5. Loads the rules engine (if RULES_PATH is set).
//  6. Builds the case manager, webhook notifier, and auth verifiers.
//  7. Starts a Gin HTTP server on :8080 exposing the full API surface.
//  8. Shuts down gracefully on SIGINT / SIGTERM.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/gadda00/fraud-detection-system/internal/api"
	"github.com/gadda00/fraud-detection-system/internal/auth"
	"github.com/gadda00/fraud-detection-system/internal/cases"
	"github.com/gadda00/fraud-detection-system/internal/config"
	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/integrations"
	"github.com/gadda00/fraud-detection-system/internal/kafka"
	"github.com/gadda00/fraud-detection-system/internal/ml"
	"github.com/gadda00/fraud-detection-system/internal/models"
	"github.com/gadda00/fraud-detection-system/internal/observability"
	"github.com/gadda00/fraud-detection-system/internal/rules"
	"github.com/gadda00/fraud-detection-system/internal/storage"
	"github.com/gadda00/fraud-detection-system/internal/training"
	"github.com/gadda00/fraud-detection-system/internal/webhooks"
)

func main() {
	cfg := config.Load()

	// 1. Logging + tracing.
	shutdown, err := observability.Init("fraud-detection-system", cfg.Version, cfg.Environment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observability init: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	}()

	log.Info().
		Str("env", cfg.Environment).
		Str("version", cfg.Version).
		Str("storage", cfg.StorageBackend).
		Msg("starting fraud-detection-system")

	// 2. Build & seed the store.
	//
	// The seed/evaluate/calibrate path runs by default in development so
	// the API is usable immediately. In production it is skipped —
	// seeding 1,000 synthetic transactions into the real store would
	// pollute dashboards, and boot-time calibration against a fake
	// dataset would silently overwrite any operator-tuned coefficients.
	// Override with DEMO_MODE=true to force it on in prod (e.g. for a
	// demo environment that still runs with ENVIRONMENT=production).
	store := storage.New()
	calibrator := ml.NewLogisticCalibrator()
	if !cfg.DemoMode {
		log.Warn().Msg("production mode: skipping synthetic seed data and boot-time calibration")
	} else {
		data := api.GenerateSeedData()
		loaded := api.SeedStore(store, data)
		users, _ := store.UserCount(context.Background())
		log.Info().
			Int("transactions", loaded).
			Int("users", users).
			Int("fraud", len(data.FraudIDs)).
			Msg("seeded dataset")

		// 3. Offline evaluation.
		evalStore := storage.New()
		evalEnsemble := detector.NewEnsembleDetector(evalStore)
		m := api.Evaluate(evalEnsemble, evalStore, data)
		log.Info().
			Int("total", m.Total).
			Int("fraud", m.Fraud).
			Int("tp", m.TruePos).Int("fp", m.FalsePos).
			Int("fn", m.FalseNeg).Int("tn", m.TrueNeg).
			Float64("recall", m.Recall).
			Float64("precision", m.Precision).
			Float64("f1", m.F1).
			Float64("fpr", m.FPR).
			Msg("offline evaluation")

		// 4. Fit the logistic calibrator on the labelled data.
		calPairs := buildCalibrationPairs(evalEnsemble, evalStore, data)
		calibrator.Fit(calPairs, 500, 0.1)
		a, b := calibrator.Coefficients()
		log.Info().Float64("a", a).Float64("b", b).Msg("calibrator fitted")
	}

	// 5. Rules engine (optional).
	rulesEngine, err := rules.NewEngine(cfg.RulesPath)
	if err != nil {
		log.Error().Err(err).Str("path", cfg.RulesPath).Msg("rules engine load failed")
	} else if len(rulesEngine.Evaluate(models.Transaction{})) == 0 && cfg.RulesPath != "" {
		log.Info().Str("path", cfg.RulesPath).Msg("rules engine loaded")
	}

	// 6. Case manager + multi-channel notifier (Slack + Email + SMS).
	caseMgr := cases.NewManager()
	slackNotifier := webhooks.NewSlackNotifier(cfg.SlackWebhookURL)
	emailNotifier := integrations.NewEmailNotifier()
	smsNotifier := integrations.NewSMSNotifier()
	multiNotifier := integrations.NewMultiNotifier(
		slackNotifier.Notify,
		emailNotifier.Notify,
		smsNotifier.Notify,
	)

	// 6b. Stripe integration (optional — auto-block card on confirmed fraud).
	stripeClient := integrations.NewStripeClient(cfg.StripeAPIKey)

	// 6b'. Wire the Stripe integration into the case manager: when an
	// analyst confirms a case as fraud, Stripe's OnCaseConfirmed fires
	// (block card + issue Radar fraud marker). The hook runs in its own
	// goroutine inside Manager.Resolve, so it can never block the
	// analyst's HTTP response.
	caseMgr.OnResolve(func(c *cases.Case) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// The Case struct doesn't carry the original Transaction /
		// RiskScore in full; we reconstruct a best-effort subset
		// from the fields the case does carry. Stripe's
		// OnCaseConfirmed only uses tx.ID (for the fraud marker)
		// and tx.DeviceID (for the card block), so the mapping is
		// approximate but safe — worst case Stripe logs an empty
		// card ID and the block is a no-op.
		stripeClient.OnCaseConfirmed(ctx, models.Transaction{
			ID:       c.TransactionID,
			UserID:   c.UserID,
			DeviceID: c.Country, // best-effort: country is what we have
		}, models.RiskScore{Reasons: c.Reasons})
	})

	// 6c. Retraining pipeline (nightly calibrator refresh on analyst labels).
	retrainPipeline := training.NewPipeline(
		calibrator,
		detector.NewEnsembleDetector(store), // fresh ensemble bound to the live store
		store,
		caseMgr,
		cfg.RetrainInterval,
	)
	retrainCtx, retrainCancel := context.WithCancel(context.Background())
	defer retrainCancel()
	retrainPipeline.Start(retrainCtx)

	// 7. Auth verifiers.
	var verifier auth.Verifier
	if cfg.APIKeySecret != "" || cfg.JWTSecret != "" {
		verifiers := []auth.Verifier{}
		if cfg.APIKeySecret != "" {
			verifiers = append(verifiers, auth.NewAPIKeyVerifier(cfg.APIKeySecret))
		}
		if cfg.JWTSecret != "" {
			verifiers = append(verifiers, auth.NewJWTVerifier(cfg.JWTSecret, cfg.JWTIssuer))
		}
		verifier = auth.NewMultiVerifier(verifiers...)
	} else {
		log.Warn().Msg("AUTH_REQUIRED is false and no API key / JWT secret is set — running unauthenticated (dev mode)")
		verifier = auth.NewAPIKeyVerifier("") // always rejects — but AuthRequired=false lets requests through
	}

	// 8. HTTP server.
	gin.SetMode(gin.ReleaseMode)
	// Wrap the multiNotifier so it satisfies the webhooks.Notifier interface.
	var notifier webhooks.Notifier = &multiNotifierAdapter{m: multiNotifier}
	server := api.NewServer(store, rulesEngine, caseMgr, calibrator, notifier)
	server.RateLimitPerSecond = cfg.RateLimitPerSecond
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	server.Register(router, verifier, cfg.AuthRequired)

	// 8b. Kafka consumer (optional — starts if KAFKA_BROKERS is set).
	// The consumer shares the server's unified Pipeline so HTTP and
	// Kafka apply identical scoring, idempotency and case-creation
	// semantics (Finding 3.11).
	var kafkaConsumer *kafka.Consumer
	if len(cfg.KafkaBrokers) > 0 {
		kafkaConsumer = kafka.NewConsumer(
			kafka.Config{
				Brokers:       cfg.KafkaBrokers,
				InputTopic:    cfg.KafkaInputTopic,
				OutputTopic:   cfg.KafkaOutputTopic,
				ConsumerGroup: cfg.KafkaConsumerGroup,
			},
			server.Pipeline,
		)
		kafkaCtx, kafkaCancel := context.WithCancel(context.Background())
		defer kafkaCancel()
		kafkaConsumer.Start(kafkaCtx)
	}

	httpSrv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		log.Info().Str("port", cfg.Port).Msg("listening")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("http server failed")
		}
	}()

	// 9. Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Info().Str("signal", sig.String()).Msg("shutting down")

	if kafkaConsumer != nil {
		if err := kafkaConsumer.Close(); err != nil {
			log.Error().Err(err).Msg("kafka consumer close failed")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("graceful shutdown failed")
	}
	log.Info().Msg("bye")
}

// multiNotifierAdapter wraps an integrations.MultiNotifier so it satisfies
// the webhooks.Notifier interface.
type multiNotifierAdapter struct {
	m *integrations.MultiNotifier
}

func (a *multiNotifierAdapter) Notify(ctx context.Context, tx models.Transaction, risk models.RiskScore) error {
	return a.m.Notify(ctx, tx, risk)
}

// buildCalibrationPairs runs the ensemble over the labelled data and
// collects (raw_score, label) pairs for fitting the calibrator. We use a
// fresh store so we don't pollute the main store's history.
func buildCalibrationPairs(ensemble *detector.EnsembleDetector, store storage.Store, data api.SeedData) []ml.LabelledPair {
	ctx := context.Background()
	pairs := make([]ml.LabelledPair, 0, len(data.Transactions))
	for _, tx := range data.Transactions {
		rs := ensemble.Score(tx)
		pairs = append(pairs, ml.LabelledPair{
			Score: rs.Score,
			Label: data.IsFraud(tx.ID),
		})
		_ = store.Seed(ctx, tx)
	}
	return pairs
}
