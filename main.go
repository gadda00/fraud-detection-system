// Command fraud-detection-system starts the real-time transaction fraud
// scoring service.
//
// On boot it:
//
//  1. Loads configuration from environment variables.
//  2. Initialises structured logging + OpenTelemetry tracing.
//  3. Builds the storage backend (in-memory by default; Redis or Postgres
//     when configured).
//  4. Seeds the store with a realistic, labelled dataset (1000 transactions,
//     50 users, 5% fraud).
//  5. Runs an offline evaluation of the ensemble detector and logs the
//     recall / precision / FPR.
//  6. Fits the logistic calibrator on the labelled data.
//  7. Loads the rules engine (if RULES_PATH is set).
//  8. Builds the case manager, webhook notifier, and auth verifiers.
//  9. Starts a Gin HTTP server on :8080 exposing the full API surface.
//  10. Shuts down gracefully on SIGINT / SIGTERM.
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
        "github.com/gadda00/fraud-detection-system/internal/ml"
        "github.com/gadda00/fraud-detection-system/internal/models"
        "github.com/gadda00/fraud-detection-system/internal/observability"
        "github.com/gadda00/fraud-detection-system/internal/rules"
        "github.com/gadda00/fraud-detection-system/internal/storage"
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
        store := storage.New()
        data := api.GenerateSeedData()
        loaded := api.SeedStore(store, data)
        log.Info().
                Int("transactions", loaded).
                Int("users", store.UserCount()).
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
        calibrator := ml.NewLogisticCalibrator()
        calPairs := buildCalibrationPairs(evalEnsemble, evalStore, data)
        calibrator.Fit(calPairs, 500, 0.1)
        a, b := calibrator.Coefficients()
        log.Info().Float64("a", a).Float64("b", b).Msg("calibrator fitted")

        // 5. Rules engine (optional).
        rulesEngine, err := rules.NewEngine(cfg.RulesPath)
        if err != nil {
                log.Error().Err(err).Str("path", cfg.RulesPath).Msg("rules engine load failed")
        } else if len(rulesEngine.Evaluate(models.Transaction{})) == 0 && cfg.RulesPath != "" {
                log.Info().Str("path", cfg.RulesPath).Msg("rules engine loaded")
        }

        // 6. Case manager + webhook notifier.
        caseMgr := cases.NewManager()
        notifier := webhooks.NewSlackNotifier(cfg.SlackWebhookURL)

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
        server := api.NewServer(store, rulesEngine, caseMgr, calibrator, notifier)
        router := gin.New()
        router.Use(gin.Logger(), gin.Recovery())
        server.Register(router, verifier, cfg.AuthRequired)

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

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := httpSrv.Shutdown(ctx); err != nil {
                log.Error().Err(err).Msg("graceful shutdown failed")
        }
        log.Info().Msg("bye")
}

// buildCalibrationPairs runs the ensemble over the labelled data and
// collects (raw_score, label) pairs for fitting the calibrator. We use a
// fresh store so we don't pollute the main store's history.
func buildCalibrationPairs(ensemble *detector.EnsembleDetector, store *storage.Store, data api.SeedData) []ml.LabelledPair {
        pairs := make([]ml.LabelledPair, 0, len(data.Transactions))
        for _, tx := range data.Transactions {
                rs := ensemble.Score(tx)
                pairs = append(pairs, ml.LabelledPair{
                        Score: rs.Score,
                        Label: data.IsFraud(tx.ID),
                })
                store.Seed(tx)
        }
        return pairs
}
