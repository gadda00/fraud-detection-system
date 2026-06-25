// Command fraud-detection-system starts the real-time transaction fraud
// scoring service.
//
// On boot it:
//
//  1. Builds an in-memory store and seeds it with a realistic, labelled
//     dataset (1000 transactions, 50 users, 5% fraud).
//  2. Runs an offline evaluation of the ensemble detector over that
//     dataset and logs the recall / precision / FPR — a built-in smoke
//     test that the detectors actually work.
//  3. Starts a Gin HTTP server on :8080 exposing /api/score, /api/health
//     and /api/stats.
//  4. Shuts down gracefully on SIGINT / SIGTERM.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/gadda00/fraud-detection-system/internal/api"
	"github.com/gadda00/fraud-detection-system/internal/detector"
	"github.com/gadda00/fraud-detection-system/internal/storage"
)

func main() {
	// Release mode keeps Gin's startup noise out of production logs.
	gin.SetMode(gin.ReleaseMode)

	// ---------------------------------------------------------------
	// 1. Build & seed the in-memory store.
	// ---------------------------------------------------------------
	store := storage.New()
	data := api.GenerateSeedData()
	loaded := api.SeedStore(store, data)
	log.Printf("seeded %d transactions across %d users (%d labelled fraud)",
		loaded, store.UserCount(), len(data.FraudIDs))

	// ---------------------------------------------------------------
	// 2. Offline evaluation (no leakage: each tx scored against the
	//    history that preceded it). Logged once at boot so a glance at
	//    the logs confirms the detectors are healthy.
	// ---------------------------------------------------------------
	evalStore := storage.New()
	evalEnsemble := detector.NewEnsembleDetector(evalStore)
	m := api.Evaluate(evalEnsemble, evalStore, data)
	log.Printf("offline evaluation: total=%d fraud=%d normal=%d | TP=%d FP=%d FN=%d TN=%d | recall=%.3f precision=%.3f f1=%.3f fpr=%.4f",
		m.Total, m.Fraud, m.Normal,
		m.TruePos, m.FalsePos, m.FalseNeg, m.TrueNeg,
		m.Recall, m.Precision, m.F1, m.FPR)

	// ---------------------------------------------------------------
	// 3. HTTP server.
	// ---------------------------------------------------------------
	server := api.NewServer(store)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	server.Register(router)

	httpSrv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("fraud-detection-system %s listening on :8080", api.Version)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	// ---------------------------------------------------------------
	// 4. Graceful shutdown.
	// ---------------------------------------------------------------
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("received %s, shutting down...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Printf("bye")
}
