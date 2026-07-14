// Package observability provides structured logging (zerolog) and
// OpenTelemetry tracing helpers.
//
// In production the logs are JSON-formatted and shipped to a log aggregator
// (Datadog, Loki, CloudWatch). Traces are exported via OTLP to a collector
// (Tempo, Jaeger, Honeycomb).
package observability

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Init configures zerolog and OpenTelemetry. Call once at startup; the
// returned shutdown function flushes pending spans and must be called on
// graceful exit.
func Init(serviceName, version, environment string) (func(context.Context) error, error) {
	// zerolog: JSON to stdout in production, pretty-printed in dev.
	zerolog.TimeFieldFormat = time.RFC3339Nano
	if environment == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	} else {
		log.Logger = zerolog.New(os.Stdout).With().
			Timestamp().
			Str("service", serviceName).
			Str("version", version).
			Str("env", environment).
			Logger()
	}

	// OpenTelemetry: if OTEL_EXPORTER_OTLP_ENDPOINT is set, wire up OTLP/gRPC.
	// Otherwise use a no-op tracer (dev mode).
	otlpEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint == "" {
		log.Info().Msg("OTEL_EXPORTER_OTLP_ENDPOINT not set — tracing disabled")
		return func(context.Context) error { return nil }, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpointURL(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
		attribute.String("environment", environment),
	))
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(0.1)), // sample 10% in prod
	)
	otel.SetTracerProvider(tp)

	log.Info().Str("endpoint", otlpEndpoint).Msg("tracing initialised")
	return tp.Shutdown, nil
}

// StartSpan begins a tracing span and returns the context plus a function
// to end the span. Attributes are recorded as key/value pairs.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, func(err error)) {
	tracer := otel.Tracer("fraud-detection-system")
	ctx, span := tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}
}
