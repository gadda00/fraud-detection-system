# Fraud Detection System

> **Production-oriented real-time transaction fraud scoring — a
> multi-signal ensemble engine that scores transactions in sub-millisecond
> latency with full explainability for regulated finance.**

> ⚠️ **On benchmark honesty.** Synthetic benchmark metrics reported below
> (84% recall, 1.37% FPR) are from a **deterministic seed dataset**, not
> independent validation on real transaction data. Treat them as a
> regression baseline for the codebase, not as a deployable performance
> claim. Real-world recall/FPR will depend on fraud mix, labelling
> quality, and traffic shape — none of which a synthetic dataset
> captures.

[![CI](https://github.com/gadda00/fraud-detection-system/actions/workflows/ci.yml/badge.svg)](https://github.com/gadda00/fraud-detection-system/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/Coverage-80%25-brightgreen)](#)

---

## Why this exists

Banks, fintechs, and payment processors lose **$485 billion a year** to
fraud. The status quo is broken in two directions:

1. **Black-box ML models** flag transactions opaquely. When a customer asks
   "why was my card blocked?", risk-ops has no answer. Regulators (PCI-DSS,
   PSD2, GDPR Article 22) increasingly require **explainable** decisions.
2. **Static rule engines** are brittle and noisy. They either flag too much
   (annoying customers) or too little (letting fraud through).

This system threads the needle: **seven transparent statistical detectors**
fused by a **weighted-vote ensemble**, **calibrated by logistic regression**
on labelled data, **overlaid with a deterministic rules engine** for
hard-block policies, and **wrapped in a full case-management workflow**
for human analysts.

Every score ships with:
- The exact detectors that fired
- Human-readable reasons ("amount $9,000 is 1,201σ above user mean for
  category 'shopping'")
- The calibrated probability of fraud
- A case ID linking to the analyst review queue

---

## Architecture

```
                              ┌──────────────────────────────────┐
                              │           HTTP / API             │
                              │  (Gin + auth + rate limit +      │
                              │   Prometheus + OTel tracing)     │
                              └───────────────┬──────────────────┘
                                              │
                          ┌───────────────────┼───────────────────┐
                          │                   │                   │
                          ▼                   ▼                   ▼
                   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
                   │  Ensemble   │    │    Rules     │    │   Cases      │
                   │  Detector   │    │   Engine     │    │  Manager     │
                   └──────┬──────┘    └──────┬───────┘    └──────┬───────┘
                          │                  │                   │
        ┌─────────────────┼─────────────────┼────────┐          │
        │                 │                 │        │          │
        ▼                 ▼                 ▼        ▼          │
  ┌──────────┐     ┌──────────┐      ┌──────────┐ ┌──────────┐ │
  │ Z-Score  │     │   IQR    │      │ Velocity │ │   Geo    │ │
  │ Detector │     │ Detector │      │ Detector │ │ Detector │ │
  └──────────┘     └──────────┘      └──────────┘ └──────────┘ │
        │                 │                 │        │          │
        ▼                 ▼                 ▼        ▼          │
  ┌──────────┐     ┌──────────┐      ┌──────────┐              │
  │ Device   │     │ Merchant │      │Behavioral│              ▼
  │Detector  │     │ Detector │      │ Anomaly  │       ┌────────────┐
  └──────────┘     └──────────┘      └──────────┘       │  Webhooks  │
                                                        │  (Slack)   │
        ┌──────────────────────────────────────┐        └────────────┘
        │           ML Calibration Layer        │
        │  (Logistic regression + Isolation     │
        │   Forest anomaly score fusion)        │
        └──────────────────────────────────────┘
                          │
                          ▼
        ┌──────────────────────────────────────┐
        │            Storage Layer              │
        │  (in-memory / Redis / Postgres)       │
        └──────────────────────────────────────┘
```

---

## Detection signals (7 detectors)

| # | Detector | Signal | Weight |
|---|----------|--------|--------|
| 1 | **Z-Score** | Amount > 3σ above per-(user,category) mean | 20% |
| 2 | **IQR (Tukey)** | Amount outside [Q1−1.5·IQR, Q3+1.5·IQR] per category | 17% |
| 3 | **Velocity** | > 4 transactions in a 5-min rolling window | 12% |
| 4 | **Geo Distance** | Merchant country > 2,000 km from user's home country | 12% |
| 5 | **Device Fingerprint** | New or rarely-seen device ID | 10% |
| 6 | **Merchant Risk** | Curated registry of high-risk merchants (crypto, gambling, offshore) | 15% |
| 7 | **Behavioral Anomaly** | Transaction in user's quiet hours or first-ever hour-of-week cell | 14% |

The ensemble fuses these via weighted voting: only detectors that actually
fire contribute to the score, so a single strong signal can still raise an
alert. The raw score is then calibrated to a true probability by a logistic
regression fitted on labelled data.

---

## Rules engine

Deterministic, human-authored policies run alongside the statistical
detectors. Three actions:

- **block** — hard-block the transaction (score forced to 1.0)
- **review** — force into the manual review queue
- **flag** — add a weight contribution to the ensemble score

Rules are loaded from a JSON file at startup and hot-reloadable via the
`POST /admin/rules/reload` admin API. See
[`deploy/rules.example.json`](deploy/rules.example.json) for the format.

---

## Case management

Every flagged transaction creates a **Case** in the analyst review queue.
Cases have a full lifecycle:

```
open → in_review → confirmed (fraud)
                 → false_positive (cleared)
                 → escalated (senior analyst)
```

Analysts can:
- **Assign** a case to themselves
- **Resolve** with a verdict + note
- **Add notes** without changing status
- **View stats** — queue depth, confirmation rate, false-positive rate

The case queue is exposed via `GET /api/cases`, `POST /api/cases/:id/assign`,
`POST /api/cases/:id/resolve`, etc. (requires `analyst` or `admin` role).

---

## API surface

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/score` | service+ | Score a single transaction |
| `POST` | `/api/score/batch` | service+ | Score up to 1,000 transactions |
| `GET` | `/api/health` | — | Liveness probe |
| `GET` | `/api/stats` | readonly+ | Aggregate detection counters |
| `GET` | `/api/cases` | analyst+ | List cases (filter by `?status=`) |
| `GET` | `/api/cases/:id` | analyst+ | Get one case |
| `POST` | `/api/cases/:id/assign` | analyst+ | Assign to an analyst |
| `POST` | `/api/cases/:id/resolve` | analyst+ | Close with verdict |
| `POST` | `/api/cases/:id/notes` | analyst+ | Add a comment |
| `GET` | `/api/cases/stats` | analyst+ | Case queue stats |
| `POST` | `/admin/rules/reload` | admin | Hot-reload rules engine |
| `GET` | `/metrics` | — | Prometheus scrape endpoint |

### Auth

Two modes (both accepted on every endpoint):

1. **API key** — `Authorization: Bearer <API_KEY_SECRET>` (service-to-service)
2. **JWT** — `Authorization: Bearer <jwt>` with claims `sub`, `role`, `tenant_id`

Roles: `admin` > `analyst` > `service` > `readonly`.

### Example: score a transaction

```bash
curl -X POST localhost:8080/api/score \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer your-api-key' \
  -d '{
    "user_id": "u1",
    "amount": 9000,
    "currency": "USD",
    "merchant": "CryptoExchange-X",
    "category": "shopping",
    "country": "RU",
    "device_id": "dev-unknown"
  }'
```

Response:

```json
{
  "transaction_id": "live-1782399368950173677",
  "user_id": "u1",
  "amount": 9000,
  "flagged": true,
  "blocked": false,
  "review_required": true,
  "risk": {
    "score": 1.0,
    "severity": "critical",
    "reasons": [
      "amount 9000.00 is 1201.38σ above user mean 33.80 for category \"shopping\" (σ=7.46)",
      "amount 9000.00 exceeds upper Tukey fence 52.88 (Q1=26.00 Q3=36.75 IQR=10.75)",
      "transaction in RU is 7820 km from user home country US",
      "new device \"dev-unknown\" (seen 0 time(s) in history)",
      "merchant \"CryptoExchange-X\" is flagged as high-risk (cryptocurrency_exchange, score=0.85)"
    ],
    "detectors": ["zscore", "iqr", "geo_distance", "device_fingerprint", "merchant_risk"]
  },
  "calibrated_probability": 0.987,
  "rule_matches": [
    {"rule": {"id": "crypto_exchange_flag", ...}, "action": "flag", "weight": 0.5}
  ],
  "case_id": "case-live-1782399368950173677",
  "scored_at": "2026-07-14T15:23:08.950205561Z",
  "latency_us": 287
}
```

---

## Performance

> ⚠️ **These metrics are from the deterministic synthetic seed dataset,
> not independent validation on real transaction data.** They are useful
> as a regression baseline for the codebase, not as a deployable
> performance claim.

Measured on the built-in offline evaluation (1,000 labelled transactions,
950 normal + 50 fraud, replayed chronologically with no leakage):

| Metric | Value |
|--------|-------|
| **Recall** (fraud caught) | 84.0% |
| **Precision** | 76.4% |
| **F1** | 0.800 |
| **False positive rate** | 1.37% |
| **Per-transaction latency** | ~50–300 µs |
| **Throughput (single core)** | ~30,000 tx/sec |
| **Throughput (parallel)** | ~100,000+ tx/sec |
| **Docker image size** | ~15 MB (distroless) |
| **Memory per replica** | ~50–150 MB (depends on user count) |

Benchmarks (`go test -bench=. -benchtime=2s ./internal/detector/`):

```
BenchmarkEnsemble_Score-2            72282    32866 ns/op    100120 B/op    10 allocs/op
BenchmarkEnsemble_ScoreParallel-2    58629    38799 ns/op    100120 B/op    10 allocs/op
BenchmarkStore_Add-2                536378     5268 ns/op     16381 B/op     0 allocs/op
BenchmarkStore_GetUserHistory-2     592123     4941 ns/op     16384 B/op     1 allocs/op
```

---

## Observability

- **Structured logging** via zerolog (JSON in prod, pretty-printed in dev)
- **Prometheus metrics** at `/metrics` — request count, latency histogram,
  scoring count by severity, scoring latency histogram
- **OpenTelemetry tracing** — spans exported via OTLP/gRPC to a collector
  (Tempo, Jaeger, Honeycomb). 10% sampling in production.
- **Slack alerts** — high/critical severity transactions trigger a Slack
  webhook with the full transaction context

---

## Compliance

This system is designed to support (not guarantee) compliance with:

- **PCI-DSS** — no card data is stored; only transaction metadata
- **PSD2 SCA** — real-time scoring enables Strong Customer Authentication
  exemptions for low-risk transactions
- **GDPR Article 22** — every automated decision is explainable; the
  `reasons` array provides the human-readable justification required for
  solely-automated decisions
- **SOC 2** — full audit trail via case management + structured logging

---

## Quick start

```bash
# Build & run (in-memory store, no auth, no tracing — dev mode)
make run

# Or via Docker
make docker
docker run --rm -p 8080:8080 fraud-detection-system:latest

# Production mode (Redis + auth + tracing + Slack)
docker run --rm -p 8080:8080 \
  -e ENVIRONMENT=production \
  -e STORAGE_BACKEND=redis \
  -e REDIS_ADDR=redis:6379 \
  -e AUTH_REQUIRED=true \
  -e API_KEY_SECRET=your-secret-key \
  -e JWT_SECRET=your-32-byte-jwt-secret \
  -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317 \
  -e RULES_PATH=/app/rules.json \
  fraud-detection-system:latest
```

The service seeds itself with 1,000 transactions on boot **in
development mode**, so every endpoint is usable immediately. In
production (`ENVIRONMENT=production`) the seed/evaluate/calibrate path
is skipped by default — set `DEMO_MODE=true` to opt back in.

---

## Configuration

All configuration is via environment variables (12-factor). See
[`internal/config/config.go`](internal/config/config.go) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DEMO_MODE` | `true` in dev, `false` in prod | Run boot-time synthetic seed / evaluate / calibrate path |
| `PORT` | `8080` | HTTP listen port |
| `STORAGE_BACKEND` | `memory` | `memory` (only `memory` is currently wired; `redis` / `postgres` backends exist but are not selected in `main.go`) |
| `REDIS_ADDR` | `localhost:6379` | Redis address (if backend=redis) |
| `POSTGRES_DSN` | — | Postgres DSN (if backend=postgres) |
| `AUTH_REQUIRED` | `false` | Require auth on all endpoints |
| `API_KEY_SECRET` | — | Static API key for service-to-service auth |
| `JWT_SECRET` | — | HMAC secret for JWT signing |
| `RULES_PATH` | — | Path to rules JSON file |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook for alerts |
| `STRIPE_API_KEY` | — | Stripe key for card blocking on confirmed fraud |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP/gRPC endpoint for tracing |
| `RATE_LIMIT_PER_SECOND` | `1000` | Max requests per second per IP (0 disables) |

---

## Project structure

```
fraud-detection-system/
├── main.go                          # entry point, wires all subsystems
├── internal/
│   ├── api/                         # HTTP handlers (score, cases, admin)
│   ├── auth/                        # API key + JWT verifiers, RBAC roles
│   ├── cases/                       # Case management (review queue)
│   ├── config/                      # Environment-driven configuration
│   ├── detector/                    # 7 statistical detectors + ensemble
│   ├── middleware/                  # Auth, request ID, Prometheus, CORS
│   ├── ml/                          # Logistic calibrator + Isolation Forest
│   ├── models/                      # Transaction & RiskScore types
│   ├── observability/               # zerolog + OpenTelemetry
│   ├── rules/                       # Deterministic rules engine
│   ├── storage/                     # in-memory + Redis stores
│   └── webhooks/                    # Slack notifier
├── deploy/
│   ├── k8s/                         # Kubernetes Deployment + HPA
│   ├── rules.example.json           # Sample rules file
│   └── grafana/                     # Grafana dashboard JSON
├── .github/workflows/ci.yml         # Test + lint + security + build
├── Dockerfile                       # Multi-stage, distroless, ~15 MB
├── Makefile
└── go.mod
```

---

## Testing

```bash
go test ./...                     # all tests
go test -race ./...               # with race detector
go test -bench=. ./internal/detector/  # benchmarks
```

Test coverage spans every detector, the rules engine, case management,
auth, and the ML calibrator.

---

## Roadmap

This is the honest version. The repo previously advertised a flat "todo"
list that mixed genuinely missing features with work that was already
merged. The three buckets below separate what works end-to-end, what
exists but isn't connected, and what isn't built at all.

### Shipped and wired (works end-to-end)

- **7 statistical detectors + weighted-vote ensemble** — z-score, IQR,
  velocity, geo-distance, device fingerprint, merchant risk,
  behavioral anomaly. All contribute to the live `/api/score` score.
- **Logistic calibrator** — fitted on the labelled seed dataset in dev
  mode and exposed via the `calibrated_probability` field in the score
  response.
- **Deterministic rules engine** — JSON-configured, hot-reloadable via
  `POST /admin/rules/reload`. `block`, `review`, and `flag` actions all
  wired into the live score path (flag weights blend into the ensemble
  score before the block/critical override).
- **Case management** — full lifecycle (open → in_review → confirmed /
  false_positive / escalated) exposed via `/api/cases*`. Resolution
  hooks fan out async.
- **Stripe integration** — `OnCaseConfirmed` fires from the case
  manager when an analyst confirms fraud (card block + Radar fraud
  marker). Disabled (no-op) when `STRIPE_API_KEY` is unset.
- **Multi-channel alerts** — Slack (webhook), Email (SMTP), SMS
  (Twilio) fanned out through `MultiNotifier` on flagged transactions.
- **API key + JWT auth, RBAC** — admin / analyst / service / readonly
  roles enforced via `RequireRole`. Constant-time API key compare; JWT
  role claim is null-safe. Dev-mode attaches a synthetic admin principal
  so the protected endpoints are usable without credentials.
- **Rate limiting** — per-IP token bucket (`golang.org/x/time/rate`)
  with idle eviction, configured via `RATE_LIMIT_PER_SECOND`.
- **Kafka consumer** — optional streaming ingestion started when
  `KAFKA_BROKERS` is set.
- **Retraining pipeline** — nightly calibrator refresh on analyst
  labels, started at boot.
- **Observability** — zerolog structured logging, Prometheus metrics at
  `/metrics`, OpenTelemetry tracing via OTLP/gRPC, Grafana dashboard
  JSON in `deploy/grafana/`.
- **Geo detector country table** — ~195 ISO-3166 country centroids;
  `fraud_geo_detector_unmapped_country_total` Prometheus counter
  surfaces unmapped-country hits.
- **DEMO_MODE guard** — synthetic seed / evaluate / calibrate path is
  skipped in production by default; opt back in with `DEMO_MODE=true`.
- **CI** — test (race) + lint + govulncheck (fails on HIGH/CRITICAL) +
  Docker build (no push).

### Built, not yet wired (code exists but isn't connected)

- **Postgres storage backend** (`internal/storage/postgres.go`) — full
  schema + pool, but `main.go` always calls `storage.New()` (in-memory).
  Needs a backend-selection branch in `main.go` keyed on
  `cfg.StorageBackend == "postgres"`.
- **Redis storage backend** (`internal/storage/redis.go`) — same
  situation as Postgres. Needs the same selection branch.
- **Graph network detector (user-merchant bipartite fraud rings)** —
  not started; see "Not started" below.

### Not started

- **Graph network detector** — user-merchant bipartite fraud-ring
  detection. No code yet.
- **Helm chart** — referenced in the old README as a "placeholder"
  under `deploy/helm/`; that directory does not exist.
- **Multi-tenant isolation** — `Principal.TenantID` is plumbed through
  auth but no handler filters cases / stats by tenant yet.
- **Independent real-data validation** — every metric in this README is
  from the synthetic seed dataset. An honest recall/FPR claim against
  real (or even Kaggle-style public) transaction data has not been
  produced.

---

## Author

**Victor Ndunda** — AI Engineer & Founder
- GitHub: [@gadda00](https://github.com/gadda00)
- LinkedIn: [victor-ndunda](https://www.linkedin.com/in/victor-ndunda)
- Portfolio: [victorndunda.com](https://victorndunda.com)

## License

MIT — see [LICENSE](LICENSE).
