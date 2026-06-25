# Fraud Detection System

> A Go microservice for real-time transaction fraud scoring — an ensemble of
> statistical detectors that flags anomalous charges in sub-millisecond.

## Overview

A high-throughput fraud-scoring service that evaluates every incoming
transaction against the user's own spending history and returns a
calibrated risk score together with human-readable reasons. Go was chosen
for its concurrency model and low-latency GC: the service scores
transactions in **~50–300 µs** each, comfortably inside the budget needed
for 50 000+ transactions/second on modest hardware.

Rather than a single black-box model, the system fuses three transparent,
explainable detectors whose decisions can be audited by a human analyst —
a requirement in regulated financial environments.

## Features

- **Z-Score detector** — flags amounts more than 3σ above the user's
  historical mean *for the same category*.
- **IQR (Tukey fence) detector** — flags amounts outside
  `[Q1 − 1.5·IQR, Q3 + 1.5·IQR]`, again per category.
- **Velocity detector** — flags users submitting more than N transactions
  inside a rolling M-minute window (default 4 / 5 min).
- **Weighted-vote ensemble** — fuses the three detectors; abstaining
  detectors neither inflate nor dilute the score.
- **Per-category baselines** — a $600 airline ticket is compared to past
  travel, not to $5 subscriptions. This is the single biggest lever on the
  false-positive rate.
- **Explainable alerts** — every score ships with the exact reasons and the
  list of detectors that fired.
- **Built-in offline evaluation** — on startup the service replays a
  labelled 1 000-transaction dataset through the ensemble and logs
  recall / precision / FPR, so a glance at the logs confirms the detectors
  are healthy.
- **Redis-ready** — ships with an in-memory store for zero-dependency
  demos and a fully implemented Redis-backed store for horizontal
  deployments.

## Tech Stack

- **Go 1.22** + [Gin](https://github.com/gin-gonic/gin) HTTP framework
- [gonum](https://www.gonum.org/) for statistics (mean, std-dev, quantiles)
- [go-redis](https://github.com/redis/go-redis) for the optional persistent store
- Graceful shutdown, structured startup logging, multi-stage Docker build

## API

| Method | Path           | Description                                  |
|--------|----------------|----------------------------------------------|
| POST   | `/api/score`   | Score a single transaction                   |
| GET    | `/api/health`  | Liveness probe (uptime, version, user count) |
| GET    | `/api/stats`   | Aggregate detection counters & flag rate     |

### Score a transaction

```bash
curl -X POST localhost:8080/api/score \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"u1","amount":5000,"currency":"USD","merchant":"Amazon","category":"shopping"}'
```

Response:

```json
{
  "transaction_id": "live-1782399368950173677",
  "user_id": "demo-amt",
  "amount": 9000,
  "currency": "USD",
  "flagged": true,
  "risk": {
    "score": 1.0,
    "severity": "critical",
    "reasons": [
      "amount 9000.00 is 1201.38σ above user mean 33.80 for category \"shopping\" (σ=7.46)",
      "amount 9000.00 exceeds upper Tukey fence 52.88 (Q1=26.00 Q3=36.75 IQR=10.75)"
    ],
    "detectors": ["zscore", "iqr"]
  },
  "scored_at": "2026-06-25T14:56:08.950205561Z",
  "latency_us": 62
}
```

## Results

Measured by the built-in offline evaluation, which replays a labelled
dataset of 1 000 transactions (950 normal, 50 fraud) chronologically
through the ensemble — each transaction scored against only the history
that preceded it, exactly as in production.

| Metric                    | Value  |
|---------------------------|--------|
| **Recall** (fraud caught) | 84.0%  |
| **Precision**             | 76.4%  |
| **F1**                    | 0.800  |
| **False positive rate**   | 1.37%  |
| **Per-request latency**   | ~50–300 µs |
| **Ensemble weighting**    | Z-Score 40% · IQR 35% · Velocity 25% |

The honest limitation: a rapid-fire fraud burst's *first few* charges look
indistinguishable from normal spending, so velocity recall on the opening
of a burst is intentionally lower — the detector only fires once the
cadence is actually abnormal.

## Project Structure

```
fraud-detection-system/
├── main.go                      # entry point, graceful shutdown, boot-time eval
├── internal/
│   ├── models/models.go         # Transaction & RiskScore types
│   ├── storage/
│   │   ├── storage.go           # thread-safe in-memory store (capped ring buffer)
│   │   └── redis.go             # optional Redis-backed store
│   ├── detector/detector.go     # ZScore, IQR, Velocity & Ensemble detectors
│   └── api/
│       ├── handlers.go          # Gin HTTP handlers
│       └── seed.go              # 1k-tx seed data + offline evaluation harness
├── Dockerfile                   # multi-stage build (~15 MB image)
├── Makefile
└── go.mod
```

## Quick Start

```bash
make run            # go run main.go  ->  http://localhost:8080
# or
make build && ./fraud-detection-system
# or
make docker && docker run --rm -p 8080:8080 fraud-detection-system
```

The service seeds itself with 1 000 transactions on boot, so every
endpoint is usable immediately.

## How Detection Works

1. **Baseline per (user, category).** When a transaction arrives, the
   detector pulls the user's last 100 transactions and filters to the
   same category. At least 5 same-category points are required before an
   opinion is ventured; otherwise the detector abstains.
2. **Z-Score.** `z = (amount − mean) / std`. If `z > 3σ`, score ramps from
   0.5 upward (saturating at 1.0).
3. **IQR.** Compute Q1/Q3, fence the amount with Tukey's 1.5·IQR rule.
   Distance past the fence maps onto `[0.5, 1.0]`.
4. **Velocity.** Count prior transactions inside the rolling window; each
   one past the allowance adds 0.1 to the score.
5. **Ensemble.** `score = Σ(wᵢ·sᵢ) / Σ(wᵢ)` over the detectors that
   actually fired. Severity is bucketed from the score
   (`low < 0.5 ≤ medium < 0.7 ≤ high < 0.85 ≤ critical`).

## Author

**Victor Ndunda** — Data Analyst & AI Engineer
- GitHub: [@gadda00](https://github.com/gadda00)
- LinkedIn: [victor-ndunda](https://www.linkedin.com/in/victor-ndunda)

## License

MIT
