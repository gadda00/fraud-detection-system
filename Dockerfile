# syntax=docker/dockerfile:1.6

# ---- Builder ----
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

# Build.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=2.0.0" \
    -o /out/fraud-detection-system .

# ---- Runtime ----
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/fraud-detection-system /app/fraud-detection-system
COPY --from=builder /src/deploy/rules.example.json /app/rules.json

ENV PORT=8080 \
    ENVIRONMENT=production

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/app/fraud-detection-system"]
