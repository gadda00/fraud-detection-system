# syntax=docker/dockerfile:1
# Multi-stage build keeps the final image tiny (~15MB) by compiling with
# the full Go toolchain and then copying only the static binary into a
# minimal Alpine runtime.

FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o fraud-detection-system .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/fraud-detection-system .
EXPOSE 8080
CMD ["./fraud-detection-system"]
