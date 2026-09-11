# ==========================================
# Multi-stage Dockerfile for Server and CLI
# ==========================================

# Stage 1: Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies for CGO (if SQLite needed) and git
RUN apk add --no-cache gcc musl-dev git

# Copy dependency manifests
COPY go.mod go.sum* ./
RUN go mod download

# Copy application source
COPY . .

# Compile Server binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/server ./cmd/server

# Compile CLI binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/cli ./cmd/cli

# ==========================================
# Stage 2: Server Runtime Image
# ==========================================
FROM alpine:3.20 AS server

WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/server /app/server
COPY --from=builder /app/migrations /app/migrations

EXPOSE 8080

CMD ["/app/server"]

# ==========================================
# Stage 3: CLI Runtime Image
# ==========================================
FROM alpine:3.20 AS cli

WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/cli /app/cli

ENTRYPOINT ["/app/cli"]
