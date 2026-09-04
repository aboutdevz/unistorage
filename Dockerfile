# ==============================================================================
# Stage 1: Build Stage (golang:1.22-alpine AS builder specification)
# ==============================================================================
FROM golang:1.27-alpine AS builder

# Install build-time dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make

WORKDIR /src

# Leverage Docker layer caching for Go modules
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy full source tree
COPY . .

# Build arguments for reproducible provenance
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown

# Target architecture injected by Docker buildx for multi-platform builds
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Compile static binary: CGO_ENABLED=0, stripped symbols, hardened flags
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /build/unistorage \
    ./cmd/unistorage

# Create unprivileged system user and group (UID:GID 10001:10001)
RUN addgroup -g 10001 -S unistorage && \
    adduser -u 10001 -S -G unistorage -h /home/unistorage -s /sbin/nologin unistorage

# Pre-create configuration and data directories with strict permissions
RUN mkdir -p /build/config /build/data /build/tmp && \
    chown -R 10001:10001 /build/config /build/data /build/tmp && \
    chmod 0700 /build/config && \
    chmod 0750 /build/data && \
    chmod 1777 /build/tmp

# ==============================================================================
# Stage 2: Runtime Stage (Hardened Minimal alpine:3.20)
# ==============================================================================
FROM alpine:3.20

# Install runtime security certificates and timezone definitions
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl

# Import unprivileged user from builder
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Import pre-configured directories
COPY --from=builder --chown=10001:10001 /build/config /config
COPY --from=builder --chown=10001:10001 /build/data /data
COPY --from=builder --chown=10001:10001 /build/tmp /tmp

# Copy compiled static binary
COPY --from=builder --chown=10001:10001 /build/unistorage /usr/local/bin/unistorage

# Security constraints: Non-root execution
USER 10001:10001
WORKDIR /home/unistorage

# Persistent volume mounts
VOLUME ["/config", "/data"]

# Expose HTTP API & Prometheus Telemetry Port
EXPOSE 8080

# Health check probing the daemon status endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/api/v1/health || exit 1

# Default execution running daemon in foreground
ENTRYPOINT ["/usr/local/bin/unistorage"]
CMD ["daemon", "start", "--foreground", "--config", "/config", "--data", "/data"]
