# ---------------------------------------------------------------------------
# SentinelMCP Sidecar — multi-stage Docker build
# ---------------------------------------------------------------------------
# Stage 1: Build the binary with CGO disabled (static linking).
# Stage 2: Copy to alpine for minimal image with healthcheck support.
# ---------------------------------------------------------------------------

FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o sentinelmcp ./cmd/sentinelmcp

# ---------------------------------------------------------------------------
# Runtime: alpine for minimal image with wget (healthcheck support).
# For production distroless builds, use the distroless Dockerfile variant.
# ---------------------------------------------------------------------------
FROM alpine:3.21
RUN apk add --no-cache wget ca-certificates
COPY --from=builder /build/sentinelmcp /usr/local/bin/sentinelmcp
COPY config/docker-config.yaml /etc/sentinelmcp/config.yaml

EXPOSE 8080 9090

ENTRYPOINT ["sentinelmcp"]
CMD ["-config", "/etc/sentinelmcp/config.yaml"]
