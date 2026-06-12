# ---------------------------------------------------------------------------
# SentinelMCP Sidecar — multi-stage Docker build
# ---------------------------------------------------------------------------
# Stage 1: Build the binary with CGO disabled (static linking).
# Stage 2: Copy to distroless/static for minimal image (~10-15MB).
# ---------------------------------------------------------------------------

FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o sentinelmcp ./cmd/sentinelmcp

# ---------------------------------------------------------------------------
# Runtime: distroless for minimal attack surface (TR-02: no CGO, no shell).
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/sentinelmcp /usr/local/bin/sentinelmcp
COPY config/docker-config.yaml /etc/sentinelmcp/config.yaml

EXPOSE 8080 9090

ENTRYPOINT ["sentinelmcp"]
CMD ["-config", "/etc/sentinelmcp/config.yaml"]
