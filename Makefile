.PHONY: build test race vet demo docker clean fmt

# SentinelMCP Makefile

BINARY     := sentinelmcp
GO         := go
GOFLAGS    := -race -count=1
DOCKER_IMG := ghcr.io/technosiveuk-ui/sentinelmcp

## build: Build all packages
build:
	$(GO) build ./...

## test: Run all tests with race detector
test:
	$(GO) test ./... $(GOFLAGS) -timeout 3m

## race: Run all tests with verbose race detector output
race:
	$(GO) test ./... -race -v -count=1 -timeout 5m

## vet: Run go vet on all packages
vet:
	$(GO) vet ./...

## bench: Run benchmarks
bench:
	$(GO) test ./adapter/eino/ -bench=. -benchmem -count=3

## nfr: Run NFR validation tests
nfr:
	$(GO) test ./adapter/eino/ -run "TestLoad_|TestMemory_|TestDegradation_" -race -v -timeout 5m

## e2e: Run sidecar E2E tests
e2e:
	$(GO) test ./cmd/sentinelmcp/ -race -v -timeout 5m

## demo: Run the in-process demo
demo:
	$(GO) run ./cmd/demo/

## sidecar: Run the sidecar proxy locally
sidecar:
	$(GO) run ./cmd/sentinelmcp/ -config config/config.yaml

## docker: Build Docker image
docker:
	docker build -t $(DOCKER_IMG):latest .

## docker-demo: Run the full Docker demo
docker-demo:
	docker compose up --build --abort-on-container-exit

## fmt: Format all Go files
fmt:
	gofmt -w .

## clean: Remove build artifacts
clean:
	$(GO) clean
	rm -f $(BINARY) *.db *.test *.prof *.out

## check: Run all checks (fmt, vet, test)
check: fmt vet test

## help: Show this help
help:
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sort
