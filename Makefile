.PHONY: build test clean release-test fmt tidy help e2e

BINARY_NAME=scal-p
BIN_DIR=.bin
MAIN_PATH=./cmd/scalp
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

## build: build binary locally
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build \
		-trimpath \
		-ldflags "-s -w -X scal-p/internal/version.Version=$(VERSION) -X scal-p/internal/version.Commit=$(COMMIT) -X scal-p/internal/version.Date=$(DATE)" \
		-o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Binary created at $(BIN_DIR)/$(BINARY_NAME)"

## test: run all unit tests
test:
	@echo "Running unit tests..."
	go test -v ./...

## e2e: run end-to-end tests (requires npm/pnpm/yarn/bun)
e2e:
	@echo "Running end-to-end tests..."
	go test -v -tags=e2e -count=1 ./e2e/

## release-test: test goreleaser snapshot + dogfooding
release-test:
	@echo "Building scalp bootstrap..."
	go build -o /tmp/scalp-bootstrap ./cmd/scalp
	@echo "Running GoReleaser snapshot..."
	goreleaser release --snapshot --clean --config .goreleaser.yaml
	@echo "=== Dogfooding: generating checksums ==="
	/tmp/scalp-bootstrap checksum dist/*.tar.gz dist/*.zip > dist/checksums.txt
	cat dist/checksums.txt
	@echo "=== Dogfooding: verifying artifacts ==="
	for f in dist/*.tar.gz dist/*.zip; do \
		echo "Verifying $$(basename $$f)..."; \
		/tmp/scalp-bootstrap verify --artifact "$$f" --checksum dist/checksums.txt --ci; \
	done
	@echo "=== Dogfooding: all artifacts verified ==="

fmt:
	@echo "Formatting code..."
	go fmt ./...

tidy:
	@echo "Tidying go modules..."
	go mod tidy

## clean: remove binaries and artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	rm -rf dist
	@echo "Cleaned!"

help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' |  sed -e 's/^/ /'
