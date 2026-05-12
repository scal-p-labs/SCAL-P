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
		-ldflags "-s -w -X scal-p/internal/version.Version=$(VERSION) -X scal-p/internal/version.Commit=$(COMMIT) -X scal-p/internal/version.Date=$(DATE)" \
		-o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Binary created at $(BIN_DIR)/$(BINARY_NAME)"

## test: run all unit tests
test:
	@echo "Running unit tests..."
	go test -v ./...

## e2e: run end-to-end tests (requires npm)
e2e:
	@echo "Running end-to-end tests..."
	go test -v -tags=e2e -count=1 ./cmd/scalp

## release-test: test goreleaser snapshot
release-test:
	@echo "Testing GoReleaser snapshot..."
	goreleaser release --snapshot --clean --config .goreleaser.yaml

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
