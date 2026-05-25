.PHONY: build test clean release-test fmt tidy help e2e install-precommit precommit

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

## precommit: run checks locally (mirrors CI lint + unit)
precommit:
	@echo "=== Format check ==="
	@if [ -n "$$(go fmt ./...)" ]; then \
		echo "FAIL: some files are not formatted. Run 'make fmt' to fix."; \
		exit 1; \
	fi
	@echo "=== go vet ==="
	go vet ./...
	@echo "=== Build ==="
	go build -o /dev/null $(MAIN_PATH)
	@echo "=== Unit tests ==="
	go test -count=1 ./...
	@echo "All checks passed!"

## install-precommit: install pre-commit hook at .git/hooks/pre-commit
install-precommit:
	@echo "Installing pre-commit hook..."
	mkdir -p .git/hooks
	{ \
		echo '#!/bin/sh'; \
		echo '# Pre-commit hook installed by "make install-precommit"'; \
		echo 'make precommit'; \
	} > .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed at .git/hooks/pre-commit"

help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' |  sed -e 's/^/ /'
