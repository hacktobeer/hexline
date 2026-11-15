GO ?= go
BIN ?= bbs
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/hacktobeer/hexline/internal/version.Version=$(VERSION) \
	-X github.com/hacktobeer/hexline/internal/version.Commit=$(COMMIT) \
	-X github.com/hacktobeer/hexline/internal/version.BuildDate=$(DATE)

.PHONY: all build test race lint vet fmt fuzz check run migrate doctor clean cover

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/bbs

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w cmd internal

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

fuzz:
	$(GO) test ./internal/render -run '^$$' -fuzz FuzzSanitize -fuzztime 30s

check: vet test
	@test -z "$$(gofmt -l cmd internal)" || { echo "unformatted files:"; gofmt -l cmd internal; exit 1; }

run: build
	./$(BIN) serve

migrate: build
	./$(BIN) migrate

doctor: build
	./$(BIN) doctor

cover:
	$(GO) test -coverprofile=cover.out ./... && $(GO) tool cover -func=cover.out | tail -1

clean:
	rm -f $(BIN) cover.out
