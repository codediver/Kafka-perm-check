BIN     := kafka-perm-check
PKG     := ./cmd/kafka-perm-check
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build dist tidy lint clean

## build: compile for the current platform
build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BIN) $(PKG)

## dist: cross-compile for Linux, macOS, and Windows (amd64 + arm64)
dist:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-amd64   $(PKG)
	GOOS=linux   GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-arm64   $(PKG)
	GOOS=darwin  GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-amd64  $(PKG)
	GOOS=darwin  GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-arm64  $(PKG)
	GOOS=windows GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-windows-amd64.exe $(PKG)
	@echo "\nBuilt:"
	@ls -lh dist/

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## lint: run go vet
lint:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -rf bin/ dist/
