BINARY  := devsec
PKG     := ./cmd/devsec
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build test vet fmt lint run clean install tidy

all: fmt vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

test:
	go test ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

run: build
	./bin/$(BINARY) detect -p examples/sample-app

clean:
	rm -rf bin
