BINARY := coned
BIN_DIR := bin
CMD := ./cmd/coned
PKG := github.com/zzwong/coned-cli/internal/build
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY ?= $(shell test -z "$$(git status --porcelain 2>/dev/null)" && echo false || echo true)
LDFLAGS := -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE) -X $(PKG).Dirty=$(DIRTY)

.PHONY: build install test vet security fmt-check diff-check release-check check clean
build:
	mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)
install:
	go install -ldflags "$(LDFLAGS)" $(CMD)
test:
	go test -race ./...
vet:
	go vet ./...
fmt-check:
	test -z "$$(gofmt -l $$(find . -name '*.go' -type f))"
diff-check:
	git diff --check
security:
	govulncheck ./...
release-check:
	goreleaser check
	goreleaser release --snapshot --clean
check: fmt-check test vet diff-check
clean:
	rm -rf $(BIN_DIR)
