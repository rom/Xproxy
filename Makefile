# xproxy build and verification targets.
#
# Reproducible, static, cgo-free builds: the binaries have no dynamic
# dependencies and can be copied onto a minimal Fedora host.

GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG        = github.com/rom/xproxy/internal/version
LDFLAGS    = -s -w -buildid= -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).BuildDate=$(DATE)
GOFLAGS    = -trimpath -mod=mod

BIN = bin

.PHONY: all build test test-race cover fuzz lint vet fmt check clean install selinux sbom vuln

all: build

# Release binaries are built without cgo (static). The race detector needs
# cgo, so test targets do not set CGO_ENABLED; tests never use cgo either way.
build: export CGO_ENABLED = 0
build:
	mkdir -p $(BIN)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxy ./cmd/xproxy
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxyctl ./cmd/xproxyctl

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -count=1 -race ./...

cover:
	$(GO) test -count=1 -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -1

# Run every fuzz target briefly. FUZZTIME controls the per-target budget.
FUZZTIME ?= 20s
fuzz:
	@for pkg in $$($(GO) list ./...); do \
	  for f in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
	    echo "== $$pkg $$f"; \
	    $(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	  done; \
	done

vet:
	$(GO) vet ./...

fmt:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting" && exit 1)

lint:
	golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

sbom:
	$(GO) version -m $(BIN)/xproxy

check: fmt vet test-race lint

clean:
	rm -rf $(BIN) coverage.out

# Install onto the local host (run as root). See docs/SETUP.md.
PREFIX ?= /usr/local
install: build
	install -D -m 0755 $(BIN)/xproxy $(DESTDIR)$(PREFIX)/bin/xproxy
	install -D -m 0755 $(BIN)/xproxyctl $(DESTDIR)$(PREFIX)/bin/xproxyctl
	install -D -m 0644 deploy/systemd/xproxy.service $(DESTDIR)/etc/systemd/system/xproxy.service
	install -D -m 0644 deploy/systemd/xproxy.socket $(DESTDIR)/etc/systemd/system/xproxy.socket
	install -D -m 0644 deploy/systemd/xproxy-https.socket $(DESTDIR)/etc/systemd/system/xproxy-https.socket
	install -D -m 0644 deploy/systemd/xproxy-h3.socket $(DESTDIR)/etc/systemd/system/xproxy-h3.socket
	install -D -m 0644 deploy/sysctl/90-xproxy.conf $(DESTDIR)/etc/sysctl.d/90-xproxy.conf
	install -D -m 0644 deploy/logrotate/xproxy $(DESTDIR)/etc/logrotate.d/xproxy
	install -D -m 0640 -b deploy/config/xproxy.yaml $(DESTDIR)/etc/xproxy/xproxy.yaml

selinux:
	cd deploy/selinux && checkmodule -M -m -o xproxy.mod xproxy.te && semodule_package -o xproxy.pp -m xproxy.mod -f xproxy.fc
