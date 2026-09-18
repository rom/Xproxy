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
GOMODFLAG ?= -mod=mod
GOFLAGS    = -trimpath $(GOMODFLAG)

# Package version: VERSION file plus a git suffix unless HEAD is tagged.
BASE_VERSION := $(shell cat VERSION)
GIT_TAG      := $(shell git describe --tags --exact-match 2>/dev/null)
RPM_RELEASE  ?= $(if $(GIT_TAG),1,0.$(shell date -u +%Y%m%d)git$(COMMIT))
RPMDIR       ?= $(CURDIR)/rpmbuild

BIN = bin

.PHONY: all build test test-race cover fuzz lint vet fmt check clean install selinux sbom vuln dist srpm rpm rpmlint scale bench load

all: build

# Release binaries are built without cgo (static). The race detector needs
# cgo, so test targets do not set CGO_ENABLED; tests never use cgo either way.
build: export CGO_ENABLED = 0
build:
	mkdir -p $(BIN)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxy ./cmd/xproxy
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxyctl ./cmd/xproxyctl
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxy-admin ./cmd/xproxy-admin

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

# Scale validation at the 1.0 target (1000 hosts, 10 000 endpoints) and
# the routing benchmarks. See docs/PERFORMANCE.md.
scale:
	XPROXY_SCALE=full $(GO) test -count=1 -run 'TestScale$$' -v ./internal/proxy/ | grep -v '^==='

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/router/ ./internal/limits/ ./internal/metrics/

# External load test: starts the backend and a proxy on loopback and runs
# vegeta at RATE for DURATION (see test/load/README.md).
RATE     ?= 5000
DURATION ?= 30s
load: build
	@mkdir -p /tmp/xproxy-load/logs
	@$(GO) run ./test/load/backend -listen 0.0.0.0:9001 & echo $$! > /tmp/xproxy-load/backend.pid
	@$(BIN)/xproxy -config test/load/xproxy.yaml & echo $$! > /tmp/xproxy-load/xproxy.pid
	@sleep 1
	@test/load/vegeta.sh $(RATE) $(DURATION) || true
	@$(BIN)/xproxyctl -socket /tmp/xproxy-load/mgmt.sock stats | head -20 || true
	@kill $$(cat /tmp/xproxy-load/xproxy.pid) $$(cat /tmp/xproxy-load/backend.pid) 2>/dev/null || true

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
	rm -rf $(BIN) coverage.out $(RPMDIR) deploy/selinux/xproxy.pp deploy/selinux/xproxy.pp.bz2 deploy/selinux/tmp

# Install onto the local host (run as root). See docs/SETUP.md.
PREFIX ?= /usr/local
install: build
	install -D -m 0755 $(BIN)/xproxy $(DESTDIR)$(PREFIX)/bin/xproxy
	install -D -m 0755 $(BIN)/xproxyctl $(DESTDIR)$(PREFIX)/bin/xproxyctl
	install -D -m 0755 $(BIN)/xproxy-admin $(DESTDIR)$(PREFIX)/bin/xproxy-admin
	install -D -m 0644 deploy/systemd/xproxy-admin.service $(DESTDIR)/etc/systemd/system/xproxy-admin.service
	install -D -m 0644 deploy/polkit/50-xproxy-admin.rules $(DESTDIR)/etc/polkit-1/rules.d/50-xproxy-admin.rules
	install -D -m 0644 deploy/systemd/xproxy.service $(DESTDIR)/etc/systemd/system/xproxy.service
	install -D -m 0644 deploy/systemd/xproxy.socket $(DESTDIR)/etc/systemd/system/xproxy.socket
	install -D -m 0644 deploy/systemd/xproxy-https.socket $(DESTDIR)/etc/systemd/system/xproxy-https.socket
	install -D -m 0644 deploy/systemd/xproxy-h3.socket $(DESTDIR)/etc/systemd/system/xproxy-h3.socket
	install -D -m 0644 deploy/sysctl/90-xproxy.conf $(DESTDIR)/etc/sysctl.d/90-xproxy.conf
	install -D -m 0644 deploy/logrotate/xproxy $(DESTDIR)/etc/logrotate.d/xproxy
	install -D -m 0640 -b deploy/config/xproxy.yaml $(DESTDIR)/etc/xproxy/xproxy.yaml
	install -D -m 0644 deploy/sysusers/xproxy.conf $(DESTDIR)/usr/lib/sysusers.d/xproxy.conf

# SELinux module. Uses the policy development headers when present (the
# module uses reference policy interfaces and needs them); falls back to
# the raw checkmodule path for a syntax check without interfaces.
selinux:
	@if [ -f /usr/share/selinux/devel/Makefile ]; then \
	  $(MAKE) -C deploy/selinux -f /usr/share/selinux/devel/Makefile xproxy.pp && rm -rf deploy/selinux/tmp; \
	else \
	  echo "selinux-policy-devel (Fedora) or selinux-policy-dev (Debian) is required"; exit 1; \
	fi

# Source tarball with vendored modules for offline RPM builds.
dist:
	rm -rf $(RPMDIR)/SOURCES/xproxy-$(BASE_VERSION) && mkdir -p $(RPMDIR)/SOURCES
	git archive --format=tar --prefix=xproxy-$(BASE_VERSION)/ HEAD | tar -x -C $(RPMDIR)/SOURCES
	cd $(RPMDIR)/SOURCES/xproxy-$(BASE_VERSION) && $(GO) mod vendor && echo $(COMMIT) > .git-commit
	tar -C $(RPMDIR)/SOURCES -czf $(RPMDIR)/SOURCES/xproxy-$(BASE_VERSION).tar.gz xproxy-$(BASE_VERSION)
	rm -rf $(RPMDIR)/SOURCES/xproxy-$(BASE_VERSION)
	@echo "$(RPMDIR)/SOURCES/xproxy-$(BASE_VERSION).tar.gz"

RPMDEFS = --define "_topdir $(RPMDIR)" --define "xproxy_version $(BASE_VERSION)" --define "xproxy_release $(RPM_RELEASE)" --define "xproxy_commit $(COMMIT)"

srpm: dist
	rpmbuild -bs $(RPMDEFS) deploy/rpm/xproxy.spec

rpm: dist
	rpmbuild -ba $(RPMDEFS) deploy/rpm/xproxy.spec
	@ls -1 $(RPMDIR)/RPMS/*/*.rpm $(RPMDIR)/SRPMS/*.rpm

rpmlint:
	rpmlint -f deploy/rpm/xproxy.rpmlintrc deploy/rpm/xproxy.spec $(RPMDIR)/RPMS/*/*.rpm $(RPMDIR)/SRPMS/*.rpm
