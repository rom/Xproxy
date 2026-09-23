# xproxy build and verification targets.
#
# Reproducible, static, cgo-free builds: the binaries have no dynamic
# dependencies and can be copied onto a minimal Fedora host.

GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# The build date comes from the commit, not the wall clock, so two builds
# of the same revision with the same toolchain produce the same bytes and
# the checksums over a release can be reproduced independently.
DATE      ?= $(shell date -u -d "@$${SOURCE_DATE_EPOCH:-$$(git log -1 --format=%ct 2>/dev/null || echo 0)}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 1970-01-01T00:00:00Z)
PKG        = github.com/rom/xproxy/internal/version
LDFLAGS    = -s -w -buildid= -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).BuildDate=$(DATE)
# readonly: a build never rewrites go.mod or go.sum, so a tampered import
# fails the build instead of silently fetching and recording a new module.
GOMODFLAG ?= -mod=readonly
# coraza ships an @inspectFile operator that runs an external program
# (os/exec) on a request variable, and a @validateSchema operator that
# pulls in an unmaintained i18n dependency chain. Neither is used by the
# CRS or by any xproxy profile; both are compiled out so a rule file can
# never reach them.
CORAZATAGS = coraza.disabled_operators.inspectFile,coraza.disabled_operators.validateSchema
GOFLAGS    = -trimpath $(GOMODFLAG) -tags $(CORAZATAGS)

# Package version: VERSION file plus a git suffix unless HEAD is tagged.
BASE_VERSION := $(shell cat VERSION)
GIT_TAG      := $(shell git describe --tags --exact-match 2>/dev/null)
RPM_RELEASE  ?= $(if $(GIT_TAG),1,0.$(shell date -u +%Y%m%d)git$(COMMIT))
RPMDIR       ?= $(CURDIR)/rpmbuild

BIN = bin

.PHONY: all no-binaries build test test-race cover cover-gate mutate fuzz lint vet fmt check clean install selinux sbom vuln dist srpm rpm rpmlint scale bench load release build-darwin dist-darwin install-macos vet-all docs

all: build

# Release binaries are built without cgo (static). The race detector needs
# cgo, so test targets do not set CGO_ENABLED; tests never use cgo either way.
build: export CGO_ENABLED = 0
build:
	mkdir -p $(BIN)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxy ./cmd/xproxy
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xgate ./cmd/xgate
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xrelay ./cmd/xrelay
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxyctl ./cmd/xproxyctl
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxy-admin ./cmd/xproxy-admin
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/xproxy-fleet ./cmd/xproxy-fleet

test:
	$(GO) test -count=1 -tags $(CORAZATAGS) ./...

test-race:
	$(GO) test -count=1 -race -tags $(CORAZATAGS) ./...

# Coverage of every internal package by the whole suite (integration tests
# count towards the packages they exercise), under the race detector.
# Only packages with tests are run (a package without tests contributes
# nothing and needs the covdata tool with -coverpkg, which some toolchain
# installations lack).
#
# internal/sandbox is left out of this run and only this one: its tests
# apply Landlock and seccomp to a child process, which then cannot write
# the coverage file the instrumented binary tries to emit on exit. That
# is the same reason the package is outside the gate, and `make test`
# and `make test-race` run it in full.
TESTPKGS = $$($(GO) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | grep -v '/internal/sandbox$$')
cover:
	$(GO) test -count=1 -race -coverpkg=./internal/... -coverprofile=coverage.out -covermode=atomic $(TESTPKGS)
	$(GO) tool cover -func=coverage.out | tail -1

# Gate: core packages together at least COVER_MIN percent, no package
# below COVER_FLOOR. See docs/TESTS.md.
COVER_MIN   ?= 80
COVER_FLOOR ?= 60
cover-gate: cover
	$(GO) run ./test/covergate -profile coverage.out -min $(COVER_MIN) -floor $(COVER_FLOOR)

# Mutation testing on the packages whose arithmetic and comparisons guard
# admission: limiters, router, host and path normalisation.
MUTATE_PKGS ?= internal/limits internal/router internal/netutil
mutate:
	@for p in $(MUTATE_PKGS); do echo "== $$p"; gremlins unleash $$p || exit 1; done

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

# Refuse a compiled artefact tracked in git: a binary blob passes review
# unread, ships in the source tarball through `git archive`, and cannot be
# reproduced from the tree.
no-binaries:
	@bad=$$(git ls-files -z | xargs -0 -r file --mime-type -- 2>/dev/null | \
	  grep -E ':[[:space:]]+application/(x-(executable|sharedlib|pie-executable|mach-binary|archive)|vnd\.microsoft\.portable-executable)' || true); \
	if [ -n "$$bad" ]; then echo "tracked binaries:"; echo "$$bad"; exit 1; fi

vet:
	$(GO) vet -tags $(CORAZATAGS) ./...

fmt:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting" && exit 1)

lint:
	golangci-lint run --build-tags $(CORAZATAGS) ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

sbom:
	$(GO) version -m $(BIN)/xproxy

# Release artefacts in dist/: binaries tarball, vendored source tarball,
# RPMs when rpmbuild is available, SBOM and SHA256SUMS, optionally signed
# with an SSH key (SIGN_KEY). See docs/RELEASING.md.
DIST     = dist
RELNAME  = xproxy-$(BASE_VERSION)-linux-amd64
# macOS binaries, cross compiled (cgo is never needed). See docs/SETUP_MACOS.md.
DARWIN_ARCHS ?= arm64 amd64
build-darwin: export CGO_ENABLED = 0
build-darwin:
	@for a in $(DARWIN_ARCHS); do \
	  mkdir -p $(BIN)/darwin-$$a; \
	  for c in xproxy xproxyctl xproxy-admin xproxy-fleet; do \
	    GOOS=darwin GOARCH=$$a $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/darwin-$$a/$$c ./cmd/$$c || exit 1; \
	  done; \
	done
	@ls -l $(BIN)/darwin-*/

# Tarball per architecture with the launchd, sandbox and pf files.
dist-darwin: build-darwin
	@mkdir -p $(DIST)
	@for a in $(DARWIN_ARCHS); do \
	  d=$(DIST)/xproxy-$(BASE_VERSION)-darwin-$$a; rm -rf $$d && mkdir -p $$d; \
	  cp $(BIN)/darwin-$$a/* LICENSE README.md VERSION $$d/; \
	  cp -r deploy/macos deploy/config docs $$d/; \
	  tar -C $(DIST) -czf $$d.tar.gz $$(basename $$d) && rm -rf $$d; \
	done
	@ls -l $(DIST)/*darwin*

# Install onto this Mac (run with sudo on macOS). Builds for the host
# architecture, then runs deploy/macos/install.sh.
install-macos:
	@test "$$(uname -s)" = Darwin || { echo "install-macos runs on macOS"; exit 1; }
	$(MAKE) build-darwin DARWIN_ARCHS=$$(uname -m | sed 's/x86_64/amd64/')
	sh deploy/macos/install.sh $(BIN)/darwin-$$(uname -m | sed 's/x86_64/amd64/')

# Type check every supported target.
vet-all: vet
	GOOS=linux GOARCH=arm64 $(GO) vet -tags $(CORAZATAGS) ./...
	GOOS=darwin GOARCH=arm64 $(GO) vet -tags $(CORAZATAGS) ./...
	GOOS=darwin GOARCH=amd64 $(GO) vet -tags $(CORAZATAGS) ./...

release: build dist
	rm -rf $(DIST) && mkdir -p $(DIST)/$(RELNAME)
	cp $(BIN)/xproxy $(BIN)/xproxyctl $(BIN)/xproxy-admin $(BIN)/xproxy-fleet LICENSE README.md VERSION $(DIST)/$(RELNAME)/
	cp -r deploy docs $(DIST)/$(RELNAME)/
	tar -C $(DIST) -czf $(DIST)/$(RELNAME).tar.gz $(RELNAME) && rm -rf $(DIST)/$(RELNAME)
	$(MAKE) dist-darwin
	cp $(RPMDIR)/SOURCES/xproxy-$(BASE_VERSION).tar.gz $(DIST)/xproxy-$(BASE_VERSION)-src.tar.gz
	$(GO) version -m $(BIN)/xproxy > $(DIST)/xproxy-$(BASE_VERSION).sbom.txt
	@if command -v rpmbuild >/dev/null 2>&1 && [ -f /usr/lib/rpm/macros.d/macros.systemd ]; then \
	  $(MAKE) rpm && cp $(RPMDIR)/RPMS/*/*.rpm $(RPMDIR)/SRPMS/*.rpm $(DIST)/; \
	else echo "rpmbuild with the Fedora macros not found: RPMs not built"; fi
	cd $(DIST) && sha256sum * > SHA256SUMS
	@if [ -n "$(SIGN_KEY)" ]; then ssh-keygen -Y sign -f $(SIGN_KEY) -n xproxy-release $(DIST)/SHA256SUMS && echo "signed $(DIST)/SHA256SUMS.sig"; fi
	@ls -l $(DIST)

check: fmt no-binaries vet-all test-race lint

# Generated documentation: the configuration JSON schema from the Go
# types and the manual pages from docs/man/*.md and docs/CONFIG.md. Tests
# fail when the committed files are stale.
docs:
	$(GO) generate ./internal/config/schema ./internal/manpage

clean:
	rm -rf $(BIN) coverage.out $(RPMDIR) deploy/selinux/xproxy.pp deploy/selinux/xproxy.pp.bz2 deploy/selinux/tmp

# Install onto the local host (run as root). See docs/SETUP.md.
PREFIX ?= /usr/local
install: build
	install -D -m 0755 $(BIN)/xproxy $(DESTDIR)$(PREFIX)/bin/xproxy
	install -D -m 0755 $(BIN)/xgate $(DESTDIR)$(PREFIX)/bin/xgate
	install -D -m 0755 $(BIN)/xrelay $(DESTDIR)$(PREFIX)/bin/xrelay
	install -D -m 0755 $(BIN)/xproxyctl $(DESTDIR)$(PREFIX)/bin/xproxyctl
	install -D -m 0755 $(BIN)/xproxy-admin $(DESTDIR)$(PREFIX)/bin/xproxy-admin
	install -D -m 0755 $(BIN)/xproxy-fleet $(DESTDIR)$(PREFIX)/bin/xproxy-fleet
	install -D -m 0644 deploy/systemd/xproxy-fleet.service $(DESTDIR)/etc/systemd/system/xproxy-fleet.service
	install -D -m 0644 docs/man/xproxy-fleet.8 $(DESTDIR)$(PREFIX)/share/man/man8/xproxy-fleet.8
	install -D -m 0644 deploy/systemd/xproxy-admin.service $(DESTDIR)/etc/systemd/system/xproxy-admin.service
	install -D -m 0644 deploy/polkit/50-xproxy-admin.rules $(DESTDIR)/etc/polkit-1/rules.d/50-xproxy-admin.rules
	install -D -m 0644 deploy/systemd/xproxy.service $(DESTDIR)/etc/systemd/system/xproxy.service
	install -D -m 0644 deploy/systemd/xproxy.socket $(DESTDIR)/etc/systemd/system/xproxy.socket
	install -D -m 0644 deploy/systemd/xproxy-https.socket $(DESTDIR)/etc/systemd/system/xproxy-https.socket
	install -D -m 0644 deploy/systemd/xproxy-h3.socket $(DESTDIR)/etc/systemd/system/xproxy-h3.socket
	install -D -m 0644 deploy/systemd/xgate.service $(DESTDIR)/etc/systemd/system/xgate.service
	install -D -m 0644 deploy/systemd/xgate.socket $(DESTDIR)/etc/systemd/system/xgate.socket
	install -D -m 0644 deploy/systemd/xrelay.service $(DESTDIR)/etc/systemd/system/xrelay.service
	install -D -m 0644 deploy/systemd/xrelay.socket $(DESTDIR)/etc/systemd/system/xrelay.socket
	install -D -m 0644 deploy/sysctl/90-xproxy.conf $(DESTDIR)/etc/sysctl.d/90-xproxy.conf
	install -D -m 0644 deploy/logrotate/xproxy $(DESTDIR)/etc/logrotate.d/xproxy
	install -D -m 0644 deploy/logrotate/xgate $(DESTDIR)/etc/logrotate.d/xgate
	install -D -m 0644 deploy/logrotate/xrelay $(DESTDIR)/etc/logrotate.d/xrelay
	install -D -m 0640 -b deploy/config/xproxy.yaml $(DESTDIR)/etc/xproxy/xproxy.yaml
	install -D -m 0640 -b deploy/config/xgate.yaml $(DESTDIR)/etc/xproxy/xgate.yaml
	install -D -m 0640 -b deploy/config/xrelay.yaml $(DESTDIR)/etc/xproxy/xrelay.yaml
	install -D -m 0644 deploy/sysusers/xproxy.conf $(DESTDIR)/usr/lib/sysusers.d/xproxy.conf
	install -D -m 0644 deploy/tmpfiles/xproxy-cluster.conf $(DESTDIR)/usr/lib/tmpfiles.d/xproxy-cluster.conf
	install -D -m 0644 deploy/tmpfiles/xproxy-config.conf $(DESTDIR)/usr/lib/tmpfiles.d/xproxy-config.conf
	install -D -m 0644 docs/man/xproxy.8 $(DESTDIR)$(PREFIX)/share/man/man8/xproxy.8
	install -D -m 0644 docs/man/xgate.8 $(DESTDIR)$(PREFIX)/share/man/man8/xgate.8
	install -D -m 0644 docs/man/xrelay.8 $(DESTDIR)$(PREFIX)/share/man/man8/xrelay.8
	install -D -m 0644 docs/man/xproxyctl.8 $(DESTDIR)$(PREFIX)/share/man/man8/xproxyctl.8
	install -D -m 0644 docs/man/xproxy.yaml.5 $(DESTDIR)$(PREFIX)/share/man/man5/xproxy.yaml.5
	install -D -m 0644 internal/config/schema/xproxy.schema.json $(DESTDIR)$(PREFIX)/share/xproxy/xproxy.schema.json
	install -D -m 0644 deploy/grafana/xproxy-overview.json $(DESTDIR)$(PREFIX)/share/xproxy/grafana/xproxy-overview.json
	install -D -m 0644 deploy/grafana/xproxy-security.json $(DESTDIR)$(PREFIX)/share/xproxy/grafana/xproxy-security.json
	install -D -m 0644 deploy/grafana/README.md $(DESTDIR)$(PREFIX)/share/xproxy/grafana/README.md
	install -D -m 0644 deploy/prometheus/xproxy-alerts.yaml $(DESTDIR)$(PREFIX)/share/xproxy/prometheus/xproxy-alerts.yaml
	install -d -m 0755 $(DESTDIR)$(PREFIX)/share/bash-completion/completions $(DESTDIR)$(PREFIX)/share/zsh/site-functions $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	$(BIN)/xproxyctl completion bash > $(DESTDIR)$(PREFIX)/share/bash-completion/completions/xproxyctl
	$(BIN)/xproxyctl completion zsh > $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_xproxyctl
	$(BIN)/xproxyctl completion fish > $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/xproxyctl.fish

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
