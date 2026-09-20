// Package tui is the terminal user interface of xproxyctl: a full-screen
// live view of status, upstreams, bans, cluster, graphs and the security
// log, drawn with ANSI escapes on top of golang.org/x/term (docs/AMR.md,
// AMR-011 and AMR-027). Rendering is pure (data in, lines out) so it is
// testable without a terminal.
package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// Data is one refresh of everything the views show. Fields are nil or
// empty when the corresponding fetch failed; Errors explains why.
type Data struct {
	At        time.Time
	Status    *mgmt.Status
	Upstreams map[string][]upstream.Stats
	Bans      []ban.Entry
	Cluster   *cluster.Status
	Series    *mgmt.SeriesResponse
	LogLines  []string
	// Added in 1.3: pool state, per route usage, WAF statistics, served
	// certificates, telemetry exporters and dns listeners.
	Pools     map[string]upstream.PoolStatus
	Quotas    *proxy.QuotaReport
	WAF       *proxy.WAFReport
	TLS       map[string][]tlsconf.CertInfo
	Telemetry *mgmt.TelemetryView
	DNS       []dns.Status
	Errors    map[string]string
}

// Source fetches Data.
type Source interface {
	Fetch(ctx context.Context) Data
}

// clientSource fetches from the management API and the security log file.
type clientSource struct {
	c       *mgmt.Client
	logPath string
}

// NewSource creates a source over the management socket. logPath may be
// empty when the configuration is unavailable.
func NewSource(c *mgmt.Client, cfg *config.Config) Source {
	s := &clientSource{c: c}
	if cfg != nil {
		s.logPath = filepath.Join(cfg.Logging.Directory, cfg.Logging.Security.File)
	}
	return s
}

func (s *clientSource) Fetch(ctx context.Context) Data {
	d := Data{At: time.Now(), Errors: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	// live says the result is still ours to write. Each view runs in
	// its own goroutine with a second one doing the call, so that a
	// view slower than the refresh interval does not hold the others:
	// the waiting goroutine gives up at ctx.Done() and the calling one
	// is left running. That goroutine still finishes its call and used
	// to store the answer afterwards — into a Data this function had
	// already returned and the renderer was already drawing. With a
	// refresh interval shorter than a slow management call, that is a
	// write to a live map from a goroutine nobody is waiting for.
	live := true
	set := func(f func()) {
		mu.Lock()
		defer mu.Unlock()
		if !live {
			return // the fetch this belonged to has already been drawn
		}
		f()
	}
	fail := func(what string, err error) {
		set(func() { d.Errors[what] = err.Error() })
	}
	run := func(what string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan error, 1)
			go func() { done <- f() }()
			select {
			case err := <-done:
				if err != nil {
					fail(what, err)
				}
			case <-ctx.Done():
				fail(what, ctx.Err())
			}
		}()
	}
	run("status", func() error {
		st, err := s.c.Status()
		if err == nil {
			set(func() { d.Status = st })
		}
		return err
	})
	run("upstreams", func() error {
		ups, err := s.c.Upstreams()
		if err == nil {
			set(func() { d.Upstreams = ups })
		}
		return err
	})
	run("bans", func() error {
		bs, err := s.c.Bans()
		if err == nil {
			set(func() { d.Bans = bs })
		}
		return err
	})
	run("cluster", func() error {
		cs, err := s.c.ClusterStatus()
		if err == nil {
			set(func() { d.Cluster = cs })
		}
		return err
	})
	run("series", func() error {
		sr, err := s.c.Series(time.Hour, 0)
		if err == nil {
			set(func() { d.Series = sr })
		}
		return err
	})
	fetch := func(what, path string, into func() any) {
		run(what, func() error {
			v := into()
			if err := s.c.Do("GET", path, nil, v); err != nil {
				return err
			}
			set(func() {
				switch t := v.(type) {
				case *map[string]upstream.PoolStatus:
					d.Pools = *t
				case *proxy.QuotaReport:
					d.Quotas = t
				case *proxy.WAFReport:
					d.WAF = t
				case *map[string][]tlsconf.CertInfo:
					d.TLS = *t
				case *mgmt.TelemetryView:
					d.Telemetry = t
				case *[]dns.Status:
					d.DNS = *t
				}
			})
			return nil
		})
	}
	fetch("pools", "/v1/pools", func() any { return &map[string]upstream.PoolStatus{} })
	fetch("quotas", "/v1/quotas?top=3", func() any { return &proxy.QuotaReport{} })
	fetch("waf", "/v1/waf?top=12", func() any { return &proxy.WAFReport{} })
	fetch("tls", "/v1/tls", func() any { return &map[string][]tlsconf.CertInfo{} })
	fetch("telemetry", "/v1/telemetry", func() any { return &mgmt.TelemetryView{} })
	fetch("dns", "/v1/dns", func() any { return &[]dns.Status{} })
	if s.logPath != "" {
		run("log", func() error {
			lines, err := tailLines(s.logPath, 200)
			if err == nil {
				set(func() { d.LogLines = lines })
			}
			return err
		})
	}
	wg.Wait()
	// Whatever is still in flight has missed this refresh: it may take
	// the lock, but it will not write.
	mu.Lock()
	live = false
	mu.Unlock()
	return d
}

// tailLines returns the last n lines of a file, reading at most 256 KiB.
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // path from the operator's configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = 256 << 10
	start := st.Size() - window
	if start < 0 {
		start = 0
	}
	buf := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && len(buf) > 0 && err.Error() != "EOF" {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is probably partial
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}
