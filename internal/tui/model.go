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
	"github.com/rom/xproxy/internal/mgmt"
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
	fail := func(what string, err error) {
		mu.Lock()
		d.Errors[what] = err.Error()
		mu.Unlock()
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
			mu.Lock()
			d.Status = st
			mu.Unlock()
		}
		return err
	})
	run("upstreams", func() error {
		ups, err := s.c.Upstreams()
		if err == nil {
			mu.Lock()
			d.Upstreams = ups
			mu.Unlock()
		}
		return err
	})
	run("bans", func() error {
		bs, err := s.c.Bans()
		if err == nil {
			mu.Lock()
			d.Bans = bs
			mu.Unlock()
		}
		return err
	})
	run("cluster", func() error {
		cs, err := s.c.ClusterStatus()
		if err == nil {
			mu.Lock()
			d.Cluster = cs
			mu.Unlock()
		}
		return err
	})
	run("series", func() error {
		sr, err := s.c.Series(time.Hour, 0)
		if err == nil {
			mu.Lock()
			d.Series = sr
			mu.Unlock()
		}
		return err
	})
	if s.logPath != "" {
		run("log", func() error {
			lines, err := tailLines(s.logPath, 200)
			if err == nil {
				mu.Lock()
				d.LogLines = lines
				mu.Unlock()
			}
			return err
		})
	}
	wg.Wait()
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
