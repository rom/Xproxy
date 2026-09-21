package proxy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/yara"
)

// yaraGuard is a compiled YARA policy for one listener.
type yaraGuard struct {
	rules    *yara.Rules
	cfg      *config.YARAPolicy
	client   bool
	upstream bool
}

func newYARAGuard(c *config.YARAPolicy) (*yaraGuard, error) {
	var rules *yara.Rules
	var err error
	switch {
	case c.RulesFile != "":
		rules, err = yara.LoadFile(c.RulesFile)
	case c.RulesDir != "":
		rules, err = yara.LoadDir(c.RulesDir)
	default:
		return nil, fmt.Errorf("yara: rules_file or rules_dir is required")
	}
	if err != nil {
		return nil, fmt.Errorf("yara: %w", err)
	}
	g := &yaraGuard{rules: rules, cfg: c}
	for _, d := range c.Directions {
		switch d {
		case "client":
			g.client = true
		case "upstream":
			g.upstream = true
		}
	}
	return g, nil
}

// yaraStream scans one direction of a connection. It is fed the same
// bytes that are forwarded, and never changes them: a stream cannot be
// unsent, so the decision this makes is whether the connection
// continues, not what it carries.
type yaraStream struct {
	g         *yaraGuard
	scanner   *yara.Scanner
	direction string
	seen      int64
	stopped   bool
	// hit is the first rule that fired, for the log.
	hit string
}

func (g *yaraGuard) stream(direction string) *yaraStream {
	if g == nil {
		return nil
	}
	if (direction == "client" && !g.client) || (direction == "upstream" && !g.upstream) {
		return nil
	}
	return &yaraStream{g: g, scanner: g.rules.NewScanner(g.cfg.MaxWindow), direction: direction}
}

// feed gives bytes to the scanner and reports whether a rule fired.
func (s *yaraStream) feed(b []byte) bool {
	if s == nil || s.stopped || len(b) == 0 {
		return false
	}
	if s.g.cfg.MaxBytes > 0 && s.seen >= s.g.cfg.MaxBytes {
		// Past the bound the connection carries on unscanned, which is
		// stated in the configuration rather than left to be noticed.
		s.stopped = true
		return false
	}
	if s.g.cfg.MaxBytes > 0 && s.seen+int64(len(b)) > s.g.cfg.MaxBytes {
		b = b[:s.g.cfg.MaxBytes-s.seen]
	}
	s.seen += int64(len(b))
	_, _ = s.scanner.Write(b)
	// One read from the socket is where the stream paused, so it is
	// where the rules are worth evaluating: waiting for a window to
	// fill would mean a decision that arrives after the transfer.
	s.scanner.Flush()
	if !s.scanner.Fired() {
		return false
	}
	s.stopped = true
	s.hit = s.scanner.Matches()[0].Rule
	return true
}

// matches returns what fired, for the log and the security event.
func (s *yaraStream) matches() []yara.Match {
	if s == nil {
		return nil
	}
	return s.scanner.Matches()
}

// report logs a match and counts it. It returns true when the
// connection should be closed.
func (t *tcpServer) yaraReport(s *yaraStream, ip netip.Addr, sni string) bool {
	ms := s.matches()
	if len(ms) == 0 {
		return false
	}
	names := make([]string, 0, len(ms))
	tags := map[string]bool{}
	for _, m := range ms {
		names = append(names, m.Rule)
		for _, tag := range m.Tags {
			tags[tag] = true
		}
	}
	tagList := make([]string, 0, len(tags))
	for tag := range tags {
		tagList = append(tagList, tag)
	}
	t.s.stats.YARAMatches.Add(1)
	action := s.g.cfg.Action
	t.s.logs.SecurityEvent(context.Background(), action, "yara_match",
		"listener", t.cfg.Name, "client_ip", ip.String(), "sni", sni, "proto", "tcp",
		"direction", s.direction, "rules", strings.Join(names, ","), "tags", strings.Join(tagList, ","),
		"offset", ms[0].Offset)
	if action != "close" {
		return false
	}
	if bl := t.s.bans.Load(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "yara")
	}
	return true
}
