// Package streamscan applies a YARA policy to a stream as it is
// relayed.
//
// It is shared because the shape of the problem is the same wherever it
// turns up: bytes go past in both directions, rules run over a window of
// them, and a match has to be decided on before the rest of the stream
// follows -- the bytes already sent cannot be unsent, so the only thing
// left to choose is whether the connection carries on. Layer 4, SFTP
// writes, FTP transfers and the plaintext inside an intercepted TLS
// tunnel all want exactly that, and none of them wants its own copy of
// it.
package streamscan

import (
	"fmt"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/yara"
)

// Guard is a compiled YARA policy for one listener.
type Guard struct {
	rules    *yara.Rules
	Cfg      *config.YARAPolicy
	client   bool
	upstream bool
}

func New(c *config.YARAPolicy) (*Guard, error) {
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
	g := &Guard{rules: rules, Cfg: c}
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

// Stream scans one direction of a connection. It is fed the same
// bytes that are forwarded, and never changes them: a stream cannot be
// unsent, so the decision this makes is whether the connection
// continues, not what it carries.
type Stream struct {
	g       *Guard
	scanner *yara.Scanner
	// Direction is "client" or "upstream", for the record a match
	// leaves behind.
	Direction string
	seen      int64
	stopped   bool
	// hit is the first rule that fired, for the log.
	hit string
}

func (g *Guard) Stream(direction string) *Stream {
	if g == nil {
		return nil
	}
	if (direction == "client" && !g.client) || (direction == "upstream" && !g.upstream) {
		return nil
	}
	return &Stream{g: g, scanner: g.rules.NewScanner(g.Cfg.MaxWindow), Direction: direction}
}

// Feed gives bytes to the scanner and reports whether a rule fired.
func (s *Stream) Feed(b []byte) bool {
	if s == nil || s.stopped || len(b) == 0 {
		return false
	}
	if s.g.Cfg.MaxBytes > 0 && s.seen >= s.g.Cfg.MaxBytes {
		// Past the bound the connection carries on unscanned, which is
		// stated in the configuration rather than left to be noticed.
		s.stopped = true
		return false
	}
	if s.g.Cfg.MaxBytes > 0 && s.seen+int64(len(b)) > s.g.Cfg.MaxBytes {
		b = b[:s.g.Cfg.MaxBytes-s.seen]
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

// Matches returns what fired, for the log and the security event.
func (s *Stream) Matches() []yara.Match {
	if s == nil {
		return nil
	}
	return s.scanner.Matches()
}

// Policy is the configuration this stream was built from, which a
// caller reads to find out what a match should lead to.
func (s *Stream) Policy() *config.YARAPolicy {
	if s == nil {
		return nil
	}
	return s.g.Cfg
}
