package yara

import (
	"sort"
)

// Match is a rule that fired.
type Match struct {
	Rule string
	Tags []string
	Meta map[string]string
	// Strings are the patterns that occurred, with their counts.
	Strings map[string]int
	// Offset is how many bytes had gone past when the rule first
	// became true.
	Offset int64
}

// Scanner applies a rule set to a stream. It is not safe for
// concurrent use; one stream gets one scanner.
//
// Bytes are scanned in windows with an overlap of the longest pattern,
// so a match straddling two reads is still found. A rule is reported
// the first time its condition becomes true, which for a proxy is the
// point: the decision has to be available before the rest of the stream
// has gone through, not after.
type Scanner struct {
	rules *Rules
	// window is the bytes not yet scanned, plus the overlap kept from
	// the last scan.
	window []byte
	// maxWindow bounds the buffer: a stream is unbounded and the
	// scanner is not.
	maxWindow int
	// overlap is how many bytes are carried between windows.
	overlap int
	// chunk is how many new bytes are allowed to accumulate before the
	// window is scanned again. Scanning on every write would rescan the
	// overlap once per write, which a peer sending one byte at a time
	// could turn into the proxy's whole CPU; waiting for the window to
	// fill would mean a rule that fires only after a quarter of a
	// megabyte. This is the middle.
	chunk int
	// newBytes is how many bytes have arrived since the last scan.
	newBytes int

	seen    int64
	counts  map[string]int
	fired   map[string]bool
	matches []Match
	// truncated records that the overlap was not enough for some
	// pattern, so a straddling match may have been missed. It is
	// reported rather than hidden.
	truncated bool
}

// maxOverlap bounds the bytes carried between windows.
const maxOverlap = 4096

// NewScanner returns a scanner over a rule set. maxWindow bounds the
// buffered bytes; 0 takes a default of 256 KiB. The overlap is the
// longest fixed-width pattern, bounded by maxOverlap: a rule whose
// patterns are wider than that cannot be matched reliably across reads,
// and Truncated says so.
func (rs *Rules) NewScanner(maxWindow int) *Scanner {
	if maxWindow <= 0 {
		maxWindow = 256 << 10
	}
	if maxWindow < 4096 {
		maxWindow = 4096
	}
	s := &Scanner{rules: rs, maxWindow: maxWindow,
		counts: map[string]int{}, fired: map[string]bool{}}
	s.chunk = maxWindow / 8
	if s.chunk < 1024 {
		s.chunk = 1024
	}
	// The overlap is what makes a match straddling two reads still a
	// match, and it is also what is rescanned every time the scanner
	// runs. Capping it is what keeps a peer sending one byte at a time
	// from turning each byte into a full rescan; a pattern wider than
	// the cap is reported through Truncated rather than silently
	// half-checked.
	s.overlap = rs.width
	hasRegex := false
	for _, r := range rs.rules {
		for _, p := range r.Patterns {
			if p.re != nil {
				hasRegex = true
			}
		}
	}
	if hasRegex && s.overlap < maxOverlap {
		// A regular expression has no fixed width, so it gets the cap.
		s.overlap = maxOverlap
	}
	if s.overlap > maxOverlap {
		s.overlap = maxOverlap
		s.truncated = true
	}
	if s.overlap > maxWindow/2 {
		s.overlap = maxWindow / 2
		s.truncated = true
	}
	return s
}

// Write feeds bytes to the scanner. It never returns an error: a
// scanner that refused input would stop the stream it is watching.
func (s *Scanner) Write(b []byte) (int, error) {
	n := len(b)
	s.seen += int64(n)
	for len(b) > 0 {
		room := s.maxWindow - len(s.window)
		take := len(b)
		if take > room {
			take = room
		}
		s.window = append(s.window, b[:take]...)
		s.newBytes += take
		b = b[take:]
		if len(s.window) >= s.maxWindow || s.newBytes >= s.chunk {
			s.scan()
		}
	}
	return n, nil
}

// Flush scans what has arrived since the last scan. A caller that
// knows where the stream paused — a proxy, at each read from the
// socket — calls it there, so a rule fires on the bytes that have
// actually arrived rather than when enough have accumulated to fill a
// window.
func (s *Scanner) Flush() {
	if s.newBytes > 0 {
		s.scan()
	}
}

// Close scans what is left and returns the matches.
func (s *Scanner) Close() []Match {
	// Always scanned, even with an empty window: a rule whose condition
	// needs no string at all (filesize, true) still has to be decided.
	s.scan()
	s.window = nil
	return s.Matches()
}

// Matches returns the rules that have fired so far, ordered by name.
func (s *Scanner) Matches() []Match {
	out := append([]Match(nil), s.matches...)
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// Fired reports whether any rule has matched.
func (s *Scanner) Fired() bool { return len(s.matches) > 0 }

// Truncated reports that a pattern is wider than the overlap, so a
// match straddling two reads could have been missed.
func (s *Scanner) Truncated() bool { return s.truncated }

// Bytes is how many bytes have been written.
func (s *Scanner) Bytes() int64 { return s.seen }

// scan counts occurrences in the current window, evaluates every rule
// that has not fired, and keeps the overlap.
func (s *Scanner) scan() {
	s.newBytes = 0
	for _, r := range s.rules.rules {
		for _, p := range r.Patterns {
			if n := p.count(s.window); n > 0 {
				s.counts[r.Name+"\x00"+p.Name] += n
			}
		}
	}
	for _, r := range s.rules.rules {
		if s.fired[r.Name] {
			continue
		}
		e := &env{counts: map[string]int{}, filesize: s.seen}
		for _, p := range r.Patterns {
			e.counts[p.Name] = s.counts[r.Name+"\x00"+p.Name]
		}
		if !r.Cond.eval(e) {
			continue
		}
		s.fired[r.Name] = true
		if r.Private {
			continue
		}
		m := Match{Rule: r.Name, Tags: r.Tags, Meta: r.Meta, Offset: s.seen,
			Strings: map[string]int{}}
		for name, n := range e.counts {
			if n > 0 {
				m.Strings[name] = n
			}
		}
		s.matches = append(s.matches, m)
	}
	// Keep the overlap so a match across the boundary is still found.
	// The counts of the overlap region are carried with it, which means
	// a pattern inside it can be counted twice; a count is a floor on
	// what the stream contained, and for a threshold that is the safe
	// direction.
	if s.overlap > 0 && len(s.window) > s.overlap {
		keep := s.window[len(s.window)-s.overlap:]
		s.window = append(s.window[:0], keep...)
		return
	}
	if s.overlap == 0 {
		s.window = s.window[:0]
	}
}

// Scan applies the rules to a whole buffer, for a body that is already
// in memory.
func (rs *Rules) Scan(b []byte) []Match {
	s := rs.NewScanner(len(b) + rs.width + 1)
	_, _ = s.Write(b)
	return s.Close()
}
