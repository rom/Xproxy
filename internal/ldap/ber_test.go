package ldap

import (
	"strings"
	"testing"
)

// TestParseNestingBomb feeds the decoder a message nested far deeper than
// any LDAP PDU: it must be refused, not recurse until the stack dies.
func TestParseNestingBomb(t *testing.T) {
	// Wrap an empty SEQUENCE in 10 000 further SEQUENCEs, building the wire
	// form from the inside out (a leaf carrying the raw bytes keeps the
	// builder itself from recursing).
	var inner []byte
	for i := 0; i < 10000; i++ {
		inner = leaf(classUniversal|constructed, tagSequence, inner).encode(nil)
	}
	if _, _, err := parse(inner); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("nesting bomb accepted: %v", err)
	}
	// A normal, shallow message still parses.
	msg := node(classUniversal, tagSequence, integer(1), node(classApplication, appBindResponse, enumerated(0), str(""), str(""))).encode(nil)
	p, n, err := parse(msg)
	if err != nil || n != len(msg) || len(p.kids) != 2 {
		t.Fatalf("shallow parse: %v %d %+v", err, n, p)
	}
}
