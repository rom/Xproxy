package simulate

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The two text corpus formats: requests for the listeners that speak HTTP, and
// frames for the ones that speak bytes.
//
// They are text because of what an operator has when they need this. Somebody
// is looking at a security log line, or a scanner report, or a ticket that says
// "the shift supervisor's tool stopped working after the change" -- and what
// they can produce in a minute is the request or the frame. A format they can
// type, paste, and keep in the repository beside the configuration is worth
// more than a richer one they would have to generate.
//
// Both are line based, both take comments, and both use the same item
// separator, so there is one thing to learn.

// maxCorpusBytes bounds a corpus file. It is a file somebody wrote, and a
// gigabyte of it is a mistake rather than a test plan.
const maxCorpusBytes = 64 << 20

// maxItems bounds how many inputs one file may hold. A simulation sends them
// one at a time, so this is also a bound on how long a run takes.
const maxItems = 100000

// ParseRequests reads a corpus of HTTP requests.
//
//	# a comment, and a blank line, are ignored between items
//	>>> listener=edge name="the injection scanners found"
//	GET /?id=1%27+OR+1%3D1-- HTTP/1.1
//	Host: shop.example.com
//
//	>>>
//	POST /checkout HTTP/1.1
//	Host: shop.example.com
//	Content-Length: 9
//
//	qty=99999
//
// Line endings are normalised to CRLF, because HTTP requires them and a file
// somebody typed will not have them: a request refused for a bare newline
// would be a finding about the corpus rather than about the policy. An item
// with no blank line in it is a head with no body, and gets the terminator a
// request needs, for the same reason.
//
// `raw` on the separator line skips both: the item is the lines exactly as
// written, joined with one newline and with no newline after the last -- which
// is how to send something deliberately malformed. An item that needs a
// trailing newline ends with a blank line.
func ParseRequests(r io.Reader) ([]Input, error) { return parseCorpus(r, false) }

// ParseFrames reads a corpus of protocol frames as hex.
//
//	>>> listener=plant name="write single register 40001"
//	00 01 00 00 00 06 01 10 00 00 00 01
//
//	>>> listener=plant
//	# a comment inside an item is ignored too
//	0002 0000 0006 01 03 0000 0001
//
// Whitespace inside a frame is ignored, so a byte string can be grouped the way
// the protocol's own documentation groups it. Several lines concatenate into
// one payload: a frame is often easier to read split by field.
func ParseFrames(r io.Reader) ([]Input, error) { return parseCorpus(r, true) }

// parseCorpus reads either format. The separator, the directives and the
// comment rules are identical; only what the body means differs.
func parseCorpus(r io.Reader, asHex bool) ([]Input, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxCorpusBytes))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var (
		out     []Input
		cur     *Input
		body    []string
		raw     bool
		started int
	)
	flush := func() error {
		if cur == nil {
			return nil
		}
		text := strings.Join(body, "\n")
		// Checked before the terminator is added, so an item with nothing in
		// it does not become a bare CRLF pair and get sent.
		if strings.TrimSpace(text) == "" {
			return fmt.Errorf("line %d: an item with nothing in it", started)
		}
		switch {
		case asHex:
			b, err := decodeHex(text)
			if err != nil {
				return fmt.Errorf("line %d: %w", started, err)
			}
			cur.Bytes = b
		case raw:
			cur.Bytes = []byte(text)
		default:
			cur.Bytes = []byte(terminate(strings.ReplaceAll(text, "\n", "\r\n")))
		}
		out = append(out, *cur)
		cur, body, raw = nil, nil, false
		return nil
	}
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if strings.HasPrefix(text, ">>>") {
			if err := flush(); err != nil {
				return nil, err
			}
			if len(out) >= maxItems {
				return nil, fmt.Errorf("line %d: more than %d items", line, maxItems)
			}
			in, isRaw, err := directives(strings.TrimPrefix(text, ">>>"))
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			if in.Name == "" {
				in.Name = "item " + strconv.Itoa(len(out)+1)
			}
			cur, raw, started = &in, isRaw, line
			continue
		}
		if cur == nil {
			// Before the first item only comments and blank lines are allowed,
			// so a file whose separator is misspelled says so rather than
			// silently simulating nothing.
			if t := strings.TrimSpace(text); t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			return nil, fmt.Errorf("line %d: text before the first >>> separator", line)
		}
		if asHex && strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		body = append(body, text)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no items: an item starts with a >>> line")
	}
	return out, nil
}

// terminate finishes an HTTP request head.
//
// A request needs a blank line after its headers, and a file somebody typed
// usually has the headers and nothing else -- so a corpus written the obvious
// way would produce a request the parser is still waiting for. Where the item
// already has a blank line in it, it has a head and a body and is left exactly
// as written; where it has none, the terminator is added. `raw` skips this, for
// the deliberately malformed request.
func terminate(s string) string {
	if strings.Contains(s, "\r\n\r\n") {
		return s
	}
	return strings.TrimRight(s, "\r\n") + "\r\n\r\n"
}

// directives reads the key=value pairs on a separator line.
func directives(s string) (Input, bool, error) {
	var in Input
	raw := false
	for _, f := range fields(s) {
		if f == "raw" {
			raw = true
			continue
		}
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return in, false, fmt.Errorf("%q: expected key=value, or raw", f)
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "listener":
			in.Listener = v
		case "name":
			in.Name = v
		case "client":
			in.Client = v
		default:
			return in, false, fmt.Errorf("%q: listener, name, client or raw", k)
		}
	}
	return in, raw, nil
}

// fields splits a separator line, keeping a quoted value with spaces in it
// together: name="the request the scanner found" is one field.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// decodeHex reads a frame written as hex, ignoring whitespace. An odd number of
// digits is an error rather than a silently dropped nibble: a frame missing
// half a byte is a frame nobody meant to write.
func decodeHex(s string) ([]byte, error) {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '_', ':':
			// Grouping, not data: a frame is easier to check against a vendor
			// document when it is written the way the document writes it.
		default:
			b.WriteRune(r)
		}
	}
	if b.Len()%2 != 0 {
		return nil, fmt.Errorf("an odd number of hex digits (%d)", b.Len())
	}
	out, err := hex.DecodeString(b.String())
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	return out, nil
}
