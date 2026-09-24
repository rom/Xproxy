package http

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// Byte range requests, RFC 9110 section 14.
//
// A Range header is a small request that asks for a large answer, and a
// set of ranges is a small request that asks for many answers: each one
// costs the origin a read and the response a multipart part. That is the
// oldest amplification bug in HTTP -- one packet asking an origin to
// assemble hundreds of parts out of the same file, with the response
// dozens of times the size of the resource -- and it is a gateway's to
// stop, because the gateway is where the request can be judged before
// any of that work is done.
//
// RFC 9110 section 14.2 is explicit that this is the server's decision to
// make: a server "MAY coalesce any of the ranges that overlap, or that
// are separated by a gap that is smaller than the overhead of sending
// multiple parts, regardless of the order in which the corresponding
// byte-range-spec appeared", and one that will not satisfy a range set
// may ignore the header and answer the whole representation. So this
// rewrites the set rather than inventing a rule: the same bytes, fewer
// parts.
//
// What it will not do is guess. A unit other than bytes is passed
// through untouched -- an origin that does not implement it ignores it,
// and this proxy has nothing to say about a unit it cannot read -- and a
// header that is not a range set at all is dropped, once, here, rather
// than read differently by this proxy and by the origin.

// rangeAction values: what happens to a set with too many ranges.
const (
	rangeIgnore = "ignore" // drop the header; the whole representation is served
	rangeRefuse = "refuse" // 416, with Accept-Ranges so the client can retry
)

// rangePolicy is a route's compiled range policy. nil means no policy:
// the header is relayed as it arrived.
type rangePolicy struct {
	maxRanges int
	coalesce  bool
	action    string
}

// byteRange is one range-spec. From and To are inclusive offsets; a
// suffix range ("-500") has from < 0 and to as the length asked for, and
// an open range ("500-") has to < 0.
type byteRange struct{ from, to int64 }

// rangeOutcome is what the policy decided about one header.
type rangeOutcome int

const (
	rangeKeep    rangeOutcome = iota // relay it unchanged
	rangeRewrite                     // relay the value the policy produced
	rangeDrop                        // remove the header
	rangeDeny                        // answer 416
)

// apply decides one Range header. It returns the outcome, the value to
// use when the outcome is rangeRewrite, and how many ranges the client
// asked for (for the log line).
func (p *rangePolicy) apply(value string) (rangeOutcome, string, int) {
	if p == nil || value == "" {
		return rangeKeep, "", 0
	}
	unit, spec, ok := strings.Cut(value, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(unit), "bytes") {
		// Another unit, or not a range set: an origin ignores what it
		// does not implement, and this proxy does not pretend to read it.
		if !ok {
			return rangeDrop, "", 0
		}
		return rangeKeep, "", 0
	}
	// A set this cannot read whole, or one with no specs in it at all.
	// Dropping it here means the proxy and the origin agree about what
	// this request is, which is the whole reason to decide it in one
	// place.
	ranges, ok := parseByteRanges(spec)
	if !ok || len(ranges) == 0 {
		return rangeDrop, "", 0
	}
	asked := len(ranges)
	if p.coalesce {
		ranges = coalesceRanges(ranges)
	}
	if p.maxRanges > 0 && len(ranges) > p.maxRanges {
		if p.action == rangeRefuse {
			return rangeDeny, "", asked
		}
		return rangeDrop, "", asked
	}
	// An unchanged set is relayed byte for byte rather than re-rendered
	// into a value the client did not send.
	rendered := formatByteRanges(ranges)
	if len(ranges) == asked && rendered == "bytes="+strings.TrimSpace(spec) {
		return rangeKeep, "", asked
	}
	return rangeRewrite, rendered, asked
}

// maxRangeSpecs bounds what is parsed at all. A header naming more
// ranges than this is refused as malformed rather than sorted: the work
// of reading it is the work the bound exists to prevent.
const maxRangeSpecs = 256

// parseByteRanges reads a byte-range-set. It is strict: every spec must
// be one of "first-last", "first-" or "-suffix" with digits that fit an
// int64 and last >= first. RFC 9110 says a recipient that cannot parse
// the header must ignore it, and "ignore" here means the caller drops it.
//
// On failure it returns the specs it did read, and false. The caller
// drops the whole set rather than forwarding that prefix: a request built
// out of the readable half of a header is a request the client never
// sent, which is exactly the disagreement between two parsers that this
// proxy exists to prevent.
func parseByteRanges(spec string) ([]byteRange, bool) {
	var out []byteRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			// RFC 9110 tolerates empty list elements from legacy
			// senders; an empty set is caught by the caller.
			continue
		}
		if len(out) >= maxRangeSpecs {
			return out, false
		}
		first, last, ok := strings.Cut(part, "-")
		if !ok {
			return out, false
		}
		first, last = strings.TrimSpace(first), strings.TrimSpace(last)
		switch {
		case first == "" && last == "":
			return out, false
		case first == "": // a suffix range: the last N bytes
			n, err := strconv.ParseInt(last, 10, 64)
			if err != nil || n <= 0 {
				return out, false
			}
			out = append(out, byteRange{from: -1, to: n})
		case last == "": // from here to the end
			n, err := strconv.ParseInt(first, 10, 64)
			if err != nil || n < 0 {
				return out, false
			}
			out = append(out, byteRange{from: n, to: -1})
		default:
			a, err1 := strconv.ParseInt(first, 10, 64)
			b, err2 := strconv.ParseInt(last, 10, 64)
			if err1 != nil || err2 != nil || a < 0 || b < a {
				return out, false
			}
			out = append(out, byteRange{from: a, to: b})
		}
	}
	return out, true
}

// coalesceRanges merges what can be merged without changing which bytes
// were asked for: overlapping and adjacent closed ranges become one, an
// open range swallows everything at or after its start, and a suffix
// range is kept as it is because its offsets depend on a length this
// proxy does not know.
//
// The order is canonical afterwards (by start), which RFC 9110 allows
// explicitly: the server may coalesce "regardless of the order in which
// the corresponding byte-range-spec appeared".
func coalesceRanges(in []byteRange) []byteRange {
	var closed, open, suffix []byteRange
	for _, r := range in {
		switch {
		case r.from < 0:
			suffix = append(suffix, r)
		case r.to < 0:
			open = append(open, r)
		default:
			closed = append(closed, r)
		}
	}
	// One open range is enough: the earliest start covers every later
	// one, since both run to the end of the representation.
	var lowest byteRange
	if len(open) > 0 {
		lowest = open[0]
		for _, r := range open[1:] {
			if r.from < lowest.from {
				lowest = r
			}
		}
	}
	sort.Slice(closed, func(i, j int) bool {
		if closed[i].from == closed[j].from {
			return closed[i].to < closed[j].to
		}
		return closed[i].from < closed[j].from
	})
	merged := make([]byteRange, 0, len(closed)+2)
	for _, r := range closed {
		if len(open) > 0 && r.to >= lowest.from {
			// It reaches the open range, so it is part of it: inside it
			// already, or running into it, in which case the open range
			// starts earlier.
			if r.from < lowest.from {
				lowest.from = r.from
			}
			continue
		}
		if n := len(merged); n > 0 && r.from <= merged[n-1].to+1 {
			if r.to > merged[n-1].to {
				merged[n-1].to = r.to
			}
			continue
		}
		merged = append(merged, r)
	}
	if len(open) > 0 {
		merged = append(merged, lowest)
	}
	// The largest suffix covers the smaller ones; the rest are dropped.
	if len(suffix) > 0 {
		largest := suffix[0]
		for _, r := range suffix[1:] {
			if r.to > largest.to {
				largest = r
			}
		}
		merged = append(merged, largest)
	}
	return merged
}

// formatByteRanges renders a set as a Range header value.
func formatByteRanges(rs []byteRange) string {
	var b strings.Builder
	b.WriteString("bytes=")
	for i, r := range rs {
		if i > 0 {
			b.WriteByte(',')
		}
		switch {
		case r.from < 0:
			b.WriteByte('-')
			b.WriteString(strconv.FormatInt(r.to, 10))
		case r.to < 0:
			b.WriteString(strconv.FormatInt(r.from, 10))
			b.WriteByte('-')
		default:
			b.WriteString(strconv.FormatInt(r.from, 10))
			b.WriteByte('-')
			b.WriteString(strconv.FormatInt(r.to, 10))
		}
	}
	return b.String()
}

// compileRangePolicy builds a route's policy, or nil when it has none.
func compileRangePolicy(c *config.RouteRanges) *rangePolicy {
	if c == nil {
		return nil
	}
	p := &rangePolicy{maxRanges: c.MaxRanges, coalesce: true, action: rangeIgnore}
	if c.Coalesce != nil {
		p.coalesce = *c.Coalesce
	}
	if c.Action != "" {
		p.action = c.Action
	}
	if p.maxRanges == 0 {
		p.maxRanges = defaultMaxRanges
	}
	return p
}

// defaultMaxRanges is what a range set is bounded to when the section is
// present and says nothing: enough for a resuming download or a media
// player seeking, far short of a set that asks the origin to assemble
// hundreds of parts.
const defaultMaxRanges = 4

// rangeDenied answers a refused set. Accept-Ranges says the resource
// still takes ranges, so a client that asked for too many can ask again
// for fewer rather than concluding ranges are unsupported.
func rangeDenied(rw http.ResponseWriter) {
	rw.Header().Set("Accept-Ranges", "bytes")
}
