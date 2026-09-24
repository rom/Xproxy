package http

import (
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/shed"
)

// Extensible HTTP priorities, RFC 9218.
//
// A client knows things about its own requests that this proxy cannot see:
// that one fetch is a prefetch for a page nobody has asked for yet, that
// another is the stylesheet blocking the render. RFC 9218 is how it says
// so -- a `Priority` request header carrying an urgency from 0 (most
// urgent) to 7 and an incremental flag -- and it is a *hint*, which is the
// word that decides how this reads it.
//
// The hint may only lower a request's shedding class, never raise it.
// Otherwise the header is a promotion anybody can ask for, and the first
// thing a client under a rate limit or a flood would do is claim urgency
// 0, which would make shedding protect exactly the wrong traffic. Lowering
// is safe because it can only cost the client that asked: a prefetch that
// is shed first is what the client said it wanted.
//
// The header is forwarded unchanged either way. Reading it is this proxy's
// business; the backend's own prioritisation is the backend's.

// maxPriorityHeader bounds the field. RFC 9218's dictionary is a handful
// of characters; a longer one is not one.
const maxPriorityHeader = 128

// defaultUrgency is RFC 9218's own default for a request that states none.
const defaultUrgency = 3

// clientPriority is what a request's Priority header asked for.
type clientPriority struct {
	urgency int
	// incremental is the `i` flag: the response can be used as it
	// arrives. It is parsed and logged; nothing here schedules on it,
	// because this proxy does not multiplex the upstream's streams.
	incremental bool
	// stated is false when the header was absent or unreadable, in which
	// case urgency is RFC 9218's default and nothing is lowered.
	stated bool
}

// parsePriority reads an RFC 9218 Priority field: an RFC 8941 dictionary
// whose members this proxy understands are `u` (an integer 0 to 7) and `i`
// (a boolean). Anything else in it is ignored rather than refused, and a
// field that cannot be read at all is treated as absent -- a malformed
// hint is a client bug or a middlebox, and refusing a request over a
// header that only ever lowers its own priority would turn a hint into a
// way to break requests.
func parsePriority(v string) clientPriority {
	p := clientPriority{urgency: defaultUrgency}
	if v == "" || len(v) > maxPriorityHeader {
		return p
	}
	for _, member := range strings.Split(v, ",") {
		// Parameters on a member (`u=5;q=0.8`) are not ours to read.
		if i := strings.IndexByte(member, ';'); i >= 0 {
			member = member[:i]
		}
		key, value, hasValue := strings.Cut(strings.TrimSpace(member), "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "u":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 7 {
				continue
			}
			p.urgency, p.stated = n, true
		case "i":
			switch {
			case !hasValue, value == "?1":
				p.incremental, p.stated = true, true
			case value == "?0":
				p.incremental, p.stated = false, true
			}
		}
	}
	return p
}

// lower is the class a stated urgency lowers c to, and it only ever
// lowers. Urgency 0 to 3 is "at least as important as the default" and
// changes nothing; 4 and 5 give up a step; 6 and 7 -- which RFC 9218
// describes as background -- go to the class that is shed first.
func (p clientPriority) lower(c shed.Class) shed.Class {
	if !p.stated {
		return c
	}
	switch {
	case p.urgency <= defaultUrgency:
		return c
	case p.urgency <= 5:
		if c > shed.Low {
			return c - 1
		}
		return c
	default:
		return shed.Low
	}
}
