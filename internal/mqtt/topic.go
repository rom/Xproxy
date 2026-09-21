package mqtt

import (
	"errors"
	"strings"
)

var (
	// ErrBadTopic is a topic name that cannot be published to: empty,
	// or carrying a wildcard, which only a filter may.
	ErrBadTopic = errors.New("mqtt: invalid topic name")
	// ErrBadFilter is a topic filter that is not well formed: a
	// multi-level wildcard anywhere but the last level, or a wildcard
	// sharing a level with other characters.
	ErrBadFilter = errors.New("mqtt: invalid topic filter")
)

// ValidTopic checks a topic name, which is what PUBLISH carries. A
// publication has no wildcards: a broker that accepted one would fan a
// single message out to every level.
func ValidTopic(t string) error {
	if t == "" || strings.ContainsAny(t, "+#") {
		return ErrBadTopic
	}
	return nil
}

// ValidFilter checks a topic filter, which is what SUBSCRIBE carries.
func ValidFilter(f string) error {
	if f == "" {
		return ErrBadFilter
	}
	levels := strings.Split(f, "/")
	for i, l := range levels {
		switch {
		case l == "#":
			if i != len(levels)-1 {
				return ErrBadFilter
			}
		case l == "+":
		case strings.ContainsAny(l, "+#"):
			// A wildcard occupies a whole level or none of it.
			return ErrBadFilter
		}
	}
	return nil
}

// Match reports whether a topic name matches a filter, by the rules of
// MQTT 3.1.1 section 4.7: "+" is one level and "#" is the rest,
// and neither matches a topic beginning with "$" at the first level —
// which is why a subscription to "#" does not quietly hand a client the
// broker's own $SYS tree.
func Match(filter, topic string) bool {
	if filter == "" || topic == "" {
		return false
	}
	f := strings.Split(filter, "/")
	t := strings.Split(topic, "/")
	if strings.HasPrefix(topic, "$") && (f[0] == "+" || f[0] == "#") {
		return false
	}
	for i := 0; i < len(f); i++ {
		if f[i] == "#" {
			// "sport/#" matches "sport" as well as "sport/x".
			return i <= len(t)
		}
		if i >= len(t) {
			return false
		}
		if f[i] == "+" {
			continue
		}
		if f[i] != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

// Subsumes reports whether everything the filter want could deliver is
// also delivered by allowed. It is the question an allow list has to
// ask about a subscription: a client asking for "#" under an allow list
// of "sensors/+" must be refused, because a filter is not a topic and
// matching it as one would let the broadest request through.
func Subsumes(allowed, want string) bool {
	a := strings.Split(allowed, "/")
	w := strings.Split(want, "/")
	for i := 0; i < len(a); i++ {
		if a[i] == "#" {
			return true
		}
		if i >= len(w) {
			// The request is shorter: "sensors" against "sensors/+"
			// delivers nothing the allowance covers, but it also asks
			// for a level the allowance never granted.
			return false
		}
		if w[i] == "#" {
			return false // broader than anything but "#"
		}
		if a[i] == "+" {
			continue // "+" covers any single level, "+" included
		}
		if a[i] != w[i] {
			return false
		}
	}
	return len(a) == len(w)
}

// Overlaps reports whether two filters can both match some topic. It is
// the question a deny list has to ask: a subscription is refused when
// it could reach anything denied, not only when it names it exactly.
func Overlaps(a, b string) bool {
	x := strings.Split(a, "/")
	y := strings.Split(b, "/")
	for i := 0; ; i++ {
		switch {
		case i >= len(x) && i >= len(y):
			return true
		case i >= len(x):
			// "a" ran out: only a trailing "#" in "b" still matches,
			// since "#" also matches the parent level.
			return y[i] == "#" && i == len(y)-1
		case i >= len(y):
			return x[i] == "#" && i == len(x)-1
		}
		if x[i] == "#" || y[i] == "#" {
			return true
		}
		if x[i] == "+" || y[i] == "+" || x[i] == y[i] {
			continue
		}
		return false
	}
}

// Levels counts the levels of a topic or filter.
func Levels(t string) int { return strings.Count(t, "/") + 1 }
