package netutil

import (
	"strings"
)

// PathTemplate replaces the variable segments of a request path with
// "*": decimal numbers, UUIDs, long hexadecimal or base64-like tokens
// and anything else that does not look like a name, so that
// /users/42/orders/8f1c... and /users/43/orders/2a9d... share one
// template. It is used to key rate limits per endpoint and to build the
// API inventory without one entry per identifier.
func PathTemplate(path string) string {
	if path == "" || path == "/" {
		return path
	}
	parts := strings.Split(path, "/")
	for i, seg := range parts {
		if seg == "" {
			continue
		}
		if isVariableSegment(seg) {
			parts[i] = "*"
		}
	}
	out := strings.Join(parts, "/")
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// isVariableSegment reports whether a path segment looks like an
// identifier rather than a resource name.
func isVariableSegment(seg string) bool {
	// Keep a file-like name (name.ext) as it is, unless the stem is a
	// number (2024.pdf is one report of many).
	if dot := strings.LastIndexByte(seg, '.'); dot > 0 && dot < len(seg)-1 && len(seg)-dot <= 6 {
		return hasDigitsOnly(seg[:dot])
	}
	digits, hexes, letters, others := 0, 0, 0, 0
	for _, c := range seg {
		switch {
		case c >= '0' && c <= '9':
			digits++
			hexes++
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			hexes++
			letters++
		case (c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z'):
			letters++
		case c == '-' || c == '_' || c == '.' || c == '~' || c == '=' || c == '+':
			others++
		default:
			others++
		}
	}
	n := len(seg)
	switch {
	case digits == n:
		return true // a number
	case digits > 0 && hexes+others == n && n >= 16:
		return true // a hex id such as a uuid or a hash
	case n == 36 && strings.Count(seg, "-") == 4 && hexes+4 == n:
		return true
	case n >= 20 && digits >= 4 && letters+digits+others == n && float64(digits)/float64(n) >= 0.25:
		return true // an opaque token
	}
	return false
}

func hasDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
