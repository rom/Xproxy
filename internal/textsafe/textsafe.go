// Package textsafe handles strings a peer chose.
//
// A user name from an SSH handshake, a path from an SFTP request, a
// server name from a ClientHello: all of them arrive as whatever the
// other end felt like sending, and all of them end up somewhere that
// cares — a log line a person reads, a file name on disk, a field a
// collector parses. The two things worth doing to such a string are
// bounding it and taking the control characters out, and doing them in
// one place is how they stay done the same way everywhere.
package textsafe

import "strings"

// Clip bounds a peer's string and replaces the characters that would
// break whatever reads it. Each becomes "?", because a newline in a user
// name is a second log record and a carriage return is the first half of
// a line somebody else gets to write.
//
// Three groups go, not one. The C0 controls and DEL, which is the
// obvious set. The C1 controls (0x80 to 0x9f), whose eight bit forms a
// terminal may still act on -- 0x9b is CSI, so a value carrying one has
// an escape sequence in it without an ESC anywhere. And the characters
// that make a rendering disagree with the bytes behind it: the
// bidirectional overrides and isolates, the zero width spaces and
// joiners, a byte order mark in the middle of a line. The last group is
// the Trojan Source class, and a log line is exactly the kind of place
// it works: somebody reads "deny 10.0.0.1" and the bytes say something
// else.
//
// The bound is in bytes and the marker says the string was cut, so a
// reader can tell a long value from a truncated one.
func Clip(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return '?'
		}
		return r
	}, s)
	if max > 0 && len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// unsafeRune reports the characters Clip replaces. The ranges are named
// rather than spelled as numbers in a condition so the next person can
// check them against the tables they came from.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f: // the C0 controls and delete
		return true
	case r >= 0x80 && r <= 0x9f: // the C1 controls, 0x9b among them
		return true
	case r >= 0x202a && r <= 0x202e: // bidirectional embeddings and overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // bidirectional isolates
		return true
	case r >= 0x200b && r <= 0x200f: // zero width spaces, joiners and marks
		return true
	case r == 0x061c: // arabic letter mark
		return true
	case r == 0xfeff: // a byte order mark, which is only a mark at the start
		return true
	case r == 0x2028, r == 0x2029: // line and paragraph separators
		return true
	}
	return false
}

// Component reports whether a string is safe as one component of a path
// this proxy builds: letters, digits, hyphen, underscore and dot, at
// most 64 of them, and not a name made only of dots.
//
// It is deliberately narrower than what a file system would accept. The
// strings it guards are substituted into a path template, so anything
// that could be read as a separator, a parent directory or a shell
// metacharacter is refused rather than escaped — an escape is a thing
// to get wrong, and there is no name anybody needs that this rejects.
func Component(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	dots := 0
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
		case r == '.':
			dots++
		default:
			return false
		}
	}
	// "." and ".." are a parent directory wherever they land.
	return dots != len(s)
}

// Clip64 and Clip256 are the two bounds this project uses: a name that
// identifies somebody, and a path or a line of protocol text. They are
// named rather than spelled out at each call so the same thing is not
// clipped to two different lengths in two log records about it.
func Clip64(s string) string  { return Clip(s, 64) }
func Clip256(s string) string { return Clip(s, 256) }
