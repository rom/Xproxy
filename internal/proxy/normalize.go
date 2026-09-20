package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/rom/xproxy/internal/config"
)

// checkNormalization applies server.normalization to a request and
// returns "" when it passes, otherwise a short detail naming the check.
// It looks at the raw request target as the client sent it and at the
// decoded path routing will use, so that a form the two disagree about
// is refused before any component acts on either reading.
func checkNormalization(n *config.Normalization, r *http.Request) string {
	if n.AmbiguousFraming() && r.ProtoMajor == 1 {
		if detail := framingProblem(r); detail != "" {
			return detail
		}
	}
	path := r.URL.Path
	raw := r.URL.EscapedPath()
	if n.ControlChars() {
		if hasControl(path) {
			return "path_control_char"
		}
		if q := r.URL.RawQuery; q != "" {
			if hasControl(q) {
				return "query_control_char"
			}
			if dq, err := url.QueryUnescape(strings.ReplaceAll(q, "+", "%2B")); err == nil && hasControl(dq) {
				return "query_control_char"
			}
		}
	}
	if n.InvalidUTF8() && !utf8.ValidString(path) {
		return "path_invalid_utf8"
	}
	if n.RejectDoubleEncoding && hasPercentEscape(path) {
		return "path_double_encoding"
	}
	if n.RejectEncodedSlashes && hasEncodedSlash(raw) {
		return "path_encoded_slash"
	}
	if n.RejectBackslashes && strings.IndexByte(path, '\\') >= 0 {
		return "path_backslash"
	}
	if n.DotSegments() && hasDotSegments(path) {
		return "path_dot_segment"
	}
	return ""
}

// hasDotSegments reports a "." or ".." segment in the decoded path, or a
// segment starting with ".." or "." followed by ";" (a path parameter
// some servlet containers strip before resolving the dots). Routing
// resolves dot segments but the upstream receives the path as sent, so
// the two would otherwise disagree about which resource is meant.
func hasDotSegments(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
		if strings.HasPrefix(seg, "..;") || strings.HasPrefix(seg, ".;") {
			return true
		}
	}
	return false
}

// framingProblem reports ambiguous HTTP/1 message framing that the
// parser let through: several differing Content-Length values, a
// Content-Length next to a transfer coding, or a coding other than
// chunked.
func framingProblem(r *http.Request) string {
	if cls := r.Header.Values("Content-Length"); len(cls) > 1 {
		for _, v := range cls[1:] {
			if strings.TrimSpace(v) != strings.TrimSpace(cls[0]) {
				return "framing_content_length"
			}
		}
	}
	if te := r.Header.Values("Transfer-Encoding"); len(te) > 0 {
		for _, v := range te {
			for _, coding := range strings.Split(v, ",") {
				if c := strings.ToLower(strings.TrimSpace(coding)); c != "" && c != "chunked" && c != "identity" {
					return "framing_transfer_encoding"
				}
			}
		}
		if r.Header.Get("Content-Length") != "" {
			return "framing_te_cl"
		}
	}
	if len(r.TransferEncoding) > 0 && r.Header.Get("Content-Length") != "" {
		return "framing_te_cl"
	}
	for _, c := range r.TransferEncoding {
		if c != "chunked" {
			return "framing_transfer_encoding"
		}
	}
	return ""
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// hasPercentEscape reports a %XX sequence left in an already decoded
// string, the mark of double encoding.
func hasPercentEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			return true
		}
	}
	return false
}

func hasEncodedSlash(raw string) bool {
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != '%' {
			continue
		}
		if raw[i+1] == '2' && (raw[i+2] == 'F' || raw[i+2] == 'f') {
			return true
		}
		if raw[i+1] == '5' && (raw[i+2] == 'C' || raw[i+2] == 'c') {
			return true
		}
	}
	return false
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// foldIntroducesSyntax reports whether Unicode folding changed the number
// of path-significant bytes. Compatibility mappings turn characters such as
// U+2025 (‥) into "..", U+FF0F into "/" and U+FF05 into "%": a request whose
// folded path gained such bytes would be routed by one path (folded) and
// served by another (raw), so it is refused rather than let through under
// a policy it did not match.
func foldIntroducesSyntax(raw, folded string) bool {
	if raw == folded {
		return false
	}
	count := func(s string) (n int) {
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '.', '/', '\\', '%', ';', '?', '#':
				n++
			}
		}
		return n
	}
	return count(raw) != count(folded)
}

// routingPath is the decoded path folded to the configured Unicode form
// for routing; the upstream still receives the original.
func routingPath(n *config.Normalization, path string) string {
	switch n.Unicode {
	case "nfc":
		if !norm.NFC.IsNormalString(path) {
			return norm.NFC.String(path)
		}
	case "nfkc":
		if !norm.NFKC.IsNormalString(path) {
			return norm.NFKC.String(path)
		}
	}
	return path
}
