package sensitive

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// detector finds one kind of sensitive value. The regular expression
// proposes candidates, validate (checksums, dates, structure) confirms
// them, mask decides what a masked value keeps.
type detector struct {
	name     string
	re       *regexp.Regexp
	validate func(string) bool
	mask     func(string) string
	// requestOnly detectors look at requests only (a password in a
	// query string means nothing in a response).
	requestOnly bool
	// queryNames marks a detector that inspects parameter names.
	queryNames bool
}

// Names of the built-in detectors.
var builtinNames = []string{"card", "personnummer", "iban", "ssn_us", "email", "jwt", "private_key", "api_keys", "password_query"}

func builtin(name string) *detector {
	switch name {
	case "card":
		return &detector{name: name, re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), validate: validCard, mask: keepLast4}
	case "personnummer":
		return &detector{name: name, re: regexp.MustCompile(`\b(?:19|20)?\d{6}[-+]?\d{4}\b`), validate: validPersonnummer, mask: keepLast4}
	case "iban":
		return &detector{name: name, re: regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`), validate: validIBAN, mask: keepLast4}
	case "ssn_us":
		return &detector{name: name, re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), validate: validSSN, mask: keepLast4}
	case "email":
		return &detector{name: name, re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b`), validate: func(string) bool { return true }, mask: maskEmail}
	case "jwt":
		return &detector{name: name, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), validate: validJWT, mask: keepFirst8}
	case "private_key":
		return &detector{name: name, re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`), validate: func(string) bool { return true }, mask: func(string) string { return "-----BEGIN PRIVATE KEY----- [masked]" }}
	case "api_keys":
		return &detector{name: name, re: regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\b[sr]k_live_[0-9a-zA-Z]{24,}\b|\bglpat-[A-Za-z0-9_-]{20,}\b`),
			validate: func(string) bool { return true }, mask: keepFirst8}
	case "password_query":
		return &detector{name: name, re: regexp.MustCompile(`(?i)^(?:pass(?:word|wd|phrase)?|pwd|secret|client_secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|auth)$`),
			validate: func(string) bool { return true }, mask: func(string) string { return "[masked]" }, requestOnly: true, queryNames: true}
	}
	return nil
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// luhn checks the Luhn checksum of a digit string.
func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func validCard(s string) bool {
	d := digitsOnly(s)
	if len(d) < 13 || len(d) > 19 || !luhn(d) {
		return false
	}
	// Reject a run of one digit (test data, phone-like strings).
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return true
		}
	}
	return false
}

// validPersonnummer checks a Swedish personal identity number: a valid
// date (coordination numbers add 60 to the day) and the Luhn checksum
// over the ten short digits.
func validPersonnummer(s string) bool {
	d := digitsOnly(s)
	if len(d) == 12 {
		d = d[2:]
	}
	if len(d) != 10 {
		return false
	}
	month, _ := strconv.Atoi(d[2:4])
	day, _ := strconv.Atoi(d[4:6])
	if day > 60 {
		day -= 60
	}
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	if _, err := time.Parse("060102", d[:2]+d[2:4]+twoDigits(day)); err != nil {
		return false
	}
	return luhn(d)
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// validIBAN checks the ISO 13616 mod 97 checksum.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, c := range rearranged {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
		default:
			return false
		}
		if v >= 10 {
			rem = (rem*100 + v) % 97
		} else {
			rem = (rem*10 + v) % 97
		}
	}
	return rem == 1
}

func validSSN(s string) bool {
	area, group, serial := s[:3], s[4:6], s[7:]
	if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
		return false
	}
	return true
}

func validJWT(s string) bool {
	head, _, _ := strings.Cut(s, ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return false
	}
	var h map[string]any
	if json.Unmarshal(raw, &h) != nil {
		return false
	}
	_, ok := h["alg"]
	return ok
}

func keepLast4(s string) string {
	kept := 0
	out := []rune(s)
	for i := len(out) - 1; i >= 0; i-- {
		c := out[i]
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			if kept < 4 {
				kept++
				continue
			}
			out[i] = '*'
		}
	}
	return string(out)
}

func keepFirst8(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:8] + strings.Repeat("*", min(len(s)-8, 24))
}

func maskEmail(s string) string {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}
