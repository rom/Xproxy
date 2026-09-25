package assets

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Vendors resolves a hardware address prefix to a manufacturer.
//
// The built-in list is a **seed**, not a registry. The IEEE's own assignment
// file has tens of thousands of entries and changes every week, so baking a copy
// in would be baking in something that is wrong by the time it ships. What is
// here is a short list weighted towards the vendors an operational estate is
// made of, and an operator who wants the real thing loads the registry's own
// file: see Load.
//
// The vendor is also the *weakest* evidence this package uses, on purpose. A
// hardware address is three bytes anybody can set, and the classification rules
// are written so that a wrong or absent vendor name changes a device's label and
// not its role -- the role comes from what the device does.
type Vendors struct {
	mu sync.RWMutex
	// byPrefix is keyed on the lower-case colon-separated first three octets.
	byPrefix map[string]string
}

// NewVendors builds an empty table.
func NewVendors() *Vendors { return &Vendors{byPrefix: map[string]string{}} }

// Add records one prefix. The prefix may be written with colons, hyphens or
// nothing between the octets, because that is a matter of which vendor's
// documentation somebody copied from.
func (v *Vendors) Add(prefix, vendor string) error {
	p, err := normalPrefix(prefix)
	if err != nil {
		return err
	}
	if vendor == "" {
		return fmt.Errorf("vendor prefix %s: no name", prefix)
	}
	v.mu.Lock()
	v.byPrefix[p] = vendor
	v.mu.Unlock()
	return nil
}

// Lookup resolves a hardware address, or returns an empty string.
func (v *Vendors) Lookup(hw []byte) string {
	if len(hw) < 3 {
		return ""
	}
	p := hwString(hw[:3])
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.byPrefix[p]
}

// LookupPrefix resolves a prefix written as a string.
func (v *Vendors) LookupPrefix(prefix string) string {
	p, err := normalPrefix(prefix)
	if err != nil {
		return ""
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.byPrefix[p]
}

// Len is how many prefixes the table holds.
func (v *Vendors) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.byPrefix)
}

// Load reads prefixes from a file and adds them to the table.
//
// The format is the one both the IEEE's own OUI listing and every tool that
// consumes it can be reduced to with a line of shell: a prefix, whitespace or a
// comma, and the vendor name. Blank lines and lines beginning with # are
// skipped. A malformed line is an error rather than a skip, because a list an
// operator trusted and which silently dropped half its entries is worse than
// one that would not load.
//
// The bound is on the number of entries: a file is a file, and a forty-megabyte
// one is a mistake somebody should hear about.
func (v *Vendors) Load(r io.Reader, max int) (int, error) {
	if max <= 0 {
		max = 1 << 20
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	n, line := 0, 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		prefix, name, ok := splitEntry(text)
		if !ok {
			return n, fmt.Errorf("vendor list line %d: %q is not a prefix and a name", line, text)
		}
		if err := v.Add(prefix, name); err != nil {
			return n, fmt.Errorf("vendor list line %d: %w", line, err)
		}
		n++
		if n > max {
			return n, fmt.Errorf("vendor list: more than %d entries", max)
		}
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}

// splitEntry pulls a prefix and a name out of one line.
func splitEntry(text string) (prefix, name string, ok bool) {
	if i := strings.IndexByte(text, ','); i > 0 {
		return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:]), true
	}
	if i := strings.IndexAny(text, " \t"); i > 0 {
		return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:]), true
	}
	return "", "", false
}

// normalPrefix reads the first three octets of a hardware address, however they
// were written.
func normalPrefix(s string) (string, error) {
	f := strings.FieldsFunc(strings.TrimSpace(s), func(r rune) bool {
		return r == ':' || r == '-' || r == '.'
	})
	if len(f) == 1 && len(f[0]) == 6 {
		// The registry's own form: six hex digits and no separators.
		f = []string{f[0][0:2], f[0][2:4], f[0][4:6]}
	}
	if len(f) < 3 {
		return "", fmt.Errorf("%q is not a vendor prefix", s)
	}
	out := make([]byte, 0, 8)
	for i := 0; i < 3; i++ {
		if len(f[i]) != 2 || !isHex(f[i][0]) || !isHex(f[i][1]) {
			return "", fmt.Errorf("%q is not a vendor prefix", s)
		}
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, lower(f[i][0]), lower(f[i][1]))
	}
	return string(out), nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// hwString renders octets as lower-case colon-separated hex.
func hwString(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[c>>4], hex[c&0xf])
	}
	return string(out)
}

// normalHW renders a hardware address for use as a key, or "" when there is
// nothing usable. An all-zero address is not an address: it is the field a
// listener filled in with nothing.
func normalHW(b []byte) string {
	if len(b) < 3 {
		return ""
	}
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	return hwString(b)
}

// normalHWString is normalHW for an address that arrives as text.
func normalHWString(s string) string {
	f := strings.FieldsFunc(strings.TrimSpace(s), func(r rune) bool {
		return r == ':' || r == '-' || r == '.'
	})
	if len(f) < 3 {
		return ""
	}
	out := make([]byte, 0, len(f)*3)
	for i, part := range f {
		if len(part) != 2 || !isHex(part[0]) || !isHex(part[1]) {
			return ""
		}
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, lower(part[0]), lower(part[1]))
	}
	return string(out)
}

// seed is the built-in vendor list: the manufacturers an operational estate is
// mostly made of, plus the few information-technology vendors whose devices turn
// up on the same wire and are worth telling apart from them.
//
// It is short deliberately. Every entry is one somebody can check against the
// IEEE registry in a few seconds, and the classification does not depend on any
// of them being right -- a vendor name is a label, and the role comes from
// behaviour. An estate that wants the whole registry loads it.
var seed = map[string]string{
	// Industrial control
	"08:00:06": "Siemens",
	"00:0e:8c": "Siemens",
	"00:1b:1b": "Siemens",
	"00:1f:f8": "Siemens",
	"00:00:bc": "Allen-Bradley (Rockwell)",
	"00:1d:9c": "Rockwell Automation",
	"00:00:54": "Modicon (Schneider)",
	"00:80:f4": "Telemecanique (Schneider)",
	"00:01:05": "Beckhoff",
	"00:a0:45": "Phoenix Contact",
	"00:30:de": "WAGO",
	"00:00:0a": "Omron",
	// Industrial networking
	"00:90:e8": "Moxa",
	"00:80:63": "Hirschmann",
	// Information technology that shares the wire
	"00:00:0c": "Cisco",
	"00:50:56": "VMware",
	"00:0c:29": "VMware",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"00:1b:21": "Intel",
	"00:14:22": "Dell",
	"00:03:93": "Apple",
	// Devices whose vendor is close to a role
	"00:40:8c": "Axis Communications",
	"00:04:f2": "Polycom",
	"80:5e:c0": "Yealink",
	"00:07:4d": "Zebra Technologies",
}

// SeedVendors builds a table from the built-in list.
func SeedVendors() *Vendors {
	v := NewVendors()
	v.mu.Lock()
	for p, name := range seed {
		v.byPrefix[p] = name
	}
	v.mu.Unlock()
	return v
}
