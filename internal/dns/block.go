package dns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxBlockEntries bounds a block list.
const MaxBlockEntries = 2_000_000

// BlockList matches names and their subdomains.
type BlockList struct {
	names map[string]struct{}
}

// NewBlockList compiles entries: bare names (matching the name and
// every subdomain), "*.suffix" (subdomains only) and exact "=name".
func NewBlockList(entries []string) (*BlockList, error) {
	bl := &BlockList{names: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		if err := bl.add(e); err != nil {
			return nil, err
		}
	}
	return bl, nil
}

func (bl *BlockList) add(e string) error {
	e = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(e, ".")))
	if e == "" {
		return nil
	}
	if len(bl.names) >= MaxBlockEntries {
		return fmt.Errorf("block list exceeds %d entries", MaxBlockEntries)
	}
	kind := ""
	switch {
	case strings.HasPrefix(e, "*."):
		e, kind = e[2:], "*"
	case strings.HasPrefix(e, "="):
		e, kind = e[1:], "="
	}
	if !nameOK(e) {
		return fmt.Errorf("block entry %q is not a domain name", e)
	}
	bl.names[kind+e] = struct{}{}
	return nil
}

// LoadBlockFile reads a file of one name per line; # comments and hosts
// file lines (address then name) are accepted.
func (bl *BlockList) LoadBlockFile(path string) (int, error) {
	f, err := os.Open(path) //nolint:gosec // operator supplied path from the configuration
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(io.LimitReader(f, 64<<20))
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		if name == "localhost" || name == "localhost.localdomain" || name == "broadcasthost" || strings.HasPrefix(name, "ip6-") {
			continue // hosts file boilerplate
		}
		if err := bl.add(name); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// Len is the number of entries.
func (bl *BlockList) Len() int { return len(bl.names) }

// Match reports whether name (lower case, no trailing dot) is blocked.
func (bl *BlockList) Match(name string) bool {
	if bl == nil || len(bl.names) == 0 {
		return false
	}
	if _, ok := bl.names[name]; ok {
		return true
	}
	if _, ok := bl.names["="+name]; ok {
		return true
	}
	for i := 0; i < len(name); i++ {
		if name[i] != '.' {
			continue
		}
		suffix := name[i+1:]
		if _, ok := bl.names[suffix]; ok {
			return true
		}
		if _, ok := bl.names["*"+suffix]; ok {
			return true
		}
	}
	return false
}

func nameOK(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			ok := c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !ok {
				return false
			}
		}
	}
	return true
}

var errNoUpstream = errors.New("dns: no upstream answered")
