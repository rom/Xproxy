package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// MaxConfigBytes bounds the size of a configuration document. A larger file
// is rejected before parsing to keep the parser's memory use predictable.
const MaxConfigBytes = 8 << 20

// Load reads, parses, defaults and validates the configuration at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // the config path is an operator supplied flag
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	if st.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("config %s is %d bytes, limit is %d", path, st.Size(), MaxConfigBytes)
	}
	if st.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("config %s is world-writable; refusing to load", path)
	}
	return Read(io.LimitReader(f, MaxConfigBytes+1))
}

// Read parses configuration from r. It is used by Load and by tests.
func Read(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", MaxConfigBytes)
	}
	return Parse(data)
}

// Parse parses configuration bytes. Unknown fields are rejected.
func Parse(data []byte) (*Config, error) {
	return ParseWith(data, true)
}

// ParseWith is Parse with control over file existence checks; checkFiles
// false is used by tooling that validates configuration on another host.
func ParseWith(data []byte, checkFiles bool) (*Config, error) {
	var c Config
	if err := decodeOne(data, &c); err != nil {
		return nil, err
	}
	if err := resolveIncludes(&c, checkFiles); err != nil {
		return nil, err
	}
	applyDefaults(&c)
	if err := validate(&c, checkFiles); err != nil {
		return nil, err
	}
	return &c, nil
}

// decodeOne decodes exactly one strict YAML document into dst.
func decodeOne(data []byte, dst any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("config is empty")
		}
		return fmt.Errorf("parse config: %w", err)
	}
	// A second document in the stream is a configuration error, not something
	// to silently ignore.
	var extra interface{}
	if err := dec.Decode(&extra); err == nil {
		return errors.New("config contains more than one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}

// Fragment is what an included file may contain: the list sections that
// are appended to the main document. Everything else is refused.
type Fragment struct {
	RateLimits []RateLimit    `yaml:"rate_limits"`
	Upstreams  []Upstream     `yaml:"upstreams"`
	Routes     []Route        `yaml:"routes"`
	Filters    []FilterConfig `yaml:"filters"`
}

// MaxIncludes bounds the fragment files of one configuration.
const MaxIncludes = 256

// resolveIncludes reads the fragments named by c.Includes and appends
// their sections. Patterns must be absolute; a pattern that matches
// nothing is an error when files are checked (so a typo in a glob does
// not silently drop a directory) and ignored otherwise.
func resolveIncludes(c *Config, checkFiles bool) error {
	if len(c.Includes) == 0 {
		return nil
	}
	var files []string
	seen := map[string]bool{}
	for i, pat := range c.Includes {
		if !filepath.IsAbs(pat) {
			return fmt.Errorf("includes[%d]: %q must be an absolute path or glob", i, pat)
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			return fmt.Errorf("includes[%d]: %q: %w", i, pat, err)
		}
		if len(matches) == 0 && checkFiles {
			return fmt.Errorf("includes[%d]: %q matches no file", i, pat)
		}
		sort.Strings(matches)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				files = append(files, m)
			}
		}
	}
	if len(files) > MaxIncludes {
		return fmt.Errorf("includes: %d files exceed the bound of %d", len(files), MaxIncludes)
	}
	for _, path := range files {
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("include %s: %w", path, err)
		}
		if st.IsDir() {
			continue
		}
		if st.Size() > MaxConfigBytes {
			return fmt.Errorf("include %s is %d bytes, limit is %d", path, st.Size(), MaxConfigBytes)
		}
		if st.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("include %s is world-writable; refusing to load", path)
		}
		data, err := os.ReadFile(path) //nolint:gosec // operator supplied pattern
		if err != nil {
			return fmt.Errorf("include %s: %w", path, err)
		}
		var f Fragment
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		if err := decodeOne(data, &f); err != nil {
			return fmt.Errorf("include %s: %w", path, err)
		}
		c.RateLimits = append(c.RateLimits, f.RateLimits...)
		c.Upstreams = append(c.Upstreams, f.Upstreams...)
		c.Routes = append(c.Routes, f.Routes...)
		c.Filters = append(c.Filters, f.Filters...)
		c.IncludedFiles = append(c.IncludedFiles, path)
	}
	return nil
}
