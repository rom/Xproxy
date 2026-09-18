package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// A second document in the stream is a configuration error, not something
	// to silently ignore.
	var extra interface{}
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("config contains more than one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(&c)
	if err := validate(&c, checkFiles); err != nil {
		return nil, err
	}
	return &c, nil
}
