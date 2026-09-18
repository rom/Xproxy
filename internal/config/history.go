package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// History keeps the configurations that were applied, one self-contained
// YAML file per generation, so that an operator can list, diff and roll
// back beyond the previous file.
type History struct {
	dir  string
	keep int
}

// Entry describes one recorded configuration.
type Entry struct {
	ID         string    `json:"id"`
	Generation uint64    `json:"generation"`
	Applied    time.Time `json:"applied"`
	Source     string    `json:"source"`
	Note       string    `json:"note"`
	Size       int64     `json:"size"`
}

// ErrNoHistory is returned when no history directory is configured.
var ErrNoHistory = errors.New("configuration history is not configured (management.history_dir)")

// NewHistory opens a history directory, creating it with mode 0700.
func NewHistory(dir string, keep int) (*History, error) {
	if dir == "" {
		return nil, ErrNoHistory
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	if keep <= 0 {
		keep = 20
	}
	return &History{dir: dir, keep: keep}, nil
}

const historyHeader = "# xproxy configuration history"

// Record stores cfg as generation gen and prunes the oldest entries
// beyond the keep count.
func (h *History) Record(cfg *Config, gen uint64, source, note string) (Entry, error) {
	if h == nil {
		return Entry{}, ErrNoHistory
	}
	body, err := Dump(cfg)
	if err != nil {
		return Entry{}, err
	}
	now := time.Now()
	e := Entry{ID: now.UTC().Format("20060102T150405.000000000") + "-gen" + strconv.FormatUint(gen, 10),
		Generation: gen, Applied: now, Source: source, Note: note}
	var sb strings.Builder
	sb.WriteString(historyHeader + "\n")
	fmt.Fprintf(&sb, "# id: %s\n# generation: %d\n# applied: %s\n# source: %s\n# note: %s\n",
		e.ID, gen, now.Format(time.RFC3339Nano), sanitizeLine(source), sanitizeLine(note))
	sb.Write(body)
	path := filepath.Join(h.dir, e.ID+".yaml")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return Entry{}, fmt.Errorf("history: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return Entry{}, fmt.Errorf("history: %w", err)
	}
	e.Size = int64(sb.Len())
	h.prune()
	return e, nil
}

func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// prune removes the oldest entries beyond keep.
func (h *History) prune() {
	entries, err := h.List()
	if err != nil {
		return
	}
	for i := h.keep; i < len(entries); i++ {
		_ = os.Remove(filepath.Join(h.dir, entries[i].ID+".yaml"))
	}
}

// List returns the entries, newest first.
func (h *History) List() ([]Entry, error) {
	if h == nil {
		return nil, ErrNoHistory
	}
	files, err := os.ReadDir(h.dir)
	if err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	out := []Entry{}
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		e, err := h.readHeader(name)
		if err != nil {
			continue // not one of ours
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func (h *History) readHeader(name string) (Entry, error) {
	path := filepath.Join(h.dir, name)
	f, err := os.Open(path) //nolint:gosec // inside the history directory, name from ReadDir
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	e := Entry{ID: strings.TrimSuffix(name, ".yaml"), Size: st.Size()}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			if line != historyHeader {
				return Entry{}, errors.New("not a history file")
			}
			first = false
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			break
		}
		key, val, ok := strings.Cut(strings.TrimPrefix(line, "# "), ": ")
		if !ok {
			continue
		}
		switch key {
		case "generation":
			e.Generation, _ = strconv.ParseUint(val, 10, 64)
		case "applied":
			e.Applied, _ = time.Parse(time.RFC3339Nano, val)
		case "source":
			e.Source = val
		case "note":
			e.Note = val
		}
	}
	if first {
		return Entry{}, errors.New("empty")
	}
	return e, nil
}

// Load parses one entry. The id must be an entry name, not a path.
func (h *History) Load(id string) (*Config, []byte, error) {
	if h == nil {
		return nil, nil, ErrNoHistory
	}
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return nil, nil, fmt.Errorf("history: bad id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(h.dir, id+".yaml")) //nolint:gosec // id validated above
	if err != nil {
		return nil, nil, fmt.Errorf("history: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("history %s: %w", id, err)
	}
	return c, data, nil
}
