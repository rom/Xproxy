package assets

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// Persistence.
//
// An inventory that started empty on every restart would be an inventory that
// reported the whole estate as new every time the proxy was upgraded -- which
// is the fastest way to teach an operator to ignore it. So it is written out and
// read back, with the baseline in the same file: a frozen baseline that did not
// survive a restart would be worse than none, because the restart would silently
// turn the detection off.
//
// The file is JSON rather than anything cleverer for one reason: an operator who
// wants to know what the proxy thinks is on their network should be able to read
// it, diff two of them, and hand one to somebody else. That is most of the value
// of an inventory and it is worth more than a compact encoding.

// File is the on-disk form.
type File struct {
	// Version is the format. A file from a newer version is refused rather than
	// read optimistically: reading half of a record is how an inventory quietly
	// loses the evidence somebody needed.
	Version int `json:"version"`
	// Written is when it was saved, so that an operator reading a file can tell
	// whether the process that wrote it ever came back.
	Written time.Time `json:"written"`
	Assets  []*Asset  `json:"assets"`
	// Baseline is the frozen set, when there is one. It is a list rather than a
	// flag on each asset because the baseline is allowed to name devices the
	// inventory has since expired: an estate's baseline is what was there, not
	// what is still answering.
	Baseline []string `json:"baseline,omitempty"`
}

// FormatVersion is the current on-disk format.
const FormatVersion = 1

// MaxFileAssets bounds what a file may contain, so that a corrupted or hostile
// file cannot make the process allocate for as long as it has disk.
const MaxFileAssets = 1 << 20

// Save writes the inventory.
//
// It writes to a temporary file in the same directory and renames, so a reader
// sees either the old inventory or the new one and never half of either -- and a
// crash in the middle leaves the previous file intact.
func (inv *Inventory) Save(path string) error {
	if path == "" {
		return nil
	}
	f := File{Version: FormatVersion, Written: inv.now(), Assets: inv.List()}
	inv.mu.RLock()
	for id := range inv.baseline {
		f.Baseline = append(f.Baseline, id)
	}
	inv.mu.RUnlock()
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("asset inventory: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".assets-*")
	if err != nil {
		return fmt.Errorf("asset inventory: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	// An inventory names every device on a network and what each one is, which
	// is a reconnaissance document about somebody's estate. It is not
	// world-readable.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("asset inventory: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("asset inventory: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("asset inventory: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("asset inventory: %w", err)
	}
	return nil
}

// Load reads an inventory from a file and merges it into this one.
//
// Merging rather than replacing, because the process may already have seen
// something between starting and loading, and a device that is answering now is
// more interesting than the record of it from before the restart.
func (inv *Inventory) Load(path string) (int, error) {
	fh, err := os.Open(path) //nolint:gosec // an operator named this path
	if err != nil {
		if os.IsNotExist(err) {
			// No file yet is the ordinary first run, not a failure.
			return 0, nil
		}
		return 0, fmt.Errorf("asset inventory: %w", err)
	}
	defer func() { _ = fh.Close() }()
	return inv.Read(fh)
}

// Read reads an inventory from anywhere.
func (inv *Inventory) Read(r io.Reader) (int, error) {
	var f File
	dec := json.NewDecoder(io.LimitReader(r, 1<<30))
	if err := dec.Decode(&f); err != nil {
		return 0, fmt.Errorf("asset inventory: %w", err)
	}
	if f.Version != FormatVersion {
		// Refused rather than read optimistically: reading half of a record is
		// how an inventory quietly loses the evidence somebody needed.
		return 0, fmt.Errorf("asset inventory: format version %d, want %d", f.Version, FormatVersion)
	}
	if len(f.Assets) > MaxFileAssets {
		return 0, fmt.Errorf("asset inventory: %d assets in the file", len(f.Assets))
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	n := 0
	for _, a := range f.Assets {
		if a == nil || a.ID == "" {
			continue
		}
		if _, dup := inv.byID[a.ID]; dup {
			// Already seen since the restart. What is answering now wins.
			continue
		}
		if len(inv.byID) >= inv.max {
			break
		}
		c := a.clone()
		if c.Protos == nil {
			c.Protos = map[string]uint64{}
		}
		inv.byID[c.ID] = c
		if c.Hardware != "" {
			inv.byHW[c.Hardware] = c
		}
		for _, s := range c.Addrs {
			if ip, err := netip.ParseAddr(s); err == nil {
				if _, taken := inv.byAddr[ip]; !taken {
					inv.byAddr[ip] = c
				}
			}
		}
		n++
	}
	if f.Baseline != nil {
		if inv.baseline == nil {
			inv.baseline = map[string]bool{}
		}
		for _, id := range f.Baseline {
			inv.baseline[id] = true
		}
		// An asset already in the inventory that the restored baseline names is
		// no longer new: the baseline is the estate's own statement about what
		// belongs, and it outranks the fact that this process has not seen the
		// device before.
		for id, a := range inv.byID {
			if inv.baseline[id] {
				a.New = false
			}
		}
	}
	return n, nil
}
