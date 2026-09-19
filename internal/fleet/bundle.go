// Package fleet operates many proxies from one place: a controller
// serves each node the configuration bundle assigned to it and collects
// the nodes' status, and an agent inside every proxy fetches its bundle,
// applies it through the ordinary reload path and reports back.
//
// The transport is HTTPS with mutual TLS between the agent and the
// controller; a node is identified by the name in its certificate. A
// bundle is a set of files (the configuration and what it references,
// such as rule files) with a content digest; the agent long polls for a
// digest other than the one it applied, so a change reaches the fleet
// within seconds without the controller ever connecting to a node.
package fleet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// ConfigFile is the bundle entry the proxy loads as its configuration.
const ConfigFile = "xproxy.yaml"

const (
	maxBundleFiles = 256
	maxBundleBytes = 16 << 20
	maxPathDepth   = 8
)

// File is one bundle entry. Content is base64 in JSON.
type File struct {
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Content []byte `json:"content"`
}

// Bundle is the set of files assigned to a node.
type Bundle struct {
	Digest    string    `json:"digest"`
	Generated time.Time `json:"generated"`
	Files     []File    `json:"files"`
}

// Digest returns the content digest of files: SHA-256 over the sorted
// paths, modes and contents.
func Digest(files []File) string {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, f := range sorted {
		_, _ = fmt.Fprintf(h, "%s\x00%o\x00%d\x00", f.Path, f.Mode, len(f.Content))
		h.Write(f.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ValidPath reports whether p is a safe relative path for a bundle
// entry: clean, below the bundle directory, without special characters.
func ValidPath(p string) bool {
	if p == "" || len(p) > 255 || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return false
	}
	if path.Clean(p) != p || p == "." {
		return false
	}
	parts := strings.Split(p, "/")
	if len(parts) > maxPathDepth {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// Validate checks the bundle's shape and parses its configuration file
// without file existence checks (the referenced files live on the node,
// or in the bundle itself).
func (b *Bundle) Validate() error {
	if len(b.Files) == 0 {
		return errors.New("bundle is empty")
	}
	if len(b.Files) > maxBundleFiles {
		return fmt.Errorf("bundle has %d files, limit is %d", len(b.Files), maxBundleFiles)
	}
	total := 0
	seen := map[string]bool{}
	var cfgData []byte
	for _, f := range b.Files {
		if !ValidPath(f.Path) {
			return fmt.Errorf("bundle path %q is not allowed", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("bundle path %q repeated", f.Path)
		}
		seen[f.Path] = true
		if f.Mode&^0o777 != 0 || f.Mode&0o600 != 0o600 {
			return fmt.Errorf("bundle path %q: mode %o must be a permission set readable by the owner", f.Path, f.Mode)
		}
		total += len(f.Content)
		if f.Path == ConfigFile {
			cfgData = f.Content
		}
	}
	if total > maxBundleBytes {
		return fmt.Errorf("bundle is %d bytes, limit is %d", total, maxBundleBytes)
	}
	if cfgData == nil {
		return fmt.Errorf("bundle has no %s", ConfigFile)
	}
	if _, err := config.ParseWith(cfgData, false); err != nil {
		return fmt.Errorf("%s: %w", ConfigFile, err)
	}
	if want := Digest(b.Files); b.Digest != "" && b.Digest != want {
		return errors.New("bundle digest does not match its content")
	}
	return nil
}

// Read builds a bundle from directories; a later directory overrides
// the files of an earlier one, so a common directory can carry shared
// files and a node directory the node's own. Dot files and directories
// are skipped, everything else must be a regular file.
func Read(dirs ...string) (*Bundle, error) {
	files := map[string]File{}
	for _, dir := range dirs {
		root, err := os.OpenRoot(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == "." {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("%s: not a regular file", filepath.Join(dir, p))
			}
			if !ValidPath(p) {
				return fmt.Errorf("%s: path not allowed in a bundle", filepath.Join(dir, p))
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Size() > maxBundleBytes {
				return fmt.Errorf("%s: larger than %d bytes", filepath.Join(dir, p), maxBundleBytes)
			}
			data, err := fs.ReadFile(root.FS(), p)
			if err != nil {
				return err
			}
			files[p] = File{Path: p, Mode: uint32(info.Mode().Perm()) | 0o600, Content: data} //nolint:gosec // permission bits
			return nil
		})
		_ = root.Close()
		if err != nil {
			return nil, err
		}
	}
	b := &Bundle{Generated: time.Now().UTC().Truncate(time.Second)}
	for _, f := range files {
		b.Files = append(b.Files, f)
	}
	sort.Slice(b.Files, func(i, j int) bool { return b.Files[i].Path < b.Files[j].Path })
	b.Digest = Digest(b.Files)
	return b, nil
}

// Write places the bundle's files under dir, each written to a
// temporary file and renamed into place inside the directory (never
// following a link out of it), and returns a function that restores the
// previous contents, for a bundle the proxy then refuses to load. A file
// that existed before and is not in the bundle is left alone.
func Write(dir string, b *Bundle) (restore func() error, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	type previous struct {
		path    string
		existed bool
		mode    fs.FileMode
		data    []byte
	}
	prev := make([]previous, 0, len(b.Files))
	restore = func() error {
		r, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		defer func() { _ = r.Close() }()
		var first error
		for i := len(prev) - 1; i >= 0; i-- {
			p := prev[i]
			var err error
			if p.existed {
				err = writeFile(r, p.path, p.data, p.mode)
			} else {
				err = r.Remove(p.path)
			}
			if err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	for _, f := range b.Files {
		if !ValidPath(f.Path) {
			return restore, fmt.Errorf("bundle path %q is not allowed", f.Path)
		}
		p := previous{path: f.Path}
		if st, err := root.Stat(f.Path); err == nil {
			if !st.Mode().IsRegular() {
				return restore, fmt.Errorf("%s exists and is not a regular file", f.Path)
			}
			data, err := root.ReadFile(f.Path)
			if err != nil {
				return restore, err
			}
			p.existed, p.mode, p.data = true, st.Mode().Perm(), data
			if bytes.Equal(data, f.Content) && p.mode == fs.FileMode(f.Mode) {
				continue
			}
		}
		if d := path.Dir(f.Path); d != "." {
			if err := root.MkdirAll(d, 0o750); err != nil {
				return restore, err
			}
		}
		prev = append(prev, p)
		if err := writeFile(root, f.Path, f.Content, fs.FileMode(f.Mode)); err != nil {
			return restore, err
		}
	}
	return restore, nil
}

// writeFile writes data to name inside root through a temporary file.
func writeFile(root *os.Root, name string, data []byte, mode fs.FileMode) error {
	tmp := name + ".fleet-tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}
