package waf

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// plugin is one Core Rule Set plugin: up to three SecLang files named
// <name>-config.conf, <name>-before.conf and <name>-after.conf, found
// directly in crs.plugins_dir, in a subdirectory (a checked out plugin
// repository) or in that subdirectory's plugins/ folder.
type plugin struct {
	name string
	// config, before and after are file system paths ("" when absent).
	config, before, after string
	// dirs are the directories whose data files rules may reference.
	dirs []string
}

// pluginSuffixes are the CRS plugin file kinds in load order.
var pluginSuffixes = []string{"-config.conf", "-before.conf", "-after.conf"}

// loadPlugins finds the plugins under dir; when only is not empty, just
// those, and every listed one must exist.
func loadPlugins(dir string, only []string) ([]plugin, error) {
	found := map[string]*plugin{}
	dirSeen := map[string]bool{}
	add := func(file string) {
		base := filepath.Base(file)
		for _, suf := range pluginSuffixes {
			name, ok := strings.CutSuffix(base, suf)
			if !ok || name == "" {
				continue
			}
			p := found[name]
			if p == nil {
				p = &plugin{name: name}
				found[name] = p
			}
			switch suf {
			case "-config.conf":
				p.config = file
			case "-before.conf":
				p.before = file
			default:
				p.after = file
			}
			d := filepath.Dir(file)
			if !dirSeen[name+"\x00"+d] {
				dirSeen[name+"\x00"+d] = true
				p.dirs = append(p.dirs, d)
			}
			return
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("crs.plugins_dir: %w", err)
	}
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if !e.IsDir() {
			add(full)
			continue
		}
		for _, sub := range []string{full, filepath.Join(full, "plugins")} {
			files, err := os.ReadDir(sub)
			if err != nil {
				continue
			}
			for _, f := range files {
				if !f.IsDir() {
					add(filepath.Join(sub, f.Name()))
				}
			}
		}
	}
	out := make([]plugin, 0, len(found))
	if len(only) > 0 {
		for _, name := range only {
			p, ok := found[name]
			if !ok {
				return nil, fmt.Errorf("crs.plugins: no plugin %q under %s", name, dir)
			}
			out = append(out, *p)
		}
		return out, nil
	}
	for _, p := range found {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	if len(out) == 0 {
		return nil, fmt.Errorf("crs.plugins_dir: no *-config.conf, *-before.conf or *-after.conf files under %s", dir)
	}
	return out, nil
}

// pluginFS layers plugin directories over the rule set file system so
// that data files a plugin references (@pmFromFile, @ipMatchFromFile)
// resolve by their bare name or under plugins/, as they do in a CRS
// installation where the plugins folder sits next to rules/.
type pluginFS struct {
	base   fs.FS
	layers []fs.FS
}

func newPluginFS(base fs.FS, plugins []plugin) fs.FS {
	seen := map[string]bool{}
	var layers []fs.FS
	for _, p := range plugins {
		for _, d := range p.dirs {
			if seen[d] {
				continue
			}
			seen[d] = true
			layers = append(layers, os.DirFS(d))
		}
	}
	if len(layers) == 0 {
		return base
	}
	return &pluginFS{base: base, layers: layers}
}

func (u *pluginFS) Open(name string) (fs.File, error) {
	f, err := u.base.Open(name)
	if err == nil {
		return f, nil
	}
	names := []string{name}
	if rest, ok := strings.CutPrefix(name, "plugins/"); ok && fs.ValidPath(rest) {
		names = append(names, rest)
	}
	for _, l := range u.layers {
		for _, n := range names {
			if f, err := l.Open(n); err == nil {
				return f, nil
			}
		}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// Glob is implemented so that Include patterns keep working through
// the union; only the base is globbed, plugin files are inlined.
func (u *pluginFS) Glob(pattern string) ([]string, error) {
	if g, ok := u.base.(fs.GlobFS); ok {
		return g.Glob(pattern)
	}
	return fs.Glob(u.base, pattern)
}

// writePluginFiles appends the given plugin files to b.
func writePluginFiles(b *strings.Builder, plugins []plugin, pick func(p *plugin) string) error {
	for i := range plugins {
		f := pick(&plugins[i])
		if f == "" {
			continue
		}
		data, err := os.ReadFile(f) //nolint:gosec // operator configured plugin directory
		if err != nil {
			return fmt.Errorf("plugin %s: %w", plugins[i].name, err)
		}
		fmt.Fprintf(b, "\n# --- plugin %s: %s ---\n", plugins[i].name, path.Base(filepath.ToSlash(f)))
		b.Write(data)
		b.WriteString("\n")
	}
	return nil
}
