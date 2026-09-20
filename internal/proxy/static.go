package proxy

import (
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// staticSite is a compiled routes[].static action. Files are opened
// through os.Root, so a path can never leave the root through "..",
// which CleanPath removed anyway, or through a symbolic link pointing
// outside, which the kernel refuses under openat2 semantics.
type staticSite struct {
	cfg  *config.RouteStatic
	root *os.Root
}

func openStatic(rc *config.RouteStatic) (*staticSite, error) {
	root, err := os.OpenRoot(rc.Root)
	if err != nil {
		return nil, err
	}
	return &staticSite{cfg: rc, root: root}, nil
}

func (ss *staticSite) close() {
	if ss != nil && ss.root != nil {
		_ = ss.root.Close()
	}
}

// static answers a request from the route's file tree. The request path
// after strip_prefix or rewrite_path selects the file; directories serve
// their index or, when enabled, a listing; a missing file falls back to
// `fallback` when set (single page applications) or answers 404.
func (s *Server) static(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute) {
	ss := cr.static
	cr.respOps.apply(rw.Header(), &tvars{r: r, st: st})
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		rw.Header().Set("Allow", "GET, HEAD")
		s.plainStatus(rw, r, http.StatusMethodNotAllowed)
		return
	}
	rel, _ := cr.outboundPath(st.path, "", r, st)
	rel = netutil.CleanPath(rel)
	if !ss.cfg.DotFiles && hasDotSegment(rel) {
		s.stats.StaticNotFound.Add(1)
		s.plainStatus(rw, r, http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(rel, "/")
	if name == "" {
		name = "."
	}
	f, info, err := ss.open(name)
	if err == nil && info.IsDir() {
		// Directories: canonical trailing slash, then the index file,
		// then a listing.
		if !strings.HasSuffix(r.URL.Path, "/") && rel != "/" {
			_ = f.Close()
			// The cleaned routing path, not the raw one: "//evil.example"
			// would otherwise become a protocol-relative Location.
			rw.Header().Set("Location", st.path+"/")
			s.plainStatus(rw, r, http.StatusMovedPermanently)
			return
		}
		if index := ss.cfg.IndexFile(); index != "" {
			if idx, iinfo, ierr := ss.open(path.Join(name, index)); ierr == nil && !iinfo.IsDir() {
				_ = f.Close()
				f, info, err = idx, iinfo, nil
			} else if ierr == nil {
				_ = idx.Close()
			}
		}
		if err == nil && info.IsDir() {
			if !ss.cfg.Listing {
				_ = f.Close()
				s.stats.StaticNotFound.Add(1)
				s.plainStatus(rw, r, http.StatusNotFound)
				return
			}
			entries, rerr := f.ReadDir(-1)
			_ = f.Close()
			if rerr != nil {
				s.plainStatus(rw, r, http.StatusInternalServerError)
				return
			}
			s.stats.StaticServed.Add(1)
			ss.listing(rw, r, rel, entries)
			return
		}
	}
	if err != nil && ss.cfg.Fallback != "" {
		f, info, err = ss.open(strings.TrimPrefix(ss.cfg.Fallback, "/"))
		if err == nil && info.IsDir() {
			_ = f.Close()
			err = fs.ErrNotExist
		}
	}
	if err != nil {
		// Missing, unreadable, escaping through a symbolic link, not a
		// regular file: all 404, so that the tree's shape leaks nothing.
		s.stats.StaticNotFound.Add(1)
		if !errors.Is(err, fs.ErrNotExist) {
			s.logs.Error.Debug("static file refused", "route", cr.cfg.Name, "path", rel, "error", err.Error())
		}
		s.plainStatus(rw, r, http.StatusNotFound)
		return
	}
	defer func() { _ = f.Close() }()
	if ss.cfg.MaxFileBytes > 0 && info.Size() > ss.cfg.MaxFileBytes {
		s.stats.StaticNotFound.Add(1)
		s.plainStatus(rw, r, http.StatusNotFound)
		return
	}
	h := rw.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	if ss.cfg.CacheControl != "" {
		h.Set("Cache-Control", ss.cfg.CacheControl)
	}
	h.Set("ETag", staticETag(info))
	if h.Get("Content-Type") == "" {
		if ct := staticContentType(info.Name()); ct != "" {
			h.Set("Content-Type", ct)
		}
	}
	s.stats.StaticServed.Add(1)
	// ServeContent handles ranges, conditional requests and HEAD; with a
	// content type already set it does not sniff.
	http.ServeContent(rw, r, info.Name(), info.ModTime(), f)
}

// open opens a name relative to the root and stats it.
func (ss *staticSite) open(name string) (*os.File, fs.FileInfo, error) {
	f, err := ss.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fs.ErrNotExist // devices, sockets, pipes
	}
	return f, info, nil
}

// hasDotSegment reports whether any segment starts with a dot (.git,
// .env, .htaccess); such files are never served unless dot_files is set.
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 1 && seg[0] == '.' {
			return true
		}
	}
	return false
}

// staticETag is a weak validator from size and modification time; it
// changes whenever the file does and costs no read.
func staticETag(info fs.FileInfo) string {
	return `W/"` + strconv.FormatInt(info.ModTime().UnixNano(), 36) + "-" + strconv.FormatInt(info.Size(), 36) + `"`
}

// staticContentType maps the extension; the types clients mishandle are
// listed explicitly so that a host's mime database cannot change them.
func staticContentType(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".json", ".map":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".wasm":
		return "application/wasm"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".xml":
		return "application/xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".pdf":
		return "application/pdf"
	case "":
		return "application/octet-stream"
	}
	return "" // ServeContent decides from the extension registry or sniffs
}

// listing writes a plain directory index. Names are escaped; hidden
// entries stay hidden unless dot_files is set.
func (ss *staticSite) listing(rw http.ResponseWriter, r *http.Request, rel string, entries []fs.DirEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	var b strings.Builder
	title := html.EscapeString(rel)
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of " + title + "</title></head><body><h1>Index of " + title + "</h1><ul>")
	if rel != "/" {
		b.WriteString(`<li><a href="../">../</a></li>`)
	}
	for _, e := range entries {
		name := e.Name()
		if !ss.cfg.DotFiles && strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			name += "/"
		}
		esc := html.EscapeString(name)
		size := ""
		if info, err := e.Info(); err == nil && !e.IsDir() {
			size = " <small>" + strconv.FormatInt(info.Size(), 10) + " bytes, " + info.ModTime().UTC().Format(time.RFC3339) + "</small>"
		}
		fmt.Fprintf(&b, `<li><a href="%s">%s</a>%s</li>`, esc, esc, size)
	}
	b.WriteString("</ul></body></html>\n")
	h := rw.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(b.Len()))
	rw.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = rw.Write([]byte(b.String()))
	}
}
