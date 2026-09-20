package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/tmpl"
)

// maxErrorPage bounds one error document.
const maxErrorPage = 1 << 20

// errorPages are a loaded error_pages section.
type errorPages struct {
	pages     map[string]*tmpl.Template
	ctype     string
	json      bool
	intercept map[int]bool
}

// loadErrorPages reads and parses the documents of cfg.
func loadErrorPages(cfg *config.ErrorPages) (*errorPages, error) {
	if cfg == nil {
		return nil, nil
	}
	e := &errorPages{pages: map[string]*tmpl.Template{}, ctype: cfg.ContentType, json: cfg.JSON == nil || *cfg.JSON, intercept: map[int]bool{}}
	for k, f := range cfg.Pages {
		path := f
		if !strings.HasPrefix(f, "/") {
			path = filepath.Join(cfg.Dir, f)
		}
		fh, err := os.Open(path) //nolint:gosec // operator configured document
		if err != nil {
			return nil, fmt.Errorf("error_pages.%s: %w", k, err)
		}
		data, err := io.ReadAll(io.LimitReader(fh, maxErrorPage+1))
		_ = fh.Close()
		if err != nil {
			return nil, fmt.Errorf("error_pages.%s: %w", k, err)
		}
		if len(data) > maxErrorPage {
			return nil, fmt.Errorf("error_pages.%s: %s exceeds 1 MiB", k, path)
		}
		t, err := tmpl.ParseLenient(string(data))
		if err != nil {
			return nil, fmt.Errorf("error_pages.%s: %w", k, err)
		}
		e.pages[k] = t
	}
	for _, st := range cfg.InterceptUpstream {
		e.intercept[st] = true
	}
	return e, nil
}

// lookup finds the document for a status: exact, class, default.
func (e *errorPages) lookup(status int) *tmpl.Template {
	if e == nil {
		return nil
	}
	if t := e.pages[strconv.Itoa(status)]; t != nil {
		return t
	}
	if t := e.pages[strconv.Itoa(status/100)+"xx"]; t != nil {
		return t
	}
	return e.pages["default"]
}

// wantsJSON reports whether the client prefers JSON over HTML.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	j, h := strings.Index(accept, "application/json"), strings.Index(accept, "text/html")
	return j >= 0 && (h < 0 || j < h)
}

// errorPagesFor returns the pages that apply to the request: the route's,
// then the server's.
func (s *Server) errorPagesFor(rw *responseWriter) *errorPages {
	if rw.st != nil && rw.st.cr != nil && rw.st.cr.errPages != nil {
		return rw.st.cr.errPages
	}
	if rt := s.rt.Load(); rt != nil {
		return rt.errorPages
	}
	return nil
}

// jsonError is the JSON form of an error response.
type jsonError struct {
	Status    int    `json:"status"`
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// render produces the body and content type for status, or false when
// the pages have nothing for it.
func (e *errorPages) render(r *http.Request, st *reqState, status int, reason string) ([]byte, string, bool) {
	if e == nil {
		return nil, "", false
	}
	if e.json && wantsJSON(r) {
		je := jsonError{Status: status, Error: http.StatusText(status)}
		if st != nil {
			je.RequestID = st.id
		}
		b, _ := json.Marshal(je)
		return append(b, '\n'), "application/json", true
	}
	t := e.lookup(status)
	if t == nil {
		return nil, "", false
	}
	var v tmpl.Resolver = &tvars{r: r, st: st, status: status, reason: reason}
	if strings.HasPrefix(strings.ToLower(e.ctype), "text/html") {
		// Request-derived values (path, query, headers, cookies) land in a
		// browser-rendered page: escape them so a crafted URL cannot inject
		// markup into the error page (reflected XSS).
		v = htmlEscaping{v}
	}
	return []byte(t.Expand(v)), e.ctype, true
}

// htmlEscaping wraps a resolver so every expanded value is HTML-escaped.
type htmlEscaping struct{ r tmpl.Resolver }

func (h htmlEscaping) Resolve(name, arg string) (string, bool) {
	v, ok := h.r.Resolve(name, arg)
	return html.EscapeString(v), ok
}

// interceptBody replaces an upstream response body with the error page
// for its status.
func (e *errorPages) interceptBody(resp *http.Response, r *http.Request, st *reqState) {
	if e == nil || !e.intercept[resp.StatusCode] || st.grpc {
		return
	}
	body, ctype, ok := e.render(r, st, resp.StatusCode, "upstream")
	if !ok {
		return
	}
	_ = resp.Body.Close()
	if r.Method == http.MethodHead {
		body = nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", ctype)
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("Cache-Control", "no-store")
	for _, h := range []string{"Content-Encoding", "ETag", "Last-Modified", "Transfer-Encoding"} {
		resp.Header.Del(h)
	}
	resp.TransferEncoding = nil
}
