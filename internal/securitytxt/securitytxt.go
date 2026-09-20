// Package securitytxt serves a virtual security.txt (RFC 9116) from the
// proxy, without a file on any origin and without a route.
//
// A security.txt tells a finder where to report a vulnerability. The
// document belongs to the organisation, not to the application, so
// putting it on every origin means every team that owns an origin has to
// remember it, and the one host that forgot is the one a finder tries.
// Here it is configuration: one document, or several, each answering for
// the hosts, the client networks and the listeners it names.
//
// The proxy answers /.well-known/security.txt and the legacy
// /security.txt before routing, so a document is served for a host that
// has no route at all — which is exactly the parked name a scanner
// reaches first. A request that matches no document is routed as usual,
// so an origin that serves its own file keeps doing so.
package securitytxt

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// Path is the well-known location (RFC 9116 section 3); LegacyPath is
// the top-level one the RFC keeps for compatibility.
const (
	Path       = "/.well-known/security.txt"
	LegacyPath = "/security.txt"
)

// ContentType is what RFC 9116 requires.
const ContentType = "text/plain; charset=utf-8"

// maxBody bounds a rendered or configured document.
const maxBody = 64 << 10

// Doc is one compiled document and the requests it answers.
type Doc struct {
	name string
	// hosts are exact lower-case names; suffixes are wildcard patterns
	// stored as ".example.com" and match one label or more.
	hosts     map[string]bool
	suffixes  []string
	hostRE    *regexp.Regexp
	clients   []netip.Prefix
	listeners map[string]bool
	body      []byte
	maxAge    int
}

// Name is the configured name, for the status view and the access log.
func (d *Doc) Name() string { return d.name }

// Body is the rendered document.
func (d *Doc) Body() []byte { return d.body }

// Set is every configured document, in configuration order: the first
// one that matches answers, so a document with no selectors placed last
// is the fallback for every other host.
type Set struct{ docs []*Doc }

// New compiles the configuration. It returns an error for anything
// validation should already have refused, so that a mistake cannot
// reach a served document.
func New(cfgs []config.SecurityTxt, now time.Time) (*Set, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}
	s := &Set{}
	for i := range cfgs {
		d, err := compile(&cfgs[i], now)
		if err != nil {
			return nil, fmt.Errorf("security_txt[%d] (%s): %w", i, cfgs[i].Name, err)
		}
		s.docs = append(s.docs, d)
	}
	return s, nil
}

// Docs lists the compiled documents in order.
func (s *Set) Docs() []*Doc {
	if s == nil {
		return nil
	}
	return s.docs
}

func compile(c *config.SecurityTxt, now time.Time) (*Doc, error) {
	d := &Doc{name: c.Name, hosts: map[string]bool{}, maxAge: int(c.CacheFor.D().Seconds())}
	for _, h := range c.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		switch {
		case h == "":
			return nil, errors.New("empty host")
		case strings.HasPrefix(h, "*."):
			// "*.example.com" matches a.example.com and a.b.example.com,
			// and not example.com itself, which is the same rule the
			// router uses for a wildcard host.
			d.suffixes = append(d.suffixes, h[1:])
		default:
			d.hosts[h] = true
		}
	}
	if c.HostRegex != "" {
		re, err := regexp.Compile(c.HostRegex)
		if err != nil {
			return nil, fmt.Errorf("host_regex: %w", err)
		}
		d.hostRE = re
	}
	for _, cidr := range c.ClientCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("client_cidrs: %q is not a CIDR", cidr)
		}
		d.clients = append(d.clients, p.Masked())
	}
	if len(c.Listeners) > 0 {
		d.listeners = map[string]bool{}
		for _, l := range c.Listeners {
			d.listeners[l] = true
		}
	}
	body, err := render(c, now)
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("document is %d bytes, over the %d byte bound", len(body), maxBody)
	}
	d.body = body
	return d, nil
}

// Match returns the first document that answers for this request, or
// nil when none does and the request should be routed as usual.
func (s *Set) Match(host string, client netip.Addr, listener string) *Doc {
	if s == nil {
		return nil
	}
	host = strings.ToLower(host)
	for _, d := range s.docs {
		if d.matches(host, client, listener) {
			return d
		}
	}
	return nil
}

func (d *Doc) matches(host string, client netip.Addr, listener string) bool {
	if d.listeners != nil && !d.listeners[listener] {
		return false
	}
	if len(d.clients) > 0 && !netutil.Contains(d.clients, client) {
		return false
	}
	// Host selectors are a union: a document with several kinds answers
	// for a name any one of them names.
	if len(d.hosts) == 0 && len(d.suffixes) == 0 && d.hostRE == nil {
		return true
	}
	if d.hosts[host] {
		return true
	}
	for _, suf := range d.suffixes {
		if strings.HasSuffix(host, suf) && len(host) > len(suf) {
			return true
		}
	}
	return d.hostRE != nil && d.hostRE.MatchString(host)
}

// Serve writes the document. Only GET and HEAD are answered; anything
// else gets 405, because a security.txt is a file and nothing else.
func (d *Doc) Serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ContentType)
	h.Set("Content-Length", fmt.Sprint(len(d.body)))
	h.Set("X-Content-Type-Options", "nosniff")
	if d.maxAge > 0 {
		h.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", d.maxAge))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(d.body)
}

// render builds the document text: the operator's own body when there
// is one, otherwise the fields in the order RFC 9116 lists them.
func render(c *config.SecurityTxt, now time.Time) ([]byte, error) {
	if c.Body != "" {
		return []byte(normalizeEOL(c.Body)), nil
	}
	if len(c.Contact) == 0 {
		return nil, errors.New("contact is required")
	}
	exp, err := expiry(c, now)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	if c.Comment != "" {
		for _, line := range strings.Split(strings.TrimSuffix(normalizeEOL(c.Comment), "\n"), "\n") {
			if line == "" {
				b.WriteString("#\n")
				continue
			}
			b.WriteString("# " + line + "\n")
		}
	}
	// Contact first and Expires straight after: a finder reads the top
	// of the file, and a parser needs both.
	writeField(&b, "Contact", c.Contact)
	b.WriteString("Expires: " + exp.UTC().Format(time.RFC3339) + "\n")
	writeField(&b, "Encryption", c.Encryption)
	writeField(&b, "Acknowledgments", c.Acknowledgments)
	if len(c.PreferredLanguages) > 0 {
		// One field, comma separated (RFC 9116 section 2.5.8).
		b.WriteString("Preferred-Languages: " + strings.Join(c.PreferredLanguages, ", ") + "\n")
	}
	writeField(&b, "Canonical", c.Canonical)
	writeField(&b, "Policy", c.Policy)
	writeField(&b, "Hiring", c.Hiring)
	writeField(&b, "CSAF", c.CSAF)
	for _, e := range sortedExtra(c.Extra) {
		writeField(&b, e.name, e.values)
	}
	return []byte(b.String()), nil
}

// expiry is the Expires value: the configured instant, or valid_for
// from now, which a reload refreshes.
func expiry(c *config.SecurityTxt, now time.Time) (time.Time, error) {
	if c.Expires != "" {
		t, err := time.Parse(time.RFC3339, c.Expires)
		if err != nil {
			return time.Time{}, fmt.Errorf("expires: %q is not an RFC 3339 time", c.Expires)
		}
		return t, nil
	}
	return now.Add(c.ValidFor.D()), nil
}

func writeField(b *strings.Builder, name string, values []string) {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			b.WriteString(name + ": " + v + "\n")
		}
	}
}

type extraField struct {
	name   string
	values []string
}

// sortedExtra orders the operator's own fields by name, so the rendered
// document is the same on every node of a cluster.
func sortedExtra(m map[string][]string) []extraField {
	out := make([]extraField, 0, len(m))
	for k, v := range m {
		out = append(out, extraField{name: k, values: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// normalizeEOL makes every line ending a single LF. RFC 9116 allows CRLF
// and LF; a file edited on one platform and served from another
// otherwise carries whichever the editor left, and a lone CR is not a
// line ending at all.
func normalizeEOL(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}
