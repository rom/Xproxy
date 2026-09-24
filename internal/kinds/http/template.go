package http

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/expr"
	"github.com/rom/xproxy/internal/tmpl"
)

// tvars resolves template variables for one request. status and reason
// are set for error pages; captures come from the route's rewrite or
// path regular expression match.
type tvars struct {
	r      *http.Request
	st     *reqState
	rt     *runtime // for lookups a when expression needs before the route is known
	status int
	reason string
}

func (v *tvars) Resolve(name, arg string) (string, bool) {
	r, st := v.r, v.st
	switch name {
	case "client_ip":
		if st != nil && st.clientIP.IsValid() {
			return st.clientIP.String(), true
		}
	case "request_id":
		if st != nil {
			return st.id, true
		}
	case "host":
		if st != nil && st.host != "" {
			return st.host, true
		}
		if r != nil {
			h, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				h = r.Host
			}
			return h, true
		}
	case "path":
		if r != nil {
			return r.URL.Path, true
		}
	case "raw_query":
		if r != nil {
			return r.URL.RawQuery, true
		}
	case "method":
		if r != nil {
			return r.Method, true
		}
	case "scheme":
		if r != nil {
			if r.TLS != nil {
				return "https", true
			}
			return "http", true
		}
	case "route":
		if st != nil {
			return st.route, true
		}
	case "upstream":
		if st != nil {
			return st.upstream, true
		}
	case "tenant":
		if st != nil && st.cr != nil {
			return st.cr.cfg.Tenant, true
		}
	case "country":
		if st != nil {
			if st.country == "" && v.rt != nil && v.rt.geo != nil && st.clientIP.IsValid() {
				// Asked before the route's own lookup (a when expression):
				// resolve now, the handler reuses the value.
				st.country = v.rt.geo.Country(st.clientIP)
			}
			return st.country, st.country != ""
		}
	case "ja4":
		if st != nil {
			return st.ja4, st.ja4 != ""
		}
	case "tls_version":
		if r != nil && r.TLS != nil {
			return tls.VersionName(r.TLS.Version), true
		}
	case "tls_cipher":
		if r != nil && r.TLS != nil {
			return tls.CipherSuiteName(r.TLS.CipherSuite), true
		}
	case "status":
		if v.status != 0 {
			return strconv.Itoa(v.status), true
		}
	case "status_text":
		if v.status != 0 {
			return http.StatusText(v.status), true
		}
	case "reason":
		return v.reason, v.reason != ""
	case "time":
		return time.Now().UTC().Format(time.RFC3339), true
	case "date":
		return time.Now().UTC().Format("2006-01-02"), true
	case "hour":
		return strconv.Itoa(time.Now().UTC().Hour()), true
	case "minute":
		return strconv.Itoa(time.Now().UTC().Minute()), true
	case "weekday":
		return time.Now().UTC().Weekday().String()[:3], true
	case "header":
		if r != nil {
			val := r.Header.Get(arg)
			return val, val != ""
		}
	case "cookie":
		if r != nil {
			if c, err := r.Cookie(arg); err == nil {
				return c.Value, true
			}
		}
	case "query":
		if r != nil {
			vals := r.URL.Query()[arg]
			if len(vals) > 0 {
				return vals[0], true
			}
		}
	case "cert":
		if r != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			return certField(r.TLS.PeerCertificates[0], arg)
		}
	default:
		if st != nil {
			return st.capture(name)
		}
	}
	return "", false
}

// capture returns a numeric or named group of the request's regular
// expression match.
func (st *reqState) capture(name string) (string, bool) {
	if len(st.captures) == 0 {
		return "", false
	}
	if n, err := strconv.Atoi(name); err == nil {
		if n >= 0 && n < len(st.captures) {
			return st.captures[n], true
		}
		return "", false
	}
	for i, cn := range st.captureNames {
		if cn == name && i < len(st.captures) {
			return st.captures[i], true
		}
	}
	return "", false
}

// headerOp is one templated set or add.
type headerOp struct {
	name string
	t    *tmpl.Template
}

// compiledOps are a route's header operations with parsed templates.
type compiledOps struct {
	remove []string
	set    []headerOp
	add    []headerOp
	// strip names the headers whose templates carry client certificate
	// fields; a client supplied copy is removed before the operations run,
	// whether or not `when` admits them, so a request without a
	// certificate cannot present its own identity value.
	strip  []string
	static bool
	when   *expr.Expr // nil applies always
}

// compileOps parses the templates of h; captures names the groups the
// route's regular expressions define.
func compileOps(h config.HeaderOps, captures []string) (compiledOps, error) {
	out := compiledOps{remove: h.Remove, static: true}
	if h.When != "" {
		w, err := expr.Parse(h.When, config.ExprVars(), captures...)
		if err != nil {
			return out, err
		}
		out.when = w
	}
	for k, v := range h.Set {
		t, err := tmpl.Parse(v, captures...)
		if err != nil {
			return out, err
		}
		out.set = append(out.set, headerOp{name: k, t: t})
		out.static = out.static && t.Static()
		if usesCert(t) {
			out.strip = append(out.strip, k)
		}
	}
	for k, v := range h.Add {
		t, err := tmpl.Parse(v, captures...)
		if err != nil {
			return out, err
		}
		out.add = append(out.add, headerOp{name: k, t: t})
		out.static = out.static && t.Static()
		if usesCert(t) {
			out.strip = append(out.strip, k)
		}
	}
	return out, nil
}

// usesCert reports whether t references a ${cert:...} field.
func usesCert(t *tmpl.Template) bool {
	for _, n := range t.Names() {
		if n == "cert" {
			return true
		}
	}
	return false
}

// apply performs the operations on h with v for the templates (nil v
// renders variables empty).
func (o *compiledOps) apply(h http.Header, v *tvars) {
	for _, k := range o.strip {
		h.Del(k)
	}
	if o.when != nil {
		if v == nil || !o.when.Eval(v) {
			return
		}
	}
	for _, k := range o.remove {
		h.Del(k)
	}
	var r tmpl.Resolver
	if v != nil {
		r = v
	}
	for _, op := range o.set {
		h.Set(op.name, op.t.Expand(r))
	}
	for _, op := range o.add {
		h.Add(op.name, op.t.Expand(r))
	}
}

// certField returns one field of the client certificate for ${cert:...}
// and cert(...): cn, subject, issuer (RFC 2253), serial (hex),
// fingerprint (SHA-256 hex of the DER), sans (DNS names, addresses,
// emails and URIs, comma separated), not_after (RFC 3339), client_cert
// (RFC 9440's Structured Fields Byte Sequence), xfcc (an Envoy style
// X-Forwarded-Client-Cert value) or pem (the URL encoded PEM).
func certField(c *x509.Certificate, field string) (string, bool) {
	switch field {
	case "cn":
		return c.Subject.CommonName, c.Subject.CommonName != ""
	case "subject":
		return c.Subject.String(), true
	case "issuer":
		return c.Issuer.String(), true
	case "serial":
		if c.SerialNumber == nil {
			return "", false
		}
		return c.SerialNumber.Text(16), true
	case "fingerprint":
		sum := sha256.Sum256(c.Raw)
		return hex.EncodeToString(sum[:]), true
	case "sans":
		sans := certSANs(c)
		return strings.Join(sans, ","), len(sans) > 0
	case "not_after":
		return c.NotAfter.UTC().Format(time.RFC3339), true
	case "pem":
		return url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))), true
	case "client_cert":
		// RFC 9440's Client-Cert: the leaf in a Structured Fields Byte
		// Sequence, which is standard base64 between colons.
		return sfBinary(c.Raw), true
	case "xfcc":
		sum := sha256.Sum256(c.Raw)
		parts := []string{"Hash=" + hex.EncodeToString(sum[:]), "Subject=" + strconv.Quote(c.Subject.String())}
		for _, u := range c.URIs {
			parts = append(parts, "URI="+u.String())
		}
		for _, d := range c.DNSNames {
			parts = append(parts, "DNS="+d)
		}
		return strings.Join(parts, ";"), true
	}
	return "", false
}

func certSANs(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs))
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, c.EmailAddresses...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}
