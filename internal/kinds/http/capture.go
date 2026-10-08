package http

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/capture"
)

// The capture hook. The proxy terminates TLS, so what a capture on the
// wire in front of it holds is ciphertext; what this writes is the
// exchange as the proxy parsed and answered it, which is the view a
// wire capture cannot produce. Nothing here runs unless a capture is
// recording and a rule wants this exchange, so the cost on an ordinary
// request is one atomic load.

// captureState is the per-request bookkeeping, built only for a request
// a rule wants.
type captureState struct {
	reqBody  *boundedTee
	respBody *boundedTee
}

// boundedTee keeps the first max bytes of what passes through it and
// remembers that it stopped.
type boundedTee struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedTee) add(p []byte) {
	if b == nil || b.max <= 0 {
		return
	}
	room := b.max - b.buf.Len()
	if room <= 0 {
		b.truncated = b.truncated || len(p) > 0
		return
	}
	if len(p) > room {
		b.buf.Write(p[:room])
		b.truncated = true
		return
	}
	b.buf.Write(p)
}

// beginCapture decides whether this request is captured and prepares
// the body buffers when it is. It is called once the route is known,
// which is the earliest point a rule on routes can be answered.
func (s *engine) beginCapture(r *http.Request, st *reqState) {
	c := s.host.Capture()
	if c == nil || !c.Active() {
		return
	}
	// The hook ran, so whatever it decided is the decision: a request
	// that gets here and is not wanted must not be offered again at the
	// end (see finishCapture).
	st.pcapAsked = true
	if !c.Wants(listenerName(st), st.host, st.route, r.Method, st.path, st.clientIP) {
		return
	}
	cs := &captureState{}
	if n := c.MaxBody(); n > 0 {
		cs.reqBody = &boundedTee{max: n}
		cs.respBody = &boundedTee{max: n}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &captureBody{ReadCloser: r.Body, tee: cs.reqBody}
		}
	}
	st.pcap = cs
}

// captureBody copies what is read into the tee. A body the handler
// never reads is a body the upstream never saw, so the capture is of
// what happened rather than of what was available.
type captureBody struct {
	io.ReadCloser
	tee *boundedTee
}

func (b *captureBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.tee.add(p[:n])
	}
	return n, err
}

// finishCapture writes the exchange. It runs from the access-log defer,
// so it sees the status the client actually got and the deny reason.
func (s *engine) finishCapture(rw *responseWriter, r *http.Request, st *reqState) {
	c := s.host.Capture()
	if c == nil {
		return
	}
	cs := st.pcap
	if cs == nil {
		// A request refused before the hook — a ban, the maintenance
		// gate, a bad host, the concurrency ceiling — never reached it,
		// and those are exactly the refusals a `denied` rule is written
		// for. Offer the exchange to the rules here instead. There are
		// no bodies: nothing read the request, and the refusal is its
		// own answer.
		if st.pcapAsked || !c.Active() {
			return
		}
	}
	redact := c.Redact()
	e := &capture.Exchange{
		Start:     st.start,
		Kind:      "http",
		Listener:  listenerName(st),
		Client:    addrPort(st.clientIP, r.RemoteAddr),
		Server:    serverAddrPort(r),
		RequestID: st.id,
		Route:     st.route,
		Host:      st.host,
		Method:    r.Method,
		Path:      st.path,
		Status:    rw.Status(),
		Denied:    st.denied,
	}
	e.Request = serialiseRequest(r, redact)
	if cs != nil && cs.reqBody != nil && cs.reqBody.buf.Len() > 0 {
		e.Request = append(e.Request, cs.reqBody.buf.Bytes()...)
		e.RequestTruncated = cs.reqBody.truncated
	}
	e.Response = serialiseResponse(rw, r, redact)
	if cs != nil && cs.respBody != nil && cs.respBody.buf.Len() > 0 {
		e.Response = append(e.Response, cs.respBody.buf.Bytes()...)
		e.ResponseTruncated = cs.respBody.truncated
	}
	c.Write(e)
}

// listenerName is the listener this request arrived on, for the capture rules
// that select on it. A request that was refused before routing still has one.
func listenerName(st *reqState) string {
	if st == nil || st.ln == nil {
		return ""
	}
	return st.ln.Name
}

// serialiseRequest renders the request head the way it reached the
// proxy: the request line, the Host, then the headers in name order so
// two captures of the same request compare.
func serialiseRequest(r *http.Request, redact []string) []byte {
	var b bytes.Buffer
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	uri := r.RequestURI
	if uri == "" && r.URL != nil {
		uri = r.URL.RequestURI()
	}
	fmt.Fprintf(&b, "%s %s %s\r\n", r.Method, uri, proto)
	if r.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", headerValue(r.Host))
	}
	writeHeaders(&b, r.Header, redact)
	b.WriteString("\r\n")
	return b.Bytes()
}

// serialiseResponse renders the response head the proxy wrote.
func serialiseResponse(rw *responseWriter, r *http.Request, redact []string) []byte {
	var b bytes.Buffer
	status := rw.Status()
	if status == 0 {
		// Nothing was written: the client went away, or the connection
		// was taken over. Say so rather than inventing a 200.
		b.WriteString("HTTP/1.1 000 No Response\r\n\r\n")
		return b.Bytes()
	}
	proto := r.Proto
	if proto == "" || !strings.HasPrefix(proto, "HTTP/1") {
		// A capture is read by an HTTP dissector, which wants a status
		// line; HTTP/2 and HTTP/3 have none on the wire.
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&b, "%s %d %s\r\n", proto, status, http.StatusText(status))
	writeHeaders(&b, rw.Header(), redact)
	b.WriteString("\r\n")
	return b.Bytes()
}

func writeHeaders(b *bytes.Buffer, h http.Header, redact []string) {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if isRedacted(k, redact) {
			fmt.Fprintf(b, "%s: %s\r\n", k, capture.Redacted)
			continue
		}
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, headerValue(v))
		}
	}
}

func isRedacted(name string, redact []string) bool {
	for _, r := range redact {
		if strings.EqualFold(name, r) {
			return true
		}
	}
	return false
}

// headerValue keeps a value on one line. Every one of these came from a
// request, and a value carrying a newline would otherwise write a
// header of the attacker's choosing into the capture file, where the
// next reader's tooling parses it.
func headerValue(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '\r' || v[i] == '\n' {
			out = append(out, ' ')
			continue
		}
		out = append(out, v[i])
	}
	return string(out)
}

// addrPort pairs the resolved client address with the port the
// connection came from, so two clients behind one address are two
// conversations in the file rather than one interleaved mess.
func addrPort(ip netip.Addr, remote string) netip.AddrPort {
	var port uint16
	if _, p, err := net.SplitHostPort(remote); err == nil {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	if !ip.IsValid() {
		ip = netip.AddrFrom4([4]byte{0, 0, 0, 0})
	}
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// serverAddrPort is the listener the request arrived on, when the
// server put it in the context, and a placeholder otherwise.
func serverAddrPort(r *http.Request) netip.AddrPort {
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ap, err := netip.ParseAddrPort(la.String()); err == nil {
			return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0)
}
