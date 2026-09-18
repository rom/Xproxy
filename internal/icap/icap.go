// Package icap is an ICAP client (RFC 3507) used to hand requests and
// responses to external scanners such as anti-virus or data loss
// prevention engines (docs/AMR.md, AMR-015 and AMR-028).
//
// Supported: OPTIONS (preview size, ISTag, 204 support), REQMOD and
// RESPMOD with preview and "204 No Content", modified requests, replacement
// responses (block pages), a bounded connection pool per service, plain
// TCP and TLS transports, and per-service fail-open or fail-closed policy.
// Every read is bounded in size and time.
package icap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Limits on ICAP responses.
const (
	maxICAPHeaderBytes = 64 << 10
	maxHTTPHeaderBytes = 64 << 10
	maxReplacementBody = 4 << 20
)

// Verdict is the outcome of a modification request.
type Verdict struct {
	// Kind is one of Unmodified, ModifiedRequest, Replaced, ModifiedResponse.
	Kind Kind
	// Request is the modified request headers and body (ModifiedRequest).
	Request *http.Request
	// Response is the replacement (Replaced) or modified response
	// (ModifiedResponse), with a bounded body already read.
	Response *http.Response
	// ISTag and Status come from the ICAP response for logging.
	ISTag  string
	Status int
}

// Kind classifies a verdict.
type Kind int

// pooledConn keeps the buffered reader with its connection so that bytes
// read ahead (for example the CRLF that ends a chunked body) are never lost
// between exchanges.
type pooledConn struct {
	net.Conn
	r *bufio.Reader
}

// Verdict kinds.
const (
	Unmodified Kind = iota
	ModifiedRequest
	Replaced
	ModifiedResponse
)

func (k Kind) String() string {
	switch k {
	case ModifiedRequest:
		return "modified_request"
	case Replaced:
		return "replaced"
	case ModifiedResponse:
		return "modified_response"
	default:
		return "unmodified"
	}
}

// Service is one ICAP endpoint with its pool.
type Service struct {
	cfg      config.ICAPService
	u        *url.URL
	host     string
	tlsCfg   *tls.Config
	pool     chan *pooledConn
	preview  atomic.Int64 // -1 unknown/none
	allow204 atomic.Bool
	istag    atomic.Pointer[string]
	ok       atomic.Bool

	Requests, Unmodifieds, Modifieds, Replacements, Errors, Bypassed atomic.Uint64
}

// NewService prepares a service and probes it with OPTIONS. A failed probe
// is not fatal: the service is retried on use and reported in status.
func NewService(cfg config.ICAPService) (*Service, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("icap %s: %w", cfg.Name, err)
	}
	s := &Service{cfg: cfg, u: u, host: u.Host, pool: make(chan *pooledConn, cfg.MaxConns)}
	s.preview.Store(-1)
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		port := "1344"
		if u.Scheme == "icaps" {
			port = "11344"
		}
		s.host = net.JoinHostPort(u.Host, port)
	}
	if u.Scheme == "icaps" {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if cfg.TLS != nil {
			if cfg.TLS.ServerName != "" {
				tc.ServerName = cfg.TLS.ServerName
			}
			if cfg.TLS.CAFile != "" {
				pem, err := os.ReadFile(cfg.TLS.CAFile) //nolint:gosec // validated configuration path
				if err != nil {
					return nil, fmt.Errorf("icap %s ca: %w", cfg.Name, err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("icap %s: ca file contains no certificates", cfg.Name)
				}
				tc.RootCAs = pool
			}
		}
		s.tlsCfg = tc
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout.D())
	defer cancel()
	_ = s.Options(ctx)
	return s, nil
}

// Name returns the service name.
func (s *Service) Name() string { return s.cfg.Name }

// Status is the management view of a service.
type Status struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	Reachable    bool   `json:"reachable"`
	ISTag        string `json:"istag,omitempty"`
	Preview      int64  `json:"preview"`
	Allow204     bool   `json:"allow_204"`
	Requests     uint64 `json:"requests"`
	Unmodified   uint64 `json:"unmodified"`
	Modified     uint64 `json:"modified"`
	Replacements uint64 `json:"replacements"`
	Errors       uint64 `json:"errors"`
	Bypassed     uint64 `json:"bypassed"`
}

// Status returns counters.
func (s *Service) Status() Status {
	st := Status{Name: s.cfg.Name, URL: s.cfg.URL, Reachable: s.ok.Load(), Preview: s.preview.Load(), Allow204: s.allow204.Load(),
		Requests: s.Requests.Load(), Unmodified: s.Unmodifieds.Load(), Modified: s.Modifieds.Load(), Replacements: s.Replacements.Load(),
		Errors: s.Errors.Load(), Bypassed: s.Bypassed.Load()}
	if t := s.istag.Load(); t != nil {
		st.ISTag = *t
	}
	return st
}

// Close drops pooled connections.
func (s *Service) Close() {
	for {
		select {
		case c := <-s.pool:
			_ = c.Close()
		default:
			return
		}
	}
}

func (s *Service) dial(ctx context.Context) (*pooledConn, error) {
	select {
	case c := <-s.pool:
		return c, nil
	default:
	}
	d := &net.Dialer{Timeout: s.cfg.ConnectTimeout.D()}
	var c net.Conn
	var err error
	if s.tlsCfg != nil {
		td := &tls.Dialer{NetDialer: d, Config: s.tlsCfg}
		c, err = td.DialContext(ctx, "tcp", s.host)
	} else {
		c, err = d.DialContext(ctx, "tcp", s.host)
	}
	if err != nil {
		return nil, err
	}
	return &pooledConn{Conn: c, r: bufio.NewReaderSize(c, 64<<10)}, nil
}

func (s *Service) release(c *pooledConn, reuse bool) {
	if !reuse {
		_ = c.Close()
		return
	}
	select {
	case s.pool <- c:
	default:
		_ = c.Close()
	}
}

// Options probes the service.
func (s *Service) Options(ctx context.Context) error {
	c, err := s.dial(ctx)
	if err != nil {
		s.ok.Store(false)
		return err
	}
	deadline := time.Now().Add(s.cfg.Timeout.D())
	_ = c.SetDeadline(deadline)
	var b bytes.Buffer
	fmt.Fprintf(&b, "OPTIONS %s ICAP/1.0\r\nHost: %s\r\nUser-Agent: xproxy-icap/1\r\nEncapsulated: null-body=0\r\n\r\n", s.u.String(), s.u.Host)
	if _, err := c.Write(b.Bytes()); err != nil {
		s.release(c, false)
		s.ok.Store(false)
		return err
	}
	r := c.r
	status, hdr, err := readICAPHeader(r)
	if err != nil {
		s.release(c, false)
		s.ok.Store(false)
		return err
	}
	if status != 200 {
		s.release(c, false)
		s.ok.Store(false)
		return fmt.Errorf("icap options: status %d", status)
	}
	if v := hdr.Get("Preview"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			s.preview.Store(n)
		}
	} else {
		s.preview.Store(-1)
	}
	s.allow204.Store(strings.Contains(hdr.Get("Allow"), "204"))
	if t := hdr.Get("ISTag"); t != "" {
		s.istag.Store(&t)
	}
	// OPTIONS may carry an opt-body; drain if declared.
	if enc := hdr.Get("Encapsulated"); strings.Contains(enc, "opt-body") {
		_, _ = io.Copy(io.Discard, io.LimitReader(httputil.NewChunkedReader(r), 64<<10))
		for i := 0; i < 32; i++ {
			if l, err := readLine(r); err != nil || l == "" {
				break
			}
		}
	}
	s.release(c, !strings.EqualFold(hdr.Get("Connection"), "close"))
	s.ok.Store(true)
	return nil
}

// Reqmod sends the request headers and body for modification. body may be
// nil. The caller owns req; a ModifiedRequest verdict carries a new one.
func (s *Service) Reqmod(ctx context.Context, req *http.Request, body []byte) (*Verdict, error) {
	hdr := requestHeaderBlock(req)
	enc := "req-hdr=0, null-body=" + strconv.Itoa(len(hdr))
	if body != nil {
		enc = "req-hdr=0, req-body=" + strconv.Itoa(len(hdr))
	}
	return s.modify(ctx, "REQMOD", enc, [][]byte{hdr}, body)
}

// Respmod sends the original request headers, the response headers and
// the response body for modification.
func (s *Service) Respmod(ctx context.Context, req *http.Request, resp *http.Response, body []byte) (*Verdict, error) {
	rh := requestHeaderBlock(req)
	sh := responseHeaderBlock(resp)
	enc := fmt.Sprintf("req-hdr=0, res-hdr=%d, null-body=%d", len(rh), len(rh)+len(sh))
	if body != nil {
		enc = fmt.Sprintf("req-hdr=0, res-hdr=%d, res-body=%d", len(rh), len(rh)+len(sh))
	}
	return s.modify(ctx, "RESPMOD", enc, [][]byte{rh, sh}, body)
}

func (s *Service) modify(ctx context.Context, method, encapsulated string, blocks [][]byte, body []byte) (*Verdict, error) {
	s.Requests.Add(1)
	v, err := s.modifyOnce(ctx, method, encapsulated, blocks, body)
	if err != nil {
		s.Errors.Add(1)
		s.ok.Store(false)
		return nil, err
	}
	s.ok.Store(true)
	switch v.Kind {
	case Unmodified:
		s.Unmodifieds.Add(1)
	case Replaced:
		s.Replacements.Add(1)
	default:
		s.Modifieds.Add(1)
	}
	return v, nil
}

func (s *Service) modifyOnce(ctx context.Context, method, encapsulated string, blocks [][]byte, body []byte) (*Verdict, error) {
	c, err := s.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("icap dial: %w", err)
	}
	reuse := false
	defer func() { s.release(c, reuse) }()
	deadline := time.Now().Add(s.cfg.Timeout.D())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)

	preview := s.preview.Load()
	usePreview := body != nil && preview >= 0 && int64(len(body)) > preview && s.cfg.Preview != "off"
	if s.cfg.Preview != "auto" && s.cfg.Preview != "off" {
		if n, err := strconv.ParseInt(s.cfg.Preview, 10, 64); err == nil {
			preview, usePreview = n, body != nil && int64(len(body)) > n
		}
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s ICAP/1.0\r\nHost: %s\r\nUser-Agent: xproxy-icap/1\r\nAllow: 204\r\n", method, s.u.String(), s.u.Host)
	if usePreview {
		fmt.Fprintf(&b, "Preview: %d\r\n", preview)
	}
	fmt.Fprintf(&b, "Encapsulated: %s\r\n\r\n", encapsulated)
	for _, blk := range blocks {
		b.Write(blk)
	}
	if body != nil {
		if usePreview {
			writeChunk(&b, body[:preview])
			b.WriteString("0\r\n\r\n")
		} else {
			writeChunk(&b, body)
			b.WriteString("0\r\n\r\n")
		}
	}
	if _, err := c.Write(b.Bytes()); err != nil {
		return nil, fmt.Errorf("icap write: %w", err)
	}
	r := c.r
	status, hdr, err := readICAPHeader(r)
	if err != nil {
		return nil, fmt.Errorf("icap read: %w", err)
	}
	if status == 100 && usePreview {
		var rest bytes.Buffer
		writeChunk(&rest, body[preview:])
		rest.WriteString("0\r\n\r\n")
		if _, err := c.Write(rest.Bytes()); err != nil {
			return nil, fmt.Errorf("icap write rest: %w", err)
		}
		status, hdr, err = readICAPHeader(r)
		if err != nil {
			return nil, fmt.Errorf("icap read: %w", err)
		}
	}
	v := &Verdict{Status: status, ISTag: strings.Trim(hdr.Get("ISTag"), `"`)}
	if t := hdr.Get("ISTag"); t != "" {
		s.istag.Store(&t)
	}
	reuse = !strings.EqualFold(hdr.Get("Connection"), "close")
	switch status {
	case 204:
		v.Kind = Unmodified
		return v, nil
	case 200:
		kind, req, resp, err := readEncapsulated(r, hdr.Get("Encapsulated"), method) //nolint:bodyclose // bounded in-memory body owned by the verdict consumer
		if err != nil {
			reuse = false
			return nil, err
		}
		v.Kind, v.Request, v.Response = kind, req, resp
		return v, nil
	default:
		reuse = false
		return nil, fmt.Errorf("icap status %d", status)
	}
}

func writeChunk(b *bytes.Buffer, data []byte) {
	if len(data) == 0 {
		return
	}
	fmt.Fprintf(b, "%x\r\n", len(data))
	b.Write(data)
	b.WriteString("\r\n")
}

// readICAPHeader parses the ICAP status line and headers.
func readICAPHeader(r *bufio.Reader) (int, http.Header, error) {
	line, err := readLine(r)
	if err != nil {
		return 0, nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "ICAP/1.") {
		return 0, nil, fmt.Errorf("bad icap status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status < 100 || status > 599 {
		return 0, nil, fmt.Errorf("bad icap status %q", parts[1])
	}
	hdr := http.Header{}
	total := len(line)
	for {
		l, err := readLine(r)
		if err != nil {
			return 0, nil, err
		}
		total += len(l)
		if total > maxICAPHeaderBytes {
			return 0, nil, errors.New("icap header too large")
		}
		if l == "" {
			return status, hdr, nil
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return 0, nil, fmt.Errorf("bad icap header %q", l)
		}
		hdr.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readEncapsulated parses the HTTP message the ICAP server returned.
func readEncapsulated(r *bufio.Reader, enc, method string) (Kind, *http.Request, *http.Response, error) {
	type entry struct {
		name string
		off  int
	}
	parts := strings.Split(enc, ",")
	entries := make([]entry, 0, len(parts))
	for _, part := range parts {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return 0, nil, nil, fmt.Errorf("bad Encapsulated %q", enc)
		}
		off, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || off < 0 {
			return 0, nil, nil, fmt.Errorf("bad Encapsulated %q", enc)
		}
		entries = append(entries, entry{strings.TrimSpace(k), off})
	}
	if len(entries) == 0 {
		return 0, nil, nil, errors.New("missing Encapsulated header")
	}
	// Header blocks come in order; each has a length given by the next
	// offset. The body (if any) is the last entry and is chunked.
	var reqHdr, resHdr []byte
	hasBody := false
	for i, e := range entries {
		switch e.name {
		case "req-hdr", "res-hdr":
			if i+1 >= len(entries) {
				return 0, nil, nil, errors.New("header block without terminator in Encapsulated")
			}
			n := entries[i+1].off - e.off
			if n < 0 || n > maxHTTPHeaderBytes {
				return 0, nil, nil, errors.New("encapsulated header block too large")
			}
			blk := make([]byte, n)
			if _, err := io.ReadFull(r, blk); err != nil {
				return 0, nil, nil, err
			}
			if e.name == "req-hdr" {
				reqHdr = blk
			} else {
				resHdr = blk
			}
		case "req-body", "res-body":
			hasBody = true
		case "null-body", "opt-body":
		default:
			return 0, nil, nil, fmt.Errorf("unknown Encapsulated entry %q", e.name)
		}
	}
	var body []byte
	if hasBody {
		var err error
		body, err = io.ReadAll(io.LimitReader(httputil.NewChunkedReader(r), maxReplacementBody+1))
		if err != nil {
			return 0, nil, nil, fmt.Errorf("icap body: %w", err)
		}
		if len(body) > maxReplacementBody {
			return 0, nil, nil, errors.New("icap replacement body too large")
		}
		// The chunked reader stops at the zero chunk; the message ends with
		// an optional trailer and a blank line, which must be consumed so
		// the connection can carry the next exchange.
		for i := 0; i < 32; i++ {
			l, err := readLine(r)
			if err != nil {
				return 0, nil, nil, err
			}
			if l == "" {
				break
			}
		}
	}
	switch {
	case resHdr != nil:
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(resHdr)), nil)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("icap encapsulated response: %w", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Del("Transfer-Encoding")
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if method == "RESPMOD" {
			return ModifiedResponse, nil, resp, nil
		}
		return Replaced, nil, resp, nil
	case reqHdr != nil:
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqHdr)))
		if err != nil {
			return 0, nil, nil, fmt.Errorf("icap encapsulated request: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Del("Transfer-Encoding")
		if body != nil {
			req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		return ModifiedRequest, req, nil, nil
	}
	return 0, nil, nil, errors.New("icap 200 without encapsulated headers")
}

// requestHeaderBlock renders the request line and headers as sent to the
// upstream. Hop-by-hop headers are omitted.
func requestHeaderBlock(req *http.Request) []byte {
	var b bytes.Buffer
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, uri, req.Host)
	writeHeaders(&b, req.Header)
	b.WriteString("\r\n")
	return b.Bytes()
}

func responseHeaderBlock(resp *http.Response) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	writeHeaders(&b, resp.Header)
	b.WriteString("\r\n")
	return b.Bytes()
}

var hopByHop = map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true}

func writeHeaders(b *bytes.Buffer, h http.Header) {
	for k, vs := range h {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			if strings.ContainsAny(v, "\r\n") {
				continue
			}
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}
