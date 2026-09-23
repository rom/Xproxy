package ftp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	wire "github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/textsafe"
)

// A transfer is handed to an ICAP service the way every ICAP scanner
// expects to be given a file: encapsulated in an HTTP message (RFC
// 3507 section 4). FTP has no HTTP message of its own, so the proxy
// makes one that says truthfully what is happening -- a PUT of the
// stored path for an upload, a GET and its response for a download --
// with the ftp:// URL of the real file, so a log at the scanner names
// something an operator can find.
//
// Scanning means buffering. A verdict that arrives after the bytes
// have gone is not a control, so the file is held until the service
// answers, up to the service's max_body; past that
// body_limit_action decides, exactly as it does for an HTTP body.

// icapDecision is what a scan concluded about one transfer.
type icapDecision struct {
	// blocked is the reason to cut the transfer, empty to let it pass.
	blocked string
	// head is what was read and must still be delivered.
	head []byte
	// scanned reports whether the service actually saw the bytes.
	scanned bool
}

// scanTransfer reads the file, asks the service, and says what to do.
// The returned bytes are what has been consumed from src and still has
// to reach dst when the transfer is allowed.
func (se *session) scanTransfer(svc *icap.Service, src io.Reader, path string, upload bool) (icapDecision, error) {
	cfg := svc.Config()
	limit := cfg.MaxBody
	if limit <= 0 {
		limit = 10 << 20
	}
	// One byte past the bound tells an oversize file from an exact fit.
	buf := make([]byte, 0, 64<<10)
	head := bytes.NewBuffer(buf)
	n, err := io.CopyN(head, src, limit+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return icapDecision{}, err
	}
	body := head.Bytes()
	if n > limit {
		switch cfg.BodyLimitAction {
		case "bypass":
			// Too large to scan and the operator chose to let those
			// through. It is said out loud, because a file that is
			// never scanned is the one an attacker would choose.
			se.t.engine.Logs().Security.Warn("ftp transfer past the scanner's body limit was not scanned",
				"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
				"path", textsafe.Clip256(path), "limit", limit, "service", svc.Name())
			return icapDecision{head: body, scanned: false}, nil
		default:
			return icapDecision{blocked: "larger than the scanner's max_body", head: body}, nil
		}
	}

	req, err := se.icapRequest(path, upload, body)
	if err != nil {
		return icapDecision{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout.D()+time.Second)
	defer cancel()
	var v *icap.Verdict
	if upload {
		v, err = svc.Reqmod(ctx, req, body)
	} else {
		resp := &http.Response{
			Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":   []string{"application/octet-stream"},
				"Content-Length": []string{strconv.Itoa(len(body))},
			},
			Request:       req,
			ContentLength: int64(len(body)),
			Body:          io.NopCloser(bytes.NewReader(body)),
		}
		v, err = svc.Respmod(ctx, req, resp, body)
	}
	if err != nil {
		// fail: open or closed, as the service was configured. The
		// choice is the operator's; what is not optional is saying
		// which way it went.
		if cfg.Fail == "open" {
			se.t.engine.Logs().Error.Warn("ftp transfer passed unscanned: the icap service failed",
				"listener", se.t.cfg.Name, "service", svc.Name(), "err", err.Error())
			return icapDecision{head: body, scanned: false}, nil
		}
		return icapDecision{blocked: "the scanner could not be reached", head: body}, nil
	}
	if v.Kind == icap.Replaced {
		return icapDecision{blocked: se.icapBlockReason(v), head: body, scanned: true}, nil
	}
	// A modified body is delivered as the scanner rewrote it, which is
	// what REQMOD is for: a stripped macro, a cleaned archive.
	if v.Kind == icap.ModifiedRequest && v.Request != nil && v.Request.Body != nil {
		b, rerr := io.ReadAll(io.LimitReader(v.Request.Body, limit))
		_ = v.Request.Body.Close()
		if rerr == nil {
			return icapDecision{head: b, scanned: true}, nil
		}
	}
	if v.Kind == icap.ModifiedResponse && v.Response != nil && v.Response.Body != nil {
		b, rerr := io.ReadAll(io.LimitReader(v.Response.Body, limit))
		_ = v.Response.Body.Close()
		if rerr == nil {
			return icapDecision{head: b, scanned: true}, nil
		}
	}
	return icapDecision{head: body, scanned: true}, nil
}

// icapRequest builds the HTTP message that carries the file. The URL
// is the ftp one so that the scanner's own log names the real file,
// and the client address travels in X-Client-IP, which is the header
// ICAP services conventionally read for it.
func (se *session) icapRequest(path string, upload bool, body []byte) (*http.Request, error) {
	method := http.MethodGet
	if upload {
		method = http.MethodPut
	}
	u := &url.URL{Scheme: "ftp", Host: se.target, Path: path}
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body)) //nolint:noctx // not sent over the network; it is the ICAP encapsulation
	if err != nil {
		return nil, fmt.Errorf("icap request: %w", err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Client-IP", se.ip.String())
	if se.user != "" {
		req.Header.Set("X-Authenticated-User", textsafe.Clip64(se.user))
	}
	return req, nil
}

// icapBlockReason is what the scanner said, reduced to something safe
// to put in a 550 and in the log. A scanner's text is remote input.
func (se *session) icapBlockReason(v *icap.Verdict) string {
	reason := "refused by the scanner"
	if v.Response != nil {
		if s := v.Response.Header.Get("X-Infection-Found"); s != "" {
			return reason + ": " + textsafe.Clip256(s)
		}
		if s := v.Response.Header.Get("X-Violations-Found"); s != "" {
			return reason + ": " + textsafe.Clip256(s)
		}
	}
	return reason
}

// icapFor returns the service to scan this transfer with, or nil when
// this direction is not scanned.
func (t *server) icapFor(upload bool) *icap.Service {
	if t.f.ICAP == nil {
		return nil
	}
	if upload && !t.f.ICAP.ScansUploads() {
		return nil
	}
	if !upload && !t.f.ICAP.ScansDownloads() {
		return nil
	}
	return t.engine.ICAPService(t.f.ICAP.Service)
}

// scanned moves a transfer that a service has to see first. The file
// is read, scanned, and only then delivered; what is left over after
// the scanned part is streamed, since the service has had its say.
func (se *session) scanned(svc *icap.Service, dst io.Writer, src io.Reader, c wire.Command, upload bool, scan *streamscan.Stream) (int64, string) {
	path := se.resolve(c.Arg)
	d, err := se.scanTransfer(svc, src, path, upload)
	if err != nil {
		if svc.Config().Fail == "open" {
			se.t.engine.Logs().Error.Warn("ftp transfer passed unscanned: reading it failed",
				"listener", se.t.cfg.Name, "service", svc.Name(), "err", err.Error())
		} else {
			return 0, "the transfer could not be scanned"
		}
	}
	if d.scanned {
		se.t.engine.Counters().FTPScanned.Add(1)
	}
	if d.blocked != "" {
		se.t.engine.Counters().FTPScanBlocked.Add(1)
		se.t.engine.Logs().SecurityEvent(context.Background(), "deny", "ftp_icap_blocked",
			"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
			"path", textsafe.Clip256(path), "command", c.Verb, "service", svc.Name(), "reason", d.blocked)
		return 0, d.blocked
	}
	// What was held goes out now, through the same bounds a streamed
	// transfer passes: the size limit and the rule set still apply.
	total, reason := se.copyData(dst, bytes.NewReader(d.head), scan)
	if reason != "" {
		return total, reason
	}
	n, reason := se.copyData(dst, src, scan)
	return total + n, reason
}
