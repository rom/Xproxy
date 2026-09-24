package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/icap"
	sftpwire "github.com/rom/xproxy/internal/sftp"
	"github.com/rom/xproxy/internal/textsafe"
)

// SFTP has no whole-file transfer to hand a scanner. A file is a
// handle, a run of WRITEs at offsets, and a CLOSE, and the scanner
// wants the file. So a scanned upload is held rather than forwarded:
// the proxy answers each WRITE itself, assembles what the file turns
// out to be, scans it when the handle is closed, and only then replays
// the writes to the server.
//
// That is what makes it a control rather than a report. The cost is
// the file in memory until the close, bounded by the service's
// max_body, and the write replies the client sees are the proxy's
// rather than the server's -- so a server that would have refused the
// write for its own reasons says so at the close instead.

// heldWrite is one WRITE the proxy answered and kept.
type heldWrite struct {
	id     uint32
	packet sftpwire.Packet
}

// scanState is the held upload on one handle.
type scanState struct {
	// body is the file as the writes have made it. Writes may arrive
	// at any offset, so it is assembled by offset rather than
	// appended.
	body []byte
	// writes are the packets to replay once the scanner allows it.
	writes []heldWrite
	// over is set once the file passed the service's max_body, so the
	// rest is handled by body_limit_action rather than accumulated.
	over bool
	// released is set once the writes have been replayed, so a second
	// close does not replay them again.
	released bool
}

// put records one write, returning false when the file has outgrown
// what may be held.
func (s *scanState) put(off uint64, data []byte, limit uint64) bool {
	end := off + uint64(len(data))
	// A write far out makes a file that large, so the offset is bounded
	// by the same number the size is: a one byte write at a terabyte is
	// a terabyte file, not a one byte one.
	if end < off || end > limit {
		s.over = true
		return false
	}
	if uint64(len(s.body)) < end {
		grown := make([]byte, end)
		copy(grown, s.body)
		s.body = grown
	}
	copy(s.body[off:], data)
	return true
}

// icapForSFTP returns the service a write should go through, or nil.
func (t *server) icapForSFTP(p *sftpPolicy) *icap.Service {
	if p == nil || p.icap == nil || !p.icap.ScansUploads() {
		return nil
	}
	return t.engine.ICAPService(p.icap.Service)
}

// scanUpload asks the service about a finished file and says what to
// do with it.
func (se *session) scanUpload(svc *icap.Service, path string, body []byte) (blocked string, scanned bool) {
	cfg := svc.Config()
	u := &url.URL{Scheme: "sftp", Host: se.target, Path: path}
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body)) //nolint:noctx // not sent over the network; it is the ICAP encapsulation
	if err != nil {
		return se.sftpScanFailed(svc, err), false
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("X-Client-IP", se.ip.String())
	if se.user != "" {
		req.Header.Set("X-Authenticated-User", textsafe.Clip64(se.user))
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout.D()+time.Second)
	defer cancel()
	v, err := svc.Reqmod(ctx, req, body)
	if err != nil {
		return se.sftpScanFailed(svc, err), false
	}
	if v.Kind == icap.Replaced {
		reason := "refused by the scanner"
		if v.Response != nil {
			if s := v.Response.Header.Get("X-Infection-Found"); s != "" {
				reason += ": " + textsafe.Clip256(s)
			}
		}
		return reason, true
	}
	return "", true
}

// sftpScanFailed applies the service's fail direction to a scan that
// could not be made, and says which way it went either way. It returns
// the reason to refuse, empty where the service fails open; nothing was
// scanned in either case.
func (se *session) sftpScanFailed(svc *icap.Service, err error) string {
	if svc.Config().Fail == "open" {
		se.t.engine.Logs().Error.Warn("sftp write passed unscanned: the icap service failed",
			"listener", se.t.cfg.Name, "service", svc.Name(), "err", err.Error())
		return ""
	}
	return "the scanner could not be reached"
}

// overLimit applies body_limit_action to a file too large to hold.
func (se *session) overLimit(svc *icap.Service, path string) string {
	if svc.Config().BodyLimitAction == "bypass" {
		se.t.engine.Logs().Security.Warn("sftp write past the scanner's body limit was not scanned",
			"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
			"path", textsafe.Clip256(path), "limit", svc.Config().MaxBody, "service", svc.Name())
		return ""
	}
	return "larger than the scanner's max_body"
}

// reportBlocked writes the security event for a refused file.
func (se *session) reportBlocked(svc *icap.Service, path, reason string) {
	t := se.t
	t.engine.Counters().SFTPScanBlocked.Add(1)
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "sftp_icap_blocked",
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
		"principal", se.principal, "path", textsafe.Clip256(path),
		"service", svc.Name(), "reason", reason)
	if bl := t.engine.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "sftp_icap")
	}
}

// scanNote is what the access log says about a held file at its close.
func scanNote(blocked string, n int) string {
	if blocked != "" {
		return fmt.Sprintf("blocked after %d bytes: %s", n, blocked)
	}
	return fmt.Sprintf("released %d bytes", n)
}

// replayedIDs remembers the writes this proxy sent for the client, so
// the answers to them can be dropped instead of reaching a client that
// was answered already. It is bounded by the writes one held file can
// have, which the body limit bounds in turn.
type replayedIDs struct {
	mu  sync.Mutex
	ids map[uint32]bool
}

func newReplayed() *replayedIDs { return &replayedIDs{ids: map[uint32]bool{}} }

func (r *replayedIDs) add(id uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids[id] = true
}

// took reports whether this id was one of ours, and forgets it: a
// server answers each request once.
func (r *replayedIDs) took(id uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ids[id] {
		return false
	}
	delete(r.ids, id)
	return true
}

// holdWrite keeps one write for the scanner. It reports whether the
// write was held, and the reason to refuse it when there is one.
func (se *session) holdWrite(svc *icap.Service, f *sftpFile, r sftpwire.Request, pkt sftpwire.Packet) (bool, string) {
	limit := svc.Config().MaxBody
	if limit <= 0 {
		limit = 10 << 20
	}
	if f.held.put(r.Offset, r.Data, uint64(limit)) { //nolint:gosec // positive by the line above
		// The packet is kept whole, because what is replayed has to be
		// what the client sent: the proxy is not rewriting the file,
		// only delaying it.
		f.held.writes = append(f.held.writes, heldWrite{id: r.ID, packet: pkt.Clone()})
		return true, ""
	}
	// Past what may be held.
	if reason := se.overLimit(svc, f.path); reason != "" {
		return false, reason
	}
	return false, ""
}

// releaseHeld replays what was kept, so the server sees the writes in
// the order the client made them.
func (se *session) releaseHeld(f *sftpFile, write func(io.Writer, sftpwire.Packet) error, upCh io.Writer, replayed *replayedIDs) error {
	if f.held == nil || f.held.released {
		return nil
	}
	f.held.released = true
	for _, w := range f.held.writes {
		replayed.add(w.id)
		if err := write(upCh, w.packet); err != nil {
			return err
		}
	}
	f.held.writes, f.held.body = nil, nil
	return nil
}

// finishHeld scans a file at its close and either releases it or
// refuses it. It returns the reason it was blocked, empty when it was
// let through, and the size the file had.
func (se *session) finishHeld(svc *icap.Service, f *sftpFile,
	write func(io.Writer, sftpwire.Packet) error, upCh, clientCh io.Writer,
	replayed *replayedIDs, closeID uint32,
) (string, int) {
	n := len(f.held.body)
	blocked := ""
	if f.held.over {
		// Never held to the end, so never scanned; overLimit has
		// already said which way body_limit_action went.
		blocked = se.overLimit(svc, f.path)
	} else {
		var scanned bool
		blocked, scanned = se.scanUpload(svc, f.path, f.held.body)
		if scanned {
			se.t.engine.Counters().SFTPScanned.Add(1)
		}
	}
	if blocked != "" {
		se.reportBlocked(svc, f.path, blocked)
		se.refused.Add(1)
		se.t.engine.Counters().SFTPRefused.Add(1)
		se.t.engine.Counters().Refuse("ssh", "sftp_icap")
		// The writes are dropped rather than replayed, so the file the
		// scanner refused never reaches the server. The empty file the
		// OPEN created does remain: the proxy cannot unmake it without
		// issuing a remove of its own, which would be a write it was
		// never asked to make.
		f.held.writes, f.held.body, f.held.released = nil, nil, true
		_ = write(clientCh, sftpwire.StatusPacket(closeID, sftpwire.StatusFailure, "refused by policy"))
		return blocked, n
	}
	if err := se.releaseHeld(f, write, upCh, replayed); err != nil {
		return "", n
	}
	return "", n
}
