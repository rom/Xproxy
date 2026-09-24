package vnc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	cssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rfb"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/textsafe"
)

// The parts of a session that are not the handshake: reaching the
// target through SSH, recording the stream, asking for a factor, and
// the relay that applies view_only.

// sshDialer reaches a VNC target through an SSH connection the gateway
// makes itself, which is the usual way a VNC server is reached safely
// -- done here once rather than by every operator with their own
// ssh -L.
type sshDialer struct {
	cfg *config.VNCOverSSH
	cc  *cssh.ClientConfig
}

func newSSHDialer(c *config.VNCOverSSH) (*sshDialer, error) {
	key, err := os.ReadFile(c.KeyFile) //nolint:gosec // an operator named this path
	if err != nil {
		return nil, fmt.Errorf("key_file: %w", err)
	}
	signer, err := cssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("key_file: %w", err)
	}
	// The host keys are pinned. An unpinned tunnel authenticates
	// nothing, and authenticating the far end is the whole reason for
	// the tunnel.
	cb, err := knownhosts.New(c.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}
	return &sshDialer{cfg: c, cc: &cssh.ClientConfig{
		User:            c.User,
		Auth:            []cssh.AuthMethod{cssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         15 * time.Second,
	}}, nil
}

// dial opens an SSH connection and a channel through it to the VNC
// server. A connection per session rather than a shared one: two
// people's sessions sharing a tunnel means one closing it ends both.
func (d *sshDialer) dial(endpoint string) (net.Conn, error) {
	host := d.cfg.Address
	if host == "" {
		h, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, err
		}
		host = net.JoinHostPort(h, "22")
	}
	client, err := cssh.Dial("tcp", host, d.cc)
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", host, err)
	}
	target := d.cfg.Target
	if target == "" {
		target = "127.0.0.1:5900"
	}
	conn, err := client.Dial("tcp", target)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ssh %s -> %s: %w", host, target, err)
	}
	return &sshConn{Conn: conn, client: client}, nil
}

// sshConn closes the SSH connection with the channel it carried.
type sshConn struct {
	net.Conn
	client *cssh.Client
}

func (c *sshConn) Close() error {
	err := c.Conn.Close()
	_ = c.client.Close()
	return err
}

// openRecording starts the file once the desktop is known.
func (se *session) openRecording() {
	if !se.t.recorder.Enabled() {
		return
	}
	who := textsafe.Clip64(se.user)
	if who == "" {
		who = "anonymous"
	}
	// The recording of a graphical session is its protocol stream, not
	// a terminal: the header says so, and says what the framebuffer
	// was, so a player knows what the event data holds.
	rec, err := se.t.recorder.Open(sessionrec.Header{
		Width: int(se.width), Height: int(se.height),
		Title: fmt.Sprintf("%s@%s (%s) via %s", who, se.target, textsafe.Clip64(se.desktop), se.t.cfg.Name),
		Env: map[string]string{
			"XPROXY_PROTOCOL": "rfb",
			"XPROXY_STREAM":   "rfb-server-to-client",
			"XPROXY_RFB":      se.upVersion.String(),
		},
		Tag: who,
		Ext: ".rfb.cast",
	})
	if err != nil {
		se.t.engine.Logs().Error.Warn("vnc session recording could not be opened",
			"listener", se.t.cfg.Name, "user", who, "err", err.Error())
		return
	}
	se.rec = rec
	se.rec.Mark(fmt.Sprintf("xproxy: %s %dx%d, client %s/%s, target %s/%s",
		textsafe.Clip64(se.desktop), se.width, se.height,
		se.clientVersion, rfb.SecurityName(se.clientSec),
		se.upVersion, rfb.SecurityName(se.upSec)))
}

func (se *session) closeRecording() {
	res := se.rec.Close()
	if res.File == "" {
		return
	}
	t := se.t
	t.engine.Counters().VNCRecorded.Add(1)
	t.engine.Logs().Access.Info("vnc_recording", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target,
		"file", res.File, "bytes", res.Bytes, "truncated", res.Truncated)
	if res.Truncated {
		attrs := []any{"listener", t.cfg.Name, "file", res.File}
		if res.Err != nil {
			attrs = append(attrs, "err", res.Err.Error())
		}
		t.engine.Logs().Error.Warn("vnc recording is short of the session", attrs...)
	}
}

// pumpToClient copies what the target showed, recording it. The
// recording is this direction only: it is what was on the screen,
// which is what a recording of a graphical session is for.
//
// A framed listener reads the picture and bounds it. An opaque one
// copies bytes, which is what a desktop that must use the tight
// encoding needs and what leaves the bounds unenforceable.
func (se *session) pumpToClient() string {
	if se.t.px.framed {
		return se.framedToClient()
	}
	buf := make([]byte, 64<<10)
	for {
		if se.t.v.IdleTimeout > 0 {
			_ = se.up.SetReadDeadline(time.Now().Add(se.t.v.IdleTimeout.D()))
		}
		n, err := se.up.Read(buf)
		if n > 0 {
			se.rec.Out(buf[:n])
			if _, werr := se.client.Write(buf[:n]); werr != nil {
				return "write"
			}
		}
		if err != nil {
			return endReason(err)
		}
	}
}

// pumpToTarget copies what the client sent, applying the policy. This
// direction is always framed, whatever pixel_stream says: a message is
// only as long as its type says, so framing is what lets a gateway drop
// one and forward the next -- and a message type whose length it does
// not know, which is where the vendors put file transfer, cannot be
// forwarded at all without losing the stream after it.
func (se *session) pumpToTarget() string { return se.framedToTarget() }

// endReason names why a copy stopped. A timeout is the idle deadline
// rather than a peer hanging up, and the two are worth telling apart
// in a log line.
func endReason(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "idle"
	}
	return "closed"
}

// askFactor checks the second factor before the target is dialled.
// RFB has nowhere to ask a question -- there is no prompt in the
// protocol and no terminal to draw one on -- so the code arrives with
// the credential: VeNCrypt's plain subtype carries a username and a
// password field, and the password field is the code.
//
// That is why a listener with mfa must offer a plain subtype, which
// validation requires at load: any other subtype proves knowledge of
// one shared desktop password and carries no name, so there is nothing
// to look an enrolment up by.
func (se *session) askFactor() string {
	t := se.t
	if se.factorUser == "" {
		se.factorFailed("no_identity")
		return "mfa_no_identity"
	}
	se.user = se.factorUser
	now := time.Now()
	switch {
	case !se.wantsFactor():
		return ""
	case t.mfaGuard.Locked(se.user, now):
		se.factorFailed("locked")
		return "mfa_locked"
	case t.mfaGuard.Verify(se.user, se.factorCode, now) != nil:
		se.factorFailed("wrong_code")
		return "mfa_failed"
	}
	t.engine.Counters().VNCMFAOK.Add(1)
	t.engine.Logs().SecurityEvent(context.Background(), "allow", "vnc_mfa",
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user))
	return ""
}

func (se *session) wantsFactor() bool {
	g := se.t.mfaGuard
	if g.Enrolled(se.user) {
		return true
	}
	return se.t.v.MFA.RequireEnrolment == nil || *se.t.v.MFA.RequireEnrolment
}

func (se *session) factorFailed(why string) {
	t := se.t
	t.engine.Counters().VNCMFAFailed.Add(1)
	t.deny(se.ip, "vnc_mfa_failed", textsafe.Clip64(se.user)+" "+why)
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "vnc_mfa_failed",
		"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "reason", why)
}
