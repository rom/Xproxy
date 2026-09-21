package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/mfa"
)

// sshKey writes a fresh ed25519 key pair and returns the private key
// file, the signer and the authorized_keys line.
func sshKey(t *testing.T, dir, name string) (string, ssh.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(der), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return path, signer, string(ssh.MarshalAuthorizedKey(sshPub))
}

// targetSSH is a minimal SSH server standing in for a real host: it
// accepts any key, answers session channels, and records what it was
// asked to do.
type targetSSH struct {
	ln   net.Listener
	cfg  *ssh.ServerConfig
	mu   sync.Mutex
	reqs []string
	// echo answers exec and shell by echoing what it read.
	sftpFiles map[string][]byte
}

func startTargetSSH(t *testing.T, hostKey ssh.Signer) *targetSSH {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(hostKey)
	tg := &targetSSH{ln: ln, cfg: cfg, sftpFiles: map[string][]byte{}}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tg.serve(c)
		}
	}()
	return tg
}

func (tg *targetSSH) addr() string { return tg.ln.Addr().String() }

func (tg *targetSSH) seen() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]string(nil), tg.reqs...)
}

func (tg *targetSSH) record(s string) {
	tg.mu.Lock()
	tg.reqs = append(tg.reqs, s)
	tg.mu.Unlock()
}

func (tg *targetSSH) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	conn, chans, reqs, err := ssh.NewServerConn(c, tg.cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		tg.record("channel:" + nc.ChannelType())
		switch nc.ChannelType() {
		case "session":
			ch, chReqs, err := nc.Accept()
			if err != nil {
				return
			}
			go tg.session(ch, chReqs)
		case "direct-tcpip":
			ch, _, err := nc.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(ch, ch)
				_ = ch.Close()
			}()
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "no")
		}
	}
}

func (tg *targetSSH) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for r := range reqs {
		payload := ""
		if len(r.Payload) >= 4 {
			n := binary.BigEndian.Uint32(r.Payload)
			if int(n) <= len(r.Payload)-4 {
				payload = string(r.Payload[4 : 4+n])
			}
		}
		tg.record(r.Type + ":" + payload)
		switch r.Type {
		case "exec":
			_ = r.Reply(true, nil)
			_, _ = fmt.Fprintf(ch, "ran %s", payload)
			_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
			return
		case "shell":
			_ = r.Reply(true, nil)
			_, _ = io.WriteString(ch, "shell\n")
			return
		case "subsystem":
			if payload != "sftp" {
				_ = r.Reply(false, nil)
				continue
			}
			_ = r.Reply(true, nil)
			tg.sftp(ch)
			return
		default:
			_ = r.Reply(true, nil)
		}
	}
}

// sftp answers enough of SFTP version 3 for the proxy's policy to be
// exercised end to end: a version exchange and a status per request.
func (tg *targetSSH) sftp(ch ssh.Channel) {
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(ch, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > 1<<20 {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(ch, body); err != nil {
			return
		}
		typ := body[0]
		tg.record(fmt.Sprintf("sftp:%d", typ))
		var reply []byte
		if typ == 1 { // INIT
			reply = []byte{0, 0, 0, 5, 2, 0, 0, 0, 3}
		} else {
			id := uint32(0)
			if len(body) >= 5 {
				id = binary.BigEndian.Uint32(body[1:])
			}
			payload := binary.BigEndian.AppendUint32(nil, id)
			payload = binary.BigEndian.AppendUint32(payload, 0) // OK
			payload = binary.BigEndian.AppendUint32(payload, 0) // message
			payload = binary.BigEndian.AppendUint32(payload, 0) // language
			reply = binary.BigEndian.AppendUint32(nil, uint32(len(payload)+1))
			reply = append(reply, 101)
			reply = append(reply, payload...)
		}
		if _, err := ch.Write(reply); err != nil {
			return
		}
	}
}

// bastion builds a proxy in front of a target, returning its address
// and the client key that may use it.
func bastion(t *testing.T, extra string) (*Server, string, ssh.Signer, *targetSSH) {
	t.Helper()
	dir := t.TempDir()
	hostKeyPath, hostSigner, _ := sshKey(t, dir, "host")
	targetHostKeyPath, targetHostSigner, _ := sshKey(t, dir, "target_host")
	_ = targetHostKeyPath
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, clientSigner, clientAuthorized := sshKey(t, dir, "client")

	tg := startTargetSSH(t, targetHostSigner)

	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(clientAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", tg.addr(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(targetHostSigner.PublicKey()))))
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = hostSigner

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
        upstream_user: operator
%s
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, authorized, upKeyPath, known, extra, tg.addr())
	s, _ := startServer(t, yaml)
	return s, s.Addrs()["bastion"], clientSigner, tg
}

func dialBastion(t *testing.T, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial bastion: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSSHExec runs a command through the bastion and checks the target
// saw it, that the proxy authenticated onwards as its own user, and
// that the counters moved.
func TestSSHExec(t *testing.T) {
	s, addr, key, tg := bastion(t, "")
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("uptime")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "ran uptime" {
		t.Fatalf("got %q", out)
	}
	seen := strings.Join(tg.seen(), "|")
	if !strings.Contains(seen, "exec:uptime") {
		t.Fatalf("the target did not see the command: %s", seen)
	}
	sn := s.stats.snapshot()
	if sn.SSHSessions != 1 || sn.SSHChannels != 1 {
		t.Fatalf("counters: sessions %d channels %d", sn.SSHSessions, sn.SSHChannels)
	}
}

// A key that is not in authorized_keys never reaches the target.
func TestSSHUnknownKey(t *testing.T) {
	s, addr, _, tg := bastion(t, "")
	dir := t.TempDir()
	_, other, _ := sshKey(t, dir, "intruder")
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(other)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if len(tg.seen()) != 0 {
		t.Fatal("an unauthenticated client reached the target")
	}
	if sn := s.stats.snapshot(); sn.SSHAuthFailed == 0 {
		t.Fatal("the failure was not counted")
	}
}

// exec is refused when it is not in allow_requests: the channel opens,
// the request does not.
func TestSSHExecRefused(t *testing.T) {
	s, addr, key, tg := bastion(t, "        allow_requests: [pty-req, shell, subsystem, window-change, signal]")
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("uptime"); err == nil {
		t.Fatal("exec should have been refused")
	}
	for _, r := range tg.seen() {
		if strings.HasPrefix(r, "exec:") {
			t.Fatalf("the refused command reached the target: %s", r)
		}
	}
	if sn := s.stats.snapshot(); sn.SSHRefused == 0 {
		t.Fatal("the refusal was not counted")
	}
}

// With allow_commands only the listed commands run.
func TestSSHCommandPolicy(t *testing.T) {
	_, addr, key, tg := bastion(t, `        allow_commands: ["^(uptime|df -h)$"]`)
	c := dialBastion(t, addr, key)
	ok, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := ok.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("allowed command: %q %v", out, err)
	}
	bad, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Output("rm -rf /"); err == nil {
		t.Fatal("the command should have been refused")
	}
	for _, r := range tg.seen() {
		if strings.Contains(r, "rm -rf") {
			t.Fatalf("the refused command reached the target: %s", r)
		}
	}
}

// A port forward is refused when the channel type is not allowed, and
// allowed only to the listed destinations when it is.
func TestSSHForwardPolicy(t *testing.T) {
	t.Run("channel type refused", func(t *testing.T) {
		_, addr, key, tg := bastion(t, "")
		c := dialBastion(t, addr, key)
		if _, err := c.Dial("tcp", "10.0.0.5:5432"); err == nil {
			t.Fatal("direct-tcpip should have been refused")
		}
		for _, r := range tg.seen() {
			if r == "channel:direct-tcpip" {
				t.Fatal("the refused channel reached the target")
			}
		}
	})
	t.Run("destination policy", func(t *testing.T) {
		extra := "        allow_channels: [session, direct-tcpip]\n" +
			"        forward: [\"10.0.0.0/8:5432\", \"*.db.internal:*\"]"
		_, addr, key, tg := bastion(t, extra)
		c := dialBastion(t, addr, key)
		conn, err := c.Dial("tcp", "10.0.0.5:5432")
		if err != nil {
			t.Fatalf("allowed forward: %v", err)
		}
		_ = conn.Close()
		for _, bad := range []string{"10.0.0.5:22", "192.168.1.1:5432", "db.example.com:5432"} {
			if _, err := c.Dial("tcp", bad); err == nil {
				t.Fatalf("%s should have been refused", bad)
			}
		}
		n := 0
		for _, r := range tg.seen() {
			if r == "channel:direct-tcpip" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("the target saw %d forwards, want 1", n)
		}
	})
}

// A subsystem that is not allowed is refused even though "subsystem" is.
func TestSSHSubsystemPolicy(t *testing.T) {
	_, addr, key, tg := bastion(t, "        allow_subsystems: [sftp]")
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("netconf"); err == nil {
		t.Fatal("netconf should have been refused")
	}
	for _, r := range tg.seen() {
		if strings.Contains(r, "netconf") {
			t.Fatalf("the refused subsystem reached the target: %s", r)
		}
	}
}

// sftpSession opens an sftp subsystem channel and returns it.
func sftpSession(t *testing.T, c *ssh.Client) ssh.Channel {
	t.Helper()
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(reqs)
	ok, err := ch.SendRequest("subsystem", true, sshStringBytes("sftp"))
	if err != nil || !ok {
		t.Fatalf("subsystem: %v", err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	return ch
}

func sshStringBytes(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

func sftpPacket(typ byte, body []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)+1))
	out = append(out, typ)
	return append(out, body...)
}

func sftpStr(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

func readSFTP(t *testing.T, ch ssh.Channel) (byte, []byte) {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(ch, hdr[:]); err != nil {
		t.Fatalf("read sftp: %v", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(ch, body); err != nil {
		t.Fatalf("read sftp body: %v", err)
	}
	return body[0], body[1:]
}

// The SFTP policy is where "may use sftp" stops being the whole
// decision: a read-only session may open a file for reading and not for
// writing, and may not remove one.
func TestSFTPReadOnly(t *testing.T) {
	extra := "        sftp: {read_only: true, allow_paths: [\"/srv/data/**\"]}"
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)

	if _, err := ch.Write(sftpPacket(1, binary.BigEndian.AppendUint32(nil, 3))); err != nil {
		t.Fatal(err)
	}
	if typ, _ := readSFTP(t, ch); typ != 2 {
		t.Fatalf("version reply was type %d", typ)
	}
	// An open for reading inside the tree is allowed.
	body := binary.BigEndian.AppendUint32(nil, 1)
	body = append(body, sftpStr("/srv/data/report.csv")...)
	body = binary.BigEndian.AppendUint32(body, 0x1) // read
	body = binary.BigEndian.AppendUint32(body, 0)   // no attributes
	if _, err := ch.Write(sftpPacket(3, body)); err != nil {
		t.Fatal(err)
	}
	if typ, _ := readSFTP(t, ch); typ != 101 {
		t.Fatalf("open reply was type %d", typ)
	}
	// The same open for writing is refused, by the proxy.
	write := binary.BigEndian.AppendUint32(nil, 2)
	write = append(write, sftpStr("/srv/data/report.csv")...)
	write = binary.BigEndian.AppendUint32(write, 0x2|0x8)
	write = binary.BigEndian.AppendUint32(write, 0)
	if _, err := ch.Write(sftpPacket(3, write)); err != nil {
		t.Fatal(err)
	}
	typ, payload := readSFTP(t, ch)
	if typ != 101 || binary.BigEndian.Uint32(payload[4:]) != 3 {
		t.Fatalf("write open should be permission denied: type %d payload %v", typ, payload)
	}
	// And a path outside the tree, even read-only.
	outside := binary.BigEndian.AppendUint32(nil, 3)
	outside = append(outside, sftpStr("/etc/shadow")...)
	outside = binary.BigEndian.AppendUint32(outside, 0x1)
	outside = binary.BigEndian.AppendUint32(outside, 0)
	if _, err := ch.Write(sftpPacket(3, outside)); err != nil {
		t.Fatal(err)
	}
	if typ, payload := readSFTP(t, ch); typ != 101 || binary.BigEndian.Uint32(payload[4:]) != 3 {
		t.Fatalf("path outside the tree should be denied: type %d", typ)
	}
	// Exactly one open reached the target.
	n := 0
	for _, r := range tg.seen() {
		if r == "sftp:3" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the target saw %d opens, want 1", n)
	}
	if sn := s.stats.snapshot(); sn.SFTPRefused < 2 {
		t.Fatalf("refusals counted: %d", sn.SFTPRefused)
	}
}

// A path that climbs above its own root has a meaning the proxy cannot
// see, so it is refused rather than guessed at.
func TestSFTPRelativeEscape(t *testing.T) {
	extra := "        sftp: {allow_paths: [\"/srv/data/**\"]}"
	_, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	if _, err := ch.Write(sftpPacket(1, binary.BigEndian.AppendUint32(nil, 3))); err != nil {
		t.Fatal(err)
	}
	readSFTP(t, ch)
	body := binary.BigEndian.AppendUint32(nil, 1)
	body = append(body, sftpStr("../../etc/shadow")...)
	body = binary.BigEndian.AppendUint32(body, 0x1)
	body = binary.BigEndian.AppendUint32(body, 0)
	if _, err := ch.Write(sftpPacket(3, body)); err != nil {
		t.Fatal(err)
	}
	if typ, payload := readSFTP(t, ch); typ != 101 || binary.BigEndian.Uint32(payload[4:]) != 3 {
		t.Fatalf("an escaping path should be denied: type %d", typ)
	}
	for _, r := range tg.seen() {
		if r == "sftp:3" {
			t.Fatal("the escaping open reached the target")
		}
	}
}

// A client outside allow_clients never gets to authenticate.
func TestSSHAllowClients(t *testing.T) {
	s, addr, key, tg := bastion(t, "        allow_clients: [\"192.0.2.0/24\"]")
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("a denied client connected")
	}
	if len(tg.seen()) != 0 {
		t.Fatal("a denied client reached the target")
	}
	if sn := s.stats.snapshot(); sn.SSHRejected == 0 {
		t.Fatal("the refusal was not counted")
	}
}

// A target whose host key is not in known_hosts is not connected to:
// the bastion is the one place that can notice a machine in the middle.
func TestSSHUnknownHostKey(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	_, targetHostSigner, _ := sshKey(t, dir, "target_host")
	_, otherSigner, _ := sshKey(t, dir, "other_host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, clientSigner, clientAuthorized := sshKey(t, dir, "client")
	tg := startTargetSSH(t, targetHostSigner)

	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(clientAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	// known_hosts names a different key for this address.
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", tg.addr(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))))
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, authorized, upKeyPath, known, tg.addr())
	s, _ := startServer(t, yaml)
	c, err := ssh.Dial("tcp", s.Addrs()["bastion"], &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		// The proxy may close during or just after authentication;
		// either way nothing is relayed.
		return
	}
	defer func() { _ = c.Close() }()
	if _, err := c.NewSession(); err == nil {
		t.Fatal("a session was relayed to a target with an unknown host key")
	}
}

// enrolMFA writes an enrolment file and returns its path and secret.
func enrolMFA(t *testing.T, dir, user string) (string, []byte) {
	t.Helper()
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mfa")
	if err := os.WriteFile(path, []byte(user+":"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return path, raw
}

// TestSSHMFA is the second factor on the bastion: the key alone is a
// partial success, and the session only exists once a one-time code
// has been answered too.
func TestSSHMFA(t *testing.T) {
	dir := t.TempDir()
	mfaFile, secret := enrolMFA(t, dir, "alice")
	s, addr, key, tg := bastion(t, "        mfa: {file: "+mfaFile+", skew: 1}")

	code := func() string {
		c, err := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.Params{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	answer := func(string, string, []string, []bool) ([]string, error) {
		return []string{code()}, nil
	}
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
			ssh.KeyboardInteractive(answer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with the second factor: %v", err)
	}
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("exec: %q %v", out, err)
	}
	if len(tg.seen()) == 0 {
		t.Fatal("nothing reached the target")
	}
	if sn := s.stats.snapshot(); sn.MFAVerified != 1 {
		t.Fatalf("verified: %d", sn.MFAVerified)
	}
}

// The right key with the wrong code is not a session.
func TestSSHMFAWrongCode(t *testing.T) {
	dir := t.TempDir()
	mfaFile, _ := enrolMFA(t, dir, "alice")
	s, addr, key, tg := bastion(t, "        mfa: {file: "+mfaFile+"}")

	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
			ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
				return []string{"000000"}, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("a wrong code was accepted")
	}
	if len(tg.seen()) != 0 {
		t.Fatal("a half-authenticated client reached the target")
	}
	if sn := s.stats.snapshot(); sn.MFAFailed == 0 {
		t.Fatal("the failure was not counted")
	}
}

// The key alone is not enough: a client that will not do
// keyboard-interactive never gets a session.
func TestSSHMFAKeyAlone(t *testing.T) {
	dir := t.TempDir()
	mfaFile, _ := enrolMFA(t, dir, "alice")
	_, addr, key, tg := bastion(t, "        mfa: {file: "+mfaFile+"}")

	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("the key alone opened a session")
	}
	if len(tg.seen()) != 0 {
		t.Fatal("a half-authenticated client reached the target")
	}
}

// A code cannot be used twice, even inside its own time step.
func TestSSHMFAReplay(t *testing.T) {
	dir := t.TempDir()
	mfaFile, secret := enrolMFA(t, dir, "alice")
	_, addr, key, _ := bastion(t, "        mfa: {file: "+mfaFile+"}")

	code, err := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	dial := func() error {
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User: "alice",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(key),
				ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
					return []string{code}, nil
				}),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
			Timeout:         5 * time.Second,
		})
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if err := dial(); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := dial(); err == nil {
		t.Fatal("the same code opened a second session")
	}
}

// A user with no enrolment is refused, and is asked for a code first so
// that nothing distinguishes an enrolled name from one that is not.
func TestSSHMFANotEnrolled(t *testing.T) {
	dir := t.TempDir()
	mfaFile, _ := enrolMFA(t, dir, "someone-else")
	_, addr, key, _ := bastion(t, "        mfa: {file: "+mfaFile+"}")

	asked := false
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
			ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
				asked = true
				return []string{"000000"}, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("an unenrolled user was accepted")
	}
	if !asked {
		t.Fatal("the unenrolled user was refused without being asked, which says the name is not enrolled")
	}
}
