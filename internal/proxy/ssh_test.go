package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
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
	// handles numbers the handles the sftp stand-in hands out.
	handles int
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
			if payload == "cat" {
				// One command reads its input and echoes it, so a test
				// can see what crossed the channel in that direction.
				// The others answer and end at once, which is the
				// timing the reply race lives in.
				_, _ = io.Copy(ch, ch)
			} else {
				_, _ = fmt.Fprintf(ch, "ran %s", payload)
			}
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
		switch typ {
		case 1: // INIT
			reply = []byte{0, 0, 0, 5, 2, 0, 0, 0, 3}
		case 3, 11: // OPEN, OPENDIR: answer with a handle
			id := uint32(0)
			if len(body) >= 5 {
				id = binary.BigEndian.Uint32(body[1:])
			}
			tg.mu.Lock()
			tg.handles++
			h := fmt.Sprintf("h%d", tg.handles)
			tg.mu.Unlock()
			payload := binary.BigEndian.AppendUint32(nil, id)
			payload = append(payload, sftpStr(h)...)
			reply = binary.BigEndian.AppendUint32(nil, uint32(len(payload)+1))
			reply = append(reply, 102)
			reply = append(reply, payload...)
		default:
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
	if typ, _ := readSFTP(t, ch); typ != 102 {
		t.Fatalf("open reply was type %d, want a handle", typ)
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

// TestSSHFileTransferHole is the gap an sftp policy has without this
// check: scp and rsync never open the sftp subsystem, so every path and
// operation rule there is simply not on their path.
func TestSSHFileTransferHole(t *testing.T) {
	extra := "        sftp: {read_only: true, allow_paths: [\"/srv/data/**\"]}"
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)

	for _, cmd := range []string{
		"scp -t /srv/data/x",
		"scp -f /etc/shadow",
		"rsync --server -vlogDtpre.iLsfxC . /srv/",
		"/usr/lib/openssh/sftp-server",
		"LANG=C scp -t /tmp/x",
		// A wrapper is all it takes to walk past a check that reads
		// only the first word.
		"env scp -t /tmp/x",
		"sudo -u root rsync --server . /srv/",
		"sh -c 'scp -t /srv/data/x'",
		"nice -n 19 /usr/bin/scp -t /tmp/x",
	} {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Output(cmd); err == nil {
			t.Errorf("%q was allowed past the sftp policy", cmd)
		}
		_ = sess.Close()
	}
	for _, r := range tg.seen() {
		if strings.HasPrefix(r, "exec:") {
			t.Fatalf("a file transfer command reached the target: %s", r)
		}
	}
	if sn := s.stats.snapshot(); sn.SSHRefused == 0 {
		t.Fatal("the refusals were not counted")
	}
	// An ordinary command still runs: the check names transfer helpers,
	// not every command.
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("ordinary command: %q %v", out, err)
	}
}

// With no sftp policy there is nothing to bypass, so the helpers run.
func TestSSHFileTransferAllowedWithoutSFTP(t *testing.T) {
	_, addr, key, tg := bastion(t, "")
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("scp -t /tmp/x"); err != nil {
		t.Fatalf("scp should run where no sftp policy exists: %v", err)
	}
	found := false
	for _, r := range tg.seen() {
		if strings.HasPrefix(r, "exec:scp") {
			found = true
		}
	}
	if !found {
		t.Fatal("the command did not reach the target")
	}
}

// A principal that brings its own sftp policy to a listener with none
// gets the transfer default its own policy implies, not the listener's:
// otherwise the entry that carefully restricts sftp keeps scp beside it.
func TestSSHPrincipalSFTPClosesTransfers(t *testing.T) {
	_, addr, key, tg := bastion(t, `        principals:
          - name: everyone
            policy:
              sftp: {read_only: true}`)
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("scp -t /tmp/x"); err == nil {
		t.Fatal("scp ran past the principal's own sftp policy")
	}
	for _, r := range tg.seen() {
		if strings.HasPrefix(r, "exec:scp") {
			t.Fatal("the command reached the target")
		}
	}
}

// env requests are filtered: a terminal type passes, a loader variable
// never does, whatever the allow list says.
func TestSSHEnvFiltering(t *testing.T) {
	_, addr, key, tg := bastion(t, "        allow_env: [TERM, LANG, \"LC_*\", BUILD_ID]")
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []struct {
		name, value string
		want        bool
	}{
		{"TERM", "xterm-256color", true},
		{"LC_ALL", "C.UTF-8", true},
		{"BUILD_ID", "4821", true},
		{"LD_PRELOAD", "/tmp/evil.so", false},
		{"BASH_ENV", "/tmp/evil.sh", false},
		{"PATH", "/tmp:/usr/bin", false},
		{"PYTHONSTARTUP", "/tmp/evil.py", false},
		{"EDITOR", "vi", false}, // not on the allow list
	} {
		err := sess.Setenv(ok.name, ok.value)
		if (err == nil) != ok.want {
			t.Errorf("Setenv(%q) = %v, want allowed=%v", ok.name, err, ok.want)
		}
	}
	for _, r := range tg.seen() {
		for _, bad := range []string{"LD_PRELOAD", "BASH_ENV", "PATH", "PYTHONSTARTUP", "EDITOR"} {
			if strings.HasPrefix(r, "env:"+bad) {
				t.Errorf("%s reached the target", bad)
			}
		}
	}
}

// A principal entry gives one key its own policy, and a key no entry
// covers is refused rather than served under the listener's default.
func TestSSHPrincipals(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	_, targetHostSigner, _ := sshKey(t, dir, "target_host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, opsSigner, opsAuthorized := sshKey(t, dir, "ops")
	_, botSigner, botAuthorized := sshKey(t, dir, "bot")
	_, straySigner, strayAuthorized := sshKey(t, dir, "stray")
	tg := startTargetSSH(t, targetHostSigner)

	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(opsAuthorized+botAuthorized+strayAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", tg.addr(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(targetHostSigner.PublicKey()))))
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
        allow_requests: [pty-req, env, shell, exec, subsystem, window-change, signal]
        principals:
          - name: ops
            fingerprints: ["%s"]
            policy: {upstream_user: operator}
          - name: bot
            fingerprints: ["%s"]
            policy:
              upstream_user: ci
              allow_commands: ["^deploy( |$)"]
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, authorized, upKeyPath, known,
		ssh.FingerprintSHA256(opsSigner.PublicKey()),
		ssh.FingerprintSHA256(botSigner.PublicKey()), tg.addr())
	s, _ := startServer(t, yaml)
	addr := s.Addrs()["bastion"]

	// ops gets the listener's command policy, which is everything.
	ops := dialBastion(t, addr, opsSigner)
	sess, err := ops.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("ops: %q %v", out, err)
	}

	// bot gets its own, narrower one.
	bot := dialBastion(t, addr, botSigner)
	allowed, err := bot.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allowed.Output("deploy 2026.3.1"); err != nil {
		t.Fatalf("bot's own command was refused: %v", err)
	}
	refused, err := bot.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refused.Output("uptime"); err == nil {
		t.Fatal("bot ran a command outside its policy")
	}

	// A key in authorized_keys that no entry covers is refused: the
	// list is the policy, so falling back would be the opposite of
	// what it says.
	if _, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(straySigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}); err == nil {
		t.Fatal("a key no principal covers was accepted")
	}
}

// A principal may be denied outright, which is how a key stays in
// authorized_keys while the person it belongs to is off.
func TestSSHPrincipalDeny(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	_, targetHostSigner, _ := sshKey(t, dir, "target_host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, signer, authorizedLine := sshKey(t, dir, "client")
	tg := startTargetSSH(t, targetHostSigner)
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(authorizedLine), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", tg.addr(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(targetHostSigner.PublicKey()))))
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
        principals:
          - name: on-leave
            fingerprints: ["%s"]
            policy: {deny: true}
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, authorized, upKeyPath, known, ssh.FingerprintSHA256(signer.PublicKey()), tg.addr())
	s, _ := startServer(t, yaml)
	if _, err := ssh.Dial("tcp", s.Addrs()["bastion"], &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}); err == nil {
		t.Fatal("a denied principal connected")
	}
	if len(tg.seen()) != 0 {
		t.Fatal("a denied principal reached the target")
	}
}

// sftpOpen writes an OPEN request and returns nothing; the caller reads
// the reply.
func sftpOpen(t *testing.T, ch ssh.Channel, id uint32, path string, flags uint32) {
	t.Helper()
	body := binary.BigEndian.AppendUint32(nil, id)
	body = append(body, sftpStr(path)...)
	body = binary.BigEndian.AppendUint32(body, flags)
	body = binary.BigEndian.AppendUint32(body, 0) // no attributes
	if _, err := ch.Write(sftpPacket(3, body)); err != nil {
		t.Fatal(err)
	}
}

// sftpWriteReq writes a WRITE request on a handle.
func sftpWriteReq(t *testing.T, ch ssh.Channel, id uint32, handle string, offset uint64, data []byte) {
	t.Helper()
	body := binary.BigEndian.AppendUint32(nil, id)
	body = append(body, sftpStr(handle)...)
	body = binary.BigEndian.AppendUint64(body, offset)
	body = binary.BigEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	if _, err := ch.Write(sftpPacket(6, body)); err != nil {
		t.Fatal(err)
	}
}

// sftpInit does the version exchange and returns once the server has
// answered.
func sftpInit(t *testing.T, ch ssh.Channel) {
	t.Helper()
	if _, err := ch.Write(sftpPacket(1, binary.BigEndian.AppendUint32(nil, 3))); err != nil {
		t.Fatal(err)
	}
	if typ, _ := readSFTP(t, ch); typ != 2 {
		t.Fatalf("version reply was type %d", typ)
	}
}

// sftpOpenHandle opens a path and returns the handle the server gave.
func sftpOpenHandle(t *testing.T, ch ssh.Channel, id uint32, path string, flags uint32) string {
	t.Helper()
	sftpOpen(t, ch, id, path, flags)
	typ, payload := readSFTP(t, ch)
	if typ != 102 {
		t.Fatalf("open %s: reply type %d, want a handle", path, typ)
	}
	n := binary.BigEndian.Uint32(payload[4:])
	return string(payload[8 : 8+n])
}

// sftpDenied reports whether the next reply is a permission-denied
// status.
func sftpDenied(t *testing.T, ch ssh.Channel) bool {
	t.Helper()
	typ, payload := readSFTP(t, ch)
	return typ == 101 && binary.BigEndian.Uint32(payload[4:]) == 3
}

// dialBastionAs connects under a chosen login name, which is what a
// path template stands in.
func dialBastionAs(t *testing.T, addr, user string, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

// A path pattern may name the session's own user, which is how one
// listener says "your own directory" rather than listing everybody's.
func TestSFTPPathTemplating(t *testing.T) {
	_, addr, key, tg := bastion(t, `        sftp: {allow_paths: ["/home/{user}/**"], deny_paths: ["/home/{user}/.ssh/**"]}`)
	c := dialBastion(t, addr, key) // alice
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	sftpOpen(t, ch, 1, "/home/alice/report.csv", 0x1)
	if typ, _ := readSFTP(t, ch); typ != 102 {
		t.Fatalf("alice's own directory was refused: type %d", typ)
	}
	for _, path := range []string{"/home/bob/report.csv", "/home/alice/.ssh/authorized_keys"} {
		sftpOpen(t, ch, 2, path, 0x1)
		if !sftpDenied(t, ch) {
			t.Errorf("%s was allowed", path)
		}
	}
	n := 0
	for _, r := range tg.seen() {
		if r == "sftp:3" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the target saw %d opens, want 1", n)
	}
}

// A login name that would change what a pattern means is refused rather
// than substituted: "../.." in an allow list is an allow list for
// somebody else.
func TestSFTPTemplateNameRefused(t *testing.T) {
	_, addr, key, tg := bastion(t, `        sftp: {allow_paths: ["/home/{user}/**"]}`)
	c, err := dialBastionAs(t, addr, "../../etc", key)
	if err != nil {
		t.Fatal(err)
	}
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(reqs)
	ok, err := ch.SendRequest("subsystem", true, sshStringBytes("sftp"))
	if err == nil && ok {
		t.Fatal("a name that cannot stand in a pattern opened an sftp session")
	}
	for _, r := range tg.seen() {
		if strings.HasPrefix(r, "sftp:") {
			t.Fatalf("the session reached the target: %s", r)
		}
	}
}

// File-level policy: what a file is called decides whether it may be
// opened at all, and every extension in the name is read.
func TestSFTPExtensionPolicy(t *testing.T) {
	_, addr, key, _ := bastion(t, `        sftp: {allow_paths: ["/srv/data/**"], allow_extensions: [csv, txt], deny_extensions: [exe, php]}`)
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	var id uint32
	for _, c := range []struct {
		path string
		want bool // allowed
	}{
		{"/srv/data/report.csv", true},
		{"/srv/data/notes.txt", true},
		{"/srv/data/README", true},     // claims no extension, so claims nothing to refuse
		{"/srv/data/notes.md", false},  // not on the allow list
		{"/srv/data/x.CSV", true},      // the comparison is without case
		{"/srv/data/shell.php", false}, // denied outright
		{"/srv/data/a.exe.csv", false}, // an exe whatever the last suffix says
		{"/srv/data/invoice.pdf.exe", false},
	} {
		id++
		sftpOpen(t, ch, id, c.path, 0x1)
		typ, payload := readSFTP(t, ch)
		allowed := typ == 102
		if !allowed && (typ != 101 || binary.BigEndian.Uint32(payload[4:]) != 3) {
			t.Fatalf("%s: unexpected reply type %d", c.path, typ)
		}
		if allowed != c.want {
			t.Errorf("%s: allowed=%v, want %v", c.path, allowed, c.want)
		}
	}
}

// A size bound is counted from where a write ends, not from how much
// has been sent, so writing out of order does not walk past it.
func TestSFTPMaxFileBytes(t *testing.T) {
	s, addr, key, _ := bastion(t, `        sftp: {allow_paths: ["/srv/data/**"], max_file_bytes: 64}`)
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	h := sftpOpenHandle(t, ch, 1, "/srv/data/upload.bin", 0x2|0x8)
	sftpWriteReq(t, ch, 2, h, 0, make([]byte, 40))
	if sftpDenied(t, ch) {
		t.Fatal("a write inside the bound was refused")
	}
	sftpWriteReq(t, ch, 3, h, 40, make([]byte, 40))
	if !sftpDenied(t, ch) {
		t.Fatal("a write past the bound was allowed")
	}
	// A second file, written far out: the bound is about the file the
	// writes make, not the bytes that arrived.
	h2 := sftpOpenHandle(t, ch, 4, "/srv/data/sparse.bin", 0x2|0x8)
	sftpWriteReq(t, ch, 5, h2, 1<<20, []byte{1})
	if !sftpDenied(t, ch) {
		t.Fatal("a one byte write at a megabyte made a file past the bound")
	}
	if sn := s.stats.snapshot(); sn.SFTPRefused < 2 {
		t.Fatalf("refusals counted: %d", sn.SFTPRefused)
	}
}

// A write to a handle whose open this proxy never decided on cannot be
// held to any bound, so it is not a write to pass on.
func TestSFTPUnknownHandle(t *testing.T) {
	_, addr, key, tg := bastion(t, `        sftp: {allow_paths: ["/srv/data/**"], max_file_bytes: 1024}`)
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)
	sftpWriteReq(t, ch, 1, "invented", 0, []byte("payload"))
	if !sftpDenied(t, ch) {
		t.Fatal("a write on an invented handle was allowed")
	}
	for _, r := range tg.seen() {
		if r == "sftp:6" {
			t.Fatal("the write reached the target")
		}
	}
}

// Rules read what is written, per file: two uploads on one channel are
// two files, and a match refuses that write rather than the other's.
func TestSFTPYARAWrite(t *testing.T) {
	rules := rulesFile(t)
	extra := fmt.Sprintf(`        sftp:
          allow_paths: ["/srv/data/**"]
          yara: {rules_file: %s, action: log}`, rules)
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	clean := sftpOpenHandle(t, ch, 1, "/srv/data/clean.bin", 0x2|0x8)
	dirty := sftpOpenHandle(t, ch, 2, "/srv/data/dirty.bin", 0x2|0x8)

	sftpWriteReq(t, ch, 3, clean, 0, []byte("nothing of interest here"))
	if sftpDenied(t, ch) {
		t.Fatal("a clean write was refused")
	}
	sftpWriteReq(t, ch, 4, dirty, 0, []byte("carrying a TOP-SECRET-MARKER out"))
	if !sftpDenied(t, ch) {
		t.Fatal("a write a rule matched was allowed")
	}
	// The other file is untouched by the other's match: one scanner per
	// handle, not one per channel.
	sftpWriteReq(t, ch, 5, clean, 24, []byte(" and still nothing"))
	if sftpDenied(t, ch) {
		t.Fatal("the clean file was refused for what another file carried")
	}
	writes := 0
	for _, r := range tg.seen() {
		if r == "sftp:6" {
			writes++
		}
	}
	if writes != 2 {
		t.Fatalf("the target saw %d writes, want 2", writes)
	}
	if sn := s.stats.snapshot(); sn.YARAMatches == 0 {
		t.Fatal("the match was not counted")
	}
}

// A target that finishes a command and closes its channel while the
// reply to the exec that started it is still on its way back must not
// cost the client that reply. The window is small, so this runs the
// exchange enough times to catch it: before the fix it failed about
// one run in a hundred with EOF from a command that had in fact run.
func TestSSHExecReplyNotLost(t *testing.T) {
	_, addr, key, _ := bastion(t, "")
	c := dialBastion(t, addr, key)
	for i := 0; i < 400; i++ {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		out, err := sess.Output("uptime")
		if err != nil || string(out) != "ran uptime" {
			t.Fatalf("run %d: %q %v", i, out, err)
		}
	}
}

// recorded waits for the listener to finish and close a recording. The
// file is written as the session runs and closed when the channel ends,
// which is after the client's own connection has gone.
func recorded(t *testing.T, s *Server, want uint64) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if s.stats.snapshot().SSHRecorded >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d recordings were closed, want %d", s.stats.snapshot().SSHRecorded, want)
}

// readCast reads the one recording in a directory and returns its
// header and events.
func readCast(t *testing.T, dir string) (map[string]any, [][]any) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 {
		t.Fatalf("recordings in %s: %v", dir, names)
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0])) //nolint:gosec // a directory this test made
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("recording mode %v: it holds everything the session showed", perm)
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var hdr map[string]any
	if err := json.Unmarshal([]byte(parts[0]), &hdr); err != nil {
		t.Fatalf("header %q: %v", parts[0], err)
	}
	var evs [][]any
	for _, p := range parts[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(p), &ev); err != nil {
			t.Fatalf("event %q: %v", p, err)
		}
		evs = append(evs, ev)
	}
	return hdr, evs
}

// castText joins the data of every event of one kind.
func castText(evs [][]any, kind string) string {
	var b strings.Builder
	for _, ev := range evs {
		if len(ev) == 3 && ev[1] == kind {
			if s, ok := ev[2].(string); ok {
				b.WriteString(s)
			}
		}
	}
	return b.String()
}

// What the session showed is written to a file that can be replayed,
// and what was typed is not, because the input stream carries what the
// screen never showed.
func TestSSHRecording(t *testing.T) {
	dir := t.TempDir()
	extra := fmt.Sprintf("        recording: {directory: %s}", dir)
	s, addr, key, _ := bastion(t, extra)
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("exec: %q %v", out, err)
	}
	_ = c.Close()
	recorded(t, s, 1)

	hdr, evs := readCast(t, dir)
	if hdr["version"] != float64(2) {
		t.Fatalf("header = %v", hdr)
	}
	if hdr["command"] != "uptime" {
		t.Errorf("the command is not in the header: %v", hdr["command"])
	}
	if title, _ := hdr["title"].(string); !strings.Contains(title, "alice") {
		t.Errorf("title = %q, which does not say whose session it is", title)
	}
	if got := castText(evs, "o"); got != "ran uptime" {
		t.Errorf("recorded output %q, want %q", got, "ran uptime")
	}
	if got := castText(evs, "i"); got != "" {
		t.Errorf("input was recorded without being asked for: %q", got)
	}
}

// With input on, the keystrokes are there too — which is the setting
// that turns a recording into a keylogger, and why it is not the
// default.
func TestSSHRecordingInput(t *testing.T) {
	dir := t.TempDir()
	extra := fmt.Sprintf("        recording: {directory: %s, input: true}", dir)
	s, addr, key, _ := bastion(t, extra)
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	sess.Stdin = strings.NewReader("hunter2\n")
	out, err := sess.Output("cat")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "hunter2\n" {
		t.Fatalf("the session itself lost the line: %q", out)
	}
	_ = c.Close()
	recorded(t, s, 1)

	_, evs := readCast(t, dir)
	if got := castText(evs, "i"); !strings.Contains(got, "hunter2") {
		t.Errorf("input = %q, want the typed line", got)
	}
}

// The bound stops the file rather than the session, and the file says
// so: a recording that is silently short still looks like the whole
// session.
func TestSSHRecordingBound(t *testing.T) {
	dir := t.TempDir()
	extra := fmt.Sprintf("        recording: {directory: %s, max_file_bytes: 4096}", dir)
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 9000)
	out, err := sess.Output(long)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	// The session itself is untouched by the bound.
	if len(out) != len("ran ")+len(long) {
		t.Fatalf("the session lost output: %d bytes", len(out))
	}
	if len(tg.seen()) == 0 {
		t.Fatal("nothing reached the target")
	}
	_ = c.Close()
	recorded(t, s, 1)

	_, evs := readCast(t, dir)
	if len(castText(evs, "o")) >= len(out) {
		t.Error("the bound did not stop the recording")
	}
	if !strings.Contains(castText(evs, "m"), "max_file_bytes") {
		t.Error("the file does not say it is short")
	}
}

// A principal may be recorded where the listener is not, and a
// principal may be spared where it is.
func TestSSHRecordingPerPrincipal(t *testing.T) {
	dir := t.TempDir()
	quiet := t.TempDir()
	testDir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, testDir, "host")
	_, targetHostSigner, _ := sshKey(t, testDir, "target_host")
	upKeyPath, _, _ := sshKey(t, testDir, "upstream")
	_, watchedSigner, watchedAuthorized := sshKey(t, testDir, "watched")
	_, sparedSigner, sparedAuthorized := sshKey(t, testDir, "spared")
	tg := startTargetSSH(t, targetHostSigner)

	authorized := filepath.Join(testDir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(watchedAuthorized+sparedAuthorized), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(testDir, "known_hosts")
	line := fmt.Sprintf("%s %s", tg.addr(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(targetHostSigner.PublicKey()))))
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
        recording: {directory: %s}
        principals:
          - name: spared
            fingerprints: ["%s"]
            policy:
              recording: {enabled: false}
          - name: watched
            fingerprints: ["%s"]
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: %s}]
`, hostKeyPath, authorized, upKeyPath, known, dir,
		ssh.FingerprintSHA256(sparedSigner.PublicKey()),
		ssh.FingerprintSHA256(watchedSigner.PublicKey()), tg.addr())
	s, _ := startServer(t, yaml)
	addr := s.Addrs()["bastion"]

	for _, signer := range []ssh.Signer{sparedSigner, watchedSigner} {
		c := dialBastion(t, addr, signer)
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Output("uptime"); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	recorded(t, s, 1)
	if _, evs := readCast(t, dir); !strings.Contains(castText(evs, "o"), "ran uptime") {
		t.Error("the watched principal was not recorded")
	}
	if entries, err := os.ReadDir(quiet); err != nil || len(entries) != 0 {
		t.Errorf("the spared principal wrote something: %v %v", entries, err)
	}
}
