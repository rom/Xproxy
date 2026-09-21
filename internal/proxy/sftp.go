package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sftp"
)

// sftpPolicy is the compiled form of an ssh listener's sftp section.
type sftpPolicy struct {
	readOnly   bool
	allowPaths []string
	denyPaths  []string
	denyOps    map[string]bool
	maxPacket  int
}

func newSFTPPolicy(c *config.SFTPPolicy) (*sftpPolicy, error) {
	p := &sftpPolicy{readOnly: c.ReadOnly, maxPacket: c.MaxPacketSize,
		allowPaths: c.AllowPaths, denyPaths: c.DenyPaths, denyOps: map[string]bool{}}
	for _, op := range c.DenyOperations {
		op = strings.ToLower(op)
		if !config.SFTPOperations[op] {
			return nil, fmt.Errorf("sftp deny_operations: %q is not an operation", op)
		}
		p.denyOps[op] = true
	}
	return p, nil
}

// check decides one SFTP request. It returns the reason it was refused,
// empty when the request may go on.
func (p *sftpPolicy) check(r sftp.Request) string {
	op := sftp.TypeName(r.Type)
	if r.Type == sftp.INIT {
		// Only version 3 is parsed here. A client that negotiates
		// higher would send packets this cannot be trusted to read, and
		// guessing at them is how a policy stops holding.
		if r.Flags > sftp.Version {
			return "version"
		}
		return ""
	}
	if p.denyOps[op] {
		return "operation"
	}
	if p.readOnly && r.Writes {
		return "read_only"
	}
	for _, name := range []string{r.Path, r.Target} {
		if name == "" {
			continue
		}
		clean, ok := sftp.CleanPath(name)
		if !ok {
			// A path that climbs above its own root means whatever the
			// server's working directory makes it mean, which the proxy
			// cannot see. There is no honest way to check it.
			return "relative_path"
		}
		for _, d := range p.denyPaths {
			if sftp.MatchPath(d, clean) {
				return "path_denied"
			}
		}
		if len(p.allowPaths) == 0 {
			continue
		}
		allowed := false
		for _, a := range p.allowPaths {
			if sftp.MatchPath(a, clean) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "path_not_allowed"
		}
	}
	return ""
}

// relaySFTP relays an sftp subsystem channel, deciding each request.
// Both directions are framed: a refusal is a packet the proxy writes
// into the client's stream, so it has to go between whole packets
// rather than into the middle of one.
func (se *sshSession) relaySFTP(clientCh, upCh ssh.Channel) {
	t := se.t
	p := t.sftp
	var mu sync.Mutex
	write := func(dst io.Writer, pkt sftp.Packet) error {
		mu.Lock()
		defer mu.Unlock()
		_, err := dst.Write(pkt.Encode())
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("sftp to client")
		br := bufio.NewReaderSize(upCh, 32<<10)
		for {
			pkt, err := sftp.ReadPacket(br, p.maxPacket)
			if err != nil {
				return
			}
			if write(clientCh, pkt) != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("sftp to target")
		br := bufio.NewReaderSize(clientCh, 32<<10)
		for {
			pkt, err := sftp.ReadPacket(br, p.maxPacket)
			if err != nil {
				if errors.Is(err, sftp.ErrTooLarge) || errors.Is(err, sftp.ErrMalformed) {
					t.s.stats.SFTPRefused.Add(1)
					t.deny(se.ip, "sftp_malformed", err.Error())
				}
				_ = upCh.CloseWrite()
				return
			}
			req, err := sftp.ParseRequest(pkt)
			if err != nil {
				t.s.stats.SFTPRefused.Add(1)
				t.deny(se.ip, "sftp_malformed", err.Error())
				_ = upCh.CloseWrite()
				return
			}
			if reason := p.check(req); reason != "" {
				se.refused.Add(1)
				t.s.stats.SFTPRefused.Add(1)
				t.deny(se.ip, "sftp_refused", sftp.TypeName(req.Type)+" "+reason+" "+sftpClip(req.Path))
				if req.Type == sftp.INIT {
					// There is no status packet before the version
					// exchange, so the only answer is to end it.
					_ = upCh.CloseWrite()
					return
				}
				_ = write(clientCh, sftp.StatusPacket(req.ID, sftp.StatusPermissionDenied, "refused by policy"))
				continue
			}
			t.s.stats.SFTPRequests.Add(1)
			t.s.logs.Access.Info("sftp", "listener", t.cfg.Name, "client_ip", se.ip.String(),
				"user", trimUser(se.user), "target", se.target,
				"op", sftp.TypeName(req.Type), "path", sftpClip(req.Path))
			if write(upCh, pkt) != nil {
				return
			}
		}
	}()
	wg.Wait()
}

// sftpClip bounds what a path or command contributes to a log line and
// keeps control characters out of it.
func sftpClip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}

// knownHostsCallback verifies a target's host key against an OpenSSH
// known_hosts file. The file is read once, at build time: a bastion
// that re-reads it per connection would accept a key added between two
// connections of the same session.
func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a path from the configuration
	if err != nil {
		return nil, err
	}
	type entry struct {
		hosts []string
		key   string
	}
	var entries []entry
	for len(raw) > 0 {
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		raw = rest
		if marker == "revoked" {
			// A revoked key is one to refuse, and this loader has no
			// way to express that beyond not accepting it. Treating it
			// as a trusted entry would be the opposite of what the file
			// says, so it is dropped.
			continue
		}
		entries = append(entries, entry{hosts: hosts, key: string(key.Marshal())})
	}
	if len(entries) == 0 {
		return nil, errors.New("no host keys in the file")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		want := string(key.Marshal())
		addr := remote.String()
		for _, e := range entries {
			if e.key != want {
				continue
			}
			for _, h := range e.hosts {
				if h == hostname || h == addr || strings.HasPrefix(hostname, h+":") {
					return nil
				}
			}
		}
		return fmt.Errorf("host key for %s is not in known_hosts (%s)", hostname, ssh.FingerprintSHA256(key))
	}, nil
}

// copyBounded copies without the large buffer io.Copy would allocate
// per channel; an SSH channel's window is 64 KiB, so a 32 KiB buffer is
// never the limit.
func copyBounded(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	return io.CopyBuffer(dst, src, buf)
}
