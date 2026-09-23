package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/safe"
	sftpwire "github.com/rom/xproxy/internal/sftp"
	"github.com/rom/xproxy/internal/streamscan"
	"github.com/rom/xproxy/internal/textsafe"
)

// sftpPolicy is the compiled form of an ssh listener's sftp section.
type sftpPolicy struct {
	readOnly   bool
	allowPaths []string
	denyPaths  []string
	denyOps    map[string]bool
	allowExt   map[string]bool
	denyExt    map[string]bool
	maxFile    int64
	maxOpen    int
	maxPacket  int
	yara       *streamscan.Guard
	// icap names the scanning service written files go through, when
	// one is configured.
	icap *config.TransferICAP
	// vars are the substitutions the path lists actually carry. Only
	// these are resolved, and only these have to be a name that can
	// stand in a pattern: a listener with no principals has no
	// principal name, which is a reason to refuse {principal} and no
	// reason to refuse {user}.
	vars map[string]bool
}

func newSFTPPolicy(c *config.SFTPPolicy) (*sftpPolicy, error) {
	p := &sftpPolicy{readOnly: c.ReadOnly, maxPacket: c.MaxPacketSize,
		maxFile: c.MaxFileBytes, maxOpen: c.MaxOpenFiles,
		allowPaths: c.AllowPaths, denyPaths: c.DenyPaths, denyOps: map[string]bool{},
		icap:     c.ICAP,
		allowExt: map[string]bool{}, denyExt: map[string]bool{}}
	for _, op := range c.DenyOperations {
		op = strings.ToLower(op)
		if !config.SFTPOperations[op] {
			return nil, fmt.Errorf("sftp deny_operations: %q is not an operation", op)
		}
		p.denyOps[op] = true
	}
	for _, e := range c.AllowExtensions {
		p.allowExt[strings.ToLower(e)] = true
	}
	for _, e := range c.DenyExtensions {
		p.denyExt[strings.ToLower(e)] = true
	}
	p.vars = map[string]bool{}
	for _, list := range [][]string{c.AllowPaths, c.DenyPaths} {
		for _, pattern := range list {
			for name := range config.SFTPPathVars {
				if strings.Contains(pattern, "{"+name+"}") {
					p.vars[name] = true
				}
			}
		}
	}
	if c.YARA != nil {
		g, err := streamscan.New(c.YARA)
		if err != nil {
			return nil, err
		}
		p.yara = g
	}
	return p, nil
}

// forSession substitutes {user} and {principal} in the path lists. It
// returns the policy itself when there is nothing to substitute, so the
// common case shares one compiled policy across every session.
//
// A name that could change what a pattern means is refused rather than
// escaped: a login of "../.." expanded into an allow list is an allow
// list for somebody else's directory, and a login carrying "*" is one
// that widens its own rule. Names like that do not belong to people, so
// refusing the session costs nothing real and guessing costs the
// policy.
func (p *sftpPolicy) forSession(user, principal string) (*sftpPolicy, error) {
	if p == nil || len(p.vars) == 0 {
		return p, nil
	}
	for _, v := range []struct{ name, value string }{{"user", user}, {"principal", principal}} {
		if p.vars[v.name] && !textsafe.Component(v.value) {
			return nil, fmt.Errorf("{%s}: %q cannot stand in a path pattern", v.name, textsafe.Clip256(v.value))
		}
	}
	r := strings.NewReplacer("{user}", user, "{principal}", principal)
	out := *p
	out.allowPaths = make([]string, len(p.allowPaths))
	for i, a := range p.allowPaths {
		out.allowPaths[i] = r.Replace(a)
	}
	out.denyPaths = make([]string, len(p.denyPaths))
	for i, d := range p.denyPaths {
		out.denyPaths[i] = r.Replace(d)
	}
	return &out, nil
}

// extensionAllowed applies the extension lists to one name. Every
// extension a name carries is read, not only the last: "invoice.pdf.exe"
// is an exe on every server that runs one, and a check that looks only
// at the last suffix of what it is given is a check the name chooses
// the answer to.
func (p *sftpPolicy) extensionAllowed(name string) bool {
	if len(p.allowExt) == 0 && len(p.denyExt) == 0 {
		return true
	}
	base := path.Base(name)
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		// No extension at all. An allow list is about what a file is
		// called, and a name that claims nothing claims nothing to
		// allow, so it passes unless a deny list catches it elsewhere.
		return true
	}
	exts := parts[1:]
	for _, e := range exts {
		if p.denyExt[strings.ToLower(e)] {
			return false
		}
	}
	if len(p.allowExt) == 0 {
		return true
	}
	// The last extension is the one the server acts on, so it is the
	// one the allow list has to cover.
	return p.allowExt[strings.ToLower(exts[len(exts)-1])]
}

// check decides one SFTP request. It returns the reason it was refused,
// empty when the request may go on.
func (p *sftpPolicy) check(r sftpwire.Request) string {
	op := sftpwire.TypeName(r.Type)
	if r.Type == sftpwire.INIT {
		// Only version 3 is parsed here. A client that negotiates
		// higher would send packets this cannot be trusted to read, and
		// guessing at them is how a policy stops holding.
		if r.Flags > sftpwire.Version {
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
		clean, ok := sftpwire.CleanPath(name)
		if !ok {
			// A path that climbs above its own root means whatever the
			// server's working directory makes it mean, which the proxy
			// cannot see. There is no honest way to check it.
			return "relative_path"
		}
		for _, d := range p.denyPaths {
			if sftpwire.MatchPath(d, clean) {
				return "path_denied"
			}
		}
		switch r.Type {
		case sftpwire.OPEN, sftpwire.RENAME, sftpwire.SYMLINK:
			// The requests that decide what a file is called. A stat or
			// a remove is not: refusing to delete a file because of
			// what it is called leaves it there.
			if !p.extensionAllowed(clean) {
				return "extension"
			}
		}
		if len(p.allowPaths) == 0 {
			continue
		}
		allowed := false
		for _, a := range p.allowPaths {
			if sftpwire.MatchPath(a, clean) {
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

// sftpFile is what the proxy remembers about one open handle: the path
// it was opened on, how far it has been written, and the rules reading
// what goes into it.
type sftpFile struct {
	path    string
	written int64
	yara    *streamscan.Stream
	// held is the upload this proxy is keeping until a scanner has
	// seen it, nil when this file is not scanned.
	held *scanState
}

// sftpFiles is the handle table of one session. The two relay
// directions share it — a handle is created by the server's reply and
// used by the client's next request — so every access takes the lock.
type sftpFiles struct {
	mu      sync.Mutex
	pending map[uint32]pendingOpen // request id -> what its OPEN asked for
	open    map[string]*sftpFile   // handle -> file
	max     int
}

// pendingOpen is an OPEN waiting for the handle the server will answer
// with: the path it named, and whether what is written to it is held
// for a scanner.
type pendingOpen struct {
	path string
	scan bool
}

func newSFTPFiles(max int) *sftpFiles {
	return &sftpFiles{pending: map[uint32]pendingOpen{}, open: map[string]*sftpFile{}, max: max}
}

// expect records the path an OPEN named, so the handle the server
// answers with can be connected to it.
func (f *sftpFiles) expect(id uint32, path string, scan bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) >= f.max {
		// A client that opens without ever reading the answers would
		// otherwise grow this table without bound. Dropping the oldest
		// is not possible here without an order, and dropping the new
		// one only loses the association, which the write path treats
		// as an unknown handle.
		return
	}
	f.pending[id] = pendingOpen{path: path, scan: scan}
}

// bind connects a handle to the path its OPEN named.
func (f *sftpFiles) bind(id uint32, handle string, g *streamscan.Guard) {
	f.mu.Lock()
	defer f.mu.Unlock()
	po, ok := f.pending[id]
	if !ok {
		return
	}
	delete(f.pending, id)
	if len(f.open) >= f.max {
		return
	}
	file := &sftpFile{path: po.path, yara: g.Stream("client")}
	if po.scan {
		file.held = &scanState{}
	}
	f.open[handle] = file
}

// file returns the record for a handle, or nil when the proxy never saw
// the open it came from.
func (f *sftpFiles) file(handle string) *sftpFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open[handle]
}

// take removes a handle and returns what the proxy knew about it, so
// a close can act on the file it is closing.
func (f *sftpFiles) take(handle string) *sftpFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	file := f.open[handle]
	delete(f.open, handle)
	return file
}

// relaySFTP relays an sftp subsystem channel, deciding each request.
// Both directions are framed: a refusal is a packet the proxy writes
// into the client's stream, so it has to go between whole packets
// rather than into the middle of one.
//
// The server's direction is read too, for one packet: the HANDLE reply
// that says which handle the OPEN this proxy decided on became. Without
// it a WRITE names something the proxy cannot connect to a path, and a
// size bound or a rule set over what is written would be a bound on
// nothing.
func (se *session) relaySFTP(clientCh, upCh cssh.Channel, p *sftpPolicy) {
	t := se.t
	files := newSFTPFiles(p.maxOpen)
	svc := t.icapForSFTP(p)
	// replayed holds the ids of writes this proxy sent on the client's
	// behalf. The client was answered when it sent them, so the
	// server's answers to those same ids must not reach it too.
	replayed := newReplayed()
	var mu sync.Mutex
	write := func(dst io.Writer, pkt sftpwire.Packet) error {
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
			pkt, err := sftpwire.ReadPacket(br, p.maxPacket)
			if err != nil {
				return
			}
			if pkt.Type == sftpwire.HANDLE {
				if id, handle, err := sftpwire.ParseHandleReply(pkt); err == nil {
					files.bind(id, handle, p.yara)
				}
			}
			// A reply to a write this proxy replayed is the answer to a
			// request the client already had an answer for. Passing it
			// on would be a second status for one id, which is the kind
			// of thing that desynchronises a client for good.
			if pkt.Type == sftpwire.STATUS && replayed.took(sftpwire.StatusID(pkt)) {
				continue
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
			pkt, err := sftpwire.ReadPacket(br, p.maxPacket)
			if err != nil {
				if errors.Is(err, sftpwire.ErrTooLarge) || errors.Is(err, sftpwire.ErrMalformed) {
					t.engine.Counters().SFTPRefused.Add(1)
					t.deny(se.ip, "sftp_malformed", err.Error())
				}
				_ = upCh.CloseWrite()
				return
			}
			req, err := sftpwire.ParseRequest(pkt)
			if err != nil {
				t.engine.Counters().SFTPRefused.Add(1)
				t.deny(se.ip, "sftp_malformed", err.Error())
				_ = upCh.CloseWrite()
				return
			}
			reason := p.check(req)
			if reason == "" {
				reason = se.sftpWrite(p, files, req)
			}
			if reason != "" {
				se.refused.Add(1)
				t.engine.Counters().SFTPRefused.Add(1)
				t.deny(se.ip, "sftp_refused", sftpwire.TypeName(req.Type)+" "+reason+" "+textsafe.Clip256(se.sftpName(files, req)))
				if req.Type == sftpwire.INIT {
					// There is no status packet before the version
					// exchange, so the only answer is to end it.
					_ = upCh.CloseWrite()
					return
				}
				_ = write(clientCh, sftpwire.StatusPacket(req.ID, sftpwire.StatusPermissionDenied, "refused by policy"))
				if reason == "yara" && p.yara != nil && p.yara.Cfg.Action == "close" {
					// The rules said close, and on a file transfer the
					// thing to close is the transfer: the refusal above
					// is what the client is told, and this is what stops
					// the rest of the file arriving.
					_ = upCh.CloseWrite()
					return
				}
				continue
			}
			note := ""
			switch req.Type {
			case sftpwire.OPEN:
				// A handle opened for writing is scanned when a service
				// is configured for it. Reading the flags is what tells
				// an upload from a download, before either has moved a
				// byte.
				files.expect(req.ID, req.Path, svc != nil && req.Flags&sftpwire.FlagWrite != 0)
			case sftpwire.OPENDIR:
				files.expect(req.ID, req.Path, false)
			case sftpwire.WRITE:
				// A write to a held file is answered here and kept: the
				// server sees it only once the scanner has allowed the
				// whole file.
				if f := files.file(req.Handle); f != nil && f.held != nil && !f.held.released {
					if held, reason := se.holdWrite(svc, f, req, pkt); reason != "" {
						se.refused.Add(1)
						t.engine.Counters().SFTPRefused.Add(1)
						t.deny(se.ip, "sftp_refused", "WRITE "+reason+" "+textsafe.Clip256(f.path))
						_ = write(clientCh, sftpwire.StatusPacket(req.ID, sftpwire.StatusFailure, "refused by policy"))
						continue
					} else if held {
						_ = write(clientCh, sftpwire.StatusPacket(req.ID, sftpwire.StatusOK, "ok"))
						continue
					}
					// Not held after all (the bound was passed and the
					// service said bypass): the writes already kept are
					// released below and this one goes on as usual.
					if err := se.releaseHeld(f, write, upCh, replayed); err != nil {
						return
					}
				}
			case sftpwire.CLOSE:
				if f := files.take(req.Handle); f != nil && f.held != nil && !f.held.released {
					blocked, n := se.finishHeld(svc, f, write, upCh, clientCh, replayed, req.ID)
					note = scanNote(blocked, n)
					if blocked != "" {
						// The file never reached the server, so the
						// close is answered here rather than forwarded.
						t.engine.Logs().Access.Info("sftp", "listener", t.cfg.Name, "client_ip", se.ip.String(),
							"user", textsafe.Clip64(se.user), "principal", se.principal, "target", se.target,
							"op", "CLOSE", "path", textsafe.Clip256(f.path), "scan", note)
						continue
					}
				}
			}
			t.engine.Counters().SFTPRequests.Add(1)
			attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(),
				"user", textsafe.Clip64(se.user), "principal", se.principal, "target", se.target,
				"op", sftpwire.TypeName(req.Type), "path", textsafe.Clip256(se.sftpName(files, req))}
			if note != "" {
				attrs = append(attrs, "scan", note)
			}
			t.engine.Logs().Access.Info("sftp", attrs...)
			if write(upCh, pkt) != nil {
				return
			}
		}
	}()
	wg.Wait()
}

// sftpName is the path a request concerns, for the log: its own, or the
// one the handle it names was opened on.
func (se *session) sftpName(files *sftpFiles, r sftpwire.Request) string {
	if r.Path != "" || r.Handle == "" {
		return r.Path
	}
	if f := files.file(r.Handle); f != nil {
		return f.path
	}
	return ""
}

// sftpWrite applies what only a write can be judged on: how much of a
// file it makes, and what is in it. It returns the reason to refuse, or
// empty.
func (se *session) sftpWrite(p *sftpPolicy, files *sftpFiles, r sftpwire.Request) string {
	if r.Type != sftpwire.WRITE {
		return ""
	}
	if p.maxFile <= 0 && p.yara == nil {
		return ""
	}
	f := files.file(r.Handle)
	if f == nil {
		// A handle from an open this proxy never saw decided. That is
		// either a client writing to something it did not open through
		// here, or a table that filled; either way there is no file to
		// hold to a bound, and a write that cannot be judged is not a
		// write to pass on.
		return "unknown_handle"
	}
	if p.maxFile > 0 {
		// The end of this write, not the count of bytes sent: a client
		// that writes out of order would otherwise stay under any
		// total while making a file of any size.
		if end := int64(r.Offset) + int64(len(r.Data)); end > f.written { //nolint:gosec // an offset bounded by the packet size below
			f.written = end
		}
		if f.written > p.maxFile {
			return "max_file_bytes"
		}
	}
	if f.yara != nil && f.yara.Feed(r.Data) {
		se.sftpYARAReport(f)
		return "yara"
	}
	return ""
}

// sftpYARAReport records a match on one file.
func (se *session) sftpYARAReport(f *sftpFile) {
	t := se.t
	ms := f.yara.Matches()
	names := make([]string, 0, len(ms))
	tags := map[string]bool{}
	for _, m := range ms {
		names = append(names, m.Rule)
		for _, tag := range m.Tags {
			tags[tag] = true
		}
	}
	tagList := make([]string, 0, len(tags))
	for tag := range tags {
		tagList = append(tagList, tag)
	}
	sort.Strings(tagList)
	t.engine.Counters().YARAMatches.Add(1)
	t.engine.Logs().SecurityEvent(context.Background(), f.yara.Policy().Action, "yara_match",
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "proto", "sftp",
		"user", textsafe.Clip64(se.user), "principal", se.principal, "path", textsafe.Clip256(f.path),
		"rules", strings.Join(names, ","), "tags", strings.Join(tagList, ","))
	if bl := t.engine.Bans(); bl != nil && se.ip.IsValid() {
		bl.Observe(se.ip, "yara")
	}
}

// knownHostsCallback verifies a target's host key against an OpenSSH
// known_hosts file. The file is read once, at build time: a bastion
// that re-reads it per connection would accept a key added between two
// connections of the same session.
func knownHostsCallback(path string) (cssh.HostKeyCallback, error) {
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
		marker, hosts, key, _, rest, err := cssh.ParseKnownHosts(raw)
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
	return func(hostname string, remote net.Addr, key cssh.PublicKey) error {
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
		return fmt.Errorf("host key for %s is not in known_hosts (%s)", hostname, cssh.FingerprintSHA256(key))
	}, nil
}

// copyBounded copies without the large buffer io.Copy would allocate
// per channel; an SSH channel's window is 64 KiB, so a 32 KiB buffer is
// never the limit.
func copyBounded(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	return io.CopyBuffer(dst, src, buf)
}
