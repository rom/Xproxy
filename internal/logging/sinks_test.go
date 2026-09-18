package logging

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

func TestRedactor(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Redaction{ClientIP: "hash", HashSecretFile: filepath.Join(dir, "k"), UserAgent: "drop", Referer: "origin", Claims: "hash", DropFields: []string{"referer_len"}}
	r, err := NewRedactor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := NewRedactor(cfg) // same key file: same pseudonyms
	ip, _ := r.Attr(slog.String("client_ip", "203.0.113.9"))
	ip2, _ := r2.Attr(slog.String("client_ip", "203.0.113.9"))
	if !strings.HasPrefix(ip.Value.String(), "h:") || ip.Value.String() != ip2.Value.String() || ip.Value.String() == "203.0.113.9" {
		t.Fatalf("hash: %v %v", ip, ip2)
	}
	if _, keep := r.Attr(slog.String("user_agent", "x")); keep {
		t.Fatal("user agent kept")
	}
	ref, _ := r.Attr(slog.String("referer", "https://example.com/private/page?token=1"))
	if ref.Value.String() != "https://example.com" {
		t.Fatalf("referer: %v", ref)
	}
	sub, _ := r.Attr(slog.String("jwt_sub", "alice"))
	if !strings.HasPrefix(sub.Value.String(), "h:") {
		t.Fatalf("claims: %v", sub)
	}
	prov, _ := r.Attr(slog.String("jwt_provider", "idp"))
	if prov.Value.String() != "idp" {
		t.Fatal("provider name should not be hashed")
	}
	if _, keep := r.Attr(slog.String("referer_len", "3")); keep {
		t.Fatal("drop_fields")
	}
	path, keep := r.Attr(slog.String("path", "/x"))
	if !keep || path.Value.String() != "/x" {
		t.Fatal("unrelated attribute changed")
	}
	tr, _ := NewRedactor(&config.Redaction{ClientIP: "truncate", UserAgent: "keep", Referer: "keep", Claims: "keep"})
	v4, _ := tr.Attr(slog.String("client_ip", "203.0.113.9"))
	v6, _ := tr.Attr(slog.String("client_ip", "2001:db8:abcd:1234::1"))
	if v4.Value.String() != "203.0.113.0/24" || v6.Value.String() != "2001:db8:abcd::/48" {
		t.Fatalf("truncate: %v %v", v4, v6)
	}
	bad, _ := tr.Attr(slog.String("client_ip", "garbage"))
	if bad.Value.String() != "?" {
		t.Fatal("garbage ip")
	}
}

func TestRedactionInStreams(t *testing.T) {
	dir := t.TempDir()
	on := true
	cfg := config.Logging{Directory: dir, Level: "info",
		Access: config.LogStream{File: "access.log", Sinks: []string{"file"}}, Error: config.LogStream{File: "error.log", Sinks: []string{"file"}},
		Security: config.LogStream{File: "security.log", Sinks: []string{"file"}}, Audit: config.LogStream{File: "audit.log", Sinks: []string{"file"}},
		Redaction: &config.Redaction{Enabled: &on, Streams: []string{"access"}, ClientIP: "truncate", UserAgent: "drop", Referer: "drop", Claims: "drop"}}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.Access.Info("request", "client_ip", "203.0.113.9", "user_agent", "ua", "path", "/")
	l.Audit.Info("action", "client_ip", "203.0.113.9")
	l.Close()
	a, _ := os.ReadFile(filepath.Join(dir, "access.log"))
	if !strings.Contains(string(a), `"client_ip":"203.0.113.0/24"`) || strings.Contains(string(a), "user_agent") {
		t.Fatalf("access not redacted: %s", a)
	}
	au, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	if !strings.Contains(string(au), `"client_ip":"203.0.113.9"`) {
		t.Fatalf("audit should be untouched: %s", au)
	}
	if !l.Stats().Redaction {
		t.Fatal("stats")
	}
}

// parseJournal decodes a native journald datagram into fields.
func parseJournal(t *testing.T, b []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	for len(b) > 0 {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			t.Fatalf("unterminated field: %q", b)
		}
		line := b[:nl]
		if eq := bytes.IndexByte(line, '='); eq >= 0 {
			out[string(line[:eq])] = string(line[eq+1:])
			b = b[nl+1:]
			continue
		}
		key := string(line)
		b = b[nl+1:]
		n := binary.LittleEndian.Uint64(b[:8])
		out[key] = string(b[8 : 8+n])
		b = b[8+n+1:]
	}
	return out
}

func TestJournaldSink(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "j.sock")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cfg := config.Logging{Directory: dir, Level: "info", Journald: &config.Journald{Socket: sock, Identifier: "xproxy-test"},
		Access: config.LogStream{File: "a", Sinks: []string{"journald"}}, Error: config.LogStream{File: "e", Sinks: []string{"journald"}},
		Security: config.LogStream{File: "s", Sinks: []string{"journald"}}, Audit: config.LogStream{File: "au", Sinks: []string{"journald"}}}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Security.Warn("security", "client_ip", "203.0.113.9", "reason", "waf", "multi", "line1\nline2", "bad key!", "x")
	buf := make([]byte, 65536)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	f := parseJournal(t, buf[:n])
	if f["PRIORITY"] != "4" || f["SYSLOG_IDENTIFIER"] != "xproxy-test" || f["XPROXY_STREAM"] != "security" || f["XPROXY_CLIENT_IP"] != "203.0.113.9" || f["XPROXY_MULTI"] != "line1\nline2" || f["XPROXY_BAD_KEY_"] != "x" {
		t.Fatalf("fields: %v", f)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(f["MESSAGE"]), &m); err != nil || m["reason"] != "waf" || m["stream"] != "security" {
		t.Fatalf("message: %q %v", f["MESSAGE"], err)
	}
	if journalKey("_x") != "" || journalKey("9x") != "" || journalKey("client-ip") != "CLIENT_IP" {
		t.Fatal("journalKey")
	}
	// No files were created for journald-only streams.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("unexpected files: %v", entries)
	}
}

func syslogCfg(dir, network, addr, format string) config.Logging {
	return config.Logging{Directory: dir, Level: "info",
		Syslog: &config.Syslog{Network: network, Address: addr, Format: format, Facility: "local3", AppName: "xproxy", Hostname: "edge1", QueueSize: 64},
		Access: config.LogStream{File: "a", Sinks: []string{"syslog"}}, Error: config.LogStream{File: "e", Sinks: []string{"syslog"}},
		Security: config.LogStream{File: "s", Sinks: []string{"syslog"}}, Audit: config.LogStream{File: "au", Sinks: []string{"syslog"}}}
}

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	l, err := Open(syslogCfg(t.TempDir(), "udp", pc.LocalAddr().String(), "rfc5424"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Access.Info("request", "status", 200)
	buf := make([]byte, 9000)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	// <local3(19)*8+info(6)> = <158>1 TIMESTAMP edge1 xproxy PID access - {json}
	if !strings.HasPrefix(msg, "<158>1 ") || !strings.Contains(msg, " edge1 xproxy ") || !strings.Contains(msg, " access - {") || !strings.Contains(msg, `"status":200`) {
		t.Fatalf("rfc5424: %q", msg)
	}
	deadline := time.Now().Add(2 * time.Second)
	for l.Stats().SyslogSent == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Stats().SyslogSent != 1 {
		t.Fatalf("sent counter %+v", l.Stats())
	}
}

func TestSyslogTCPFramingAndTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "collector.test")
	pair, _ := tls.LoadX509KeyPair(cert, key)
	for _, mode := range []string{"tcp", "tcp+tls"} {
		var ln net.Listener
		var err error
		if mode == "tcp" {
			ln, err = net.Listen("tcp", "127.0.0.1:0")
		} else {
			ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		}
		if err != nil {
			t.Fatal(err)
		}
		got := make(chan string, 4)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 16384)
			n, _ := c.Read(buf)
			got <- string(buf[:n])
		}()
		cfg := syslogCfg(dir, mode, ln.Addr().String(), "rfc3164")
		cfg.Syslog.CAFile = ca.Path
		cfg.Syslog.ServerName = "collector.test"
		l, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		l.Error.Error("boom", "code", 7)
		select {
		case frame := <-got:
			// Octet counting: "LEN <PRI>..." with PRI local3(19)*8+err(3)=155.
			sp := strings.IndexByte(frame, ' ')
			n, err := strconv.Atoi(frame[:sp])
			if err != nil || n != len(frame)-sp-1 {
				t.Fatalf("%s framing: %q", mode, frame)
			}
			body := frame[sp+1:]
			if !strings.HasPrefix(body, "<155>") || !strings.Contains(body, " edge1 xproxy[") || !strings.Contains(body, `"code":7`) {
				t.Fatalf("%s rfc3164: %q", mode, body)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no frame received", mode)
		}
		l.Close()
		ln.Close()
	}
}

func TestSyslogUnixAndDrops(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "log")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	l, err := Open(syslogCfg(dir, "unix", sock, "rfc3164"))
	if err != nil {
		t.Fatal(err)
	}
	l.Audit.Info("action", "who", "root")
	buf := make([]byte, 9000)
	srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf[:n]), "<158>") || !strings.Contains(string(buf[:n]), `"who":"root"`) {
		t.Fatalf("unix: %q", buf[:n])
	}
	l.Close()

	// Unreachable collector: logging never blocks and drops are counted.
	l2, err := Open(syslogCfg(dir, "tcp", "127.0.0.1:1", "rfc5424"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 500; i++ {
		l2.Access.Info("request", "i", i)
	}
	if time.Since(start) > time.Second {
		t.Fatal("logging blocked on an unreachable collector")
	}
	if l2.Stats().SyslogDropped < 400 {
		t.Fatalf("drops not counted: %+v", l2.Stats())
	}
	l2.Close()
}

func TestMultiSink(t *testing.T) {
	dir := t.TempDir()
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	cfg := syslogCfg(dir, "udp", pc.LocalAddr().String(), "rfc5424")
	cfg.Security = config.LogStream{File: "security.log", Sinks: []string{"file", "syslog"}}
	on := true
	cfg.Redaction = &config.Redaction{Enabled: &on, Streams: []string{"security"}, ClientIP: "truncate", UserAgent: "keep", Referer: "keep", Claims: "keep"}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.SecurityEvent(context.Background(), "deny", "waf", "client_ip", "203.0.113.9")
	buf := make([]byte, 9000)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	f, _ := os.ReadFile(filepath.Join(dir, "security.log"))
	for name, s := range map[string]string{"file": string(f), "syslog": string(buf[:n])} {
		if !strings.Contains(s, `"client_ip":"203.0.113.0/24"`) || !strings.Contains(s, `"stream":"security"`) {
			t.Fatalf("%s: redaction or stream missing: %s", name, s)
		}
	}
}
