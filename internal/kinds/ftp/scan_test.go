package ftp_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/icap/icaptest"
	"github.com/rom/xproxy/internal/proxy"
)

// What happens at the edges of a scanned transfer: a file too large for
// the service to see, a service that cannot be reached, a direction the
// operator did not ask to have scanned, and a body the scanner hands
// back rewritten. Each of those is a decision about whether a file
// reaches the server, which is the whole point of putting a scanner in
// front of one.

// scanner starts a bastion whose ftp section scans transfers through a
// fake ICAP service, with extra per-service settings.
func scanner(t *testing.T, ftpICAP, service string) (*proxy.Server, string, *targetFTP, *icaptest.Server) {
	t.Helper()
	fake := icaptest.New(t, 0)
	top := fmt.Sprintf("icap:\n  services:\n    - {name: av, url: %q%s}\n", fake.URL(), service)
	s, addr, tg := ftpBastionWith(t, "        icap: {"+ftpICAP+"}", top)
	return s, addr, tg, fake
}

// store sends a file and returns the reply the transfer ended with.
func store(t *testing.T, c *ftpClient, path, body string) (int, string) {
	t.Helper()
	data := c.passive()
	if code, text := c.cmd("STOR %s", path); code != 150 {
		t.Fatalf("STOR was %d %q", code, text)
	}
	conn, err := net.Dial("tcp", data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, body); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	return c.reply()
}

// fetch asks for a file and returns what arrived and the reply the
// transfer ended with.
func fetch(t *testing.T, c *ftpClient, path string) (string, int, string) {
	t.Helper()
	data := c.passive()
	conn, err := net.Dial("tcp", data)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if code, text := c.cmd("RETR %s", path); code != 150 {
		t.Fatalf("RETR was %d %q", code, text)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	code, text := c.reply()
	return string(got), code, text
}

// A file larger than the service's max_body cannot be scanned at all.
// What happens to it is the operator's choice, and both answers have to
// work: reject means the file does not land, bypass means it does and
// the fact that nothing looked at it is said out loud.
func TestAFilePastTheScannersBoundIsRefusedOrLetThroughAsConfigured(t *testing.T) {
	big := strings.Repeat("x", 4096)

	t.Run("reject", func(t *testing.T) {
		s, addr, tg, fake := scanner(t, "service: av", ", fail: closed, max_body: 1024, body_limit_action: reject")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		code, text := store(t, c, "big.bin", big)
		if code != 426 {
			t.Fatalf("an unscannable upload ended %d %q, want 426", code, text)
		}
		if !strings.Contains(text, "max_body") {
			t.Errorf("the client was not told why: %q", text)
		}
		if got := tg.lastStored(); got != "" {
			t.Errorf("the unscanned file landed anyway: %d octets", len(got))
		}
		if n := len(mods(fake)); n != 0 {
			t.Errorf("a file past the bound was sent to the scanner %d times", n)
		}
		if st := s.Stats(); st.FTPScanBlocked != 1 || st.FTPScanned != 0 {
			t.Errorf("blocked %d scanned %d, want 1 and 0", st.FTPScanBlocked, st.FTPScanned)
		}
	})

	t.Run("bypass", func(t *testing.T) {
		s, addr, tg, fake := scanner(t, "service: av", ", fail: closed, max_body: 1024, body_limit_action: bypass")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		if code, text := store(t, c, "big.bin", big); code != 226 {
			t.Fatalf("a bypassed upload ended %d %q, want 226", code, text)
		}
		if got := tg.lastStored(); got != big {
			t.Errorf("the server got %d octets, want the %d that were sent", len(got), len(big))
		}
		if n := len(mods(fake)); n != 0 {
			t.Errorf("a bypassed file was sent to the scanner %d times", n)
		}
		// Nothing was scanned, so nothing is counted as scanned: a
		// counter that says otherwise is worse than no counter.
		if st := s.Stats(); st.FTPScanned != 0 || st.FTPScanBlocked != 0 {
			t.Errorf("scanned %d blocked %d, want 0 and 0", st.FTPScanned, st.FTPScanBlocked)
		}
	})
}

// A download is scanned as what it is: a response, through RESPMOD,
// with the ftp URL of the real file so the scanner's own log names
// something an operator can find.
func TestADownloadIsScannedAsAResponseAndCanBeRefused(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		s, addr, tg, fake := scanner(t, "service: av, uploads: false, downloads: true", ", fail: closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		got, code, text := fetch(t, c, "/pub/file.txt")
		if code != 226 {
			t.Fatalf("a clean download ended %d %q", code, text)
		}
		if got != tg.content {
			t.Errorf("the client got %q, want %q", got, tg.content)
		}
		if m := mods(fake); len(m) != 1 || m[0] != "RESPMOD" {
			t.Errorf("a download was sent as %v, want one RESPMOD", m)
		}
		if st := s.Stats(); st.FTPScanned != 1 {
			t.Errorf("ftp_scanned %d, want 1", st.FTPScanned)
		}
	})

	t.Run("refused", func(t *testing.T) {
		// The fake refuses anything whose URL names /virus, which is
		// how it stands in for a signature hit.
		s, addr, _, _ := scanner(t, "service: av, uploads: false, downloads: true", ", fail: closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		got, code, text := fetch(t, c, "/virus")
		if code != 426 {
			t.Fatalf("a refused download ended %d %q, want 426", code, text)
		}
		if !strings.Contains(text, "scanner") {
			t.Errorf("the client was not told why: %q", text)
		}
		if got != "" {
			t.Errorf("%d octets of a refused file reached the client", len(got))
		}
		if st := s.Stats(); st.FTPScanBlocked != 1 {
			t.Errorf("ftp_scan_blocked %d, want 1", st.FTPScanBlocked)
		}
	})
}

// The service is asked about the direction it was given and no other.
// A listener that scans uploads does not hand the scanner every
// download as well, which would double the bill and the latency for
// something nobody asked for.
func TestTheScannerIsAskedOnlyAboutTheDirectionItWasGiven(t *testing.T) {
	t.Run("downloads are not scanned by default", func(t *testing.T) {
		_, addr, tg, fake := scanner(t, "service: av", ", fail: closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		got, code, _ := fetch(t, c, "/pub/file.txt")
		if code != 226 || got != tg.content {
			t.Fatalf("the download ended %d with %q", code, got)
		}
		if n := len(mods(fake)); n != 0 {
			t.Errorf("a download was sent to the scanner %d times", n)
		}
	})

	t.Run("uploads can be left out", func(t *testing.T) {
		_, addr, tg, fake := scanner(t, "service: av, uploads: false, downloads: true", ", fail: closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		const payload = "not for the scanner"
		if code, text := store(t, c, "plain.txt", payload); code != 226 {
			t.Fatalf("the upload ended %d %q", code, text)
		}
		if got := tg.lastStored(); got != payload {
			t.Errorf("the server got %q", got)
		}
		if n := len(mods(fake)); n != 0 {
			t.Errorf("an upload was sent to the scanner %d times", n)
		}
	})
}

// A scanner may hand the body back changed rather than refusing it: a
// stripped macro, a cleaned archive. What it returns is what is
// delivered, in both directions.
func TestABodyTheScannerRewritesIsDeliveredAsRewritten(t *testing.T) {
	t.Run("an upload the scanner cleans", func(t *testing.T) {
		// The fake rewrites the body of anything whose URL names
		// /modify.
		s, addr, tg, _ := scanner(t, "service: av", ", fail: closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		if code, text := store(t, c, "/modify", "the original, with a macro in it"); code != 226 {
			t.Fatalf("the upload ended %d %q", code, text)
		}
		if got := tg.lastStored(); got != "clean" {
			t.Errorf("the server got %q, want the scanner's version", got)
		}
		if st := s.Stats(); st.FTPScanned != 1 || st.FTPScanBlocked != 0 {
			t.Errorf("scanned %d blocked %d, want 1 and 0", st.FTPScanned, st.FTPScanBlocked)
		}
	})

	t.Run("a download the scanner cleans", func(t *testing.T) {
		_, addr, _, _ := scanner(t, "service: av, uploads: false, downloads: true", ", fail: closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		got, code, text := fetch(t, c, "/rewrite")
		if code != 226 {
			t.Fatalf("the download ended %d %q", code, text)
		}
		if got != "rewritten" {
			t.Errorf("the client got %q, want the scanner's version", got)
		}
	})
}

// A scanner that cannot be reached is the case an operator has to have
// decided in advance, because both answers are wrong in one way: fail
// closed stops the business, fail open lets through exactly the file an
// attacker would send while the scanner is down. The proxy does what it
// was told, and says which way it went.
func TestAScannerThatCannotBeReachedFailsAsConfigured(t *testing.T) {
	// A port nobody is listening on: a scanner that is not there is
	// commoner than one that answers wrongly.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := dead.Addr().String()
	_ = dead.Close()

	bastion := func(t *testing.T, fail string) (*proxy.Server, string, *targetFTP) {
		t.Helper()
		top := fmt.Sprintf("icap:\n  services:\n    - {name: av, url: \"icap://%s/scan\", fail: %s, connect_timeout: 1s, timeout: 2s}\n", gone, fail)
		return ftpBastionWith(t, "        icap: {service: av}", top)
	}

	t.Run("closed", func(t *testing.T) {
		s, addr, tg := bastion(t, "closed")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		code, text := store(t, c, "any.bin", "a file nobody could look at")
		if code != 426 {
			t.Fatalf("an unscannable upload ended %d %q, want 426", code, text)
		}
		if !strings.Contains(text, "reached") {
			t.Errorf("the client was not told why: %q", text)
		}
		if got := tg.lastStored(); got != "" {
			t.Errorf("the file landed with the scanner down: %q", got)
		}
		if st := s.Stats(); st.FTPScanBlocked != 1 {
			t.Errorf("ftp_scan_blocked %d, want 1", st.FTPScanBlocked)
		}
	})

	t.Run("open", func(t *testing.T) {
		s, addr, tg := bastion(t, "open")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		const payload = "a file nobody looked at"
		if code, text := store(t, c, "any.bin", payload); code != 226 {
			t.Fatalf("the upload ended %d %q, want 226", code, text)
		}
		if got := tg.lastStored(); got != payload {
			t.Errorf("the server got %q", got)
		}
		if st := s.Stats(); st.FTPScanned != 0 {
			t.Errorf("ftp_scanned %d for a file the scanner never saw", st.FTPScanned)
		}
	})
}
