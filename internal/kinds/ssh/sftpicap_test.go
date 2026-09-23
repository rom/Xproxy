package ssh_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/icap/icaptest"
	"github.com/rom/xproxy/internal/proxy"
)

// icapBastion is a bastion whose sftp policy scans what is written.
func icapBastion(t *testing.T, fail string) (*proxy.Server, string, cssh.Signer, *targetSSH, *icaptest.Server) {
	t.Helper()
	fake := icaptest.New(t, 0)
	extra := `        sftp: {allow_paths: ["/srv/data/**"], icap: {service: av}}`
	top := fmt.Sprintf("icap:\n  services:\n    - {name: av, url: %q, fail: %s}\n", fake.URL(), fail)
	s, addr, key, tg := bastionWith(t, extra, top)
	return s, addr, key, tg, fake
}

// sftpStatus reads one reply and returns its status code, or -1 when
// the packet was not a status.
func sftpStatus(t *testing.T, ch cssh.Channel) int {
	t.Helper()
	typ, payload := readSFTP(t, ch)
	if typ != 101 || len(payload) < 8 {
		return -1
	}
	return int(binary.BigEndian.Uint32(payload[4:]))
}

// mods is the scanning requests the fake saw, leaving out the OPTIONS
// probe every service answers when it is built.
func mods(f *icaptest.Server) []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	out := make([]string, 0, len(f.Requests))
	for _, m := range f.Requests {
		if m == "REQMOD" || m == "RESPMOD" {
			out = append(out, m)
		}
	}
	return out
}

// SFTP has no whole-file transfer, so a scanned upload is held: the
// proxy answers the writes itself and the server sees nothing until
// the close. A file the scanner refuses never reaches the server at
// all, which is the difference between a control and a report.
func TestSFTPICAPHoldsAWriteUntilTheCloseAndBlocks(t *testing.T) {
	s, addr, key, tg, fake := icapBastion(t, "closed")
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	h := sftpOpenHandle(t, ch, 1, "/srv/data/bad.bin", 0x2|0x8)
	sftpWriteReq(t, ch, 2, h, 0, []byte("EICAR-test-body"))
	if got := sftpStatus(t, ch); got != 0 {
		t.Fatalf("the held write was answered %d, want 0 (the proxy answers it)", got)
	}
	// Nothing has been scanned yet: the file is not finished.
	if n := len(mods(fake)); n != 0 {
		t.Errorf("the scanner was asked %d times before the close", n)
	}
	// The write has not reached the target either.
	for _, r := range tg.seen() {
		if r == "sftp:6" {
			t.Fatal("a held write reached the target before the close")
		}
	}

	sftpCloseReq(t, ch, 3, h)
	if got := sftpStatus(t, ch); got != 4 {
		t.Fatalf("the close of a refused file was answered %d, want 4", got)
	}
	if n := len(mods(fake)); n != 1 {
		t.Errorf("the scanner was asked %d times at the close, want 1", n)
	}
	for _, r := range tg.seen() {
		if r == "sftp:6" {
			t.Fatal("the refused file reached the target")
		}
	}
	if sn := s.Stats(); sn.SFTPScanBlocked != 1 {
		t.Errorf("sftp_scan_blocked %d, want 1", sn.SFTPScanBlocked)
	}
}

// A clean file is released at the close: the writes reach the server
// then, in the order the client made them, and the client is not
// answered twice for any of them.
func TestSFTPICAPReleasesACleanFileAtTheClose(t *testing.T) {
	s, addr, key, tg, fake := icapBastion(t, "closed")
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	h := sftpOpenHandle(t, ch, 1, "/srv/data/good.bin", 0x2|0x8)
	for i, chunk := range []string{"one ", "two ", "three"} {
		sftpWriteReq(t, ch, uint32(2+i), h, uint64(len("one ")*i), []byte(chunk))
		if got := sftpStatus(t, ch); got != 0 {
			t.Fatalf("write %d was answered %d", i, got)
		}
	}
	sftpCloseReq(t, ch, 9, h)
	// The close is forwarded, so what comes back is the target's own
	// answer to it -- exactly one status, not one per replayed write.
	if got := sftpStatus(t, ch); got != 0 {
		t.Fatalf("the close was answered %d, want 0", got)
	}
	writes := 0
	for _, r := range tg.seen() {
		if r == "sftp:6" {
			writes++
		}
	}
	if writes != 3 {
		t.Errorf("the target saw %d writes, want the 3 that were held", writes)
	}
	if n := len(mods(fake)); n != 1 {
		t.Errorf("the scanner was asked %d times, want 1 for the whole file", n)
	}
	fake.Mu.Lock()
	bodies := append([]string(nil), fake.Bodies...)
	fake.Mu.Unlock()
	if len(bodies) != 1 || bodies[0] != "one two three" {
		t.Errorf("the scanner saw %q, want the assembled file", bodies)
	}
	if sn := s.Stats(); sn.SFTPScanned != 1 {
		t.Errorf("sftp_scanned %d, want 1", sn.SFTPScanned)
	}
}

// A read is not held: sftp downloads are a run of reads at offsets
// with no end to scan at, so the section does not claim to cover them
// and a read goes straight through.
func TestSFTPICAPDoesNotHoldReads(t *testing.T) {
	_, addr, key, tg, fake := icapBastion(t, "closed")
	c := dialBastion(t, addr, key)
	ch := sftpSession(t, c)
	sftpInit(t, ch)

	h := sftpOpenHandle(t, ch, 1, "/srv/data/get.bin", 0x1)
	sftpReadReq(t, ch, 2, h, 0, 16)
	// Whatever the target answers, the request reached it rather than
	// being held here. It travels through two goroutines, so wait for
	// it rather than reading the log the instant it was sent.
	deadline := time.Now().Add(5 * time.Second)
	reads := 0
	for {
		reads = 0
		for _, r := range tg.seen() {
			if r == "sftp:5" {
				reads++
			}
		}
		if reads > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if reads != 1 {
		t.Errorf("the target saw %d reads, want 1", reads)
	}
	if n := len(mods(fake)); n != 0 {
		t.Errorf("a read was sent to the scanner %d times", n)
	}
}
