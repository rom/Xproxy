package ftp_test

import (
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rom/xproxy/internal/testutil"
)

// waitFor retries until ok holds or five seconds pass. The counters a
// refusal moves are written on the session goroutine, so a test that
// read them the instant a reply arrived would be racing it.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s and it did not happen", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A restart marker plus an upload is not an upload of the bytes that
// arrive: it is an edit of a file at an offset, and the bytes that
// arrive are a fragment. A rule set that would match the whole file
// never sees it, so an upload in two REST-offset halves would pass a
// scanner that refuses the file. The gateway refuses the resumed
// transfer instead, because it cannot scan bytes it will never be shown.
func TestAResumedUploadIsRefusedWhereThereIsAScanner(t *testing.T) {
	rules := testutil.YARARules(t)
	s, addr, tg := ftpBastion(t, "        yara: {rules_file: "+rules+", directions: [client]}")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("REST 100"); code != 350 {
		t.Fatalf("REST was %d, want the server's 350", code)
	}
	_ = c.passive()
	if code, text := c.cmd("STOR /pub/notes.txt"); code != 451 {
		t.Fatalf("a resumed upload was answered %d %q, want 451", code, text)
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "STOR") {
			t.Errorf("the resumed upload reached the target: %s", seen)
		}
	}
	waitFor(t, "the refusal to be counted by reason", func() bool {
		return s.Stats().Refusals["ftp"]["rest_unscannable"] == 1
	})
	// An upload with no marker through the same policy still works,
	// which is the half that proves this is about the offset.
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, text := c.cmd("STOR /pub/notes.txt"); code != 150 {
		t.Fatalf("an ordinary upload after the marker was cleared: %d %q", code, text)
	}
	_, _ = dc.Write([]byte("ordinary content\r\n"))
	_ = dc.Close()
	if code, _ := c.reply(); code != 226 {
		t.Errorf("the completion was %d, want 226", code)
	}
}

// Without a scanner a resumed transfer is relayed, and the size bound is
// about the file rather than about one transfer: the offset counts
// towards it, so two halves cannot each be inside it.
func TestTheSizeBoundCountsTheRestartOffset(t *testing.T) {
	s, addr, tg := ftpBastion(t, "        max_file_bytes: 64")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("REST 60"); code != 350 {
		t.Fatalf("REST was %d", code)
	}
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := c.cmd("STOR /pub/notes.txt"); code != 150 {
		t.Fatalf("the resumed upload was refused")
	}
	// Ten bytes at offset sixty is seventy, which is past the bound even
	// though the transfer itself is nowhere near it.
	_, _ = dc.Write([]byte("0123456789"))
	_ = dc.Close()
	if code, _ := c.reply(); code != 426 {
		t.Errorf("the completion was %d, want 426: the offset was not counted", code)
	}
	if got := tg.lastStored(); len(got) > 64 {
		t.Errorf("%d bytes reached the target", len(got))
	}
	waitFor(t, "the bound to be counted", func() bool { return s.Stats().FTPRefused >= 1 })
}

// A marker applies to the transfer that follows it and to nothing else,
// which is what RFC 3659 says and what a server does. A proxy that kept
// one would be holding a decision the server has forgotten.
func TestARestartMarkerAppliesOnlyToTheNextTransfer(t *testing.T) {
	_, addr, _ := ftpBastion(t, "        max_file_bytes: 64")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("REST 60"); code != 350 {
		t.Fatalf("REST was %d", code)
	}
	// Anything in between clears it.
	if code, _ := c.cmd("NOOP"); code != 200 {
		t.Fatalf("NOOP was %d", code)
	}
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := c.cmd("STOR /pub/notes.txt"); code != 150 {
		t.Fatalf("STOR was refused")
	}
	_, _ = dc.Write([]byte("0123456789"))
	_ = dc.Close()
	if code, _ := c.reply(); code != 226 {
		t.Errorf("the completion was %d: the cleared marker was still being counted", code)
	}
}

// A marker that is not a byte offset is refused here. RFC 3659 lets a
// server define its own marker format, which is a value this proxy
// cannot reason about and so will not carry.
func TestARestartMarkerMustBeAByteOffset(t *testing.T) {
	s, addr, tg := ftpBastion(t, "")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	// Surrounding whitespace is trimmed, as everywhere else in the
	// protocol; what is refused is a marker that is not a plain
	// non-negative decimal.
	for _, arg := range []string{"-1", "abc", "1e9", "0x10", "", "+5", "007", "99999999999999999999"} {
		if code, _ := c.cmd("REST %s", arg); code != 501 {
			t.Errorf("REST %q was answered %d, want 501", arg, code)
		}
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "REST") && seen != "REST 0" {
			t.Errorf("a malformed marker reached the target: %q", seen)
		}
	}
	waitFor(t, "the refusals to be counted", func() bool {
		return s.Stats().Refusals["ftp"]["rest_invalid"] == 8
	})
	// A plain offset is relayed.
	if code, _ := c.cmd("REST 0"); code != 350 {
		t.Errorf("REST 0 was refused")
	}
}

// RNTO without an RNFR the server accepted is half a decision. The
// gateway refuses it rather than forwarding a rename it never saw the
// source of.
func TestRenameNeedsItsPair(t *testing.T) {
	s, addr, tg := ftpBastion(t, "")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("RNTO /pub/new.txt"); code != 503 {
		t.Errorf("a bare RNTO was answered %d, want 503", code)
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "RNTO") {
			t.Errorf("a bare RNTO reached the target: %s", seen)
		}
	}
	// The pair works.
	if code, _ := c.cmd("RNFR /pub/old.txt"); code != 350 {
		t.Fatalf("RNFR was %d", code)
	}
	if code, _ := c.cmd("RNTO /pub/new.txt"); code != 250 {
		t.Errorf("RNTO after RNFR was %d, want 250", code)
	}
	// And the pair is forgotten once it is used, so a second RNTO is
	// refused again.
	if code, _ := c.cmd("RNTO /pub/newer.txt"); code != 503 {
		t.Errorf("a second RNTO was answered %d, want 503", code)
	}
	// Anything in between breaks the pair, which is what the server does.
	if code, _ := c.cmd("RNFR /pub/old.txt"); code != 350 {
		t.Fatalf("RNFR was %d", code)
	}
	if code, _ := c.cmd("NOOP"); code != 200 {
		t.Fatalf("NOOP was %d", code)
	}
	if code, _ := c.cmd("RNTO /pub/new.txt"); code != 503 {
		t.Errorf("RNTO after an interruption was answered %d, want 503", code)
	}
	waitFor(t, "the refusals to be counted", func() bool {
		return s.Stats().Refusals["ftp"]["rename_out_of_order"] == 3
	})
}

// An RNFR the path policy refuses never reaches the server, so the RNTO
// that would have completed it is refused too: the rename cannot be half
// applied.
func TestARefusedRenameSourceRefusesTheDestination(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        allow_paths: [\"/pub/**\"]")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("RNFR /etc/passwd"); code != 550 {
		t.Fatalf("RNFR outside the allowed tree was %d, want 550", code)
	}
	if code, _ := c.cmd("RNTO /pub/mine.txt"); code != 503 {
		t.Errorf("RNTO after a refused RNFR was %d, want 503", code)
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "RN") {
			t.Errorf("part of the rename reached the target: %s", seen)
		}
	}
}

// The shapes a proxy and a server would read differently are refused
// rather than matched: each of them is a way for the path the policy
// checked and the path the server opens to be two different files.
func TestThePathShapesTheProxyWillNotGuessAbout(t *testing.T) {
	s, addr, tg := ftpBastion(t, "        allow_paths: [\"/pub/**\"]")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	cases := map[string]string{
		// A backslash is a separator on a Windows server and a character
		// in a pattern here.
		`/pub\..\..\etc\passwd`: "path_separator",
		`/pub/a\b`:              "path_separator",
		// Bytes that are not valid UTF-8 are a different string on each
		// side of an overlong or truncated sequence.
		"/pub/\xe0\x80\xafetc": "path_encoding",
		"/pub/caf\xc3":         "path_encoding",
	}
	for arg, want := range cases {
		if code, _ := c.cmd("RETR %s", arg); code != 550 {
			t.Errorf("%q was answered %d, want 550", arg, code)
		}
		waitFor(t, "the refusal to be counted as "+want, func() bool {
			return s.Stats().Refusals["ftp"][want] >= 1
		})
	}
	for _, seen := range tg.commands() {
		if strings.Contains(seen, `\`) || !utf8.ValidString(seen) {
			t.Errorf("a path the proxy would not match reached the target: %q", seen)
		}
	}
	// An ordinary path in another script is not refused: this is about
	// the shapes that cannot be compared, not about everything above
	// ASCII.
	if code, _ := c.cmd("RETR /pub/café.txt"); code == 550 {
		t.Error("a valid UTF-8 path was refused")
	}
}

// MLST answers on the control channel and MLSD opens a data connection,
// which is the one difference between them a proxy has to know: treating
// MLST as a transfer would leave it waiting for a connection nobody
// makes.
func TestMLSTAnswersWithoutADataConnectionAndMLSDWithOne(t *testing.T) {
	_, addr, _ := ftpBastion(t, "        allow_paths: [\"/pub/**\"]")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, text := c.cmd("MLST /pub/notes.txt"); code != 250 {
		t.Errorf("MLST was %d %q, want 250 with no data connection", code, text)
	}
	// The path policy applies to both.
	if code, _ := c.cmd("MLST /etc/passwd"); code != 550 {
		t.Errorf("MLST outside the allowed tree was %d, want 550", code)
	}
	if code, _ := c.cmd("MLSD /etc"); code != 550 {
		t.Errorf("MLSD outside the allowed tree was %d, want 550", code)
	}
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	if code, _ := c.cmd("MLSD /pub"); code != 150 {
		t.Errorf("MLSD inside the allowed tree did not open a data connection")
	}
}

// CCC puts the rest of the session, including every path, back in clear
// on the wire. It is refused twice over: it is not in the default
// command list, and it has a refusal of its own for the listener whose
// operator put it there.
func TestCCCIsRefusedTwiceOver(t *testing.T) {
	t.Run("not in the default list", func(t *testing.T) {
		s, addr, tg := ftpBastion(t, "")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		if code, _ := c.cmd("CCC"); code != 502 {
			t.Errorf("CCC was answered %d, want 502", code)
		}
		for _, seen := range tg.commands() {
			if seen == "CCC" {
				t.Error("CCC reached the target")
			}
		}
		waitFor(t, "the refusal to be counted", func() bool {
			return s.Stats().Refusals["ftp"]["command_refused"] == 1
		})
	})
	t.Run("named in the command list", func(t *testing.T) {
		s, addr, tg := ftpBastion(t, "        commands: [USER, PASS, QUIT, NOOP, CCC]")
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		if code, text := c.cmd("CCC"); code != 534 {
			t.Errorf("CCC was answered %d %q, want 534", code, text)
		}
		for _, seen := range tg.commands() {
			if seen == "CCC" {
				t.Error("CCC reached the target even though the gateway refused it")
			}
		}
		waitFor(t, "the refusal to be counted by its own reason", func() bool {
			return s.Stats().Refusals["ftp"]["ccc_refused"] == 1
		})
	})
}
