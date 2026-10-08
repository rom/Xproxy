package sftp_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/sftp"
)

func str(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

func req(typ byte, id uint32, parts ...[]byte) sftp.Packet {
	body := binary.BigEndian.AppendUint32(nil, id)
	for _, p := range parts {
		body = append(body, p...)
	}
	return sftp.Packet{Type: typ, Body: body}
}

func TestReadPacket(t *testing.T) {
	p := sftp.Packet{Type: sftp.STAT, Body: []byte("abc")}
	got, err := sftp.ReadPacket(bytes.NewReader(p.Encode()), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != sftp.STAT || string(got.Body) != "abc" {
		t.Fatalf("got %+v", got)
	}
	if _, err := sftp.ReadPacket(bytes.NewReader(p.Encode()), 2); !errors.Is(err, sftp.ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	// A zero length has no room for the type octet.
	if _, err := sftp.ReadPacket(bytes.NewReader([]byte{0, 0, 0, 0}), 1024); !errors.Is(err, sftp.ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestParseRequest(t *testing.T) {
	cases := []struct {
		name   string
		packet sftp.Packet
		path   string
		writes bool
	}{
		{"open for reading", req(sftp.OPEN, 1, str("/srv/a"), binary.BigEndian.AppendUint32(nil, sftp.FlagRead), binary.BigEndian.AppendUint32(nil, 0)), "/srv/a", false},
		{"open for writing", req(sftp.OPEN, 2, str("/srv/a"), binary.BigEndian.AppendUint32(nil, sftp.FlagWrite), binary.BigEndian.AppendUint32(nil, 0)), "/srv/a", true},
		{"open creating", req(sftp.OPEN, 3, str("/srv/a"), binary.BigEndian.AppendUint32(nil, sftp.FlagRead|sftp.FlagCreat), binary.BigEndian.AppendUint32(nil, 0)), "/srv/a", true},
		{"stat", req(sftp.STAT, 4, str("/srv/a")), "/srv/a", false},
		{"remove", req(sftp.REMOVE, 5, str("/srv/a")), "/srv/a", true},
		{"mkdir", req(sftp.MKDIR, 6, str("/srv/a")), "/srv/a", true},
		{"read by handle", req(sftp.READ, 7, str("h")), "", false},
		{"write by handle", req(sftp.WRITE, 8, str("h"), binary.BigEndian.AppendUint64(nil, 0), str("data")), "", true},
	}
	for _, c := range cases {
		got, err := sftp.ParseRequest(c.packet)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.Path != c.path || got.Writes != c.writes {
			t.Errorf("%s: path %q writes %v", c.name, got.Path, got.Writes)
		}
	}
	// A write names a handle, an offset and the bytes themselves, which
	// is what a size bound and a rule set need.
	w, err := sftp.ParseRequest(req(sftp.WRITE, 10, str("h"), binary.BigEndian.AppendUint64(nil, 4096), str("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if w.Handle != "h" || w.Offset != 4096 || string(w.Data) != "payload" {
		t.Fatalf("write: %+v", w)
	}
	// A handle is the server's opaque bytes, not text: it must survive
	// what a name would be refused for.
	h, err := sftp.ParseRequest(req(sftp.CLOSE, 11, str("\xff\x00\xfe")))
	if err != nil {
		t.Fatal(err)
	}
	if h.Handle != "\xff\x00\xfe" {
		t.Fatalf("handle: %q", h.Handle)
	}
	id, handle, err := sftp.ParseHandleReply(sftp.Packet{Type: sftp.HANDLE,
		Body: append(binary.BigEndian.AppendUint32(nil, 7), str("\xff\x01")...)})
	if err != nil || id != 7 || handle != "\xff\x01" {
		t.Fatalf("handle reply: %d %q %v", id, handle, err)
	}
	if _, _, err := sftp.ParseHandleReply(sftp.Packet{Type: sftp.DATA}); err == nil {
		t.Fatal("a reply that is not a handle should not parse as one")
	}

	// Rename names two paths, and both are the policy's business.
	r, err := sftp.ParseRequest(req(sftp.RENAME, 9, str("/srv/a"), str("/etc/passwd")))
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != "/srv/a" || r.Target != "/etc/passwd" || !r.Writes {
		t.Fatalf("rename: %+v", r)
	}
}

func TestParseRequestMalformed(t *testing.T) {
	bad := map[string]sftp.Packet{
		"truncated id":         {Type: sftp.STAT, Body: []byte{0, 0}},
		"length past end":      {Type: sftp.STAT, Body: append(binary.BigEndian.AppendUint32(nil, 1), 0, 0, 0, 9, 'a')},
		"not utf-8":            {Type: sftp.STAT, Body: append(binary.BigEndian.AppendUint32(nil, 1), str("\xff\xfe")...)},
		"open with no flags":   {Type: sftp.OPEN, Body: append(binary.BigEndian.AppendUint32(nil, 1), str("/a")...)},
		"write with no offset": {Type: sftp.WRITE, Body: append(binary.BigEndian.AppendUint32(nil, 1), str("h")...)},
		"write with no data": {Type: sftp.WRITE, Body: append(append(binary.BigEndian.AppendUint32(nil, 1), str("h")...),
			binary.BigEndian.AppendUint64(nil, 0)...)},
		"close with no handle": {Type: sftp.CLOSE, Body: binary.BigEndian.AppendUint32(nil, 1)},
	}
	for name, p := range bad {
		if _, err := sftp.ParseRequest(p); err == nil {
			t.Errorf("%s: should not parse", name)
		}
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]struct {
		out string
		ok  bool
	}{
		"/srv/data/a":           {"/srv/data/a", true},
		"/srv/data/./a":         {"/srv/data/a", true},
		"/srv/data/b/../a":      {"/srv/data/a", true},
		"/srv/data/../../etc/x": {"/etc/x", true},
		"../../etc/shadow":      {"../../etc/shadow", false},
		"..":                    {"..", false},
		"":                      {"", false},
	}
	for in, want := range cases {
		got, ok := sftp.CleanPath(in)
		if ok != want.ok || (want.ok && got != want.out) {
			t.Errorf("CleanPath(%q) = %q, %v want %q, %v", in, got, ok, want.out, want.ok)
		}
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/srv/data/**", "/srv/data/a/b/c", true},
		{"/srv/data/**", "/srv/data", true},
		{"/srv/data/**", "/srv/database/a", false},
		{"/srv/data/", "/srv/data/a", true},
		{"/srv/data/*", "/srv/data/a", true},
		{"/srv/data/*", "/srv/data/a/b", false},
		{"/srv/data/*.csv", "/srv/data/report.csv", true},
		{"/srv/data/*.csv", "/srv/data/report.txt", false},
		{"/", "/anything", true},
		{"/etc/shadow", "/etc/shadow", true},
	}
	for _, c := range cases {
		if got := sftp.MatchPath(c.pattern, c.path); got != c.want {
			t.Errorf("MatchPath(%q, %q) = %v want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestStatusPacket(t *testing.T) {
	p := sftp.StatusPacket(7, sftp.StatusPermissionDenied, "refused")
	if p.Type != sftp.STATUS {
		t.Fatalf("type %d", p.Type)
	}
	got, err := sftp.ReadPacket(bytes.NewReader(p.Encode()), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(got.Body) != 7 || binary.BigEndian.Uint32(got.Body[4:]) != sftp.StatusPermissionDenied {
		t.Fatalf("body %v", got.Body)
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add(byte(sftp.OPEN), req(sftp.OPEN, 1, str("/a"), binary.BigEndian.AppendUint32(nil, 1), binary.BigEndian.AppendUint32(nil, 0)).Body)
	f.Add(byte(sftp.STAT), req(sftp.STAT, 1, str("/a")).Body)
	f.Fuzz(func(t *testing.T, typ byte, body []byte) {
		r, err := sftp.ParseRequest(sftp.Packet{Type: typ, Body: body})
		if err != nil {
			return
		}
		// A path the policy will match must not carry a NUL: the
		// server would stop reading it where the proxy did not.
		if strings.ContainsRune(r.Path, 0) || strings.ContainsRune(r.Target, 0) {
			t.Fatalf("accepted a NUL in a path: %q %q", r.Path, r.Target)
		}
	})
}

// Every request type has the name an operator writes in a policy, and one this
// proxy has no name for still has a name in the record.
//
// This table is the vocabulary of the deny list: a policy says `remove` and
// `symlink`, and the mapping from the wire's byte to that word is what makes
// the policy mean anything. A type outside it reads as `type 42` rather than
// disappearing -- an extension nobody configured is exactly what is worth
// seeing in a log.
func TestEveryRequestTypeHasItsPolicyName(t *testing.T) {
	for _, c := range []struct {
		typ  byte
		want string
	}{
		{sftp.INIT, "init"}, {sftp.OPEN, "open"}, {sftp.CLOSE, "close"},
		{sftp.READ, "read"}, {sftp.WRITE, "write"}, {sftp.LSTAT, "lstat"},
		{sftp.FSTAT, "fstat"}, {sftp.SETSTAT, "setstat"}, {sftp.FSETSTAT, "fsetstat"},
		{sftp.OPENDIR, "opendir"}, {sftp.READDIR, "readdir"}, {sftp.REMOVE, "remove"},
		{sftp.MKDIR, "mkdir"}, {sftp.RMDIR, "rmdir"}, {sftp.REALPATH, "realpath"},
		{sftp.STAT, "stat"}, {sftp.RENAME, "rename"}, {sftp.READLINK, "readlink"},
		{sftp.SYMLINK, "symlink"},
	} {
		if got := sftp.TypeName(c.typ); got != c.want {
			t.Errorf("TypeName(%d) = %q, want %q", c.typ, got, c.want)
		}
		// A packet names itself the same way, which is what the deny list
		// is matched against.
		if got := (sftp.Packet{Type: c.typ}).Name(); got != c.want {
			t.Errorf("Packet{%d}.Name() = %q, want %q", c.typ, got, c.want)
		}
	}
	for _, typ := range []byte{sftp.EXTENDED, sftp.EXTENDEDREPLY, 42, 0} {
		if got := sftp.TypeName(typ); !strings.HasPrefix(got, "type ") {
			t.Errorf("TypeName(%d) = %q, want it to name the number", typ, got)
		}
	}
}

// StatusID is how a proxy tells its own answers from the client's, so a packet
// too short to carry an id must read as zero rather than as whatever follows
// in memory -- and a packet that is not a STATUS at all must not be read for
// one.
func TestStatusIDIsOnlyReadFromAStatusThatCarriesOne(t *testing.T) {
	id, code := uint32(0x11223344), uint32(4)
	p := sftp.StatusPacket(id, code, "permission denied")
	if got := sftp.StatusID(p); got != id {
		t.Errorf("StatusID = %#x, want %#x", got, id)
	}
	for _, c := range []struct {
		name string
		p    sftp.Packet
	}{
		{"not a status", sftp.Packet{Type: sftp.DATA, Body: p.Body}},
		{"truncated to three bytes", sftp.Packet{Type: sftp.STATUS, Body: p.Body[:3]}},
		{"no body at all", sftp.Packet{Type: sftp.STATUS}},
	} {
		if got := sftp.StatusID(c.p); got != 0 {
			t.Errorf("%s: StatusID = %#x, want 0", c.name, got)
		}
	}
}

// The handle reply is the one packet from the server a proxy has to read: a
// WRITE names a handle, and without this the proxy cannot connect that handle
// to the path it decided about. So a reply it cannot read has to be an error
// rather than an empty handle, which would silently match every write.
func TestAHandleReplyThatCannotBeReadIsAnError(t *testing.T) {
	good := sftp.Packet{Type: sftp.HANDLE,
		Body: append(binary.BigEndian.AppendUint32(nil, 7), str("h1")...)}
	id, h, err := sftp.ParseHandleReply(good)
	if err != nil || id != 7 || h != "h1" {
		t.Fatalf("ParseHandleReply = %d, %q, %v", id, h, err)
	}
	for _, c := range []struct {
		name string
		p    sftp.Packet
	}{
		{"another packet type", sftp.Packet{Type: sftp.STATUS, Body: good.Body}},
		{"no id", sftp.Packet{Type: sftp.HANDLE}},
		{"an id and no handle", sftp.Packet{Type: sftp.HANDLE,
			Body: binary.BigEndian.AppendUint32(nil, 7)}},
		{"a handle length longer than the body", sftp.Packet{Type: sftp.HANDLE,
			Body: append(binary.BigEndian.AppendUint32(nil, 7),
				binary.BigEndian.AppendUint32(nil, 64)...)}},
	} {
		if _, h, err := sftp.ParseHandleReply(c.p); err == nil {
			t.Errorf("%s: no error, handle %q", c.name, h)
		}
	}
}

// Clone is the contract a reader relies on: a packet's bytes are not kept past
// the packet, and a proxy holding writes to replay them at a close keeps them
// for a long time. So a clone must not alias.
func TestCloneDoesNotAliasTheBody(t *testing.T) {
	p := sftp.Packet{Type: sftp.WRITE, Body: []byte("payload")}
	c := p.Clone()
	p.Body[0] = 'X'
	if c.Body[0] != 'p' {
		t.Errorf("the clone followed the original: %q", c.Body)
	}
	if c.Type != p.Type {
		t.Errorf("type = %d, want %d", c.Type, p.Type)
	}
}
