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
		{"write by handle", req(sftp.WRITE, 8, str("h")), "", true},
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
		"truncated id":       {Type: sftp.STAT, Body: []byte{0, 0}},
		"length past end":    {Type: sftp.STAT, Body: append(binary.BigEndian.AppendUint32(nil, 1), 0, 0, 0, 9, 'a')},
		"not utf-8":          {Type: sftp.STAT, Body: append(binary.BigEndian.AppendUint32(nil, 1), str("\xff\xfe")...)},
		"open with no flags": {Type: sftp.OPEN, Body: append(binary.BigEndian.AppendUint32(nil, 1), str("/a")...)},
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
