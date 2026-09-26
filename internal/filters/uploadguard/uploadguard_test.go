package uploadguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
	"github.com/rom/xproxy/internal/intel"
)

type part struct {
	field, name, ctype string
	data               []byte
}

func multipartRequest(t *testing.T, parts ...part) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		if p.name == "" {
			h.Set("Content-Disposition", `form-data; name="`+p.field+`"`)
		} else {
			h.Set("Content-Disposition", `form-data; name="`+p.field+`"; filename="`+p.name+`"`)
		}
		if p.ctype != "" {
			h.Set("Content-Type", p.ctype)
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write(p.data)
	}
	_ = w.Close()
	r := httptest.NewRequest("POST", "http://app.test/upload", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", w.FormDataContentType())
	return r
}

var (
	pngBytes = append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, bytes.Repeat([]byte{0}, 64)...)
	jpgBytes = append([]byte{0xff, 0xd8, 0xff, 0xe0}, bytes.Repeat([]byte{1}, 64)...)
	pdfBytes = []byte("%PDF-1.7\n1 0 obj <<>> endobj\n")
	peBytes  = append([]byte("MZ\x90\x00"), bytes.Repeat([]byte{0}, 60)...)
)

func build(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	f, err := filtertest.Build("upload_guard", "uploads", opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUploadGuard(t *testing.T) {
	f := build(t, filter.Options{"max_files": 2, "max_file_bytes": 1024, "max_total_bytes": 4096,
		"allowed_extensions": []any{"jpg", "png", "pdf", "docx"}, "fields": []any{"file", "attachment"}})
	cases := []struct {
		name   string
		req    *http.Request
		status int
		detail string
	}{
		{"png ok", multipartRequest(t, part{"file", "photo.png", "image/png", pngBytes}, part{"title", "", "", []byte("hi")}), 0, ""},
		{"two files ok", multipartRequest(t, part{"file", "a.jpg", "image/jpeg", jpgBytes}, part{"attachment", "b.pdf", "application/pdf", pdfBytes}), 0, ""},
		{"no files ok", multipartRequest(t, part{"title", "", "", []byte("hi")}), 0, ""},
		{"too many", multipartRequest(t, part{"file", "a.jpg", "", jpgBytes}, part{"file", "b.jpg", "", jpgBytes}, part{"file", "c.jpg", "", jpgBytes}), 400, "file_count"},
		{"wrong field", multipartRequest(t, part{"avatar", "a.jpg", "", jpgBytes}), 400, "field"},
		{"extension denied", multipartRequest(t, part{"file", "shell.php", "image/png", pngBytes}), 415, "extension:shell.php"},
		{"extension not allowed", multipartRequest(t, part{"file", "notes.txt", "text/plain", []byte("hello")}), 415, "extension:notes.txt"},
		{"no extension", multipartRequest(t, part{"file", "README", "", []byte("hello")}), 415, "extension:README"},
		{"double extension hidden", multipartRequest(t, part{"file", "invoice.pdf.exe", "", peBytes}), 415, "extension:invoice.pdf.exe"},
		{"double extension odd", multipartRequest(t, part{"file", "photo.html.jpg", "image/jpeg", jpgBytes}), 415, "double_extension:photo.html.jpg"},
		{"version dots ok", multipartRequest(t, part{"file", "report.2024.v2.pdf", "application/pdf", pdfBytes}), 0, ""},
		{"traversal name", multipartRequest(t, part{"file", "../../etc/passwd.png", "", pngBytes}), 400, "filename"},
		{"control name", multipartRequest(t, part{"file", "a\x01b.png", "", pngBytes}), 400, ""},
		{"pe as png", multipartRequest(t, part{"file", "cute.png", "image/png", peBytes}), 415, "executable:pe"},
		{"script as jpg", multipartRequest(t, part{"file", "cute.jpg", "image/jpeg", []byte("#!/bin/sh\nrm -rf /\n")}), 415, "executable:script"},
		{"php in image", multipartRequest(t, part{"file", "cute.jpg", "image/jpeg", append(append([]byte(nil), jpgBytes...), []byte("<?php system($_GET['c']); ?>")...)}), 415, "executable:server_script"},
		{"magic mismatch", multipartRequest(t, part{"file", "cute.png", "image/png", jpgBytes}), 415, "type_mismatch:image/jpeg"},
		{"declared mismatch", multipartRequest(t, part{"file", "cute.png", "application/pdf", pngBytes}), 415, "declared_mismatch:image/png"},
		{"docx is zip", multipartRequest(t, part{"file", "a.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", []byte("PK\x03\x04rest")}), 0, ""},
		{"file too large", multipartRequest(t, part{"file", "big.jpg", "image/jpeg", append(append([]byte(nil), jpgBytes...), bytes.Repeat([]byte{2}, 2000)...)}), 413, "file_size"},
	}
	for _, c := range cases {
		res := filtertest.Run(f, c.req, nil)
		v := res.Request
		if c.status == 0 {
			if v.Deny {
				t.Errorf("%s: denied %+v", c.name, v)
			}
			continue
		}
		if !v.Deny || v.Status != c.status || v.Reason != "upload" || !strings.HasPrefix(v.Detail, c.detail) {
			t.Errorf("%s: got %+v want %d %s", c.name, v, c.status, c.detail)
		}
		if v.Response == nil {
			t.Errorf("%s: no problem body", c.name)
		}
	}
	// The body is replayed for the upstream after inspection.
	r := multipartRequest(t, part{"file", "photo.png", "image/png", pngBytes})
	want, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(want))
	res := filtertest.Run(f, r, nil)
	got, _ := io.ReadAll(r.Body)
	if !bytes.Equal(got, want) || res.Request.Deny {
		t.Fatal("body not replayed")
	}
	if len(res.Attrs) != 4 || res.Attrs[0] != "upload_files" || res.Attrs[1] != 1 {
		t.Fatalf("attrs %v", res.Attrs)
	}
	// Total size over the limit is refused before parsing.
	huge := multipartRequest(t, part{"file", "a.jpg", "", bytes.Repeat([]byte{1}, 5000)})
	if v := filtertest.Run(f, huge, nil).Request; !v.Deny || v.Status != 413 || v.Detail != "total_size" {
		t.Fatalf("total size: %+v", v)
	}
	// Other bodies pass untouched.
	plain := httptest.NewRequest("POST", "http://app.test/api", strings.NewReader(`{"a":1}`))
	plain.Header.Set("Content-Type", "application/json")
	if v := filtertest.Run(f, plain, nil).Request; v.Deny {
		t.Fatalf("json body: %+v", v)
	}
	if v := filtertest.Run(f, httptest.NewRequest("GET", "http://app.test/", nil), nil).Request; v.Deny {
		t.Fatal("get denied")
	}
}

func TestUploadGuardModes(t *testing.T) {
	// Defaults: any extension but the built-in deny list; double extensions checked along the chain.
	f := build(t, nil)
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "notes.txt", "text/plain", []byte("hello")}), nil).Request; v.Deny {
		t.Fatalf("txt with defaults: %+v", v)
	}
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "x.php.png", "image/png", pngBytes}), nil).Request; !v.Deny {
		t.Fatal("php hidden in a chain accepted")
	}
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "x.exe", "", peBytes}), nil).Request; !v.Deny {
		t.Fatal("exe accepted")
	}
	// Allowing exe explicitly overrides the deny list; the executable check still applies unless off.
	f = build(t, filter.Options{"allowed_extensions": []any{"exe"}, "deny_executables": false})
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "setup.exe", "application/x-msdownload", peBytes}), nil).Request; v.Deny {
		t.Fatalf("allowed exe: %+v", v)
	}
	// double_extensions: allow looks at the last extension only.
	f = build(t, filter.Options{"double_extensions": "allow"})
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "x.php.png", "image/png", pngBytes}), nil).Request; v.Deny {
		t.Fatalf("allow mode: %+v", v)
	}
	// strict_magic refuses unrecognised content for known and unknown extensions.
	f = build(t, filter.Options{"strict_magic": true})
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "data.bin2", "", []byte("just text")}), nil).Request; !v.Deny || !strings.HasPrefix(v.Detail, "type_unknown") {
		t.Fatalf("strict: %+v", v)
	}
	// check_magic off accepts a mismatch.
	f = build(t, filter.Options{"check_magic": false})
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "a.png", "image/png", jpgBytes}), nil).Request; v.Deny {
		t.Fatalf("magic off: %+v", v)
	}
	// raw_uploads treats a plain body as one file named from the path or disposition.
	f = build(t, filter.Options{"raw_uploads": true, "allowed_extensions": []any{"png"}})
	raw := httptest.NewRequest("PUT", "http://app.test/files/avatar.png", bytes.NewReader(pngBytes))
	raw.Header.Set("Content-Type", "image/png")
	if v := filtertest.Run(f, raw, nil).Request; v.Deny {
		t.Fatalf("raw png: %+v", v)
	}
	raw = httptest.NewRequest("PUT", "http://app.test/files/avatar.png", bytes.NewReader(peBytes))
	raw.Header.Set("Content-Type", "image/png")
	if v := filtertest.Run(f, raw, nil).Request; !v.Deny {
		t.Fatal("raw pe accepted")
	}
	raw = httptest.NewRequest("POST", "http://app.test/files", bytes.NewReader(pngBytes))
	raw.Header.Set("Content-Type", "application/octet-stream")
	raw.Header.Set("Content-Disposition", `attachment; filename="shot.php"`)
	if v := filtertest.Run(f, raw, nil).Request; !v.Deny || !strings.HasPrefix(v.Detail, "extension:shot.php") {
		t.Fatalf("raw disposition name: %+v", v)
	}
	// Bad options.
	for _, o := range []filter.Options{
		{"max_files": 0.5}, {"max_files": 100000}, {"max_file_bytes": -1}, {"max_total_bytes": 10, "max_file_bytes": 100},
		{"double_extensions": "maybe"}, {"allowed_extensions": []any{"a/b"}}, {"denied_extensions": []any{""}}, {"fields": []any{""}}, {"bogus": 1},
	} {
		if _, err := filtertest.Build("upload_guard", "u", o); err == nil {
			t.Errorf("options %v accepted", o)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := extensions("invoice.PDF.exe"); len(got) != 2 || got[0] != "pdf" || got[1] != "exe" {
		t.Fatalf("extensions %v", got)
	}
	if extensions(".bashrc") != nil || extensions("README") != nil {
		t.Fatal("dot file or bare name has an extension")
	}
	if detect(pdfBytes) != "application/pdf" || detect([]byte("PK\x03\x04")) != "application/zip" || detect([]byte("plain words")) != "" || detect([]byte("<html><body>")) != "text/html" {
		t.Fatal("detect")
	}
	if !declaredMatches("image/jpg", "image/jpeg") || declaredMatches("application/pdf", "image/png") || !declaredMatches("application/vnd.ms-excel", "application/x-ole") {
		t.Fatal("declaredMatches")
	}
	if executableKind([]byte("hello")) != "" || executableKind([]byte("<%@ page language=\"java\" %>")) != "server_script" {
		t.Fatal("executableKind")
	}
	if !looksLikeExtension("html") || looksLikeExtension("2024") || looksLikeExtension("v2") || looksLikeExtension("holiday") {
		t.Fatal("looksLikeExtension")
	}
}

// A file's digest is asked about, and the answer is the list's action: block
// refuses the upload, anything else notes it and lets the file through.
//
// The guard is where this happens because it is already reading every byte of
// every file: the digest costs the pass it was making anyway, and no other
// filter has the file assembled.
func TestAnUploadIsAskedAboutByItsDigest(t *testing.T) {
	// Two payloads, one listed with block and one with log. The list holds the
	// SHA-256 of each, which is how a feed names a file.
	bad := []byte("this exact file has been seen elsewhere")
	noted := []byte("this one is only worth a line in the log")
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sum := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	set, err := intel.New([]intel.Spec{
		{Name: "bad-files", Kind: "hash", Action: "block", File: write("bad.txt", sum(bad)+"\n")},
		{Name: "noted-files", Kind: "hash", Action: "log", File: write("noted.txt", sum(noted)+"\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := filtertest.BuildWithEnv("upload_guard", "uploads",
		filter.Options{"max_file_bytes": 4096, "check_magic": false, "deny_executables": false, "raw_uploads": true},
		filter.Env{Intel: func() *intel.Set { return set }})
	if err != nil {
		t.Fatal(err)
	}
	// The listed file: refused, and the verdict names the list so the data
	// plane counts it where every other match is counted.
	v := filtertest.Run(f, multipartRequest(t, part{"f", "invoice.txt", "text/plain", bad}), nil).Request
	if !v.Deny || v.Status != http.StatusForbidden {
		t.Fatalf("a listed digest: deny=%v status=%d detail=%q", v.Deny, v.Status, v.Detail)
	}
	if v.ThreatList != "bad-files" {
		t.Errorf("ThreatList %q, want bad-files", v.ThreatList)
	}
	if !strings.HasPrefix(v.Detail, "threat_intel:") {
		t.Errorf("detail %q, want the check named", v.Detail)
	}
	// The log-only file goes through, with the list in the access log: a hash
	// list has nobody to challenge, so the third action does not exist here
	// and a log list must not become a block.
	res := filtertest.Run(f, multipartRequest(t, part{"f", "notes.txt", "text/plain", noted}), nil)
	if res.Request.Deny {
		t.Fatalf("a log-only list refused an upload: %+v", res.Request)
	}
	if !strings.Contains(fmt.Sprint(res.Attrs...), "noted-files") {
		t.Errorf("the access log does not name the list: %v", res.Attrs)
	}
	// A file nothing lists is untouched.
	if v := filtertest.Run(f, multipartRequest(t, part{"f", "ok.txt", "text/plain", []byte("ordinary")}), nil).Request; v.Deny {
		t.Errorf("an unlisted file was refused: %+v", v)
	}
	// And a raw body is one file too, so an upload that is not multipart is
	// asked about as well -- a client that could skip the digest by sending
	// the payload as the whole body would have a bypass one header long.
	raw := httptest.NewRequest("POST", "http://app.test/upload", bytes.NewReader(bad))
	raw.Header.Set("Content-Type", "application/octet-stream")
	if v := filtertest.Run(f, raw, nil).Request; !v.Deny || v.ThreatList != "bad-files" {
		t.Errorf("a raw upload of a listed file: %+v", v)
	}
	// A file longer than the sniff window is digested whole, not only its
	// first 512 bytes.
	long := append(append([]byte{}, bytes.Repeat([]byte("a"), 600)...), "tail"...)
	longSet, err := intel.New([]intel.Spec{
		{Name: "long-files", Kind: "hash", Action: "block", File: write("long.txt", sum(long)+"\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	f2, err := filtertest.BuildWithEnv("upload_guard", "uploads",
		filter.Options{"max_file_bytes": 4096, "check_magic": false, "deny_executables": false},
		filter.Env{Intel: func() *intel.Set { return longSet }})
	if err != nil {
		t.Fatal(err)
	}
	if v := filtertest.Run(f2, multipartRequest(t, part{"f", "big.txt", "text/plain", long}), nil).Request; !v.Deny {
		t.Error("a file past the sniff window was not digested whole")
	}
}
