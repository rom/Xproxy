package uploadguard

import (
	"bytes"
	"net/http"
	"strings"
)

// detect names the content family of a file from its first bytes:
// Go's sniffer for the web types plus signatures for documents,
// archives and executables it does not know. "" means unrecognised.
func detect(head []byte) string {
	if len(head) == 0 {
		return ""
	}
	for _, s := range signatures {
		if len(head) >= s.offset+len(s.magic) && bytes.Equal(head[s.offset:s.offset+len(s.magic)], s.magic) {
			return s.family
		}
	}
	ct := http.DetectContentType(head)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch ct {
	case "application/octet-stream", "text/plain":
		return ""
	}
	return ct
}

type signature struct {
	offset int
	magic  []byte
	family string
}

var signatures = []signature{
	{0, []byte("%PDF-"), "application/pdf"},
	{0, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, "image/png"},
	{0, []byte{0xff, 0xd8, 0xff}, "image/jpeg"},
	{0, []byte("GIF87a"), "image/gif"},
	{0, []byte("GIF89a"), "image/gif"},
	{0, []byte("BM"), "image/bmp"},
	{8, []byte("WEBP"), "image/webp"},
	{0, []byte("PK\x03\x04"), "application/zip"},
	{0, []byte("PK\x05\x06"), "application/zip"},
	{0, []byte("Rar!\x1a\x07"), "application/x-rar"},
	{0, []byte{0x1f, 0x8b}, "application/gzip"},
	{0, []byte("7z\xbc\xaf\x27\x1c"), "application/x-7z"},
	{0, []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), "application/x-ole"},
	{0, []byte("MZ"), "application/x-msdownload"},
	{0, []byte{0x7f, 'E', 'L', 'F'}, "application/x-elf"},
	{0, []byte{0xfe, 0xed, 0xfa, 0xce}, "application/x-mach-o"},
	{0, []byte{0xfe, 0xed, 0xfa, 0xcf}, "application/x-mach-o"},
	{0, []byte{0xce, 0xfa, 0xed, 0xfe}, "application/x-mach-o"},
	{0, []byte{0xcf, 0xfa, 0xed, 0xfe}, "application/x-mach-o"},
	{0, []byte{0xca, 0xfe, 0xba, 0xbe}, "application/x-mach-o"},
	{0, []byte("!<arch>\n"), "application/x-archive"},
	{0, []byte("\x00asm"), "application/wasm"},
	{4, []byte("ftyp"), "video/mp4"},
	{0, []byte("ID3"), "audio/mpeg"},
	{0, []byte("OggS"), "audio/ogg"},
	{0, []byte("fLaC"), "audio/flac"},
	{0, []byte("RIFF"), "application/x-riff"},
	{0, []byte("{\\rtf"), "application/rtf"},
	{0, []byte("SQLite format 3"), "application/x-sqlite3"},
}

// families maps extensions to the content family their bytes must show.
var families = map[string]string{
	"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp",
	"pdf": "application/pdf",
	"zip": "application/zip", "docx": "application/zip", "xlsx": "application/zip", "pptx": "application/zip", "odt": "application/zip", "ods": "application/zip", "odp": "application/zip", "jar": "application/zip", "apk": "application/zip", "epub": "application/zip",
	"doc": "application/x-ole", "xls": "application/x-ole", "ppt": "application/x-ole", "msg": "application/x-ole",
	"gz": "application/gzip", "tgz": "application/gzip", "rar": "application/x-rar", "7z": "application/x-7z",
	"mp4": "video/mp4", "m4a": "video/mp4", "mov": "video/mp4", "mp3": "audio/mpeg", "ogg": "audio/ogg", "flac": "audio/flac", "wav": "application/x-riff", "avi": "application/x-riff", "webm": "video/webm",
	"rtf": "application/rtf", "sqlite": "application/x-sqlite3", "wasm": "application/wasm",
	"exe": "application/x-msdownload", "dll": "application/x-msdownload",
}

func expectedFamily(ext string) string { return families[ext] }

func familyMatches(want, detected string) bool {
	if want == detected {
		return true
	}
	// Go's sniffer reports "video/webm" for webm and "video/mp4" for
	// mp4 family files; audio in an mp4 container sniffs as video.
	return strings.HasPrefix(detected, want)
}

// declaredMatches compares the part's declared media type with the
// detected family; a generic declaration or one of the same top level
// type is fine (image/jpg for image/jpeg, text/xml for image/svg+xml).
func declaredMatches(declared, detected string) bool {
	if declared == detected || declared == "*/*" {
		return true
	}
	dTop, _, _ := strings.Cut(declared, "/")
	tTop, _, _ := strings.Cut(detected, "/")
	if dTop == tTop {
		return true
	}
	switch {
	case declared == "text/xml" || declared == "application/xml":
		return strings.HasSuffix(detected, "+xml") || detected == "text/xml"
	case strings.HasPrefix(declared, "application/vnd.openxmlformats") || strings.HasPrefix(declared, "application/vnd.oasis") || declared == "application/java-archive":
		return detected == "application/zip"
	case strings.HasPrefix(declared, "application/vnd.ms-") || declared == "application/msword":
		return detected == "application/x-ole" || detected == "application/zip"
	case declared == "application/x-gzip" || declared == "application/x-tar" || declared == "application/x-compressed":
		return detected == "application/gzip"
	case declared == "application/x-zip-compressed":
		return detected == "application/zip"
	}
	return false
}

// executableKind recognises programs and server side code by content,
// whatever the name says: PE, ELF and Mach-O images, shell and
// interpreter scripts, PHP, JSP and ASP tags, Windows script files.
func executableKind(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("MZ")):
		return "pe"
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		return "elf"
	case bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xce}), bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(head, []byte{0xce, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(head, []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(head, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "mach-o"
	case bytes.HasPrefix(head, []byte("#!")):
		return "script"
	}
	lower := bytes.ToLower(head)
	for _, tag := range [][]byte{[]byte("<?php"), []byte("<?="), []byte("<%@"), []byte("<%="), []byte("<jsp:"), []byte("<script runat="), []byte("<script language=\"vbscript\""), []byte("<script language=\"jscript\"")} {
		if bytes.Contains(lower, tag) {
			return "server_script"
		}
	}
	return ""
}
