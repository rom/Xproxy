// Package uploadguard is a built-in filter kind that inspects file
// uploads before they reach the application: how many files, how large,
// which extensions (including the ones hidden in double extensions such
// as invoice.pdf.exe), whether the bytes match the declared type, and
// whether the content is an executable or a server side script whatever
// it is called.
//
//	filters:
//	  - name: uploads
//	    kind: upload_guard
//	    options:
//	      max_files: 10
//	      max_file_bytes: 10485760          # per file
//	      max_total_bytes: 52428800         # per request, buffered and replayed
//	      allowed_extensions: [jpg, jpeg, png, gif, webp, pdf, docx, xlsx]
//	      denied_extensions: []             # added to the built-in list
//	      double_extensions: deny           # deny, or allow to look at the last one only
//	      check_magic: true                 # bytes must match the extension and declared type
//	      strict_magic: false               # true also refuses files of unrecognised content
//	      deny_executables: true            # PE, ELF, Mach-O, scripts, server side code
//	      raw_uploads: false                # true also treats a non multipart body as one file
//	      fields: []                        # form field names that may carry files (empty: any)
//
// Multipart bodies are buffered up to max_total_bytes (a larger request
// is refused with 413) and replayed to the upstream unchanged. Denials
// carry reason "upload", a detail naming the check and the file, and a
// JSON problem body; the access log carries upload_files and
// upload_bytes for inspected requests.
package uploadguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rom/xproxy/internal/filter"
)

// Config is the options schema.
type Config struct {
	MaxFiles          int      `json:"max_files"`
	MaxFileBytes      int64    `json:"max_file_bytes"`
	MaxTotalBytes     int64    `json:"max_total_bytes"`
	AllowedExtensions []string `json:"allowed_extensions"`
	DeniedExtensions  []string `json:"denied_extensions"`
	DoubleExtensions  string   `json:"double_extensions"`
	CheckMagic        *bool    `json:"check_magic"`
	StrictMagic       bool     `json:"strict_magic"`
	DenyExecutables   *bool    `json:"deny_executables"`
	RawUploads        bool     `json:"raw_uploads"`
	Fields            []string `json:"fields"`
	MaxFilenameLength int      `json:"max_filename_length"`
}

// DefaultDeniedExtensions are refused unless allowed_extensions lists
// them explicitly: executables, installers, scripts and server side code.
var DefaultDeniedExtensions = []string{
	"exe", "dll", "com", "bat", "cmd", "scr", "pif", "msi", "msp", "cpl", "hta", "lnk", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "reg",
	"sh", "bash", "zsh", "csh", "ksh", "elf", "bin", "run", "app", "dmg", "pkg", "deb", "rpm", "apk",
	"php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "inc", "jsp", "jspx", "jsw", "jsv", "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx", "cer",
	"cgi", "pl", "py", "pyc", "rb", "jar", "war", "ear", "class", "swf", "htaccess", "htpasswd",
}

const (
	defaultMaxFiles      = 10
	defaultMaxFileBytes  = 10 << 20
	defaultMaxTotalBytes = 64 << 20
	maxTotalBound        = 1 << 30
	sniffLen             = 512
)

func parse(opts filter.Options) (*guard, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.MaxFiles == 0 {
		c.MaxFiles = defaultMaxFiles
	}
	if c.MaxFiles < 1 || c.MaxFiles > 10000 {
		errs = append(errs, errors.New("max_files: must be between 1 and 10000"))
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = defaultMaxFileBytes
	}
	if c.MaxFileBytes < 1 || c.MaxFileBytes > maxTotalBound {
		errs = append(errs, errors.New("max_file_bytes: must be between 1 and 1 GiB"))
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = defaultMaxTotalBytes
	}
	if c.MaxTotalBytes < 1 || c.MaxTotalBytes > maxTotalBound {
		errs = append(errs, errors.New("max_total_bytes: must be between 1 and 1 GiB"))
	}
	if c.MaxTotalBytes < c.MaxFileBytes {
		errs = append(errs, errors.New("max_total_bytes: must be at least max_file_bytes"))
	}
	if c.DoubleExtensions == "" {
		c.DoubleExtensions = "deny"
	}
	if c.DoubleExtensions != "deny" && c.DoubleExtensions != "allow" {
		errs = append(errs, errors.New("double_extensions: must be deny or allow"))
	}
	if c.MaxFilenameLength == 0 {
		c.MaxFilenameLength = 255
	}
	if c.MaxFilenameLength < 1 || c.MaxFilenameLength > 4096 {
		errs = append(errs, errors.New("max_filename_length: must be between 1 and 4096"))
	}
	g := &guard{cfg: &c, allowed: map[string]bool{}, denied: map[string]bool{}, fields: map[string]bool{}}
	for i, e := range c.AllowedExtensions {
		e = normExt(e)
		if e == "" {
			errs = append(errs, fmt.Errorf("allowed_extensions[%d]: not an extension", i))
			continue
		}
		g.allowed[e] = true
	}
	for _, e := range DefaultDeniedExtensions {
		g.denied[e] = true
	}
	for i, e := range c.DeniedExtensions {
		e = normExt(e)
		if e == "" {
			errs = append(errs, fmt.Errorf("denied_extensions[%d]: not an extension", i))
			continue
		}
		g.denied[e] = true
	}
	for _, e := range c.AllowedExtensions {
		// An explicit allow wins over the built-in deny list.
		delete(g.denied, normExt(e))
	}
	for i, f := range c.Fields {
		if f == "" || len(f) > 128 {
			errs = append(errs, fmt.Errorf("fields[%d]: not a field name", i))
			continue
		}
		g.fields[f] = true
	}
	g.magic = c.CheckMagic == nil || *c.CheckMagic
	g.execs = c.DenyExecutables == nil || *c.DenyExecutables
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return g, nil
}

func normExt(e string) string {
	e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
	if e == "" || len(e) > 16 || strings.ContainsAny(e, "./\\ ") {
		return ""
	}
	return e
}

type guard struct {
	name    string
	cfg     *Config
	allowed map[string]bool
	denied  map[string]bool
	fields  map[string]bool
	magic   bool
	execs   bool
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance { return &instance{g: g} }

type instance struct {
	g     *guard
	files int
	bytes int64
}

// refusal is one failed check.
type refusal struct {
	status int
	check  string
	file   string
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return filter.Continue
	}
	ct := r.Header.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		// A multipart type Go refuses (a duplicate boundary parameter, a
		// stray token) is one most upload parsers still accept, so letting
		// it through would skip every check: refuse it instead.
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "multipart/") {
			return in.deny(&refusal{status: http.StatusBadRequest, check: "multipart_content_type"})
		}
		return filter.Continue
	}
	switch {
	case mt == "multipart/form-data":
		return in.multipart(r, params["boundary"])
	case in.g.cfg.RawUploads && r.Method != http.MethodGet && r.Method != http.MethodHead:
		return in.raw(r, mt)
	}
	return filter.Continue
}

// buffer reads the body up to the total limit and restores it.
func (in *instance) buffer(r *http.Request) ([]byte, *refusal) {
	limit := in.g.cfg.MaxTotalBytes
	if r.ContentLength > limit {
		return nil, &refusal{status: http.StatusRequestEntityTooLarge, check: "total_size"}
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, &refusal{status: http.StatusBadRequest, check: "body_read"}
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if int64(len(data)) > limit {
		return nil, &refusal{status: http.StatusRequestEntityTooLarge, check: "total_size"}
	}
	return data, nil
}

func (in *instance) multipart(r *http.Request, boundary string) filter.Verdict {
	if boundary == "" {
		return in.deny(&refusal{status: http.StatusBadRequest, check: "multipart_boundary"})
	}
	data, ref := in.buffer(r)
	if ref != nil {
		return in.deny(ref)
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	for {
		part, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return in.deny(&refusal{status: http.StatusBadRequest, check: "multipart_syntax"})
		}
		name, unreadable := rawFileName(part)
		if unreadable {
			return in.deny(&refusal{status: http.StatusBadRequest, check: "multipart_disposition"})
		}
		if name == "" {
			// A plain form field; drain it (bounded by the buffer).
			_, _ = io.Copy(io.Discard, part)
			continue
		}
		if ref := in.checkFile(part.FormName(), name, part.Header.Get("Content-Type"), part); ref != nil {
			return in.deny(ref)
		}
	}
	return filter.Continue
}

func (in *instance) raw(r *http.Request, mt string) filter.Verdict {
	data, ref := in.buffer(r)
	if ref != nil {
		return in.deny(ref)
	}
	name := ""
	if cd := r.Header.Get("Content-Disposition"); cd != "" {
		_, params, err := mime.ParseMediaType(cd)
		switch {
		case err == nil:
			name = params["filename"]
		case strings.Contains(strings.ToLower(cd), "filename"):
			// The header names a file in a spelling this proxy cannot
			// read but the origin can; see rawFileName.
			return in.deny(&refusal{status: http.StatusBadRequest, check: "content_disposition"})
		}
	}
	if name == "" {
		name = path.Base(r.URL.Path)
		if name == "/" || name == "." {
			name = "upload"
		}
	}
	if ref := in.checkFile("", name, mt, bytes.NewReader(data)); ref != nil {
		return in.deny(ref)
	}
	return filter.Continue
}

// rawFileName returns the file name as the client sent it, and whether
// the part's disposition names a file in a spelling this proxy cannot
// read. The library's FileName strips directories, which would hide a
// traversal attempt.
//
// mime.ParseMediaType refuses a duplicate parameter name
// (`filename="a.jpg"; filename="shell.php"`) and a trailing bare one,
// and part.FileName falls back to the same failed parse, so both used to
// return "" and the part was taken for a plain form field: the extension
// list, the double-extension rule, the magic bytes, deny_executables and
// the size and count bounds were all skipped for a body buffer already
// replayed to the origin. PHP, Commons FileUpload, busboy, formidable
// and werkzeug accept those spellings and take one of the names, so a
// disposition that mentions a file and does not parse is refused rather
// than ignored.
func rawFileName(part *multipart.Part) (string, bool) {
	cd := part.Header.Get("Content-Disposition")
	if _, params, err := mime.ParseMediaType(cd); err == nil {
		if name, ok := params["filename"]; ok {
			return name, false
		}
		return part.FileName(), false
	}
	if strings.Contains(strings.ToLower(cd), "filename") {
		return "", true
	}
	return part.FileName(), false
}

// checkFile runs every check on one file; rd yields its content.
func (in *instance) checkFile(field, name, declared string, rd io.Reader) *refusal {
	g := in.g
	in.files++
	if in.files > g.cfg.MaxFiles {
		return &refusal{status: http.StatusBadRequest, check: "file_count", file: name}
	}
	if len(g.fields) > 0 && !g.fields[field] {
		return &refusal{status: http.StatusBadRequest, check: "field", file: name}
	}
	if ref := checkName(name, g.cfg.MaxFilenameLength); ref != nil {
		return ref
	}
	exts := extensions(name)
	if len(exts) == 0 && len(g.allowed) > 0 {
		return &refusal{status: http.StatusUnsupportedMediaType, check: "extension", file: name}
	}
	last := ""
	if len(exts) > 0 {
		last = exts[len(exts)-1]
	}
	checked := exts
	if g.cfg.DoubleExtensions == "allow" && len(exts) > 0 {
		checked = exts[len(exts)-1:]
	}
	for _, e := range checked {
		if g.denied[e] {
			return &refusal{status: http.StatusUnsupportedMediaType, check: "extension", file: name}
		}
	}
	if len(g.allowed) > 0 && !g.allowed[last] {
		return &refusal{status: http.StatusUnsupportedMediaType, check: "extension", file: name}
	}
	if len(g.allowed) > 0 && g.cfg.DoubleExtensions == "deny" {
		for _, e := range exts[:len(exts)-1] {
			if !g.allowed[e] && (g.denied[e] || families[e] != "" || looksLikeExtension(e)) {
				return &refusal{status: http.StatusUnsupportedMediaType, check: "double_extension", file: name}
			}
		}
	}
	// Content.
	head := make([]byte, sniffLen)
	n, err := io.ReadFull(rd, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return &refusal{status: http.StatusBadRequest, check: "body_read", file: name}
	}
	head = head[:n]
	size := int64(n)
	if n == sniffLen {
		rest, err := io.Copy(io.Discard, rd)
		if err != nil {
			return &refusal{status: http.StatusBadRequest, check: "body_read", file: name}
		}
		size += rest
	}
	in.bytes += size
	if size > g.cfg.MaxFileBytes {
		return &refusal{status: http.StatusRequestEntityTooLarge, check: "file_size", file: name}
	}
	if g.execs {
		if kind := executableKind(head); kind != "" {
			return &refusal{status: http.StatusUnsupportedMediaType, check: "executable:" + kind, file: name}
		}
	}
	if g.magic && n > 0 {
		detected := detect(head)
		if want := expectedFamily(last); want != "" {
			if detected == "" {
				if g.cfg.StrictMagic {
					return &refusal{status: http.StatusUnsupportedMediaType, check: "type_unknown", file: name}
				}
			} else if !familyMatches(want, detected) {
				return &refusal{status: http.StatusUnsupportedMediaType, check: "type_mismatch:" + detected, file: name}
			}
		} else if g.cfg.StrictMagic && detected == "" {
			return &refusal{status: http.StatusUnsupportedMediaType, check: "type_unknown", file: name}
		}
		if dm, _, err := mime.ParseMediaType(declared); err == nil && detected != "" && dm != "application/octet-stream" && !declaredMatches(dm, detected) {
			return &refusal{status: http.StatusUnsupportedMediaType, check: "declared_mismatch:" + detected, file: name}
		}
	}
	return nil
}

// checkName refuses names that carry paths, control characters or are
// too long; the application decides where a file goes, never the client.
func checkName(name string, maxLen int) *refusal {
	if name == "" || len(name) > maxLen || !utf8.ValidString(name) {
		return &refusal{status: http.StatusBadRequest, check: "filename", file: name}
	}
	if strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." || strings.HasPrefix(name, "..") {
		return &refusal{status: http.StatusBadRequest, check: "filename", file: name}
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return &refusal{status: http.StatusBadRequest, check: "filename", file: name}
		}
	}
	return nil
}

// extensions returns the lower-case extension chain of a name:
// "invoice.pdf.exe" gives [pdf exe]; a leading dot file has none.
func extensions(name string) []string {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 2 {
		return nil
	}
	out := parts[1:]
	if parts[0] == "" && len(out) == 1 {
		return nil
	}
	return out
}

// looksLikeExtension keeps version markers and words out of the double
// extension check: "report.2024.v2.pdf" and "my.holiday.jpg" are fine,
// "photo.html.jpg" is not. Known extensions are matched by the caller.
func looksLikeExtension(e string) bool {
	if len(e) < 2 || len(e) > 5 {
		return false
	}
	for _, c := range e {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func (in *instance) deny(ref *refusal) filter.Verdict {
	msg := map[string]any{"error": "upload refused", "reason": ref.check}
	if ref.file != "" {
		msg["file"] = ref.file
	}
	body, _ := json.Marshal(msg)
	resp := &http.Response{StatusCode: ref.status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
	detail := ref.check
	if ref.file != "" {
		f := ref.file
		if len(f) > 64 {
			f = f[:64]
		}
		detail += ":" + f
	}
	return filter.Verdict{Deny: true, Status: ref.status, Reason: "upload", Detail: detail, Response: resp, //nolint:bodyclose // sent by the data plane
		Attrs: []any{"upload_files", in.files, "upload_bytes", in.bytes}}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if in.files == 0 {
		return nil
	}
	return []any{"upload_files", in.files, "upload_bytes", strconv.FormatInt(in.bytes, 10)}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "upload_guard",
		Description: "file upload protection: count, size, extension and double extension rules, content type sniffing, executable and script detection",
		BuffersBody: true,
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			g, err := parse(opts)
			if err != nil {
				return nil, err
			}
			g.name = name
			return g, nil
		},
	})
}
