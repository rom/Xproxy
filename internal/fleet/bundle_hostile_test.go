package fleet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// A bundle is a set of files a controller sends and a node writes to
// disk as the proxy user. Everything in it — the paths, the modes, the
// sizes — comes over the network, so the reader is the boundary.

func TestValidPath(t *testing.T) {
	good := []string{
		"xproxy.yaml", "a/b.yaml", "a/b/c/d.conf", "waf/rules.conf",
		"a-b_c.d", strings.Repeat("a", 255),
	}
	for _, p := range good {
		if !ValidPath(p) {
			t.Errorf("%q was refused", p)
		}
	}
	bad := []string{
		"", ".", "..", "/etc/passwd", "a/../../etc/passwd", "../x", "a/..",
		"./a", "a/./b", "a//b", "a/", "/a", "a\\b", "C:\\x", "a\x00b",
		".hidden", "a/.hidden", ".ssh/authorized_keys", "a/b/../../..",
		strings.Repeat("a", 256), strings.Repeat("a/", 20) + "b",
	}
	for _, p := range bad {
		if ValidPath(p) {
			t.Errorf("%q was accepted", p)
		}
	}
	// Nothing that passes can leave the directory it is joined to.
	for _, p := range good {
		if joined := filepath.Join("/var/lib/xproxy", p); !strings.HasPrefix(joined, "/var/lib/xproxy/") {
			t.Errorf("%q joined to %q", p, joined)
		}
	}
}

func TestDigestCoversEveryField(t *testing.T) {
	base := []File{
		{Path: "a.yaml", Mode: 0o600, Content: []byte("one")},
		{Path: "b/c.yaml", Mode: 0o640, Content: []byte("two")},
	}
	d := Digest(base)
	if d != Digest(base) {
		t.Fatal("the digest is not stable")
	}
	// The order of the files does not matter; their content, names and
	// modes do.
	swapped := []File{base[1], base[0]}
	if Digest(swapped) != d {
		t.Error("reordering the files changed the digest")
	}
	for name, mutate := range map[string]func([]File) []File{
		"content":        func(f []File) []File { f[0].Content = []byte("other"); return f },
		"a path":         func(f []File) []File { f[0].Path = "z.yaml"; return f },
		"a mode":         func(f []File) []File { f[0].Mode = 0o644; return f },
		"an extra file":  func(f []File) []File { return append(f, File{Path: "c", Mode: 0o600, Content: []byte("x")}) },
		"a missing file": func(f []File) []File { return f[:1] },
		"an empty file":  func(f []File) []File { f[0].Content = nil; return f },
	} {
		cp := []File{
			{Path: "a.yaml", Mode: 0o600, Content: []byte("one")},
			{Path: "b/c.yaml", Mode: 0o640, Content: []byte("two")},
		}
		if Digest(mutate(cp)) == d {
			t.Errorf("%s did not change the digest", name)
		}
	}
	// Two files whose contents could be concatenated into one another
	// hash differently: the length is part of the digest.
	a := []File{{Path: "x", Mode: 0o600, Content: []byte("ab")}, {Path: "y", Mode: 0o600, Content: []byte("c")}}
	b := []File{{Path: "x", Mode: 0o600, Content: []byte("a")}, {Path: "y", Mode: 0o600, Content: []byte("bc")}}
	if Digest(a) == Digest(b) {
		t.Error("the digest does not separate one file from the next")
	}
}

func TestValidateRefusals(t *testing.T) {
	const minimal = "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:8080\"}]\n" +
		"upstreams:\n  - {name: u, endpoints: [{address: 127.0.0.1:9}]}\n" +
		"routes:\n  - {name: r, paths: [\"/\"], upstream: u}\n"
	good := func() *Bundle {
		b := &Bundle{Files: []File{{Path: ConfigFile, Mode: 0o600, Content: []byte(minimal)}}}
		b.Digest = Digest(b.Files)
		return b
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("a good bundle was refused: %v", err)
	}
	cases := map[string]func(*Bundle){
		"no files":              func(b *Bundle) { b.Files = nil; b.Digest = "" },
		"no configuration file": func(b *Bundle) { b.Files[0].Path = "other.yaml"; b.Digest = Digest(b.Files) },
		"a configuration that does not parse": func(b *Bundle) {
			b.Files[0].Content = []byte("not: [valid")
			b.Digest = Digest(b.Files)
		},
		"a configuration that is not a configuration": func(b *Bundle) {
			b.Files[0].Content = []byte("just a string\n")
			b.Digest = Digest(b.Files)
		},
		"a path that escapes": func(b *Bundle) {
			b.Files = append(b.Files, File{Path: "../../etc/passwd", Mode: 0o600, Content: []byte("x")})
			b.Digest = Digest(b.Files)
		},
		"an absolute path": func(b *Bundle) {
			b.Files = append(b.Files, File{Path: "/etc/passwd", Mode: 0o600, Content: []byte("x")})
			b.Digest = Digest(b.Files)
		},
		"a dot file": func(b *Bundle) {
			b.Files = append(b.Files, File{Path: ".ssh/authorized_keys", Mode: 0o600, Content: []byte("x")})
			b.Digest = Digest(b.Files)
		},
		"a digest that does not match": func(b *Bundle) { b.Digest = strings.Repeat("0", 64) },
		"a world writable mode": func(b *Bundle) {
			b.Files[0].Mode = 0o666
			b.Digest = Digest(b.Files)
		},
		"a group writable mode": func(b *Bundle) {
			b.Files[0].Mode = 0o660
			b.Digest = Digest(b.Files)
		},
		"a setuid mode": func(b *Bundle) {
			b.Files[0].Mode = 0o4600
			b.Digest = Digest(b.Files)
		},
		"a duplicate path": func(b *Bundle) {
			b.Files = append(b.Files, b.Files[0])
			b.Digest = Digest(b.Files)
		},
	}
	for name, mutate := range cases {
		b := good()
		mutate(b)
		if err := b.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A bundle larger than the ceiling is refused before anything is
	// written.
	big := good()
	big.Files = append(big.Files, File{Path: "big.bin", Mode: 0o600, Content: make([]byte, maxBundleBytes)})
	big.Digest = Digest(big.Files)
	if err := big.Validate(); err == nil {
		t.Error("an oversize bundle was accepted")
	}
	// A bundle with no digest at all is accepted: the digest is
	// optional, and the controller's signature covers the transport.
	nodigest := good()
	nodigest.Digest = ""
	if err := nodigest.Validate(); err != nil {
		t.Errorf("a bundle without a digest: %v", err)
	}
}

func TestReadRefusesWhatItCannotSend(t *testing.T) {
	dir := t.TempDir()
	write := func(p, body string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("xproxy.yaml", "version: 1\n", 0o644)
	write("conf.d/a.yaml", "a: 1\n", 0o600)
	write(".hidden", "secret\n", 0o600)
	write(".git/config", "secret\n", 0o600)
	b, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]File{}
	for _, f := range b.Files {
		paths[f.Path] = f
	}
	if len(paths) != 2 || paths["xproxy.yaml"].Content == nil || paths["conf.d/a.yaml"].Content == nil {
		t.Fatalf("files: %v", paths)
	}
	// Dot files and dot directories are not sent, and every mode the
	// node will write is at least 0600 and no wider than it was.
	for p, f := range paths {
		if strings.HasPrefix(p, ".") || strings.Contains(p, "/.") {
			t.Errorf("a dot entry was read: %q", p)
		}
		if f.Mode&0o600 != 0o600 {
			t.Errorf("%s has mode %o", p, f.Mode)
		}
	}
	// The digest is computed over what was read.
	if b.Digest != Digest(b.Files) {
		t.Error("the digest does not match the files")
	}
	// A later directory overrides an earlier one, file by file.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "xproxy.yaml"), []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err = Read(dir, other)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range b.Files {
		if f.Path == "xproxy.yaml" && string(f.Content) != "version: 2\n" {
			t.Errorf("the override did not win: %q", f.Content)
		}
	}
	// A directory that is not there is skipped rather than failing: a
	// node directory is optional.
	if _, err := Read(filepath.Join(dir, "missing"), dir); err != nil {
		t.Errorf("a missing directory: %v", err)
	}
	// Something that is not a regular file is refused rather than read.
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.yaml")); err == nil {
		if _, err := Read(dir); err == nil {
			t.Error("a symbolic link was read into a bundle")
		}
	}
}

func TestWriteAndRestore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "xproxy.yaml"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep.yaml"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &Bundle{Files: []File{
		{Path: "xproxy.yaml", Mode: 0o600, Content: []byte("new\n")},
		{Path: "conf.d/a.yaml", Mode: 0o640, Content: []byte("added\n")},
	}}
	restore, err := Write(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "xproxy.yaml")); string(got) != "new\n" {
		t.Fatalf("the file was not replaced: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "conf.d", "a.yaml")); string(got) != "added\n" {
		t.Fatalf("the new file is %q", got)
	}
	// A file that was there and is not in the bundle is left alone.
	if got, _ := os.ReadFile(filepath.Join(dir, "keep.yaml")); string(got) != "mine\n" {
		t.Errorf("an unrelated file changed: %q", got)
	}
	// No temporary files are left behind.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), "fleet-tmp") {
			t.Errorf("temporary file %q left behind", e.Name())
		}
	}
	// Restoring puts the previous content back and removes what was
	// added, which is what happens when the proxy refuses the bundle.
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "xproxy.yaml")); string(got) != "old\n" {
		t.Errorf("the restore gave %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "conf.d", "a.yaml")); !os.IsNotExist(err) {
		t.Error("a file added by the bundle survived the restore")
	}
	// A path that escapes is refused at write time as well as at
	// validation, and nothing before it in the bundle is left applied
	// once the caller restores.
	escape := &Bundle{Files: []File{{Path: "../escaped.yaml", Mode: 0o600, Content: []byte("x")}}}
	restore, err = Write(dir, escape)
	if err == nil {
		t.Error("a bundle with an escaping path was written")
	}
	if err := restore(); err != nil {
		t.Errorf("restore after a refused write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escaped.yaml")); err == nil {
		t.Error("a file was written outside the directory")
	}
	// A path that exists as a directory is refused rather than replaced.
	if err := os.MkdirAll(filepath.Join(dir, "adir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, &Bundle{Files: []File{{Path: "adir", Mode: 0o600, Content: []byte("x")}}}); err == nil {
		t.Error("a directory was overwritten by a bundle file")
	}
}

// TestAgentAgainstAHostileController points the agent at a server that
// answers like a controller but is not one. The node writes what it is
// told to disk, so every answer that is not a valid bundle has to stop
// at the agent.
func TestAgentAgainstAHostileController(t *testing.T) {
	var body atomic.Value
	body.Store("{}")
	var code atomic.Int32
	code.Store(200)
	var reports atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			reports.Add(1)
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(int(code.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()

	nodeDir := t.TempDir()
	cfgPath := filepath.Join(nodeDir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applies := 0
	apply := true
	// The agent always loads its client certificate, even for a
	// controller reached over plain HTTP as this one is.
	certDir := t.TempDir()
	ca := testutil.WriteCA(t, certDir)
	certFile, keyFile := ca.Issue(t, certDir, "edge1")
	cfg := config.Fleet{Controller: srv.URL, NodeID: "edge1", Interval: config.Duration(300 * time.Millisecond),
		Timeout: config.Duration(2 * time.Second), Apply: &apply,
		TLS: config.FleetTLS{CertFile: certFile, KeyFile: keyFile, CAFile: filepath.Join(certDir, "ca.pem"), ServerName: "controller"}}
	ag, err := NewAgent(cfg, cfgPath, Hooks{Apply: func() error { applies++; return nil }}, nolog)
	if err != nil {
		t.Fatal(err)
	}

	const minimal = "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:8080\"}]\n" +
		"upstreams:\n  - {name: u, endpoints: [{address: 127.0.0.1:9}]}\n" +
		"routes:\n  - {name: r, paths: [\"/\"], upstream: u}\n"
	bundleJSON := func(files []File) string {
		b := Bundle{Files: files}
		b.Digest = Digest(b.Files)
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	answers := map[string]struct {
		code int
		body string
	}{
		"not json":                            {200, "<html>hello</html>"},
		"a truncated document":                {200, `{"files":[`},
		"a json array":                        {200, `[1,2,3]`},
		"a bundle with no files":              {200, `{"files":[]}`},
		"a bundle with no configuration":      {200, bundleJSON([]File{{Path: "other.yaml", Mode: 0o600, Content: []byte("x")}})},
		"a configuration that does not parse": {200, bundleJSON([]File{{Path: ConfigFile, Mode: 0o600, Content: []byte("not: [valid")}})},
		"a path that escapes": {200, bundleJSON([]File{
			{Path: ConfigFile, Mode: 0o600, Content: []byte(minimal)},
			{Path: "../../etc/cron.d/x", Mode: 0o600, Content: []byte("* * * * * root sh\n")},
		})},
		"an absolute path": {200, bundleJSON([]File{
			{Path: ConfigFile, Mode: 0o600, Content: []byte(minimal)},
			{Path: "/etc/cron.d/x", Mode: 0o600, Content: []byte("x")},
		})},
		"a world writable file": {200, bundleJSON([]File{
			{Path: ConfigFile, Mode: 0o666, Content: []byte(minimal)},
		})},
		"a digest that does not match": {200, `{"digest":"` + strings.Repeat("0", 64) + `","files":[{"path":"` + ConfigFile + `","mode":384,"content":"eA=="}]}`},
		"a server error":               {500, `{"error":"broken"}`},
		"unauthorized":                 {401, ``},
		"a teapot":                     {418, ``},
	}
	for name, a := range answers {
		code.Store(int32(a.code)) //nolint:gosec // test status
		body.Store(a.body)
		before, _ := os.ReadFile(cfgPath)
		if err := ag.cycle(); err == nil && a.code == 200 {
			t.Errorf("%s was accepted", name)
		}
		after, _ := os.ReadFile(cfgPath)
		if string(before) != string(after) {
			t.Errorf("%s changed the configuration file: %q", name, after)
		}
		if applies != 0 {
			t.Fatalf("%s reloaded the proxy", name)
		}
		// Nothing was written outside the node directory either.
		if _, err := os.Stat(filepath.Join(filepath.Dir(nodeDir), "etc")); err == nil {
			t.Fatalf("%s wrote outside the node directory", name)
		}
	}
	// 304 and 404 are not failures: they mean unchanged and unassigned.
	for _, tc := range []struct {
		code     int
		assigned bool
	}{{304, true}, {404, false}} {
		code.Store(int32(tc.code)) //nolint:gosec // test status
		body.Store("")
		if err := ag.cycle(); err != nil {
			t.Errorf("HTTP %d: %v", tc.code, err)
		}
		if ag.Status().Assigned != tc.assigned {
			t.Errorf("HTTP %d: assigned %v", tc.code, ag.Status().Assigned)
		}
	}
	// A bundle that is a bundle is applied, and the status says so.
	code.Store(200)
	body.Store(bundleJSON([]File{{Path: ConfigFile, Mode: 0o600, Content: []byte(minimal)}}))
	if err := ag.cycle(); err != nil {
		t.Fatalf("a valid bundle: %v", err)
	}
	if applies != 1 {
		t.Fatalf("the proxy was reloaded %d times", applies)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != minimal {
		t.Fatalf("the configuration is %q", got)
	}
	st := ag.Status()
	if !st.Applied.OK || st.Applied.Digest == "" || st.LastError != "" {
		t.Fatalf("status after a good bundle: %+v", st)
	}
	if reports.Load() == 0 {
		t.Error("the node never reported its status")
	}
	// A controller that goes away is a failure the agent survives.
	srv.Close()
	if err := ag.cycle(); err == nil {
		t.Error("a closed controller was polled successfully")
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != minimal {
		t.Errorf("a failed cycle changed the configuration: %q", got)
	}
	// Poke is safe whether or not the loop is running.
	ag.Poke()
	ag.Poke()
	ag.Stop()
	ag.Stop()
}
