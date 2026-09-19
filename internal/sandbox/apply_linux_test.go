package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rom/xproxy/internal/config"
)

// helperResult is what the confined child reports back.
type helperResult struct {
	Status        *Status `json:"status"`
	ReadInside    string  `json:"read_inside"`
	ReadOutside   string  `json:"read_outside"`
	WriteInside   string  `json:"write_inside"`
	WriteReadOnly string  `json:"write_read_only"`
	Unshare       string  `json:"unshare"`
	Ptrace        string  `json:"ptrace"`
	Dumpable      int     `json:"dumpable"`
	CoreLimit     uint64  `json:"core_limit"`
	CapsEmpty     bool    `json:"caps_empty"`
	NoNewPrivs    int     `json:"no_new_privs"`
	Bind          string  `json:"bind"`
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}

// TestHelperSandbox is the confined child; it does nothing unless invoked
// by TestApplyLinux.
func TestHelperSandbox(t *testing.T) {
	root := os.Getenv("XPROXY_SANDBOX_HELPER")
	if root == "" {
		t.Skip("helper")
	}
	readDir, writeDir, outside := filepath.Join(root, "read"), filepath.Join(root, "write"), filepath.Join(root, "outside")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
management: {socket: %s/mgmt.sock}
logging: {directory: %s}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: s, paths: [/s/], static: {root: %s}}
  - {name: r, upstream: u}
sandbox:
  landlock: {read_paths: [/proc/self/status]}
`, writeDir, writeDir, readDir)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	res := helperResult{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := Apply(cfg, filepath.Join(readDir, "xproxy.yaml"), log)
	if err != nil {
		t.Fatal(err)
	}
	res.Status = st
	_, err = os.ReadFile(filepath.Join(readDir, "file"))
	res.ReadInside = errString(err)
	_, err = os.ReadFile(filepath.Join(outside, "file"))
	res.ReadOutside = errString(err)
	res.WriteInside = errString(os.WriteFile(filepath.Join(writeDir, "new"), []byte("x"), 0o600))
	res.WriteReadOnly = errString(os.WriteFile(filepath.Join(readDir, "new"), []byte("x"), 0o600))
	res.Unshare = errString(unix.Unshare(unix.CLONE_NEWUSER))
	res.Ptrace = errString(unix.PtraceAttach(os.Getppid()))
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil {
		res.Dumpable = d
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err == nil {
		res.CoreLimit = rl.Max
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err == nil {
		res.CapsEmpty = data[0].Effective|data[0].Permitted|data[0].Inheritable|data[1].Effective|data[1].Permitted|data[1].Inheritable == 0
	}
	if v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err == nil {
		res.NoNewPrivs = v
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		res.Bind = errString(unix.Bind(fd, &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}))
		_ = unix.Close(fd)
	}
	b, _ := json.Marshal(res)
	fmt.Fprintf(os.Stdout, "\nRESULT %s\n", b)
}

func TestApplyLinux(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"read", "write", "outside"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "file"), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSandbox$", "-test.v")
	cmd.Env = append(os.Environ(), "XPROXY_SANDBOX_HELPER="+root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	i := strings.LastIndex(string(out), "RESULT ")
	if i < 0 {
		t.Fatalf("no result in helper output:\n%s", out)
	}
	line := string(out[i+len("RESULT "):])
	line = line[:strings.IndexByte(line, '\n')]
	var res helperResult
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		t.Fatalf("%v: %s", err, line)
	}
	st := res.Status
	if st == nil || !st.Enabled || st.Platform != "linux" || st.AppliedAt.IsZero() {
		t.Fatalf("status %+v", st)
	}
	states := map[string]Mechanism{}
	for _, m := range st.Mechanism {
		states[m.Name] = m
	}
	for _, name := range []string{"debuggable", "capabilities", "no_new_privs", "landlock", "seccomp"} {
		if _, ok := states[name]; !ok {
			t.Fatalf("mechanism %s not reported: %+v", name, st.Mechanism)
		}
	}
	t.Logf("mechanisms: %+v", st.Mechanism)

	if m := states["debuggable"]; m.State != StateApplied {
		t.Errorf("debuggable: %+v", m)
	} else if res.Dumpable != 0 || res.CoreLimit != 0 {
		t.Errorf("dumpable %d core %d", res.Dumpable, res.CoreLimit)
	}
	if m := states["no_new_privs"]; m.State != StateApplied || res.NoNewPrivs != 1 {
		t.Errorf("no_new_privs: %+v (%d)", m, res.NoNewPrivs)
	}
	switch m := states["capabilities"]; m.State {
	case StateApplied:
		if !res.CapsEmpty {
			t.Error("capabilities reported dropped but sets not empty")
		}
	case StateFailed:
		t.Logf("capabilities not fully dropped here: %s", m.Detail)
	default:
		t.Errorf("capabilities: %+v", m)
	}
	if res.ReadInside != "ok" || res.WriteInside != "ok" {
		t.Errorf("admitted paths refused: read %s write %s", res.ReadInside, res.WriteInside)
	}
	switch m := states["landlock"]; m.State {
	case StateApplied:
		if !st.Landlocked || st.LandlockABI == 0 || len(st.ReadPaths) == 0 || len(st.WritePaths) == 0 {
			t.Errorf("landlock status %+v", st)
		}
		for _, p := range st.MissingPaths {
			if !beneathAny(p, st.ReadPaths) && !beneathAny(p, st.WritePaths) {
				t.Errorf("missing path %s is not one of the rules", p)
			}
		}
		if res.ReadOutside != unix.EACCES.Error() || res.WriteReadOnly != unix.EACCES.Error() {
			t.Errorf("landlock in force but outside read %q, read-only write %q", res.ReadOutside, res.WriteReadOnly)
		}
		if st.LandlockABI >= 4 && res.Bind != unix.EACCES.Error() {
			t.Errorf("ABI %d: bind after start %q", st.LandlockABI, res.Bind)
		}
	case StateUnavailable:
		t.Logf("landlock unavailable here: %s", m.Detail)
		if res.ReadOutside != "ok" {
			t.Errorf("without landlock outside read should work: %s", res.ReadOutside)
		}
	default:
		t.Errorf("landlock: %+v", m)
	}
	switch m := states["seccomp"]; m.State {
	case StateApplied:
		if st.Denied == 0 || res.Unshare != unix.EPERM.Error() || res.Ptrace != unix.EPERM.Error() {
			t.Errorf("seccomp in force but unshare %q ptrace %q denied %d", res.Unshare, res.Ptrace, st.Denied)
		}
	case StateUnavailable:
		t.Logf("seccomp unavailable here: %s", m.Detail)
	default:
		t.Errorf("seccomp: %+v", m)
	}
}

func TestApplyDisabledAndStrict(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
sandbox: {enabled: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := Apply(cfg, "", log)
	if err != nil || st.Enabled || len(st.Mechanism) != 0 || st.Landlocked {
		t.Fatalf("disabled: %+v %v", st, err)
	}
	if err := st.Check(cfg, ""); err != nil {
		t.Fatal(err)
	}
}
