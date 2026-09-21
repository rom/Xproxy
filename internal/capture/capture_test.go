package capture

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func testConfig(t *testing.T, rules ...config.CaptureRule) *config.Capture {
	t.Helper()
	return &config.Capture{
		Enabled:      true,
		Directory:    t.TempDir(),
		FilePrefix:   "xproxy",
		MaxFileBytes: 64 << 20,
		MaxFiles:     4,
		MaxDuration:  config.Duration(time.Hour),
		SnapLen:      262144,
		MaxBodyBytes: 4096,
		Rules:        rules,
	}
}

func newTestCapturer(t *testing.T, c *config.Capture) *Capturer {
	t.Helper()
	cp, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cp == nil {
		t.Fatal("New returned nil for an enabled section")
	}
	t.Cleanup(cp.Close)
	cp.SetActive(true, time.Minute)
	return cp
}

func exchange(host, route, method, path string, status int, denied string) *Exchange {
	return &Exchange{
		Start:     time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
		Client:    netip.MustParseAddrPort("198.51.100.7:44321"),
		Server:    netip.MustParseAddrPort("203.0.113.9:443"),
		RequestID: "req-1",
		Host:      host, Route: route, Method: method, Path: path,
		Status: status, Denied: denied,
		Request:  []byte(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\n\r\n"),
	}
}

func TestNewDisabledIsNil(t *testing.T) {
	for _, c := range []*config.Capture{nil, {Enabled: false, Directory: "/tmp"}} {
		cp, err := New(c)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if cp != nil {
			t.Error("a disabled section built a capturer")
		}
		// Every method tolerates the nil, so no caller needs a guard.
		if cp.Active() || cp.MaxBody() != 0 || cp.Redact() != nil || cp.Stats().Enabled {
			t.Error("the nil capturer claims to be doing something")
		}
		cp.SetActive(true, time.Minute)
		cp.Write(exchange("a", "r", "GET", "/", 200, ""))
		cp.Flush()
		cp.Close()
	}
}

func TestNoRulesMeansEveryExchange(t *testing.T) {
	cp := newTestCapturer(t, testConfig(t))
	if !cp.Wants("any.example", "whatever", "GET", "/anything", netip.MustParseAddr("192.0.2.1")) {
		t.Error("a section with no rules refused an exchange; it should capture all of them")
	}
}

func TestRuleSelectors(t *testing.T) {
	client := netip.MustParseAddr("198.51.100.7")
	cases := []struct {
		name  string
		rule  config.CaptureRule
		want  bool
		host  string
		route string
		meth  string
		path  string
		ip    netip.Addr
	}{
		{name: "host exact", rule: config.CaptureRule{Hosts: []string{"shop.example.com"}}, host: "shop.example.com", want: true},
		{name: "host exact miss", rule: config.CaptureRule{Hosts: []string{"shop.example.com"}}, host: "other.example.com"},
		{name: "host wildcard", rule: config.CaptureRule{Hosts: []string{"*.example.com"}}, host: "api.example.com", want: true},
		{name: "host wildcard is not the apex", rule: config.CaptureRule{Hosts: []string{"*.example.com"}}, host: "example.com"},
		{name: "route", rule: config.CaptureRule{Routes: []string{"api"}}, route: "api", want: true},
		{name: "route miss", rule: config.CaptureRule{Routes: []string{"api"}}, route: "web"},
		{name: "method case insensitive", rule: config.CaptureRule{Methods: []string{"post"}}, meth: "POST", want: true},
		{name: "method miss", rule: config.CaptureRule{Methods: []string{"POST"}}, meth: "GET"},
		{name: "path prefix", rule: config.CaptureRule{Paths: []string{"/upload"}}, path: "/upload/x", want: true},
		{name: "path prefix miss", rule: config.CaptureRule{Paths: []string{"/upload"}}, path: "/other"},
		{name: "client cidr", rule: config.CaptureRule{ClientCIDRs: []string{"198.51.100.0/24"}}, ip: client, want: true},
		{name: "client cidr miss", rule: config.CaptureRule{ClientCIDRs: []string{"10.0.0.0/8"}}, ip: client},
		// Every selector a rule names has to hold.
		{name: "two selectors both hold", rule: config.CaptureRule{Routes: []string{"api"}, Methods: []string{"GET"}}, route: "api", meth: "GET", want: true},
		{name: "two selectors one misses", rule: config.CaptureRule{Routes: []string{"api"}, Methods: []string{"POST"}}, route: "api", meth: "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := newTestCapturer(t, testConfig(t, tc.rule))
			ip := tc.ip
			if !ip.IsValid() {
				ip = client
			}
			if got := cp.Wants(tc.host, tc.route, tc.meth, tc.path, ip); got != tc.want {
				t.Errorf("Wants(host=%q route=%q method=%q path=%q ip=%s) = %v, want %v",
					tc.host, tc.route, tc.meth, tc.path, ip, got, tc.want)
			}
		})
	}
}

// A selector on the answer cannot be decided before there is one, so it
// must not admit the request early and must admit it afterwards.
func TestAnswerSelectorsAreRetrospective(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rule    config.CaptureRule
		status  int
		denied  string
		written bool
	}{
		{name: "status", rule: config.CaptureRule{Statuses: []int{403}}, status: 403, written: true},
		{name: "status miss", rule: config.CaptureRule{Statuses: []int{403}}, status: 200},
		{name: "class", rule: config.CaptureRule{Statuses: []int{4}}, status: 404, written: true},
		{name: "class miss", rule: config.CaptureRule{Statuses: []int{4}}, status: 500},
		{name: "reason", rule: config.CaptureRule{Reasons: []string{"waf"}}, status: 403, denied: "waf", written: true},
		{name: "reason with detail", rule: config.CaptureRule{Reasons: []string{"waf"}}, status: 403, denied: "waf:942100", written: true},
		{name: "reason miss", rule: config.CaptureRule{Reasons: []string{"waf"}}, status: 429, denied: "rate_limit"},
		{name: "denied any", rule: config.CaptureRule{Denied: true}, status: 429, denied: "rate_limit", written: true},
		{name: "denied but allowed", rule: config.CaptureRule{Denied: true}, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := newTestCapturer(t, testConfig(t, tc.rule))
			// The request has to be held: the selector cannot be
			// decided until the proxy has answered.
			if !cp.Wants("h", "r", "GET", "/", netip.MustParseAddr("198.51.100.7")) {
				t.Fatal("the request was turned down before there was an answer to select on")
			}
			cp.Write(exchange("h", "r", "GET", "/", tc.status, tc.denied))
			st := cp.Stats()
			if (st.Captured == 1) != tc.written {
				t.Errorf("captured %d, skipped %d; want written=%v", st.Captured, st.Skipped, tc.written)
			}
		})
	}
}

func TestFirstMatchingRuleDecides(t *testing.T) {
	cp := newTestCapturer(t, testConfig(t,
		config.CaptureRule{Name: "denials", Denied: true},
		config.CaptureRule{Name: "everything"},
	))
	cp.Write(exchange("h", "r", "GET", "/", 403, "waf"))
	cp.Write(exchange("h", "r", "GET", "/", 200, ""))
	got := map[string]uint64{}
	for _, r := range cp.Stats().Rules {
		got[r.Name] = r.Captured
	}
	if got["denials"] != 1 || got["everything"] != 1 {
		t.Errorf("rule counts %v; the refusal belongs to the first rule that matches and the rest to the catch-all", got)
	}
}

func TestMaxFlowsBoundsARule(t *testing.T) {
	cp := newTestCapturer(t, testConfig(t, config.CaptureRule{Name: "bounded", MaxFlows: 3}))
	for range 10 {
		cp.Write(exchange("h", "r", "GET", "/", 200, ""))
	}
	st := cp.Stats()
	if st.Captured != 3 {
		t.Errorf("captured %d exchanges, want the 3 the rule allows: a rule left on must not fill a disk", st.Captured)
	}
	if st.Skipped != 7 {
		t.Errorf("skipped %d, want 7", st.Skipped)
	}
	// The reported count is what was written, not what was attempted.
	if len(st.Rules) != 1 || st.Rules[0].Captured != 3 || st.Rules[0].Limit != 3 {
		t.Errorf("rule stats %+v, want 3 of 3", st.Rules)
	}
}

func TestPercentSamples(t *testing.T) {
	cp := newTestCapturer(t, testConfig(t, config.CaptureRule{Name: "none", Percent: 1}))
	for range 200 {
		cp.Write(exchange("h", "r", "GET", "/", 200, ""))
	}
	st := cp.Stats()
	if st.Captured+st.Skipped != 200 {
		t.Fatalf("%d captured and %d skipped, want 200 decisions", st.Captured, st.Skipped)
	}
	// One percent of 200 is two; anything near 200 means the sampling
	// never ran, which is the failure that matters.
	if st.Captured > 40 {
		t.Errorf("a 1%% rule captured %d of 200", st.Captured)
	}
}

func TestInactiveCapturerWritesNothing(t *testing.T) {
	cp := newTestCapturer(t, testConfig(t))
	cp.SetActive(false, 0)
	if cp.Wants("h", "r", "GET", "/", netip.MustParseAddr("198.51.100.7")) {
		t.Error("an idle capturer wants an exchange")
	}
	cp.Write(exchange("h", "r", "GET", "/", 200, ""))
	if st := cp.Stats(); st.Captured != 0 || st.Skipped != 0 {
		t.Errorf("an idle capturer recorded %+v", st)
	}
}

func TestWindowClosesItself(t *testing.T) {
	c := testConfig(t)
	cp := newTestCapturer(t, c)
	cp.SetActive(true, time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if cp.Active() {
		t.Fatal("the window did not close on its own; a capture started during an incident could run for a month")
	}
	cp.Write(exchange("h", "r", "GET", "/", 200, ""))
	if st := cp.Stats(); st.Captured != 0 {
		t.Errorf("wrote %d exchanges after the window closed", st.Captured)
	}
}

func TestSetActiveClampsToMaxDuration(t *testing.T) {
	c := testConfig(t)
	c.MaxDuration = config.Duration(time.Minute)
	cp := newTestCapturer(t, c)
	cp.SetActive(true, 24*time.Hour)
	if until := cp.Stats().Until; until.After(time.Now().Add(2 * time.Minute)) {
		t.Errorf("window ends at %s, past the configured one minute maximum", until)
	}
	// A zero duration is the configured maximum, never "forever".
	cp.SetActive(true, 0)
	st := cp.Stats()
	if st.Until.IsZero() || st.Until.After(time.Now().Add(2*time.Minute)) {
		t.Errorf("an unbounded start gave %v, want the configured maximum", st.Until)
	}
}

func TestCarryFromKeepsTheWindow(t *testing.T) {
	old := newTestCapturer(t, testConfig(t))
	old.SetActive(true, 30*time.Minute)
	until := old.Stats().Until

	fresh := newTestCapturer(t, testConfig(t))
	fresh.SetActive(false, 0)
	fresh.CarryFrom(old)
	if !fresh.Active() {
		t.Fatal("a reload during a reproduction stopped the capture")
	}
	if got := fresh.Stats().Until; !got.Equal(until) {
		t.Errorf("window ends at %s after the reload, want the original %s", got, until)
	}

	// An idle capturer carries nothing over.
	stopped := newTestCapturer(t, testConfig(t))
	stopped.SetActive(false, 0)
	after := newTestCapturer(t, testConfig(t))
	after.SetActive(false, 0)
	after.CarryFrom(stopped)
	if after.Active() {
		t.Error("a reload started a capture nobody asked for")
	}
}

func TestFileIsPrivateAndParsable(t *testing.T) {
	c := testConfig(t)
	cp := newTestCapturer(t, c)
	cp.Write(exchange("shop.example.com", "web", "GET", "/", 200, ""))
	cp.Flush()

	entries, err := os.ReadDir(c.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d files in the capture directory, want 1", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "xproxy-") || !strings.HasSuffix(name, ".pcapng") {
		t.Errorf("file named %q, want the configured prefix and a .pcapng suffix", name)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	// The file holds decrypted requests and responses.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("capture file mode %o, want 600: it holds cookies and tokens in the clear", perm)
	}

	b, err := os.ReadFile(filepath.Join(c.Directory, name))
	if err != nil {
		t.Fatal(err)
	}
	blocks := readBlocks(t, b)
	if len(blocks) < 3 || blocks[0].kind != blockSectionHeader || blocks[1].kind != blockInterface {
		t.Fatalf("file does not begin with a section header and an interface: %d blocks", len(blocks))
	}
	pkts := readPackets(t, blocks)
	if len(pkts) != 8 {
		t.Fatalf("%d packets, want a handshake, two data segments and a close", len(pkts))
	}
	for i, p := range pkts {
		if !strings.Contains(p.comment, "request_id=req-1") {
			t.Errorf("packet %d comment %q carries no request id; a frame and an access log line must name each other", i, p.comment)
		}
	}
	if st := cp.Stats(); st.Bytes == 0 || st.File == "" {
		t.Errorf("stats report %d bytes and file %q", st.Bytes, st.File)
	}
}

func TestRotationAndPruning(t *testing.T) {
	c := testConfig(t)
	c.MaxFileBytes = 1 << 20 // the smallest the validator allows
	c.MaxFiles = 2
	cp := newTestCapturer(t, c)
	e := exchange("h", "r", "POST", "/upload", 200, "")
	e.Request = append(e.Request, make([]byte, 300<<10)...)
	for range 12 {
		cp.Write(e)
	}
	cp.Flush()
	entries, err := os.ReadDir(c.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > c.MaxFiles {
		t.Errorf("%d files on disk, want at most max_files (%d)", len(entries), c.MaxFiles)
	}
	if len(entries) < 2 {
		t.Errorf("%d files after %d MiB of exchanges; the capture never rotated", len(entries), 12*300>>10)
	}
	if st := cp.Stats(); st.Captured != 12 {
		t.Errorf("captured %d exchanges across the rotation, want 12", st.Captured)
	}
}

func TestWriteFailureIsCountedNotLogged(t *testing.T) {
	c := testConfig(t)
	c.Directory = filepath.Join(t.TempDir(), "gone")
	cp := newTestCapturer(t, c)
	cp.Write(exchange("h", "r", "GET", "/", 200, ""))
	st := cp.Stats()
	if st.WriteFailures != 1 || st.Captured != 0 {
		t.Errorf("stats %+v, want one write failure and nothing captured", st)
	}
}

func TestTruncationIsCounted(t *testing.T) {
	cp := newTestCapturer(t, testConfig(t))
	e := exchange("h", "r", "POST", "/", 200, "")
	e.RequestTruncated = true
	cp.Write(e)
	if st := cp.Stats(); st.Truncated != 1 {
		t.Errorf("truncated = %d, want 1", st.Truncated)
	}
	// And the frame says so, so a reader does not believe the client
	// stopped where the bound did.
	cp.Flush()
	entries, _ := os.ReadDir(cp.cfg.Directory)
	b, err := os.ReadFile(filepath.Join(cp.cfg.Directory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	pkts := readPackets(t, readBlocks(t, b))
	if !strings.Contains(pkts[0].comment, "request=truncated") {
		t.Errorf("comment %q does not say the request was cut", pkts[0].comment)
	}
}

// Every value in a comment came from a request, and a capture file is
// opened by a person.
func TestCommentSanitises(t *testing.T) {
	e := exchange("h", "r", "GET", "/", 200, "")
	e.RequestID = "a\nb\x1b[31m c"
	e.Route = strings.Repeat("R", 300)
	got := comment(e)
	if strings.ContainsAny(got, "\r\n\x1b") {
		t.Errorf("comment %q carries control characters into the operator's terminal", got)
	}
	if len(got) > 400 {
		t.Errorf("comment is %d bytes; a request must not choose how much of the file is its own id", len(got))
	}
	if !strings.HasPrefix(got, "request_id=") {
		t.Errorf("comment %q does not start with the request id", got)
	}
}

func TestMaxBodyAndRedactReportTheConfiguration(t *testing.T) {
	c := testConfig(t)
	c.Redact = []string{"Authorization", "Cookie"}
	cp := newTestCapturer(t, c)
	if cp.MaxBody() != 0 {
		t.Errorf("MaxBody = %d with bodies off, want 0: nothing should be buffered", cp.MaxBody())
	}
	c.Bodies = true
	cp2 := newTestCapturer(t, c)
	if cp2.MaxBody() != c.MaxBodyBytes {
		t.Errorf("MaxBody = %d, want %d", cp2.MaxBody(), c.MaxBodyBytes)
	}
	if got := cp2.Redact(); len(got) != 2 {
		t.Errorf("Redact = %v, want the two configured names", got)
	}
}

func TestBadRuleIsRefusedAtBuild(t *testing.T) {
	c := testConfig(t, config.CaptureRule{Name: "bad", ClientCIDRs: []string{"not-a-cidr"}})
	if _, err := New(c); err == nil {
		t.Fatal("a rule with an unparsable CIDR built; it would then silently match nothing")
	}
	c = testConfig(t, config.CaptureRule{Name: "bad", Statuses: []int{42}})
	if _, err := New(c); err == nil {
		t.Fatal("a rule with a status that is neither a status nor a class built")
	}
}

func TestConcurrentWritesProduceOneWholeFile(t *testing.T) {
	c := testConfig(t)
	cp := newTestCapturer(t, c)
	done := make(chan struct{})
	for i := range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 25 {
				cp.Write(exchange("h", "r", "GET", "/", 200+i, ""))
			}
		}()
	}
	for range 8 {
		<-done
	}
	cp.Flush()
	entries, err := os.ReadDir(c.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(c.Directory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	// readBlocks fails the test on any block whose framing is wrong,
	// which is what interleaved writes would produce.
	pkts := readPackets(t, readBlocks(t, b))
	if want := 8 * 25 * 8; len(pkts) != want {
		t.Errorf("%d packets, want %d: a flow was interleaved or lost", len(pkts), want)
	}
	if st := cp.Stats(); st.Captured != 200 {
		t.Errorf("captured %d, want 200", st.Captured)
	}
}
