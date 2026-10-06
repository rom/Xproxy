package proxy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// captureShapedByRequest are the kinds whose traffic is not a session, so a
// session tap is the wrong shape for them.
//
// Not an exemption list to grow: each of these three is request-shaped, and what
// each needs instead is the per-exchange path the http kind already has.
//
//   - http writes one capture per request, bodies and all, and has since the
//     subsystem was built. It is the shape the others would copy.
//   - forward is an HTTP proxy: a request is the unit a rule names, and only its
//     CONNECT tunnels and SOCKS connections are sessions at all.
//   - kkdcp carries Kerberos inside HTTP POSTs, served by a net/http server of
//     its own, so it has no connection to hand a tap.
//   - dns answers queries. The TCP form has a connection, but what an operator
//     records is the query, which is the unit every one of this kind's rules,
//     counters and logs already names.
var captureShapedByRequest = map[string]string{
	"http":    "writes one capture per request already",
	"forward": "an HTTP proxy: the request is the unit",
	"kkdcp":   "Kerberos inside HTTP POSTs, on its own http.Server",
	"dns":     "the query is the unit, not the connection",
}

// TestEveryConnectionKindCanBeCaptured walks the roster, so a kind added tomorrow
// fails until an operator can record a session on it.
//
// The pcapng capture is how an incident is reconstructed when the logs are not
// enough, and a kind that cannot be captured is a blind spot an operator finds out
// about during the incident rather than before it. The transport comes from each
// kind's own registration rather than a list here, for the reason the bounds sweep
// beside this one gives: a list is the thing that goes stale.
//
// A datagram kind has no connection to tap and is not asked for one.
func TestEveryConnectionKindCanBeCaptured(t *testing.T) {
	datagram := datagramKinds(t)
	dirs, err := os.ReadDir("../kinds")
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	checked := 0
	for _, d := range dirs {
		if !d.IsDir() || datagram[d.Name()] {
			continue
		}
		if _, ok := captureShapedByRequest[d.Name()]; ok {
			continue
		}
		src := packageSource(t, filepath.Join("../kinds", d.Name()))
		if src == "" {
			continue
		}
		checked++
		// Open is the whole of it: a kind that opens a tap has a connection to
		// wrap and a refusal to record, because the type is unusable otherwise.
		if !strings.Contains(src, "Capture().Open(") {
			missing = append(missing, d.Name())
		}
	}
	if checked < 20 {
		t.Fatalf("only %d connection kinds were examined; the roster is not being read", checked)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these kinds cannot be captured: %s\n"+
			"Each needs a capture.Tap: opened before anything can refuse the session, "+
			"wrapped round the client connection, and told the refusal.", strings.Join(missing, ", "))
	}
}

// TestTheRequestShapedKindsAreStillRequestShaped keeps the list above honest: a
// kind named there must exist, and must not have grown a session tap behind the
// list's back -- which would mean the list is wrong rather than the kind.
func TestTheRequestShapedKindsAreStillRequestShaped(t *testing.T) {
	for name, why := range captureShapedByRequest {
		src := packageSource(t, filepath.Join("../kinds", name))
		if src == "" {
			t.Errorf("%s is listed as request-shaped but has no source: %s", name, why)
			continue
		}
		if strings.Contains(src, "Capture().Open(") {
			t.Errorf("%s opens a session tap, so it should not be listed as request-shaped (%s)", name, why)
		}
	}
}

// packageSource is every non-test Go file in a directory, concatenated.
func packageSource(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(src)
	}
	return b.String()
}
