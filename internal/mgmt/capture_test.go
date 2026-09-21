package mgmt

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// Turning a packet capture on writes decrypted traffic to disk, so it
// is a mutating call like any other: it goes over the socket only the
// proxy user can open, and it is audited.
func TestCaptureAPI(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
capture:
  enabled: true
  directory: %s
  max_duration: 10m
  rules:
    - {name: denials, denied: true}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`, dir)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	c := NewClient(sock)

	// A configured section is idle until somebody says otherwise.
	st, err := c.Capture(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.Active {
		t.Fatalf("status %+v, want enabled and idle", st)
	}
	if len(st.Rules) != 1 || st.Rules[0].Name != "denials" {
		t.Errorf("rules %+v, want the configured one", st.Rules)
	}

	on, off := true, false
	st, err = c.Capture(&on, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Active || st.Until.IsZero() {
		t.Fatalf("after start: %+v", st)
	}
	if d := time.Until(st.Until); d > time.Minute {
		t.Errorf("the window ends in %s, want the 30s that was asked for", d)
	}

	// A window longer than max_duration is shortened to it rather than
	// refused: the bound is the point.
	st, err = c.Capture(&on, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(st.Until); d > 11*time.Minute {
		t.Errorf("the window ends in %s, past the configured maximum", d)
	}

	st, err = c.Capture(&off, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Active || !st.Until.IsZero() {
		t.Fatalf("after stop: %+v", st)
	}

	// A duration that is not one is refused, and the state does not
	// change behind the refusal.
	var bad capture.Stats
	if err := c.doBody("POST", "/v1/capture", CaptureRequest{Active: true, Duration: "ten minutes"}, &bad); err == nil {
		t.Fatal("a malformed duration was accepted")
	} else if !strings.Contains(err.Error(), "duration") {
		t.Errorf("error %v, want one naming the duration", err)
	}
	if st, err := c.Capture(nil, 0); err != nil || st.Active {
		t.Errorf("state after the refusal: %+v %v", st, err)
	}
}

// A proxy with no capture section says so, rather than accepting the
// call and recording nothing.
func TestCaptureAPIWithoutASection(t *testing.T) {
	c := bareServer(t, Actions{})
	st, err := c.Capture(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Active {
		t.Errorf("status %+v, want a section that does not exist", st)
	}
	on := true
	if _, err := c.Capture(&on, time.Minute); err == nil {
		t.Fatal("starting a capture on a proxy without one succeeded")
	} else if !strings.Contains(err.Error(), capture.ErrNotEnabled.Error()) {
		t.Errorf("error %v, want %v", err, capture.ErrNotEnabled)
	}
	_ = errors.Is
}
