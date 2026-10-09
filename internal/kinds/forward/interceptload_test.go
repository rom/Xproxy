package forward

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// Interception is the one part of a forward proxy that holds a signing
// key, so everything it needs is settled at load: a listener that
// started with an interception section it cannot complete would be one
// that fails at the first TLS connection, having already told the
// client the tunnel was open.
func TestAnInterceptionSectionThatCannotBeCompletedIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	// A signing CA rather than a leaf: what this section holds is the
	// key the proxy mints certificates with.
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Path, ca.WriteKey(t, dir)
	notPEM := filepath.Join(dir, "not-a-pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nothing")

	for _, c := range []struct {
		name string
		in   config.ForwardIntercept
		want string
	}{
		{
			name: "a CA that is not there",
			in:   config.ForwardIntercept{CACertFile: missing, CAKeyFile: missing},
			want: "",
		},
		{
			name: "a CA that is not a certificate",
			in:   config.ForwardIntercept{CACertFile: notPEM, CAKeyFile: notPEM},
			want: "",
		},
		{
			name: "a host rule with no destination in it",
			in:   config.ForwardIntercept{CACertFile: cert, CAKeyFile: key, Hosts: []string{""}},
			want: "intercept hosts",
		},
		{
			name: "a bypass rule with no destination in it",
			in:   config.ForwardIntercept{CACertFile: cert, CAKeyFile: key, BypassHosts: []string{""}},
			want: "bypass_hosts",
		},
		{
			name: "a root CA file that is not there",
			in:   config.ForwardIntercept{CACertFile: cert, CAKeyFile: key, CAFile: missing},
			want: "intercept ca_file",
		},
		{
			name: "a root CA file with no certificates in it",
			in:   config.ForwardIntercept{CACertFile: cert, CAKeyFile: key, CAFile: notPEM},
			want: "no certificates",
		},
		{
			name: "a YARA policy that does not compile",
			in: config.ForwardIntercept{CACertFile: cert, CAKeyFile: key,
				YARA: &config.YARAPolicy{RulesFile: missing}},
			want: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			_, err := newInterceptor(&in, time.Second)
			if err == nil {
				t.Fatalf("the interceptor was built with %s", c.name)
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, which does not name %q", err, c.want)
			}
		})
	}

	// And one that is complete: the defaults it fills in are the two
	// that decide what a client may negotiate through it.
	in := config.ForwardIntercept{CACertFile: cert, CAKeyFile: key}
	built, err := newInterceptor(&in, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.alpn) != 1 || built.alpn[0] != "http/1.1" {
		t.Errorf("the default ALPN list is %v; an empty one would offer whatever the client asked for", built.alpn)
	}
	if !built.verify {
		t.Error("the upstream certificate is not verified by default, which would make interception a downgrade")
	}
}

// The tunnel device CONNECT-IP needs is opened by name, and the two
// ways that fails are said plainly: a listener with no device named,
// and a device this process cannot open. An operator reading either
// has something to act on.
func TestATunnelThatCannotBeOpenedSaysWhy(t *testing.T) {
	if _, err := openTunnel("", nil, nil); err == nil {
		t.Error("a tunnel with no device name was opened")
	}

	// An interface name longer than the kernel allows, so this fails
	// whether or not the process could open the device at all.
	_, err := openTunnel(strings.Repeat("x", 32), []string{"192.0.2.7/32"}, nil)
	if err == nil {
		t.Fatal("a device with an impossible name was opened")
	}
	if !strings.Contains(err.Error(), "tun") && !strings.Contains(err.Error(), "device") {
		t.Errorf("the error says %q, which names neither the device nor the path", err)
	}
}
