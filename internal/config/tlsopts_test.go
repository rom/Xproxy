package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSOptionValidation(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	list := filepath.Join(dir, "logs.json")
	for _, p := range []string{cert, key, list} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: ` + cert + `, key_file: ` + key + `}]
        %s
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - name: r
    upstream: app
`
	cfg, err := ParseWith([]byte(strings.Replace(base, "%s", "ocsp_stapling: {}\n        ct: {require: 2, log_list_file: "+list+"}", 1)), true)
	if err != nil {
		t.Fatal(err)
	}
	tl := cfg.Server.Listeners[0].TLS
	if !tl.OCSPStapling.IsEnabled() || tl.OCSPStapling.Refresh.D().Hours() != 1 || tl.OCSPStapling.Timeout.D().Seconds() != 5 || tl.CT.Require != 2 {
		t.Fatalf("defaults %+v %+v", tl.OCSPStapling, tl.CT)
	}
	bad := []struct{ snippet, want string }{
		{"ocsp_stapling: {timeout: 1ms}", "ocsp_stapling.timeout"},
		{"ocsp_stapling: {refresh: 1s}", "ocsp_stapling.refresh"},
		{"ct: {require: 11}", "ct.require"},
		{"ct: {enforce: true}", "ct.enforce"},
		{"ct: {require: 1, log_list_file: " + filepath.Join(dir, "missing.json") + "}", "log_list_file"},
	}
	for _, c := range bad {
		_, err := ParseWith([]byte(strings.Replace(base, "%s", c.snippet, 1)), true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.snippet, err, c.want)
		}
	}
}
