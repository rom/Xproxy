package config

import (
	"os"
	"testing"
)

// The shipped example configuration must always validate (file existence
// checks aside, since the certificates are not part of the repository).
func TestExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../../deploy/config/xproxy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseNoFiles(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) < 4 || len(c.Upstreams) != 2 {
		t.Fatalf("unexpected example shape: %d routes %d upstreams", len(c.Routes), len(c.Upstreams))
	}
}
