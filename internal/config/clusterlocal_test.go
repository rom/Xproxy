package config

import (
	"strings"
	"testing"
)

func localClusterYAML(body string) []byte {
	return []byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:8080"}]
cluster:
` + body + `
upstreams: [{name: app, endpoints: [{address: "127.0.0.1:9000"}]}]
routes: [{name: r, upstream: app}]
`)
}

// TestLocalClusterAccepted: a cluster whose addresses are Unix sockets
// loads without a certificate, which is the point of it.
func TestLocalClusterAccepted(t *testing.T) {
	c, err := ParseWith(localClusterYAML(`  node_id: xgate
  listen: unix:/run/xproxy-cluster/xgate.sock
  peers: [unix:/run/xproxy-cluster/xproxy.sock]
  local: {socket_mode: "0660", allow_uids: [990, 991]}`), false)
	if err != nil {
		t.Fatalf("a local cluster was refused: %v", err)
	}
	if !c.Cluster.IsLocal() {
		t.Error("the cluster is not recognised as local")
	}
	if got := c.Cluster.LocalSocketMode(); got != 0o660 {
		t.Errorf("socket mode = %o", got)
	}
	if len(c.Advice()) != 0 {
		t.Errorf("a fully specified local cluster produced advice: %v", c.Advice())
	}
}

// TestLocalClusterRefusals are the ways a Unix socket cluster is wrong.
func TestLocalClusterRefusals(t *testing.T) {
	for want, body := range map[string]string{
		"must both be Unix sockets": `  node_id: n
  listen: unix:/run/x/a.sock
  peers: ["10.0.0.2:7946"]`,
		"not used by a Unix socket cluster": `  node_id: n
  listen: unix:/run/x/a.sock
  peers: [unix:/run/x/b.sock]
  tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem}`,
		"must be an absolute path": `  node_id: n
  listen: unix:relative.sock
  peers: []`,
		"grants access to every user": `  node_id: n
  listen: unix:/run/x/a.sock
  peers: []
  local: {socket_mode: "0666", allow_uids: [990]}`,
		"is this node's own socket": `  node_id: n
  listen: unix:/run/x/a.sock
  peers: [unix:/run/x/a.sock]
  local: {allow_uids: [990]}`,
		"only for a Unix socket cluster": `  node_id: n
  listen: "10.0.0.1:7946"
  peers: []
  tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem, allowed_names: [n]}
  local: {allow_uids: [990]}`,
	} {
		_, err := ParseWith(localClusterYAML(body), false)
		if err == nil {
			t.Errorf("%q: accepted", want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

// TestLocalClusterAdvisesOnOpenAccess: with no allow_uids the socket's
// permissions are the whole decision, and a peer is trusted completely,
// so it is worth saying out loud.
func TestLocalClusterAdvisesOnOpenAccess(t *testing.T) {
	c, err := ParseWith(localClusterYAML(`  node_id: n
  listen: unix:/run/x/a.sock
  peers: [unix:/run/x/b.sock]`), false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range c.Advice() {
		if strings.Contains(a, "allow_uids") {
			found = true
		}
	}
	if !found {
		t.Errorf("no advice about allow_uids: %v", c.Advice())
	}
}
