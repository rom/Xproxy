package redis

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxytest"
)

// provenYAML is a listener with the estate's authorisation policy over it. The
// section is a sibling of `server:`, so this needs its own fixture.
const provenYAML = `
version: 1
server:
  listeners:
    - name: cache
      address: "127.0.0.1:0"
      kind: redis
      redis:
        upstream: rd
        require_tls: false
        require_auth: false
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: rd, endpoints: [{address: %q}]}
authorization:
  rules:
    # Two questions, two actions. The connection is the connect action, asked
    # before any name exists, so an estate covers it with networks; the
    # authenticated session is the session action, and that is where a rule
    # about people belongs.
    - {name: staff, allow: true, users: [bob], actions: [session]}
    - {name: door, allow: true, networks: ["127.0.0.0/8"], actions: [connect]}
`

// try sends a command and returns the reply, or "" when the relay closed the
// connection instead of answering. The package's own `do` fatals on a read error,
// which is the right thing everywhere else and the wrong thing here: a refusal
// after the server has accepted a credential *is* the connection ending.
func try(t *testing.T, cl *client, parts ...string) string {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	if _, err := cl.c.Write(b.Bytes()); err != nil {
		return ""
	}
	_ = cl.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := cl.br.ReadString('\n')
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "closed") ||
			strings.Contains(err.Error(), "reset") {
			return ""
		}
		t.Fatalf("%v: %v", parts, err)
	}
	return strings.TrimRight(line, "\r\n")
}

// The estate's policy is asked about the name the *server* accepted, which makes
// this the one relay kind here where an allow rule keyed on a user is an
// authenticated grant rather than a filter on a claim.
//
// Everywhere else a relay asks -- postgres at the startup packet, mysql and tds at
// their login packets -- the question comes before the server has said whether the
// password was right, so the name is asserted. Redis and AMQP can do better,
// because "has this connection authenticated" is already read from the server's own
// answer for require_auth, and the same answer proves the name.
//
// The cost is where the refusal lands, and the test says so: the credential does
// reach the server, because it is what proves the name, and what the refusal keeps
// off the server is every command after it.
func TestThePolicyIsAskedAboutTheNameTheServerAccepted(t *testing.T) {
	fs := startFake(t, &fakeServer{password: "hunter2"})
	s := proxytest.Start(t, fmt.Sprintf(provenYAML, fs.addr()))
	addr := proxytest.Addr(t, s, "cache")

	// alice is nobody the policy allows. The server accepts her password, and the
	// estate refuses the session: the acceptance is never forwarded.
	cl := dial(t, addr)
	if reply := try(t, cl, "AUTH", "alice", "hunter2"); reply != "" {
		t.Errorf("a name no rule covers was answered %q, want the connection closed", reply)
	}
	if n := s.Stats().Refusals["redis"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["redis"])
	}
	// The AUTH reached the server -- it had to, it is the only thing that can
	// judge a password -- and nothing of alice's followed it.
	if cmds, _ := fs.saw(); strings.Join(cmds, ",") != "AUTH" {
		t.Errorf("the server saw %v, want only the AUTH that proved the name", cmds)
	}

	// And bob, whom the policy does allow, gets his session.
	cl2 := dial(t, addr)
	if reply := try(t, cl2, "AUTH", "bob", "hunter2"); reply != "+OK" {
		t.Fatalf("a name the policy allows was answered %q", reply)
	}
	if reply := try(t, cl2, "GET", "k"); reply != "+val" {
		t.Errorf("a command after an allowed login answered %q", reply)
	}
	if n := s.Stats().Refusals["redis"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d after an allowed login, want still 1", n)
	}
}
