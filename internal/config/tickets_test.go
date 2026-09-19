package config

import (
	"strings"
	"testing"
	"time"
)

func TestSessionTicketsConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  session_tickets: %s
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u}
`
	ok, err := parseNoFiles([]byte(strings.Replace(base, "%s", `{secret_file: /var/lib/xproxy/tickets.key}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if st := ok.Server.SessionTickets; st == nil || st.Rotate.D() != 24*time.Hour {
		t.Fatalf("defaults %+v", ok.Server.SessionTickets)
	}
	cases := map[string]string{
		"relative":   `{secret_file: tickets.key}`,
		"missing":    `{rotate: 2h}`,
		"rotate low": `{secret_file: /var/lib/xproxy/tickets.key, rotate: 30m}`,
		"rotate big": `{secret_file: /var/lib/xproxy/tickets.key, rotate: 200h}`,
	}
	for name, c := range cases {
		if _, err := parseNoFiles([]byte(strings.Replace(base, "%s", c, 1))); err == nil || !strings.Contains(err.Error(), "session_tickets") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A change of the section needs a restart.
	to, err := parseNoFiles([]byte(strings.Replace(base, "%s", `{secret_file: /var/lib/xproxy/tickets.key, rotate: 2h}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	ch := Diff(ok, to, "a", "b")
	found := false
	for _, r := range ch.RestartNeeded {
		if r == "server.session_tickets" {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart not reported: %+v", ch)
	}
}
