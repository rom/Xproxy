package config

import (
	"strings"
	"testing"
)

// Which daemon binds a listener, checked at load.
//
// The field exists for the handful of kinds two daemons serve, and every
// way of getting it wrong has the same shape of consequence: a port
// nobody binds and a policy nobody enforces, visible only as a line in
// one daemon's log saying the listener was left to a sibling that is
// never going to take it. So each is a load error rather than a thing to
// notice later.
func daemonConfig(listenerYAML string) string {
	return `
version: 1
server:
  listeners:
` + listenerYAML + `
upstreams:
  - {name: u, endpoints: [{address: "10.0.0.5:514"}]}
`
}

func TestTheDaemonAListenerNamesIsChecked(t *testing.T) {
	for _, c := range []struct{ what, ln, want string }{
		{
			"a daemon that does not exist",
			"    - {name: l, address: \"127.0.0.1:514\", kind: syslog, daemon: xsyslog, syslog: {upstream: u, udp: false}}\n",
			"is not one of xproxy, xgate, xrelay, xot",
		},
		{
			// The dangerous one: a real daemon, spelled right, that does
			// not carry this kind's code.
			"a daemon that serves something else",
			"    - {name: l, address: \"127.0.0.1:502\", kind: modbus, daemon: xrelay, modbus: {upstream: u}}\n",
			"xrelay does not serve kind modbus, which is served by xot",
		},
		{
			"the edge daemon asked to serve a plant protocol",
			"    - {name: l, address: \"127.0.0.1:502\", kind: modbus, daemon: xproxy, modbus: {upstream: u}}\n",
			"xproxy does not serve kind modbus",
		},
	} {
		_, err := Parse([]byte(daemonConfig(c.ln)))
		if err == nil {
			t.Errorf("%s was accepted", c.what)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.what, err, c.want)
		}
	}
}

// A kind two daemons serve takes either of them, and naming the one that
// already owns it by default is not an error -- an estate that writes the
// daemon on every listener should not have to leave it off some of them.
func TestASharedKindTakesEitherDaemon(t *testing.T) {
	for _, d := range []string{"xot", "xrelay"} {
		cfg, err := Parse([]byte(daemonConfig(
			"    - {name: l, address: \"127.0.0.1:514\", kind: syslog, daemon: " + d +
				", syslog: {upstream: u, udp: false}}\n")))
		if err != nil {
			t.Fatalf("daemon: %s was refused: %v", d, err)
		}
		if got := cfg.Server.Listeners[0].Daemon; got != d {
			t.Errorf("daemon: %s came back as %q", d, got)
		}
	}
}

// Naming the only daemon that serves a kind is allowed and says nothing,
// which is what the advice is for: the field is how an operator moves a
// listener between two daemons, and a file full of it on kinds that have
// only one daemon reads as a choice somebody made and did not.
func TestNamingTheOnlyDaemonForAKindIsAdvisedAgainst(t *testing.T) {
	cfg, err := Parse([]byte(daemonConfig(
		"    - {name: l, address: \"127.0.0.1:502\", kind: modbus, daemon: xot, modbus: {upstream: u}}\n")))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, w := range cfg.Advice() {
		if strings.Contains(w, "served only by xot") {
			found = true
		}
	}
	if !found {
		t.Errorf("no advice about naming the only daemon that serves a kind: %v", cfg.Advice())
	}
}
