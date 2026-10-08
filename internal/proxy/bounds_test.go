package proxy

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
)

// concurrencyBounds are the names a connection-oriented kind may use for "how
// many of these at once". There are five rather than one because what is counted
// differs -- a session that outlives a connection, a connection, a datagram peer,
// a query in flight, a tunnel -- and each is right for its protocol. It is a
// vocabulary rather than an inconsistency; what matters is that every kind uses
// one of them.
var concurrencyBounds = []string{
	"max_sessions",    // the session is the unit (ssh, rdp, vnc, ftp, the databases)
	"max_connections", // the connection is (modbus, iec104, imap, snmp over tcp)
	"max_clients",     // a datagram peer is (coap)
	"max_in_flight",   // a query is (dns)
	"max_tunnels",     // a tunnel is (forward)
}

// TestEveryKindBoundsTheWorkOneClientCanStart walks the roster, so a kind added
// tomorrow fails until it has a ceiling.
//
// The invariant differs by transport: a connection-oriented kind bounds how many
// connections or sessions run at once, and a datagram kind has none to bound, so
// what it must have instead is a rate limit. bacnet, ntp, radius and tftp have no
// concurrency bound for exactly that reason -- asserting that they do would be
// asserting a number that cannot exist.
//
// The transport comes from each kind's own registration rather than a list here,
// because a list is the thing that goes stale. The registry itself is empty in
// this package's tests: internal/kinds import internal/proxy, so they cannot be
// linked in from here, which is why the flag is read from the source the way
// internal/config reads the ban reasons out of the kinds.
func TestEveryKindBoundsTheWorkOneClientCanStart(t *testing.T) {
	datagram := datagramKinds(t)
	var noBound, noRate []string
	for _, name := range listener.Kinds() {
		sec, ok := sectionType(name)
		if !ok {
			// A kind with no section of its own takes the listener's
			// generic bounds; there is nothing here to check.
			continue
		}
		if datagram[name] {
			if !hasAnyYAMLKey(sec, []string{"rate_limit", "rate"}) && !hasAnyYAMLKey(sec, concurrencyBounds) {
				noRate = append(noRate, name)
			}
			continue
		}
		if !hasAnyYAMLKey(sec, concurrencyBounds) {
			noBound = append(noBound, name)
		}
	}
	sort.Strings(noBound)
	sort.Strings(noRate)
	if len(noBound) > 0 {
		t.Errorf("these connection-oriented kinds bound no concurrent work: %s\nuse whichever of %s counts the right thing",
			strings.Join(noBound, ", "), strings.Join(concurrencyBounds, ", "))
	}
	if len(noRate) > 0 {
		t.Errorf("these datagram kinds have neither a rate limit nor a concurrency bound: %s",
			strings.Join(noRate, ", "))
	}
}

// datagramKinds reads Datagram: true out of each kind's registration.
func datagramKinds(t *testing.T) map[string]bool {
	t.Helper()
	dirs, err := os.ReadDir("../kinds")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	var seen bool
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("../kinds", d.Name(), "kind.go"))
		if err != nil {
			continue
		}
		seen = true
		if strings.Contains(string(b), "Datagram: true") {
			out[d.Name()] = true
		}
	}
	if !seen {
		t.Fatal("no kind registrations found; they have moved out of kind.go")
	}
	if len(out) == 0 {
		t.Fatal("no datagram kind found; the field this test reads has been renamed")
	}
	return out
}

func hasAnyYAMLKey(t reflect.Type, keys []string) bool {
	for i := 0; i < t.NumField(); i++ {
		have := yamlKey(t.Field(i).Tag.Get("yaml"))
		for _, k := range keys {
			if have == k {
				return true
			}
		}
	}
	return false
}
