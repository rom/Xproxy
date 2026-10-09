package forward

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// The parts of the SOCKS handshake the malformed-greeting test does not
// reach: the credential exchange, which only exists on a listener that
// asks for one, the two address types a client can spell a literal
// with, and the two refusals the proxy answers in the protocol's own
// words because a SOCKS client has no other way to learn why.

// socksSay writes a prefix of a SOCKS exchange, half-closes so the
// proxy's next read ends rather than waiting out the handshake timeout,
// and returns whatever came back.
func socksSay(t *testing.T, addr string, script []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if len(script) > 0 {
		if _, err := c.Write(script); err != nil {
			t.Fatal(err)
		}
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf, _ := io.ReadAll(c)
	return buf
}

// socksAuthProxy is a SOCKS listener that asks for a credential.
func socksAuthProxy(t *testing.T, ports string) string {
	t.Helper()
	hash, err := passwd.HashWithIterations("correct horse battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(t.TempDir(), "proxy.htpasswd")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr := socksProxy(t, ports, "        auth: {users_file: "+users+", realm: lab}\n")
	return addr
}

// Each field of the credential exchange is read from the network, so
// each is a place a client can stop. None of them may leave the proxy
// treating a half-read credential as one it checked.
func TestASOCKSCredentialThatStopsHalfwayIsNotServed(t *testing.T) {
	addr := socksAuthProxy(t, "80, 443")

	for _, c := range []struct {
		name   string
		script []byte
	}{
		// The greeting offers username/password, and then nothing.
		{name: "no credential at all", script: []byte{5, 1, 2}},
		{name: "an auth version that is not one", script: []byte{5, 1, 2, 9, 1, 'a'}},
		{name: "a username longer than it is", script: []byte{5, 1, 2, 1, 40, 'a', 'b'}},
		{name: "a username and no password length", script: []byte{5, 1, 2, 1, 1, 'a'}},
		{name: "a password longer than it is", script: []byte{5, 1, 2, 1, 1, 'a', 40, 'b'}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := socksSay(t, addr, c.script)
			// Two octets is the greeting reply, which is sent before
			// the credential is read. Anything more would be the proxy
			// answering a credential it never finished reading.
			if len(got) > 2 {
				t.Errorf("the proxy answered %d octets (%x) to a cut credential", len(got), got)
			}
		})
	}

	// A credential that is complete and wrong is answered: that is the
	// difference between a refusal and a dropped connection, and a
	// client that is dropped cannot tell a wrong password from a
	// broken proxy.
	wrong := append([]byte{5, 1, 2, 1, 5}, "alice"...)
	wrong = append(wrong, 5)
	got := socksSay(t, addr, append(wrong, "wrong"...))
	if len(got) < 4 {
		t.Fatalf("a wrong password was answered %x", got)
	}
	if got[3] == 0x00 {
		t.Errorf("a wrong password was accepted: %x", got)
	}

	// So is a credential with no name in it, which is complete rather
	// than cut: there is nothing to look up, and saying so is the
	// answer.
	empty := socksSay(t, addr, []byte{5, 1, 2, 1, 0, 1, 'x'})
	if len(empty) < 4 || empty[3] == 0x00 {
		t.Errorf("a credential with no username was answered %x", empty)
	}
}

// A client may spell a literal destination as an address rather than as
// a name, in either family. Both are read before anything is dialled.
func TestASOCKSRequestCanSpellTheAddressEitherWay(t *testing.T) {
	_, addr := socksProxy(t, "80", "")
	for _, c := range []struct {
		name string
		req  []byte
	}{
		{name: "IPv4", req: []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80}},
		{name: "IPv6", req: append(append([]byte{5, 1, 0, 5, 1, 0, 4}, make([]byte, 15)...), 1, 0, 80)},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := socksSay(t, addr, c.req)
			// The greeting reply and then a reply to the request: what
			// matters is that the address was read and answered rather
			// than the connection being dropped on it.
			if len(got) < 3 {
				t.Errorf("a request spelled with an address was answered %x", got)
			}
		})
	}
}

// The two refusals a tunnel can meet after the request is understood.
func TestASOCKSTunnelTheProxyWillNotOpenIsAnswered(t *testing.T) {
	t.Run("past the listener's limit", func(t *testing.T) {
		_, addr := socksProxy(t, "80, 443", "        max_tunnels: 0\n")
		c, code := socksDialRaw(t, addr, "127.0.0.1", 80)
		if c != nil {
			_ = c.Close()
		}
		if code == 0 {
			t.Error("a tunnel past the listener's limit was opened")
		}
	})

	t.Run("a destination that does not answer", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		_, addr := socksProxy(t, strconv.Itoa(port), "")
		c, code := socksDialRaw(t, addr, "127.0.0.1", port)
		if c != nil {
			_ = c.Close()
		}
		if code != socksReplyHostUnreachable {
			t.Errorf("a destination that does not answer gave %#x, want host unreachable", code)
		}
	})
}

// socksDialRaw is socksDial without its assertions, for the cases where
// the refusal is the point.
func socksDialRaw(t *testing.T, proxyAddr, host string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		_ = c.Close()
		t.Fatalf("greeting reply: %v", err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port)) //nolint:gosec // test port
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		_ = c.Close()
		t.Fatalf("request reply: %v", err)
	}
	switch head[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 4+2))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 16+2))
	case 3:
		var l [1]byte
		_, _ = io.ReadFull(c, l[:])
		_, _ = io.ReadFull(c, make([]byte, int(l[0])+2))
	}
	if head[1] != 0 {
		_ = c.Close()
		return nil, head[1]
	}
	return c, 0
}

// Every field of the request's address is read from the network, and
// each can be cut: the length that says how long a name is, the name
// itself, the four or sixteen octets of a literal, and the port behind
// them. A proxy that read past any of them would be deciding a
// destination from whatever was in memory after it.
func TestASOCKSAddressThatStopsHalfwayIsNotServed(t *testing.T) {
	_, addr := socksProxy(t, "80, 443", "")
	for _, c := range []struct {
		name   string
		script []byte
	}{
		{name: "an IPv4 literal cut short", script: []byte{5, 1, 0, 5, 1, 0, 1, 127, 0}},
		{name: "an IPv6 literal cut short", script: append([]byte{5, 1, 0, 5, 1, 0, 4}, make([]byte, 9)...)},
		{name: "a name with no length", script: []byte{5, 1, 0, 5, 1, 0, 3}},
		{name: "a name shorter than its length", script: []byte{5, 1, 0, 5, 1, 0, 3, 20, 'a', 'b', 'c'}},
		{name: "an address with no port", script: []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := socksSay(t, addr, c.script)
			// The greeting reply is two octets. A success reply would
			// be ten, and a refusal is what anything longer must be.
			if len(got) > 2 && got[1] == 0x00 {
				t.Errorf("a cut address was answered with success: %x", got)
			}
		})
	}
}

// The listener's tunnel bound, which is what stops one client's SOCKS
// sessions being the whole listener's capacity.
func TestASOCKSTunnelPastTheListenersBoundIsRefused(t *testing.T) {
	// Something that accepts and holds, so the first tunnel stays open
	// while the second is asked for.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	go func() {
		var keep []net.Conn
		for {
			c, err := hold.Accept()
			if err != nil {
				for _, k := range keep {
					_ = k.Close()
				}
				return
			}
			keep = append(keep, c)
		}
	}()
	port := hold.Addr().(*net.TCPAddr).Port
	_, addr := socksProxy(t, strconv.Itoa(port), "        max_tunnels: 1\n")

	first, code := socksDialRaw(t, addr, "127.0.0.1", port)
	if code != 0 {
		t.Fatalf("the first tunnel was refused: %#x", code)
	}
	defer func() { _ = first.Close() }()
	second, code := socksDialRaw(t, addr, "127.0.0.1", port)
	if second != nil {
		_ = second.Close()
	}
	if code == 0 {
		t.Error("a second tunnel was opened past a bound of one")
	}
}
