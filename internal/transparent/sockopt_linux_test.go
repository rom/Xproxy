//go:build linux

package transparent

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The sockaddr_in reader, which is the one place in this package where a
// byte-order mistake would be silent.
//
// The struct mixes orders on purpose and the kernel does not care what a reader
// expects: the family is a host-order uint16 and the port is network order, four
// bytes apart. Reading either with the other's order gives a plausible wrong
// answer -- a family of 512 rather than 2, or port 20480 rather than 80 -- and a
// proxy would relay to it. So both are pinned against a buffer written the way
// the kernel writes one.
func TestASockaddrInIsReadWithEachFieldsOwnByteOrder(t *testing.T) {
	// AF_INET in host order, port 80 in network order, 192.0.2.9.
	var b [16]byte
	b[0], b[1] = byte(unix.AF_INET), 0
	b[2], b[3] = 0, 80
	b[4], b[5], b[6], b[7] = 192, 0, 2, 9

	got := ip4FromSockaddr(b)
	if !got.IsValid() {
		t.Fatal("a well-formed sockaddr_in read as invalid")
	}
	if got.String() != "192.0.2.9:80" {
		t.Fatalf("read %s, want 192.0.2.9:80", got)
	}

	// A port whose two octets differ, so the test would fail if they were
	// swapped rather than passing by symmetry. 0x1f90 is 8080.
	b[2], b[3] = 0x1f, 0x90
	if got = ip4FromSockaddr(b); got.Port() != 8080 {
		t.Fatalf("port read as %d, want 8080", got.Port())
	}
}

// A family that is not AF_INET is refused rather than read as one.
//
// This is the whole guard on the buffer: the option is asked for on SOL_IP and
// this reader only understands IPv4, so a sockaddr of another family means the
// four octets at offset 4 are not an address. Reading them anyway would produce a
// valid-looking destination out of somebody else's structure.
func TestASockaddrOfAnotherFamilyIsNotReadAsIPv4(t *testing.T) {
	for _, family := range []uint16{unix.AF_INET6, unix.AF_UNIX, 0, 0xffff} {
		var b [16]byte
		b[0], b[1] = byte(family&0xff), byte(family>>8)
		b[2], b[3] = 0, 80
		b[4], b[5], b[6], b[7] = 192, 0, 2, 9
		if got := ip4FromSockaddr(b); got.IsValid() {
			t.Fatalf("family %#04x was read as %s", family, got)
		}
	}
	// And the byte order of the *family* field matters too: AF_INET written
	// big-endian is 512, which is not a family, and must not be accepted.
	var b [16]byte
	b[0], b[1] = 0, byte(unix.AF_INET)
	if got := ip4FromSockaddr(b); got.IsValid() {
		t.Fatalf("a big-endian family field was accepted as %s", got)
	}
}

// The dialler binds to the client's address, which is the whole point: the
// upstream must see the client rather than the proxy.
func TestTheDiallerBindsToTheClientsAddress(t *testing.T) {
	for _, client := range []string{"192.0.2.9", "2001:db8::5"} {
		addr := netip.MustParseAddr(client)
		base := &net.Dialer{}
		d := Dialer(base, addr)
		if d == base {
			t.Fatal("the base dialler was returned, so the caller's is now modified")
		}
		ta, ok := d.LocalAddr.(*net.TCPAddr)
		if !ok {
			t.Fatalf("%s: local address is %T", client, d.LocalAddr)
		}
		if !ta.IP.Equal(net.IP(addr.AsSlice())) {
			t.Fatalf("%s: bound to %s", client, ta.IP)
		}
		// An ephemeral port, not the client's: the proxy holds one connection
		// per client connection and cannot reuse the client's own port.
		if ta.Port != 0 {
			t.Fatalf("%s: bound to port %d rather than an ephemeral one", client, ta.Port)
		}
		if d.Control == nil {
			t.Fatalf("%s: no control function, so no option is set", client)
		}
	}
}

// Setting the option is either done or reported, and never quietly skipped.
//
// A dialler whose Control returned nil without setting IP_TRANSPARENT would
// connect from the proxy's own address while the operator believed it came from
// the client -- a wrong answer that looks right, and the failure this asserts
// against. Whether the option can be set here depends on CAP_NET_ADMIN, so the
// assertion is that the outcome is definite: either nil with the option actually
// set on the socket, or an error naming why not.
func TestTheDiallersControlEitherSetsTheOptionOrSaysWhyNot(t *testing.T) {
	d := Dialer(&net.Dialer{}, netip.MustParseAddr("192.0.2.9"))

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()

	err = d.Control("tcp4", "192.0.2.9:0", rawConn{fd: fd})
	if err != nil {
		// The kernel's own reason, not a guess at one.
		if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) &&
			!errors.Is(err, unix.ENOPROTOOPT) {
			t.Fatalf("the control function failed with something other than a "+
				"capability error: %v", err)
		}
		t.Skipf("IP_TRANSPARENT needs a capability this process does not have: %v", err)
	}
	// It returned nil, so the option must actually be on.
	for _, opt := range []struct {
		name string
		num  int
	}{{"IP_TRANSPARENT", unix.IP_TRANSPARENT}, {"IP_FREEBIND", unix.IP_FREEBIND}} {
		v, err := unix.GetsockoptInt(fd, unix.SOL_IP, opt.num)
		if err != nil {
			t.Fatalf("reading %s back: %v", opt.name, err)
		}
		if v == 0 {
			t.Fatalf("the control function returned nil with %s unset", opt.name)
		}
	}
}

// rawConn is a syscall.RawConn over one descriptor, so the dialler's Control can
// be called without opening a connection.
type rawConn struct{ fd int }

func (r rawConn) Control(f func(fd uintptr)) error { f(uintptr(r.fd)); return nil }
func (r rawConn) Read(func(uintptr) bool) error    { return nil }
func (r rawConn) Write(func(uintptr) bool) error   { return nil }

// Check answers definitely and closes what it opened.
//
// The point of Check is that a listener refuses at load rather than on the first
// connection, so it runs once per listener at startup -- and a version that
// leaked the socket it tested with would leak one descriptor per listener per
// reload, which is the sort of leak nobody notices until a long-lived process
// runs out. The descriptor count before and after is the assertion.
func TestCheckClosesTheSocketItTestsWith(t *testing.T) {
	before := openDescriptors(t)
	for i := 0; i < 20; i++ {
		// The answer depends on the capability, and either answer is fine here;
		// what must not happen is a panic or a leak.
		_ = Check()
	}
	if after := openDescriptors(t); after > before {
		t.Fatalf("descriptors went from %d to %d over twenty calls", before, after)
	}
	// And this build can do it at all, which is what Available reports.
	if !Available() {
		t.Fatal("a linux build reported IP_TRANSPARENT unavailable")
	}
}

func openDescriptors(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	return len(ents)
}

// A connection that is not a syscall.Conn has no destination to read, and the
// error says so rather than the read being attempted on something else.
func TestAConnectionWithNoDescriptorHasNoOriginalDestination(t *testing.T) {
	if _, err := originalDST(fakeConn{}); !errors.Is(err, ErrNoOriginalDestination) {
		t.Fatalf("%v, want ErrNoOriginalDestination", err)
	}
	// Destination falls through to the local address, and a connection whose
	// local address is not a TCP address has none either.
	if _, err := Destination(fakeConn{}); !errors.Is(err, ErrNoOriginalDestination) {
		t.Fatalf("Destination: %v, want ErrNoOriginalDestination", err)
	}
}

// fakeConn is a net.Conn that is not a syscall.Conn and whose local address is
// not a TCP address.
type fakeConn struct{ net.Conn }

func (fakeConn) LocalAddr() net.Addr { return &net.UnixAddr{Name: "/tmp/x", Net: "unix"} }
