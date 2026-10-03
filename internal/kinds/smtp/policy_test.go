package smtp

import (
	"net/netip"
	"testing"
)

// The two decisions this listener makes without talking to anybody: whether the
// address may connect at all, and how large the client says the message is
// going to be.
//
// Both are worth their own test because both are answered before the upstream
// is contacted. The address list is the cheapest control a mail relay has, and
// the declared size is the only chance to refuse an oversize message before the
// body arrives -- after that the choice is between a truncated delivery and a
// connection dropped mid-transfer.

func TestTheAllowListIsAnsweredBeforeAnythingIsDialled(t *testing.T) {
	// No list means every address: a listener on a submission port inside an
	// estate is already bound by where it listens.
	open := &server{}
	for _, ip := range []string{"10.0.0.5", "203.0.113.1", "2001:db8::1"} {
		if !open.allowed(netip.MustParseAddr(ip)) {
			t.Errorf("a listener with no allow list refused %s", ip)
		}
	}
	// With no list there is nothing to measure against, so an address the
	// relay never learned is admitted here and refused as soon as a list
	// exists -- which is the asymmetry below.
	if !open.allowed(netip.Addr{}) {
		t.Error("an address with no list to measure it against was refused")
	}

	t.Run("with a list", func(t *testing.T) {
		s := &server{allow: []netip.Prefix{
			netip.MustParsePrefix("10.1.0.0/16"),
			netip.MustParsePrefix("192.168.5.7/32"),
			netip.MustParsePrefix("2001:db8::/32"),
		}}
		for _, c := range []struct {
			ip   string
			want bool
		}{
			{"10.1.2.3", true},
			{"192.168.5.7", true},
			{"2001:db8::1", true},
			{"10.2.2.3", false},
			{"192.168.5.8", false},
			{"203.0.113.1", false},
		} {
			if got := s.allowed(netip.MustParseAddr(c.ip)); got != c.want {
				t.Errorf("allowed(%s) = %v, want %v", c.ip, got, c.want)
			}
		}
		// An address the relay never learned is in no network, so a list
		// refuses it: the list is the control, and a connection whose
		// address is unknown cannot be shown to be on it.
		if s.allowed(netip.Addr{}) {
			t.Error("an invalid address was admitted against a list")
		}
	})
}

// SIZE= on MAIL FROM (RFC 1870) is a declaration rather than a fact, and this
// is where the listener reads it. Everything about the parse matters: the
// parameter is one of several, the keyword is case-insensitive, and anything
// that is not a count has to read as "no declaration" rather than as zero --
// because zero would compare under every bound and let the message through.
func TestTheDeclaredSizeIsReadTheWayRFC1870WritesIt(t *testing.T) {
	for _, c := range []struct {
		arg  string
		size int64
	}{
		{"<a@b.test> SIZE=1024", 1024},
		// The keyword is case-insensitive, and it is not always last.
		{"<a@b.test> size=1024", 1024},
		{"<a@b.test> SiZe=1024 BODY=8BITMIME", 1024},
		{"<a@b.test> BODY=8BITMIME SIZE=1024", 1024},
		// A declaration of nothing is a declaration: a client saying the
		// message is empty has said something, and it is under every bound.
		{"<a@b.test> SIZE=0", 0},
	} {
		got, ok := smtpSizeParam(c.arg)
		if !ok {
			t.Errorf("%q: no size was read", c.arg)
			continue
		}
		if got != c.size {
			t.Errorf("%q read size %d, want %d", c.arg, got, c.size)
		}
	}
	// And everything that is not a declaration. Each of these has to be "no
	// size" rather than zero, because zero is under every bound: a listener
	// that read `SIZE=huge` as zero would carry the message it was configured
	// to refuse.
	for _, arg := range []string{
		"<a@b.test>",
		"<a@b.test> BODY=8BITMIME",
		"<a@b.test> SIZE=",
		"<a@b.test> SIZE=huge",
		"<a@b.test> SIZE=-1",
		"<a@b.test> SIZE=1024x",
		"<a@b.test> SIZE=99999999999999999999999",
		// A parameter that merely ends in SIZE is not SIZE.
		"<a@b.test> MAXSIZE=1024",
		"",
	} {
		if n, ok := smtpSizeParam(arg); ok {
			t.Errorf("%q read as a size of %d", arg, n)
		}
	}
}
