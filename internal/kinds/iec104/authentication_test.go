package iec104_test

import (
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/proxy"
)

// IEC 62351-5, as far as a relay in the middle can honestly go.
//
// The relay recognises the IEC 60870-5-7 exchange and carries it; it verifies no
// HMAC and holds no keys, and every case here is about the difference between
// "an exchange took place" and "the exchange was valid". Only the first is
// something a party in the middle can assert.

// challenge, reply and aggressive build the three frames of the exchange. The
// bodies are not the standard's own -- there is nothing here that reads them --
// which is the point: this relay decides from the type identification, and a test
// that supplied a plausible HMAC would suggest one was checked.
func secureASDU(t wire.Type, common uint16) []byte {
	return asdu(t, 1, wire.CauseActivation, common, 0x00, 0x00, 0x00, 0x00)
}

// expectTypeFrom reads until a frame of this type arrives, because an
// authentication reply is an activation too and the station confirms it: a test
// that read one confirmation after asking twice would be asserting about the
// answer to the wrong frame.
func expectTypeFrom(t *testing.T, c *centre, ty wire.Type, what string) *wire.Frame {
	t.Helper()
	for i := 0; i < 8; i++ {
		f := c.expect(what)
		if f.ASDU != nil && f.ASDU.Type == ty {
			return f
		}
	}
	t.Fatalf("%s: no %s arrived", what, ty)
	return nil
}

const authRules = `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: auth, action: allow, class: [security]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}
`

// The failure this mostly exists to prevent: before these types were named, a
// listener saw type 81 as an unknown type and refused it, which made the
// standard's own authentication unusable through the relay.
func TestTheAuthenticationExchangeIsCarried(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, authRules, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(secureASDU(wire.SRpNA1, 1))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(st.saw(wire.SRpNA1)) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(st.saw(wire.SRpNA1)) == 0 {
		t.Fatal("the authentication reply did not reach the station")
	}
	// And it is counted, so an estate can see which associations authenticate
	// before deciding whether to require it.
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104Authentications >= 1
	}, "the authentication counter")
}

// The exchange is counted whether or not the listener requires it. A counter that
// only moved once the requirement was in force would be no help in deciding
// whether to turn the requirement on.
func TestTheExchangeIsCountedWithoutBeingRequired(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, authRules, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(secureASDU(wire.SAsNA1, 1))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104Authentications >= 1
	}, "the counter without a requirement")
}

// `require` refuses a command on an association that has shown no exchange. The
// relay cannot tell a good HMAC from a bad one; it can tell an exchange from no
// exchange, and on this protocol that is the difference between a station running
// the standard's authentication and one that has it switched off.
func TestAnUnauthenticatedCommandIsRefused(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, authRules+`        authentication: {require: true}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the negative confirmation"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an unauthenticated command was carried: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 0 {
		t.Fatal("an unauthenticated command reached the station")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["unauthenticated"] >= 1
	}, "the unauthenticated command")
}

// And after the exchange, the same command goes through.
func TestAnAuthenticatedCommandIsCarried(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, authRules+`        authentication: {require: true}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(secureASDU(wire.SRpNA1, 1))
	c.ask(command(1, 4321, false, true))
	if f := expectTypeFrom(t, c, wire.CScNA1, "the command confirmation"); f.ASDU.Negative {
		t.Fatalf("an authenticated command was refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("the station saw %d commands", len(got))
	}
}

// An authentication belongs to the association that performed it. Crediting one
// connection's exchange to another would let a client that can open a socket ride
// on a legitimate control centre's authentication, which is the whole thing being
// defended against.
func TestAnAuthenticationDoesNotCrossAssociations(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, authRules+`        authentication: {require: true}`, st)

	// The first association authenticates and commands.
	one := dialCentre(t, addr)
	one.startdt()
	one.ask(secureASDU(wire.SRpNA1, 1))
	one.ask(command(1, 4321, false, true))
	if f := expectTypeFrom(t, one, wire.CScNA1, "the first confirmation"); f.ASDU.Negative {
		t.Fatalf("the authenticated command was refused: %+v", f.ASDU)
	}

	// The second does not, and is refused even though the listener has seen an
	// authentication.
	two := dialCentre(t, addr)
	two.startdt()
	two.ask(command(1, 4322, false, true))
	if f := two.expect("the second confirmation"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a second association rode on the first's authentication: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["unauthenticated"] >= 1
	}, "the second association's refusal")
}

// A station's own frames never satisfy the requirement, and never trip it either.
// The station is the party that challenges; its confirmation is not something a
// controlling station authenticates, and refusing it would leave a control centre
// waiting for the answer to a command this relay already let through.
func TestAStationsConfirmationIsNotHeldToTheRequirement(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, authRules+`        authentication: {require: true}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The station sends a command-typed frame upward with a confirming cause,
	// which is what its answer to a command looks like.
	up := command(1, 4321, false, true)
	up[2] = byte(wire.CauseActCon)
	st.send <- up
	f := c.expect("the confirmation")
	if f.ASDU == nil || f.ASDU.Type != wire.CScNA1 {
		t.Fatalf("the station's confirmation did not reach the centre: %+v", f.ASDU)
	}
}

// Telemetry is never held to the requirement. A relay that refused a substation's
// measurements because the control centre had not authenticated would blind the
// control room over a policy about commands.
func TestTelemetryIsNotHeldToTheRequirement(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, authRules+`        authentication: {require: true}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- measurement(1, 100, 1234)
	f := c.expect("the measurement")
	if f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 {
		t.Fatalf("telemetry was refused for want of an authentication: %+v", f.ASDU)
	}
}

// A challenge is the *station* asking, and counting it would make
// `iec104_authentications` mean "somebody mentioned authentication" rather than
// "a controlling station proved it holds the key" -- which is the whole value of
// the number when an estate is deciding whether to require the exchange.
func TestAChallengeIsNotCountedAsAnAuthentication(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, authRules, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The station challenges, which travels up.
	st.send <- secureASDU(wire.SChNA1, 1)
	expectTypeFrom(t, c, wire.SChNA1, "the challenge")
	// And a key status request, which is housekeeping either way.
	c.ask(secureASDU(wire.SKrNA1, 1))
	expectTypeFrom(t, c, wire.SKrNA1, "the key status confirmation")
	if n := s.Stats().IEC104Authentications; n != 0 {
		t.Errorf("a challenge and a key status request counted as %d authentications", n)
	}
}

// The window is read, not assumed. A listener whose window has passed refuses the
// command even though the exchange happened on this association -- which is what
// stops one authentication at connection time authorising every command for a
// week.
func TestAnAuthenticationOutsideTheWindowDoesNotCount(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, authRules+`        authentication: {require: true, window: 1ns}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(secureASDU(wire.SRpNA1, 1))
	expectTypeFrom(t, c, wire.SRpNA1, "the authentication confirmation")
	c.ask(command(1, 4321, false, true))
	if f := expectTypeFrom(t, c, wire.CScNA1, "the command confirmation"); !f.ASDU.Negative {
		t.Fatalf("a command outside the window was carried: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 0 {
		t.Fatal("a command outside the window reached the station")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["unauthenticated"] >= 1
	}, "the expired authentication")
}

// The key-management half of the exchange is in the class too. An estate rotating
// update keys through this relay would otherwise find the rotation refused while
// the challenge and reply went through, which is a worse failure than refusing
// the lot: it looks like the authentication works right up to the point the keys
// expire.
func TestTheKeyManagementTypesAreInTheSecurityClass(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, authRules, st)

	c := dialCentre(t, addr)
	c.startdt()
	for _, ty := range []wire.Type{wire.SUsNA1, wire.SUqNA1, wire.SUrNA1, wire.SUkNA1,
		wire.SUaNA1, wire.SUcNA1} {
		c.ask(secureASDU(ty, 1))
		if f := expectTypeFrom(t, c, ty, ty.String()); f.ASDU.Negative {
			t.Errorf("%s was refused by a rule allowing the security class", ty)
		}
	}
}
