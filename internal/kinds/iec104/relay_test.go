package iec104_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
	_ "github.com/rom/xproxy/internal/kinds/iec104" // the kind under test
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// station is a controlled station: it reads APDUs, answers the U-format
// handshake the way a substation gateway does, and records everything, so a
// test can say what did and did not reach the equipment.
type station struct {
	ln net.Listener

	mu   sync.Mutex
	got  []*wire.Frame
	conn net.Conn
	// seq numbers the I frames this station sends, because the relay
	// checks both directions' numbering and a station that reused a
	// sequence number would be a station the relay refuses -- correctly.
	seq uint16
	// send carries ASDUs for the station to number and send up.
	send chan []byte
	// silent reads and never answers the handshake, which is a station
	// that is reachable and not talking.
	silent bool
}

func startStation(t *testing.T, s *station) *station {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	if s.send == nil {
		s.send = make(chan []byte, 16)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *station) addr() string { return s.ln.Addr().String() }

func (s *station) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
	go func() {
		for a := range s.send {
			if _, err := c.Write(s.next(a)); err != nil {
				return
			}
		}
	}()
	rd := wire.NewReader(c)
	for {
		f, err := rd.ReadFrame()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.got = append(s.got, f)
		s.mu.Unlock()
		if s.silent {
			continue
		}
		// The handshake a substation gateway answers: STARTDT and TESTFR
		// are confirmed, and an activation is confirmed positively.
		switch {
		case f.Format == wire.FormatU:
			if con := confirmOf(f.Control); con != 0 {
				_, _ = c.Write(uframe(con))
			}
		case f.Format == wire.FormatI && f.ASDU != nil && f.ASDU.Cause.Commanding():
			// The confirmation carries the station's own sequence number,
			// not the number of the frame it answers.
			a := make([]byte, len(f.Raw)-wire.APCILen)
			copy(a, f.Raw[wire.APCILen:])
			confirm := byte(wire.CauseActCon)
			if f.ASDU.Cause == wire.CauseDeactivation {
				confirm = byte(wire.CauseDeactCon)
			}
			a[2] = confirm
			_, _ = c.Write(s.next(a))
		}
	}
}

// next wraps an ASDU in the station's next I frame.
func (s *station) next(a []byte) []byte {
	s.mu.Lock()
	send := s.seq
	s.seq = (s.seq + 1) % wire.MaxSeq
	s.mu.Unlock()
	return iframe(send, 0, a...)
}

func confirmOf(c wire.Control) wire.Control {
	switch c {
	case wire.StartDTAct:
		return wire.StartDTCon
	case wire.StopDTAct:
		return wire.StopDTCon
	case wire.TestFRAct:
		return wire.TestFRCon
	}
	return 0
}

// saw reports the frames of one type identification the station received.
func (s *station) saw(t wire.Type) []*wire.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*wire.Frame
	for _, f := range s.got {
		if f.ASDU != nil && f.ASDU.Type == t {
			out = append(out, f)
		}
	}
	return out
}

// sawControl reports how many of one control function arrived.
func (s *station) sawControl(c wire.Control) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, f := range s.got {
		if f.Format == wire.FormatU && f.Control == c {
			n++
		}
	}
	return n
}

// sawSupervisory counts the S frames that arrived.
func (s *station) sawSupervisory() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, f := range s.got {
		if f.Format == wire.FormatS {
			n++
		}
	}
	return n
}

// centre is a controlling station: the SCADA master's side.
type centre struct {
	t    *testing.T
	conn net.Conn
	rd   *wire.Reader
	send uint16
	recv uint16
}

func dialCentre(t *testing.T, addr string) *centre {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &centre{t: t, conn: c, rd: wire.NewReader(c)}
}

// write sends raw octets.
func (c *centre) write(b []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// startdt sends STARTDT_act and expects the confirmation, which is how
// every IEC 104 association begins.
func (c *centre) startdt() {
	c.t.Helper()
	c.write(uframe(wire.StartDTAct))
	f := c.expect("startdt confirmation")
	if f.Format != wire.FormatU || f.Control != wire.StartDTCon {
		c.t.Fatalf("startdt answered %s %s", f.Format, f.Control)
	}
}

// ask sends an ASDU as the next I frame and returns nothing: the answer, if
// any, is read with expect.
func (c *centre) ask(asdu []byte) {
	c.t.Helper()
	c.write(iframe(c.send, c.recv, asdu...))
	c.send = (c.send + 1) % wire.MaxSeq
}

// expect reads one frame, and checks its numbering the way a control
// centre does.
//
// The check belongs here rather than in the tests that care about it,
// because the numbering is the one property of this protocol that every
// frame has: a conforming implementation closes the association when an
// I frame's send sequence number is not the one it was counting on
// (mz-automation/lib60870, cs104_connection.c), so a frame that fails this
// is a frame that would have ended the session in a control room.
func (c *centre) expect(what string) *wire.Frame {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := c.rd.ReadFrame()
	if err != nil {
		c.t.Fatalf("%s: %v", what, err)
	}
	if f.Format == wire.FormatI {
		if f.Send != c.recv {
			c.t.Fatalf("%s: N(S) = %d, this centre was counting on %d: a "+
				"conforming centre closes the association here", what, f.Send, c.recv)
		}
		c.recv = (c.recv + 1) % wire.MaxSeq
	}
	return f
}

// expectSilence asserts that nothing arrives, which is what deny_response
// drop looks like to a control centre.
func (c *centre) expectSilence(what string) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if f, err := c.rd.ReadFrame(); err == nil {
		c.t.Fatalf("%s: got %s %v", what, f.Format, f.ASDU)
	}
}

// The frame builders, which are the same shapes the wire tests use.
func uframe(c wire.Control) []byte {
	return []byte{wire.Start, 4, byte(c), 0, 0, 0}
}

func sframe(recv uint16) []byte {
	var b [4]byte
	b[0] = 0x01
	binary.LittleEndian.PutUint16(b[2:4], recv<<1)
	return []byte{wire.Start, 4, b[0], b[1], b[2], b[3]}
}

func iframe(send, recv uint16, asdu ...byte) []byte {
	var c [4]byte
	binary.LittleEndian.PutUint16(c[0:2], send<<1)
	binary.LittleEndian.PutUint16(c[2:4], recv<<1)
	out := []byte{wire.Start, byte(4 + len(asdu)), c[0], c[1], c[2], c[3]}
	return append(out, asdu...)
}

func asdu(t wire.Type, objects byte, cause wire.Cause, common uint16, body ...byte) []byte {
	out := []byte{byte(t), objects, byte(cause), 0}
	out = binary.LittleEndian.AppendUint16(out, common)
	return append(out, body...)
}

// command builds a single command: the ASDU that opens or closes one thing.
// sel sets the select bit, which is the first half of the two-step form.
func command(common uint16, ioa uint32, sel bool, on bool) []byte {
	q := byte(0)
	if on {
		q |= 0x01
	}
	if sel {
		q |= 0x80
	}
	return asdu(wire.CScNA1, 1, wire.CauseActivation, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16), q)
}

// measurement builds a scaled measurement travelling up, which is what most
// of this protocol's traffic is.
func measurement(common uint16, ioa uint32, value int16) []byte {
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], uint16(value))
	return asdu(wire.MMeNB1, 1, wire.CauseSpontaneous, common,
		byte(ioa), byte(ioa>>8), byte(ioa>>16), v[0], v[1], 0x00)
}

const iec104YAML = `
version: 1
server:
  listeners:
    - name: grid
      address: "127.0.0.1:0"
      kind: iec104
      iec104:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: substation, endpoints: [{address: %q}]}
`

func iec104Server(t *testing.T, section string, st *station) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(iec104YAML, section, st.addr()))
	return s, proxytest.Addr(t, s, "grid")
}

// await polls a counter condition, because the counters are incremented on
// the relay's own goroutines after the frame has gone out.
func await(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so: %+v", what, s.Stats().Refusals["iec104"])
}

// The relay in its ordinary shape: a control centre connects, the
// handshake reaches the station, telemetry comes up and a command allowed
// by a rule goes down.
func TestIEC104ReverseRelay(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	if got := st.sawControl(wire.StartDTAct); got != 1 {
		t.Fatalf("the station saw %d STARTDT_act", got)
	}

	// A command inside what the rule allows reaches the station, and the
	// station's positive confirmation comes back.
	c.ask(command(1, 4321, false, true))
	f := c.expect("the command confirmation")
	if f.ASDU == nil || f.ASDU.Cause != wire.CauseActCon || f.ASDU.Negative {
		t.Fatalf("confirmation: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 1 {
		t.Fatalf("the station saw %d commands", len(got))
	} else if got[0].ASDU.Addresses[0] != 4321 {
		t.Errorf("the command named point %d", got[0].ASDU.Addresses[0])
	}

	// Telemetry travelling up reaches the centre.
	st.send <- measurement(1, 100, 1234)
	f = c.expect("a measurement")
	if f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 || f.ASDU.Addresses[0] != 100 {
		t.Fatalf("measurement: %+v", f.ASDU)
	}

	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104Commands >= 1 && sn.IEC104Frames >= 4
	}, "the frames and the command")
}

// The point of the whole kind: a command outside the policy does not reach
// the substation, and the control centre is told so in the protocol's own
// words rather than left waiting.
func TestACommandOutsideThePolicyNeverReachesTheStation(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1], addresses: ["4000-4999"]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// A point outside the allowed range.
	c.ask(command(1, 9999, false, true))
	f := c.expect("the negative confirmation")
	if f.ASDU == nil || !f.ASDU.Negative || f.ASDU.Cause != wire.CauseActCon {
		t.Fatalf("a refusal should be a negative confirmation: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 0 {
		t.Fatalf("a refused command reached the station: %+v", got[0].ASDU)
	}
	// A type no rule names at all: the default is deny.
	c.ask(asdu(wire.CRpNA1, 1, wire.CauseActivation, 1, 0, 0, 0, 1))
	f = c.expect("the reset refusal")
	if f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a reset process command was not refused: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["default_deny"] >= 1 && sn.IEC104Denied >= 2
	}, "the refusals")
	// And the session is still usable: refusing a command is not
	// refusing a link, because a control room that lost its telemetry
	// because one command was refused would be an outage.
	st.send <- measurement(1, 100, 7)
	if f := c.expect("telemetry after a refusal"); f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 {
		t.Fatalf("the link did not survive a refusal: %+v", f)
	}
}

// A refusal is answered the way the standard says a station answers, and
// only where there is something to answer. A measurement has no
// confirmation in the protocol, so inventing one would put an ASDU on the
// wire that no station would ever send -- and a control centre that
// received a "negative confirmation of a measurement" would have no idea
// what to do with it.
func TestOnlyAnActivationIsNegativelyConfirmed(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        common_addresses: ["1"]`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// A command refused by the default deny: answered.
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the command refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a refused command was not negatively confirmed: %+v", f.ASDU)
	}
	// Spontaneous telemetry naming a station outside the list: refused,
	// and answered with nothing at all.
	c.ask(measurement(99, 100, 7))
	c.expectSilence("a refused measurement")
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["common_address"] >= 1
	}, "the common address refusal")
	if got := st.saw(wire.MMeNB1); len(got) != 0 {
		t.Error("a measurement for an unnamed station reached the station")
	}
}

// monitor_only is the shorthand for the commonest requirement: a link that
// carries telemetry up and nothing down. No rule can override it.
func TestMonitorOnlyCannotBeRuledThrough(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        monitor_only: true
        default_action: allow
        rules:
          - {name: everything, action: allow, class: [command, system, monitoring]}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a command passed a monitor-only listener: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 0 {
		t.Fatal("a command reached the station through monitor_only")
	}
	// An interrogation is a system command and is refused the same way,
	// although it only asks for data: it asks the station to *do*
	// something, which is what the cause of transmission says.
	c.ask(asdu(wire.CIcNA1, 1, wire.CauseActivation, 1, 0, 0, 0, 20))
	if f := c.expect("the interrogation refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an interrogation passed monitor_only: %+v", f.ASDU)
	}
	// Telemetry still flows, which is the whole point.
	st.send <- measurement(1, 100, 42)
	if f := c.expect("telemetry"); f.ASDU == nil || f.ASDU.Type != wire.MMeNB1 {
		t.Fatalf("monitor_only refused telemetry: %+v", f)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["monitor_only"] >= 2
	}, "the monitor_only refusals")
}

// Select-before-operate: the standard describes it and the equipment mostly
// does not enforce it, so this is the check that turns a single injected
// command frame from an operation into a refusal.
func TestSelectBeforeOperateIsEnforced(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        require_select: true
        rules:
          - {name: telemetry, action: allow, class: [monitoring]}
          - {name: breakers, action: allow, types: [C_SC_NA_1]}`, st)

	c := dialCentre(t, addr)
	c.startdt()

	// A bare execute, which is what an injected frame looks like.
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the unselected refusal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a bare execute was not refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 0 {
		t.Fatalf("an unselected command reached the station: %+v", got[0].ASDU)
	}

	// The two steps, in order: the select reaches the station (it is a
	// real frame the equipment answers), and so does the execute.
	c.ask(command(1, 4321, true, true))
	if f := c.expect("the select confirmation"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the select was refused: %+v", f.ASDU)
	}
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the execute confirmation"); f.ASDU == nil || f.ASDU.Negative {
		t.Fatalf("the execute after a select was refused: %+v", f.ASDU)
	}
	if got := st.saw(wire.CScNA1); len(got) != 2 {
		t.Fatalf("the station saw %d of the two steps", len(got))
	}

	// A selection authorises one execution and not a stream of them: the
	// second execute on the same selection is refused.
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the second execute"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a selection was reused: %+v", f.ASDU)
	}

	// And a selection is for the point it named: selecting one breaker
	// does not authorise executing another.
	c.ask(command(1, 4321, true, true))
	c.expect("the select confirmation")
	c.ask(command(1, 5555, false, true))
	if f := c.expect("the wrong point"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("a selection authorised another point: %+v", f.ASDU)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104Unselected >= 3 && sn.IEC104Selects >= 2 && sn.IEC104Executes >= 3
	}, "the select counters")
}

// A deactivation withdraws a selection, which is the control centre
// thinking better of it -- and after it the execute is unselected again.
func TestADeactivationWithdrawsASelection(t *testing.T) {
	st := startStation(t, &station{})
	_, addr := iec104Server(t, `        upstream: substation
        require_select: true
        default_action: allow`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, true, true))
	c.expect("the select confirmation")
	// The withdrawal: the same command with cause deact.
	c.ask(asdu(wire.CScNA1, 1, wire.CauseDeactivation, 1, 0xe1, 0x10, 0x00, 0x81))
	c.expect("the deactivation confirmation")
	c.ask(command(1, 4321, false, true))
	if f := c.expect("the execute after a withdrawal"); f.ASDU == nil || !f.ASDU.Negative {
		t.Fatalf("an execute rode on a withdrawn selection: %+v", f.ASDU)
	}
}

// STOPDT_act is the control function worth naming: it stops data transfer,
// so a client that may send it can blind a control room without refusing a
// single command -- and a relay whose policy only looked at ASDUs would
// never see it.
func TestTheControlFunctionsAreAPolicyToo(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        allow_controls: [STARTDT_act, TESTFR_act]`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// The keepalive is allowed, and its confirmation comes back: naming an
	// activation names its confirmation, or the station's reply would be
	// refused and the centre would wait for ever.
	c.write(uframe(wire.TestFRAct))
	if f := c.expect("the test confirmation"); f.Control != wire.TestFRCon {
		t.Fatalf("testfr answered %s", f.Control)
	}
	// STOPDT is not in the list.
	c.write(uframe(wire.StopDTAct))
	c.expectSilence("a refused control function")
	if got := st.sawControl(wire.StopDTAct); got != 0 {
		t.Fatal("STOPDT_act reached the station")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["control"] >= 1
	}, "the control refusal")
}

// The sequence numbering is the only thing in this protocol that can find a
// lost, duplicated or replayed frame, and a relay sees both directions.
func TestASequenceGapIsFoundAndIsOneRefusal(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        deny_response: drop`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(measurement(1, 100, 1))
	// A replay: the same send sequence number again.
	c.send--
	c.ask(measurement(1, 100, 2))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["sequence"] >= 1
	}, "the sequence refusal")
	before := len(st.saw(wire.MMeNB1))
	// And the next frame in step with what arrived is carried: a relay
	// that refused for ever after one lost frame would take a substation
	// off the air until somebody restarted the link. What arrived was 0,
	// so 1 is in step.
	c.send = 1
	c.ask(measurement(1, 100, 3))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(st.saw(wire.MMeNB1)) <= before {
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(st.saw(wire.MMeNB1)); got <= before {
		t.Fatalf("the link never recovered: %d frames", got)
	}
}

// The supervisory frames: an S frame carries a receive sequence number and
// nothing else, and it is still worth checking, because an end
// acknowledging frames nobody sent is how a flood gets past the window.
//
// An acknowledgement is not forwarded, because it is about the stream this
// relay wrote and not about the stream the station wrote. The relay
// acknowledges the station itself, on its own count, which is what the
// station is waiting for: an end that is not acknowledged inside t1 closes
// the association.
func TestSupervisoryFramesAreCheckedToo(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow
        deny_response: drop`, st)

	c := dialCentre(t, addr)
	c.startdt()
	// Two measurements up, so there is something to acknowledge.
	st.send <- measurement(1, 100, 1)
	c.expect("the first measurement")
	st.send <- measurement(1, 100, 2)
	c.expect("the second measurement")
	// An honest acknowledgement is accepted, and the station is
	// acknowledged by the relay rather than by the centre's frame.
	c.write(sframe(2))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && st.sawSupervisory() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := st.sawSupervisory(); got == 0 {
		t.Fatal("the relay never acknowledged the two frames the station sent")
	}
	// One acknowledging a frame that was never sent does not.
	c.write(sframe(9))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["ack_ahead"] >= 1
	}, "the acknowledgement refusal")
}

// A station sending an activation *to* its control centre is a station
// behaving as a controlling station: not a shape the standard has, and what
// a compromised substation gateway pivoting upstream looks like.
func TestAStationMayNotCommandItsControlCentre(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        default_action: allow`, st)

	c := dialCentre(t, addr)
	c.startdt()
	st.send <- command(1, 4321, false, true)
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["iec104"]["station_command"] >= 1
	}, "the station command refusal")
	// The centre never saw it.
	c.expectSilence("a command from the station")
}

// Malformed is not policy: a frame the relay could not read is a frame it
// cannot decide about, and it is refused whether or not the listener is
// enforcing.
func TestMalformedFramesEndTheSession(t *testing.T) {
	for what, raw := range map[string][]byte{
		"a stream that is not this protocol": {0x16, 0x10, 0x00, 0x00},
		"a length below the minimum":         {wire.Start, 2, 0, 0},
		"an asdu with no header":             append([]byte{wire.Start, 7, 0, 0, 0, 0}, 1, 1, 3),
		"a u frame carrying an asdu":         {wire.Start, 6, byte(wire.StartDTAct), 0, 0, 0, 0x2d, 0x01},
	} {
		t.Run(what, func(t *testing.T) {
			st := startStation(t, &station{})
			s, addr := iec104Server(t, `        upstream: substation
        default_action: allow`, st)
			c := dialCentre(t, addr)
			c.write(raw)
			await(t, s, func(sn proxy.Snapshot) bool {
				return sn.IEC104Malformed >= 1
			}, what)
			// The connection is over: there is no resynchronising on a
			// protocol framed by a start octet and a length, because the
			// next 0x68 is as likely to be inside a measurement as at a
			// frame boundary. A clean close and a reset are both ends;
			// what must not happen is another frame arriving.
			_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if n, err := io.ReadAll(c.conn); err == nil && n != nil && len(n) > 0 {
				t.Errorf("the session carried on and sent %d octets", len(n))
			}
		})
	}
}

// Shadow mode: the policy is evaluated on real traffic and nothing is
// refused for policy, so an operator finds out what a command policy would
// have broken before it breaks it. The integrity checks are not shadowed.
func TestShadowModeRecordsWhatItWouldHaveRefused(t *testing.T) {
	st := startStation(t, &station{})
	s, addr := iec104Server(t, `        upstream: substation
        monitor_only: true
        allow_controls: [STARTDT_act, TESTFR_act]
      policy: {mode: shadow}`, st)

	c := dialCentre(t, addr)
	c.startdt()
	c.ask(command(1, 4321, false, true))
	// The command was carried, because nothing is refused for policy.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(st.saw(wire.CScNA1)) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(st.saw(wire.CScNA1)) == 0 {
		t.Fatal("shadow mode refused a command")
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104WouldDeny >= 1 && sn.WouldRefusals["iec104"]["monitor_only"] >= 1
	}, "the shadow ledger")
	rep := s.Shadow().Report()
	found := false
	for _, e := range rep {
		if e.Kind == "iec104" && e.Reason == "iec104_monitor_only" {
			found = true
			if e.Sample == "" {
				t.Error("the ledger kept no sample, so an operator cannot see what it was")
			}
		}
	}
	if !found {
		t.Errorf("the ledger holds %+v", rep)
	}
	// A refused *control function* is shadowed too, and it has no ASDU to
	// describe, so the ledger's sample is the function's own name -- which
	// is the whole use of the entry: "STOPDT_act would have been refused"
	// is a sentence an operator can act on.
	c.write(uframe(wire.StopDTAct))
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.WouldRefusals["iec104"]["control"] >= 1
	}, "the shadowed control function")
	foundControl := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "iec104" && e.Reason == "iec104_control" && e.Sample == "STOPDT_act" {
			foundControl = true
		}
	}
	if !foundControl {
		t.Errorf("the ledger holds %+v", s.Shadow().Report())
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && st.sawControl(wire.StopDTAct) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if st.sawControl(wire.StopDTAct) == 0 {
		t.Error("shadow mode refused the control function it only meant to record")
	}

	// And a malformed frame is still refused, because integrity is not
	// policy: a relay that forwarded what it could not read would be
	// forwarding what it could not decide about.
	c.write([]byte{0x16, 0x10, 0x00, 0x00})
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.IEC104Malformed >= 1
	}, "a malformed frame in shadow mode")
}
