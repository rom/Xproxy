package iec104

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/iec104"
)

// The relay's own end of the association's numbering.
//
// IEC 60870-5-104 numbers every I frame in each direction, contiguously,
// and a conforming implementation closes the connection on a gap rather
// than trying to recover: the reference implementation does it on the
// controlling side (mz-automation/lib60870, cs104_connection.c: "check the
// receive sequence number N(R) -- connection will be closed on an
// unexpected value") and again on the controlled side (cs104_slave.c,
// "Received sequence number out of range").
//
// So a relay that forwarded the six control octets it read would be
// transparent only for as long as it forwarded everything. The moment it
// refuses one frame -- which is the whole purpose of this listener -- the
// stream it writes is short a number, and the end reading it drops the
// association, taking the substation's telemetry away with the refused
// command. The same arithmetic runs the other way: a refused frame consumed
// one of the sender's numbers and never reached the far end, so the next
// frame forwarded arrives one ahead of what that end expects.
//
// This relay is therefore an end. It reads a numbered stream from each
// peer, decides about it, and writes its own numbered stream to the other,
// with its own acknowledgements. Only the six control octets are the
// relay's: the ASDU that arrives is the ASDU that leaves, because
// re-encoding the application layer is how a relay and a station come to
// disagree about what was said.
type endpoint struct {
	// mu guards the numbering and serialises the writes, because both
	// pumps write to this peer: the other direction's forwarded frames and
	// this direction's own refusals and acknowledgements.
	mu   sync.Mutex
	conn net.Conn
	// wait bounds one write. A peer that cannot take a frame of at most
	// 255 octets inside the listener's idle timeout is as gone as one
	// that has said nothing for it -- and without the bound a pump
	// blocked in a write holds the session, and its slot, for ever: the
	// idle timeout is a read deadline and never fires on a writer.
	wait time.Duration

	// seq is the send sequence number the next I frame written to this
	// peer carries, and sent counts the frames written.
	seq  uint16
	sent uint64
	// expect is the send sequence number the next I frame *from* this peer
	// should carry, and known says whether one has arrived yet.
	expect uint16
	known  bool
	// read counts the I frames read from this peer, and told how many of
	// them the relay has acknowledged. They are counts, for the window
	// arithmetic; the number that goes on the wire is expect, which is
	// what the peer itself is waiting to have acknowledged.
	read uint64
	told uint64
	// acked is the highest number this peer has acknowledged of what the
	// relay wrote to it, and ackedCount how many frames that is.
	acked      uint16
	ackedCount uint64
}

// attach gives this end its connection and the bound on one write.
func (e *endpoint) attach(c net.Conn, wait time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn, e.wait = c, wait
}

// write puts one APDU on the wire under the write bound. The caller holds
// the lock, because the numbering and the order of the writes are the same
// invariant: a frame numbered and then written second would arrive out of
// sequence.
func (e *endpoint) write(b []byte) error {
	if e.wait > 0 {
		_ = e.conn.SetWriteDeadline(time.Now().Add(e.wait))
	}
	_, err := e.conn.Write(b)
	return err
}

// nextSeq is the sequence number that may follow one, wrapping at the
// protocol's 15-bit space.
func nextSeq(v uint16) uint16 { return (v + 1) % wire.MaxSeq }

// arrived records an I frame read from this peer and says what, if
// anything, is wrong with its numbering.
//
// A gap moves the expectation to what arrived, so one gap is one refusal
// rather than every frame after it: a relay that refused for ever after a
// single lost frame would take a substation off the air until somebody
// restarted the link.
func (e *endpoint) arrived(send uint16, k int) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		e.expect = nextSeq(send)
		e.known = true
		e.read++
	}()
	if !e.known {
		// The first frame on a connection sets the expectation. A peer
		// that starts at a number other than zero is unusual and not
		// wrong: the numbering survives a STOPDT and a STARTDT, and only
		// a new connection resets it.
		return ""
	}
	if send != e.expect {
		return "iec104_sequence"
	}
	if k > 0 && e.read-e.told >= uint64(k) {
		// This peer has k frames outstanding that the relay has not
		// acknowledged, and this is one more. It is what an end does when
		// it has stopped reading the acknowledgements, and what a flood
		// looks like on this protocol. An honest peer never reaches it,
		// because the relay acknowledges at w and w is below k.
		return "iec104_window"
	}
	return ""
}

// acknowledged records the receive sequence number a frame from this peer
// carried, which is what releases the relay's own sending window.
//
// Every frame carries one -- the standard lets an end piggyback its
// acknowledgement on any I frame it sends, and an end with data to send
// does exactly that rather than spending a frame on an S format -- so this
// is called for I frames as well as supervisory ones.
//
// The arithmetic stays in the protocol's own modular space: how many frames
// an acknowledgement releases is the unsigned distance from the last number
// acknowledged, wrapping at the 15-bit sequence space, which is what the
// peer computes too. Doing it with a signed subtraction and a fix-up would
// be the same number by a route that has to be argued about.
func (e *endpoint) acknowledged(recv uint16) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	released := uint64((recv - e.acked) % wire.MaxSeq)
	// A receive sequence number ahead of what the relay actually wrote to
	// this peer acknowledges a frame that does not exist, which is either
	// a confused implementation or an attempt to open the window.
	if released > e.sent-e.ackedCount {
		return "iec104_ack_ahead"
	}
	e.acked = recv
	e.ackedCount += released
	return ""
}

// writeI numbers an I frame as this end's next and writes it.
//
// The APDU's octets are the caller's and are stamped in place: they came
// from one read and go out once, and a copy would be a second buffer to
// keep honest.
func (e *endpoint) writeI(raw []byte) error {
	if len(raw) < wire.APCILen {
		// Every APDU this package reads or builds is at least the control
		// information long. One that is not would be stamped outside its
		// own buffer.
		return wire.ErrLength
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	binary.LittleEndian.PutUint16(raw[2:4], e.seq<<1)
	binary.LittleEndian.PutUint16(raw[4:6], e.expect<<1)
	e.seq = nextSeq(e.seq)
	e.sent++
	e.told = e.read
	return e.write(raw)
}

// writeS acknowledges what the relay has read from this peer and nothing
// else, which is the whole of an S format frame.
func (e *endpoint) writeS() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.read == e.told {
		return nil
	}
	var out [wire.APCILen]byte
	out[0], out[1], out[2] = wire.Start, 4, 0x01
	binary.LittleEndian.PutUint16(out[4:6], e.expect<<1)
	e.told = e.read
	return e.write(out[:])
}

// writeU passes a control frame through: a U format frame carries no
// sequence numbers, so there is nothing to renumber.
func (e *endpoint) writeU(raw []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.write(raw)
}

// ackDue says whether w frames have arrived unacknowledged, which is when
// the standard says an end acknowledges them.
func (e *endpoint) ackDue(w int) bool {
	if w < 1 {
		// Configuration refuses a w below one, so this is a precondition
		// rather than a case: without it the comparison below would be
		// made against an enormous unsigned number and the relay would
		// acknowledge nothing at all.
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.read-e.told >= uint64(w)
}

// ackEvery is how often a session offers each peer the acknowledgement it
// is owed when no frame is travelling the other way to carry one.
//
// The standard's own timers are t1 = 15s (an end that is not acknowledged
// inside it closes the association) and t2 = 10s (an end that has received
// frames and has nothing to send acknowledges them anyway). A relay that
// only acknowledged at w would let a control centre that sent one command
// and waited time out, because the station's own acknowledgement stops
// here. One second is well inside both timers and costs one wakeup per
// second per session.
const ackEvery = time.Second

// acknowledge runs for the life of a session and pays each peer the
// acknowledgements the frame path did not.
func (se *session) acknowledge(stop <-chan struct{}) {
	tick := time.NewTicker(ackEvery)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if se.closed.Load() {
				return
			}
			// Both connections are up before this starts, so there is
			// no half-built end to check for here.
			if err := se.clientEnd.writeS(); err != nil {
				return
			}
			if err := se.stationEnd.writeS(); err != nil {
				return
			}
		}
	}
}
