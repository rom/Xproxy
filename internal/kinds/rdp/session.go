package rdp

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/textsafe"
)

// The relay. Everything the desktop sends is forwarded and recorded.
// Everything the client sends is looked at first, because three things
// on that side are decisions rather than traffic: a refused channel's
// data, the device announcement, and the credential.

// maxChannelMessage bounds a virtual channel message the gateway
// reassembles in order to look inside it. A device announcement is a
// few hundred bytes; anything approaching this bound is not one.
const maxChannelMessage = 64 << 10

// chunkSize is the largest piece the gateway puts back on the wire
// when it has rewritten a channel message. It is the default a server
// advertises, and staying at or under it is safe with any client.
const chunkSize = 1600

// openRecording starts the file once the session is about to begin.
func (se *session) openRecording() {
	if !se.t.recorder.Enabled() {
		return
	}
	who := textsafe.Clip64(se.user)
	if who == "" {
		who = "anonymous"
	}
	// A graphical session's recording is its protocol stream, not a
	// terminal: the header says so, and says what it holds.
	rec, err := se.t.recorder.Open(sessionrec.Header{
		Title: fmt.Sprintf("%s@%s via %s", who, se.target, se.t.cfg.Name),
		Env: map[string]string{
			"XPROXY_PROTOCOL": "rdp",
			"XPROXY_STREAM":   "rdp-server-to-client",
			"XPROXY_SECURITY": rdp.ProtocolName(se.upProtocol),
		},
		Tag: who,
		Ext: ".rdp.cast",
	})
	if err != nil {
		se.t.engine.Logs().Error.Warn("rdp session recording could not be opened",
			"listener", se.t.cfg.Name, "user", who, "err", err.Error())
		return
	}
	se.rec = rec
	se.rec.Mark(fmt.Sprintf("xproxy: %s on %s, client %s, desktop %s, channels %s",
		who, se.target, rdp.ProtocolName(se.clientProtocol), rdp.ProtocolName(se.upProtocol),
		strings.Join(se.granted, ",")))
}

func (se *session) closeRecording() {
	res := se.rec.Close()
	if res.File == "" {
		return
	}
	t := se.t
	t.engine.Counters().RDPRecorded.Add(1)
	t.engine.Logs().Access.Info("rdp_recording", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target,
		"file", res.File, "bytes", res.Bytes, "truncated", res.Truncated)
	if res.Truncated {
		attrs := []any{"listener", t.cfg.Name, "file", res.File}
		if res.Err != nil {
			attrs = append(attrs, "err", res.Err.Error())
		}
		t.engine.Logs().Error.Warn("rdp recording is short of the session", attrs...)
	}
}

// relay copies both directions once the connection sequence is done.
func (se *session) relay() string {
	var wg sync.WaitGroup
	wg.Add(2)
	reason := make(chan string, 2)
	go func() {
		defer wg.Done()
		defer safe.Guard("rdp to desktop")
		reason <- se.pumpToTarget()
		_ = se.up.Close()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("rdp to client")
		reason <- se.pumpToClient()
		_ = se.client.Close()
	}()
	wg.Wait()
	close(reason)
	for r := range reason {
		if r != "" && r != "closed" {
			return r
		}
	}
	return "closed"
}

// pumpToClient copies what the desktop showed, recording it.
func (se *session) pumpToClient() string {
	for {
		if se.t.v.IdleTimeout > 0 {
			_ = se.up.SetReadDeadline(time.Now().Add(se.t.v.IdleTimeout.D()))
		}
		pdu, err := rdp.ReadPDU(se.up)
		if err != nil {
			return endReason(err)
		}
		se.rec.Out(pdu.Raw)
		if _, err := se.client.Write(pdu.Raw); err != nil {
			return "write"
		}
	}
}

// pumpToTarget copies what the client sent, applying the policy on the
// way past.
func (se *session) pumpToTarget() string {
	for {
		if se.t.v.IdleTimeout > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(se.t.v.IdleTimeout.D()))
		}
		pdu, err := rdp.ReadPDU(se.client)
		if err != nil {
			return endReason(err)
		}
		out, drop, reason := se.decide(pdu)
		if reason != "" {
			return reason
		}
		if drop {
			continue
		}
		if _, err := se.up.Write(out); err != nil {
			return "write"
		}
	}
}

// decide says what to do with one unit from the client: forward it as
// it arrived, forward something else, or drop it.
func (se *session) decide(pdu rdp.PDU) (out []byte, drop bool, reason string) {
	// Fast path carries input events and nothing else, so there is
	// nothing in it to decide.
	if pdu.FastPath {
		return pdu.Raw, false, ""
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		// Not a data unit: the connection sequence's own units pass
		// through untouched.
		return pdu.Raw, false, ""
	}
	data, ok, err := rdp.ParseSendData(payload)
	if err != nil {
		se.t.deny(se.ip, "rdp_data_unit", err.Error())
		return nil, false, "client_protocol"
	}
	if !ok {
		return pdu.Raw, false, ""
	}
	switch {
	case se.inert[data.Channel]:
		// A channel the policy refused. The desktop has one of these
		// under a name nothing speaks, so this would go nowhere
		// anyway; dropping it keeps it off the wire entirely.
		se.t.engine.Counters().RDPChannelsRefused.Add(1)
		return nil, true, ""
	case data.Channel == se.ioChannel:
		return se.decideIO(data)
	case rdp.EqualNames(se.channelName[data.Channel], rdp.ChannelDeviceRedirection):
		return se.decideDevices(data)
	}
	return pdu.Raw, false, ""
}

// endReason names why a copy stopped.
func endReason(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "idle"
	}
	return "closed"
}

// rewrap puts a rewritten payload back inside the framing it came in.
func rewrap(data rdp.SendData, payload []byte) ([]byte, error) {
	data.Payload = payload
	return rdp.DataPDU(data.Encode())
}
