package rdp

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/rom/xproxy/internal/ntlm"
	"github.com/rom/xproxy/internal/rdp"
)

// The security negotiation, on each leg. It is the first thing that
// happens and the thing that decides everything afterwards: a gateway
// that ends up outside the encryption sees a byte stream it cannot
// read, cannot filter and cannot record.

// clientNegotiate answers the client's connection request and puts the
// client's leg inside whatever was agreed.
func (se *session) clientNegotiate() string {
	t := se.t
	pdu, err := rdp.ReadPDU(se.client)
	if err != nil {
		return "client_negotiate"
	}
	cr, err := rdp.ParseConnectionRequest(pdu.Body)
	if err != nil {
		t.deny(se.ip, "rdp_negotiate", err.Error())
		return "client_negotiate"
	}
	se.cookie = cr.Cookie

	protocol, ok := se.pickClientProtocol(cr)
	if !ok {
		// Nothing both ends can use. The failure code says which way
		// the client should come back, which is what a client acts on.
		code := uint32(rdp.FailSSLRequiredByServer)
		if t.offered&protocolBit(rdp.ProtocolSSL) == 0 {
			code = rdp.FailSSLNotAllowedByServer
		}
		out, err := rdp.ConnectionConfirm{Failure: code, HasNegotiation: true}.Encode()
		if err == nil {
			_, _ = se.client.Write(out)
		}
		t.engine.Counters().RDPRefused.Add(1)
		t.deny(se.ip, "rdp_no_protocol", rdp.ProtocolName(cr.Protocols))
		return "no_protocol"
	}
	se.clientProtocol = protocol

	out, err := rdp.ConnectionConfirm{Protocol: protocol, HasNegotiation: cr.HasNegotiation}.Encode()
	if err != nil {
		return "client_negotiate"
	}
	if _, err := se.client.Write(out); err != nil {
		return "write"
	}
	if protocol == rdp.ProtocolSSL {
		tc := tls.Server(se.client, t.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.deny(se.ip, "rdp_tls", err.Error())
			return "client_tls"
		}
		se.client = tc
	}
	return ""
}

// pickClientProtocol decides what the client's leg will use. A client
// asking for network level authentication is answered with TLS, which
// is the downgrade every remote desktop gateway performs and the
// reason one can check a second factor at all: the credential has to
// be somewhere the gateway can read it.
func (se *session) pickClientProtocol(cr rdp.ConnectionRequest) (uint32, bool) {
	t := se.t
	if !cr.HasNegotiation {
		// A client old enough to send no negotiation speaks the legacy
		// protocol and nothing else.
		if t.offersLegacy() {
			return rdp.ProtocolRDP, true
		}
		return 0, false
	}
	if cr.Protocols&(rdp.ProtocolSSL|rdp.ProtocolHybrid|rdp.ProtocolHybridEx) != 0 &&
		t.offered&protocolBit(rdp.ProtocolSSL) != 0 && t.tlsCfg != nil {
		return rdp.ProtocolSSL, true
	}
	// The legacy protocol is what is left, and a client asks for it by
	// naming no other.
	if t.offersLegacy() {
		return rdp.ProtocolRDP, true
	}
	return 0, false
}

// upstreamNegotiate opens the desktop's leg with what an operator
// asked for, which need not be what the client used.
func (se *session) upstreamNegotiate() string {
	t := se.t
	want := t.upstreamProtocol
	req := rdp.ConnectionRequest{HasNegotiation: true, Protocols: want}
	if want == rdp.ProtocolRDP {
		// The legacy protocol is requested by asking for nothing else,
		// and some desktops want the negotiation left out entirely.
		req = rdp.ConnectionRequest{}
	}
	// The routing token is carried across: a desktop behind a
	// connection broker is reached by it, and dropping it would send
	// the session to the wrong host.
	req.Cookie = se.cookie
	out, err := req.Encode()
	if err != nil {
		return "upstream_negotiate"
	}
	if _, err := se.up.Write(out); err != nil {
		return "upstream_write"
	}
	pdu, err := rdp.ReadPDU(se.up)
	if err != nil {
		return "upstream_negotiate"
	}
	cc, err := rdp.ParseConnectionConfirm(pdu.Body)
	if err != nil {
		return "upstream_negotiate"
	}
	if cc.Failure != 0 {
		t.engine.Logs().Error.Warn("rdp desktop refused the protocol this gateway asked for",
			"listener", t.cfg.Name, "target", se.target,
			"asked", rdp.ProtocolName(want), "failure", cc.Failure)
		return "upstream_protocol_refused"
	}
	se.upProtocol = cc.Protocol
	if !cc.HasNegotiation {
		se.upProtocol = rdp.ProtocolRDP
	}
	if se.upProtocol != want {
		t.engine.Logs().Error.Warn("rdp desktop chose a protocol this gateway did not ask for",
			"listener", t.cfg.Name, "target", se.target,
			"asked", rdp.ProtocolName(want), "chose", rdp.ProtocolName(se.upProtocol))
		return "upstream_protocol_refused"
	}
	switch se.upProtocol {
	case rdp.ProtocolSSL, rdp.ProtocolHybrid:
		tc := tls.Client(se.up, se.upstreamTLSFor(t.upTLS))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.engine.Logs().Error.Warn("rdp desktop's tls handshake failed",
				"listener", t.cfg.Name, "target", se.target, "err", err.Error())
			return "upstream_tls"
		}
		se.up = tc
		if se.upProtocol == rdp.ProtocolHybrid {
			return se.upstreamNLA(tc)
		}
	}
	return ""
}

// upstreamTLSFor fills in the server name from the endpoint when the
// configuration did not pin one.
func (se *session) upstreamTLSFor(base *tls.Config) *tls.Config {
	if base == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // unreachable: validation requires upstream_tls for a tls leg
	}
	tc := base.Clone()
	if tc.ServerName == "" {
		if host, _, err := net.SplitHostPort(se.target); err == nil {
			tc.ServerName = host
		}
	}
	return tc
}

// upstreamNLA proves a credential to a desktop that insists on network
// level authentication, which is what a current Windows install does
// by default.
//
// The credential is the gateway's own, named by upstream_user, and
// validation requires it: the exchange happens inside the tunnel
// before the connection sequence starts, which is before the person at
// the other end has sent anything at all. That ordering is the whole
// reason network level authentication exists, and it is also why a
// gateway cannot pass a person's own credential through it.
func (se *session) upstreamNLA(conn *tls.Conn) string {
	t := se.t
	err := rdp.Authenticate(context.Background(), conn, ntlm.Credential{
		Domain: t.upDomain, User: t.upUser, Password: t.upPassword,
		Workstation: t.cfg.Name,
	})
	if err != nil {
		t.engine.Logs().Error.Warn("rdp network level authentication to the desktop failed",
			"listener", t.cfg.Name, "target", se.target,
			"user", t.upUser, "err", err.Error())
		return "upstream_nla_failed"
	}
	return ""
}
