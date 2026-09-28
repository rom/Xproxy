package snmp

import "strings"

// The transport a message arrived on, which this listener's policy can name.
//
// It is a rule field because on this protocol the transport *is* half the
// credential. A v2c community string arriving in a plain datagram is a
// cleartext password from an address anybody can claim; the same request
// inside DTLS came from a peer that proved it holds a private key. A policy
// that could not tell them apart would have to be written for the weaker of
// the two -- which is what "USM from the plant, DTLS from the network
// operations centre" means, and why one listener can serve both and decide
// differently about each.
type Transport string

// The four transports this listener can take a message on.
const (
	// TransportUDP is a plain datagram: port 161, every poller and every
	// agent, no identity beyond a source address.
	TransportUDP Transport = "udp"
	// TransportTCP is RFC 3430's stream, unprotected.
	TransportTCP Transport = "tcp"
	// TransportTLS is RFC 6353 over TCP 10161.
	TransportTLS Transport = "tls"
	// TransportDTLS is RFC 6353 over UDP 10161, which is the same transport
	// model on the transport the protocol actually uses.
	TransportDTLS Transport = "dtls"
)

// Transports are the transports a rule may name, sorted the way this file
// declares them: weakest first, because that is the order an estate migrates
// in.
func Transports() []string {
	return []string{string(TransportUDP), string(TransportTCP),
		string(TransportTLS), string(TransportDTLS)}
}

// TransportOf reads a transport name as the configuration spells it.
func TransportOf(s string) (Transport, bool) {
	switch Transport(strings.ToLower(strings.TrimSpace(s))) {
	case TransportUDP:
		return TransportUDP, true
	case TransportTCP:
		return TransportTCP, true
	case TransportTLS:
		return TransportTLS, true
	case TransportDTLS:
		return TransportDTLS, true
	}
	return "", false
}

// Secure says whether the transport authenticated and encrypted the message
// before this relay read it, which is what RFC 6353 s3.1.2 means by a
// transport that provides authPriv.
func (t Transport) Secure() bool { return t == TransportTLS || t == TransportDTLS }

func (t Transport) String() string { return string(t) }
