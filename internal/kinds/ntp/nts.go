package ntp

import (
	"errors"
	"sync/atomic"

	wire "github.com/rom/xproxy/internal/ntp"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxy"
)

// Terminating NTS on the time port.
//
// Pass-through is the honest posture for a relay that holds no keys: the
// authentication is between the client and the server, and every visible NTS
// field is readable by anybody on the path, so "NTS is present" is a
// preservation fact and never an authentication one.
//
// Termination is the other posture, and it is available because the kind: ntske
// listener beside this one issued the cookie the packet carries. That cookie
// holds the client's two session keys, sealed under a master key only this relay
// has, so this listener can do what a server does: open the cookie, verify the
// authenticator over the whole packet, and answer with an authenticator of its
// own carrying replacement cookies.
//
// What that buys is the case NTS is awkward for otherwise. The time source does
// not have to speak NTS at all -- it can be the plain NTPv4 server that has been
// in the plant for fifteen years. The clients get authenticated time, the source
// gets a request from one address it knows, and the verification happens here
// where an operator can see it counted.
//
// And in this mode "authenticated" means this relay checked, which is the whole
// difference from pass-through: a packet whose authenticator does not verify is
// refused rather than forwarded with a note.

// The refusal reasons this mode adds.
const (
	// ReasonNoAuthenticator is an NTS-looking packet with no authenticator
	// field: cookies and a unique identifier are cheap to copy from a
	// capture, and a packet carrying them without an authenticator is either
	// a broken client or somebody's replay of the visible half.
	ReasonNoAuthenticator = "nts_no_authenticator"
	// ReasonCookieUnknown is a cookie this relay did not issue, or issued
	// under a key it no longer holds.
	ReasonCookieUnknown = "nts_cookie_unknown"
	// ReasonUnverified is an authenticator that did not verify: the packet
	// was altered or forged.
	ReasonUnverified = "nts_unverified"
	// ReasonNoCookie is a packet with an authenticator and no cookie, which
	// leaves nothing to look the keys up by.
	ReasonNoCookie = "nts_no_cookie"
	// ReasonNoSession is an answer this relay cannot authenticate to the
	// client because the request it belongs to is not the one that was
	// verified -- an interleaved answer, matched by the server's own previous
	// transmit timestamp rather than by the client's request.
	ReasonNoSession = "nts_no_session"
	// ReasonNoKeys is termination configured against a key establishment
	// listener that is not there. It is fail-closed on purpose: a listener
	// asked to verify with nothing to verify against must refuse, not pass.
	ReasonNoKeys = "nts_no_cookie_keys"
)

// terminator holds what this listener needs to terminate NTS.
type terminator struct {
	host proxy.Host
	// listener is the kind: ntske listener that issued the cookies.
	listener string
	// keys is that listener's cookie key set, looked up once and kept.
	//
	// Looked up lazily rather than at construction because the two listeners
	// are built in configuration order and either may come first: a time
	// listener that resolved this at startup would work or not depending on
	// which way round an operator wrote them.
	keys atomic.Pointer[ke.CookieKeys]
}

func newTerminator(host proxy.Host, listener string) *terminator {
	return &terminator{host: host, listener: listener}
}

func (t *terminator) cookieKeys() *ke.CookieKeys {
	if k := t.keys.Load(); k != nil {
		return k
	}
	k := t.host.NTSCookieKeys(t.listener)
	if k == nil {
		return nil
	}
	t.keys.Store(k)
	return k
}

// session is one verified request: the keys to answer under, the identifier to
// echo, and how many replacement cookies the client asked for.
type session struct {
	keys *ke.Keys
	aead uint16
	// uniqueID is the client's identifier, copied onto the answer. It is what
	// ties the answer to the request, and a client that got an answer without
	// it would have no way to know which request it belonged to.
	uniqueID []byte
	// cookies is how many to put in the answer: one per cookie the client
	// spent and one per placeholder it sent, bounded. The placeholders are
	// what keep the request as large as the answer -- without that bound this
	// listener would be an amplifier.
	cookies int
}

// verify opens the cookie and checks the authenticator.
//
// It returns the refusal reason on failure, and the reasons are separate because
// they mean different things to an operator: a cookie this relay never issued is
// a client that established keys with somebody else or is using cookies from
// before a rotation went too far, and an authenticator that did not verify is a
// packet that was tampered with.
func (t *terminator) verify(pkt *wire.Packet) (*session, string) {
	c := t.host.Counters()
	keys := t.cookieKeys()
	if keys == nil {
		return nil, ReasonNoKeys
	}
	fields := pkt.NTS()
	if !fields.Authenticator {
		// Asked before the cookie is opened, which is a decryption: a packet
		// with no authenticator cannot be accepted whatever the cookie says, so
		// there is no reason to spend the work finding out. The verification
		// below would refuse it too.
		return nil, ReasonNoAuthenticator
	}
	cookies := wire.NTSCookies(pkt.Extensions)
	if len(cookies) == 0 {
		return nil, ReasonNoCookie
	}
	// The first cookie is the one the keys come from. A client sends one;
	// several is not a shape to guess about, so the rest are treated as
	// placeholders were: a request for that many replacements.
	aead, sk, err := keys.Open(cookies[0])
	if err != nil {
		c.NTPNTSCookieUnknown.Add(1)
		return nil, ReasonCookieUnknown
	}
	if _, err := pkt.OpenNTS(sk.C2S); err != nil {
		if errors.Is(err, wire.ErrNTSVerify) {
			c.NTPNTSUnverified.Add(1)
			return nil, ReasonUnverified
		}
		// A malformed authenticator is a different fact from one that did not
		// verify, and it is counted as a refusal of its own rather than as a
		// forgery: the sender could not have produced a packet this relay would
		// accept, whatever keys it held.
		return nil, ReasonNoAuthenticator
	}
	want := fields.Cookies + fields.Placeholders
	if want > wire.MaxNTSCookies {
		want = wire.MaxNTSCookies
	}
	if want < 1 {
		want = 1
	}
	c.NTPNTSVerified.Add(1)
	return &session{keys: sk, aead: aead, uniqueID: fields.UniqueID, cookies: want}, ""
}

// requestForSource is what goes to the time server: the header, and nothing
// else.
//
// The extension fields were the client's conversation with this relay. The
// cookie names a key the source does not hold, the authenticator covers a packet
// the source will not verify, and a placeholder asks for something only the
// party that issues cookies can give. So the request is re-originated as plain
// NTPv4 -- which is the point of this mode, because the source is a time server
// that cannot speak NTS.
//
// The header is passed through unchanged rather than rebuilt. It carries the
// client's own transmit timestamp, which is the only thing in NTP that ties an
// answer to a question, and the relay's outstanding table is keyed by it.
func requestForSource(pkt *wire.Packet) []byte {
	if len(pkt.Raw) < wire.HeaderLen {
		return pkt.Raw
	}
	return pkt.Raw[:wire.HeaderLen]
}

// answer builds the packet the client gets from the answer the source gave.
//
// The time is the source's, unaltered: the header is copied octet for octet,
// because every field in it is the source's statement about its clock and a
// relay that adjusted one would be inventing time. What this adds is the
// client's unique identifier and an authenticator over the whole thing, sealed
// with the client's server-to-client key -- so the client can tell this answer
// came from the party it established keys with, and can tell it apart from an
// answer to a different request.
//
// The replacement cookies go inside the authenticator, encrypted. A cookie in
// the clear would let anybody on the path recognise the same client at its next
// exchange, which is the linkability NTS exists to remove.
func (t *terminator) answer(se *session, from *wire.Packet) ([]byte, error) {
	if len(from.Raw) < wire.HeaderLen {
		return nil, errors.New("ntp: the answer is shorter than a header")
	}
	keys := t.cookieKeys()
	if keys == nil {
		return nil, errors.New("ntp: the cookie keys are gone")
	}
	out := make([]byte, 0, wire.HeaderLen+len(se.uniqueID)+256)
	out = append(out, from.Raw[:wire.HeaderLen]...)
	if len(se.uniqueID) > 0 {
		out = append(out, wire.Extension{Type: wire.EFUniqueIdentifier, Body: se.uniqueID}.Bytes()...)
	}
	inner := make([]wire.Extension, 0, se.cookies)
	for i := 0; i < se.cookies; i++ {
		cookie, err := keys.Seal(se.aead, se.keys)
		if err != nil {
			return nil, err
		}
		inner = append(inner, wire.NTSCookieField(cookie))
	}
	out, err := wire.SealNTS(out, se.keys.S2C, inner)
	if err != nil {
		return nil, err
	}
	t.host.Counters().NTPNTSCookiesIssued.Add(uint64(len(inner))) //nolint:gosec // bounded by MaxNTSCookies
	return out, nil
}
