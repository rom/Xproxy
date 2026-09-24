package dns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"net/netip"
	"time"
)

// ednsCookie is the COOKIE option code (RFC 7873).
const ednsCookie = 10

// RcodeBadCookie asks the client to come back with the cookie it was
// just handed (RFC 7873 section 5.2.3).
const RcodeBadCookie = 23

// What a DNS cookie is for.
//
// A UDP datagram proves nothing about where it came from. Everything
// unpleasant about an open resolver follows from that: an answer sent to
// an address that did not ask, a small question drawing a large reply
// for somebody else's link, a cache poisoned by a race the attacker
// enters with no packets of their own to lose, and a security event
// recorded against an address chosen by whoever sent the packet.
//
// A cookie fixes the one thing underneath all of them: it makes the
// client prove it can receive what it asked for. The client sends eight
// bytes of its own; the server returns them with a keyed hash over the
// client's address and those bytes, and expects that back on the next
// query. Nothing about it is secret and nothing about it is
// authentication -- an on-path attacker sees the cookie -- but an
// off-path one cannot produce it for an address it does not hold, which
// is exactly the attacker every item above depends on.
//
// It also gives this proxy something it did not have: a UDP query whose
// source is worth believing. A blocked-name event from a cookie-carrying
// client can be attributed and can drive a ban, where one from a bare
// datagram cannot without letting anybody have a third party banned.
const (
	// CookiesOff ignores cookies entirely.
	CookiesOff = "off"
	// CookiesRespond answers a client that sent a cookie with one, and
	// treats a verified cookie as proof of the address. It never refuses
	// a query for the want of one, so a client that has never heard of
	// cookies is unaffected. The default.
	CookiesRespond = "respond"
	// CookiesRequire additionally refuses a UDP query that carries no
	// valid cookie, answering BADCOOKIE with a fresh one so a
	// cookie-aware client retries and succeeds. A client that sends no
	// cookie at all gets REFUSED, because there is nothing to echo.
	CookiesRequire = "require"
)

// cookieVersion is the server cookie version byte of RFC 9018.
const cookieVersion = 1

// serverCookieLen is the length this proxy issues: the four byte
// version and reserved field, a four byte timestamp and an eight byte
// hash, which is RFC 9018's interoperable form.
const serverCookieLen = 16

// cookieJar issues and verifies server cookies.
//
// The hash is HMAC-SHA256 truncated to eight bytes rather than RFC
// 9018's SipHash-2-4. The choice only matters between servers that must
// verify each other's cookies -- an anycast set sharing one secret --
// and each listener here has a secret of its own, so nothing else has to
// agree with it. A client moving between two nodes of a cluster costs
// one BADCOOKIE round trip and then works.
type cookieJar struct {
	secret   [32]byte
	lifetime time.Duration
}

// newCookieJar makes a jar with a fresh secret. A restart invalidates
// every cookie it issued, which costs each client one extra round trip
// and is why the secret is never written anywhere.
func newCookieJar(lifetime time.Duration) (*cookieJar, error) {
	j := &cookieJar{lifetime: lifetime}
	if j.lifetime <= 0 {
		j.lifetime = time.Hour
	}
	if _, err := rand.Read(j.secret[:]); err != nil {
		return nil, err
	}
	return j, nil
}

// issue builds the full option value: the client's eight bytes followed
// by a server cookie bound to them and to the client's address.
func (j *cookieJar) issue(client netip.Addr, clientCookie []byte, now time.Time) []byte {
	out := make([]byte, 0, 8+serverCookieLen)
	out = append(out, clientCookie[:8]...)
	out = append(out, cookieVersion, 0, 0, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(now.Unix())) //nolint:gosec // wraps in 2106, as RFC 9018 intends
	return append(out, j.mac(client, clientCookie[:8], out[8:16])...)
}

// mac is the keyed hash over the client's address, the client cookie and
// the server cookie's own version and timestamp fields.
//
// The address is in it because that is the whole point: a cookie is only
// proof that the holder can receive at the address it was issued to, so
// one replayed from somewhere else must not verify.
func (j *cookieJar) mac(client netip.Addr, clientCookie, meta []byte) []byte {
	m := hmac.New(sha256.New, j.secret[:])
	_, _ = m.Write(meta)
	_, _ = m.Write(clientCookie)
	addr := client.Unmap()
	if addr.IsValid() {
		b := addr.As16()
		_, _ = m.Write(b[:])
	}
	return m.Sum(nil)[:8]
}

// verify checks a full cookie option. ok says the client holds a cookie
// this listener issued to this address and it is still inside its
// lifetime; old says it verified but is past half its life, which is
// when a fresh one is worth sending.
func (j *cookieJar) verify(client netip.Addr, cookie []byte, now time.Time) (ok, old bool) {
	if len(cookie) != 8+serverCookieLen {
		// A cookie of another server's length cannot be checked: the
		// hash covers a layout this one does not know. That is not an
		// error, only an unverified client.
		return false, false
	}
	if cookie[8] != cookieVersion {
		return false, false
	}
	ts := time.Unix(int64(binary.BigEndian.Uint32(cookie[12:16])), 0)
	// The timestamp is checked in both directions. A cookie from the
	// future is one this listener did not issue -- or issued before a
	// clock correction -- and a small allowance keeps a client whose
	// reply crossed a step from having to redo the exchange.
	if now.Sub(ts) > j.lifetime || ts.Sub(now) > time.Minute {
		return false, false
	}
	want := j.mac(client, cookie[:8], cookie[8:16])
	if subtle.ConstantTimeCompare(want, cookie[16:24]) != 1 {
		return false, false
	}
	return true, now.Sub(ts) > j.lifetime/2
}

// cookieVerdict is what the cookie in a query came to.
type cookieVerdict int

const (
	// cookieNone: no cookie handling applies, or the client sent none
	// and none is required.
	cookieNone cookieVerdict = iota
	// cookieOK: the client holds a cookie this listener issued.
	cookieOK
	// cookieNew: the client asked for a cookie and gets one, but has not
	// proved anything yet.
	cookieNew
	// cookieBad: the query needs a valid cookie and did not carry one.
	// The answer is BADCOOKIE with a fresh cookie, so the client retries.
	cookieBad
	// cookieAbsent: the query needs a cookie and carries no option at
	// all, so there is nothing to echo and nothing to retry with.
	cookieAbsent
	// cookieMalformed: an option of a length RFC 7873 does not allow.
	cookieMalformed
)

// cookies applies the cookie policy to one query and returns the verdict
// with the option value the answer should carry.
//
// Over a stream transport there is nothing to prove: the peer completed
// a handshake to get here, which is what a cookie exists to establish
// (RFC 7873 section 5.2.3). A cookie is still echoed when one was sent,
// so a client can collect one over TCP and use it over UDP.
func (s *Server) cookies(p *Policy, query []byte, qEnd int, h Header, client netip.Addr, stream bool, now time.Time) (cookieVerdict, []byte) {
	if p.Cookies == CookiesOff || s.jar == nil {
		return cookieNone, nil
	}
	sent, present := clientCookie(query, qEnd, h)
	require := p.Cookies == CookiesRequire && !stream
	switch {
	case !present:
		if require {
			return cookieAbsent, nil
		}
		return cookieNone, nil
	case len(sent) != 8 && len(sent) != 8+serverCookieLen && (len(sent) < 16 || len(sent) > 40):
		// RFC 7873 section 5.2.2: a COOKIE option that is not 8 or
		// 16 to 40 bytes is a format error.
		return cookieMalformed, nil
	case len(sent) == 8:
		// First contact: the client asked for a cookie and has proved
		// nothing. Requiring means it does not get an answer yet, only
		// the cookie to come back with.
		fresh := s.jar.issue(client, sent, now)
		if require {
			return cookieBad, fresh
		}
		return cookieNew, fresh
	}
	ok, old := s.jar.verify(client, sent, now)
	switch {
	case ok && !old:
		return cookieOK, sent
	case ok:
		// Verified but ageing: return a fresh one so the client rolls
		// forward rather than being refused when it expires.
		return cookieOK, s.jar.issue(client, sent, now)
	case require:
		return cookieBad, s.jar.issue(client, sent, now)
	}
	return cookieNew, s.jar.issue(client, sent, now)
}

// clientCookie reads the COOKIE option out of a query. present says the
// option was there at all, which is different from it being usable.
func clientCookie(b []byte, qEnd int, h Header) (value []byte, present bool) {
	_ = optWalk(b, qEnd, h, func(code uint16, data []byte) {
		if code == ednsCookie && !present {
			value, present = data, true
		}
	})
	return value, present
}

// cookieRoom is the space a cookie option needs in a response, counting
// the OPT record it may have to be put in. It over-counts when the
// response already carries an OPT, which is the safe direction: the
// answer is a little smaller than it had to be rather than a datagram
// the client cannot read.
func cookieRoom(cookie []byte) int {
	if len(cookie) == 0 {
		return 0
	}
	// An OPT record is a root name (1), type and class (4), TTL (4) and
	// rdlength (2); the option adds a code and length (4).
	return 11 + 4 + len(cookie)
}

// badCookieReply builds the BADCOOKIE answer, which needs the cookie in
// it: the whole point is to hand the client what to come back with.
//
// Rcode 23 does not fit in the header. RFC 6891 section 6.1.3 splits an
// extended rcode in two -- the low four bits in the header, the high
// eight in the OPT record's TTL -- so a client that does not understand
// extended rcodes reads the low nibble and a client that does reassembles
// 23. Writing only the header would say 7, which is YXRRSET and means
// nothing here.
func badCookieReply(query []byte, qEnd int, h Header, cookie []byte) []byte {
	resp := AddCookie(Reply(query, qEnd, h, RcodeBadCookie&0xf), cookie)
	rh, err := ParseHeader(resp)
	if err != nil {
		return resp
	}
	_, rEnd, err := ParseQuestion(resp)
	if err != nil {
		return resp
	}
	setExtendedRcode(resp, rEnd, rh, RcodeBadCookie)
	return resp
}

// setExtendedRcode writes the high eight bits of an rcode into the OPT
// record's TTL, where RFC 6891 keeps them.
func setExtendedRcode(b []byte, qEnd int, h Header, rcode int) {
	_ = rrWalk(b, qEnd, h, func(ttlOff int, typ uint16, _ uint32) {
		if typ == TypeOPT {
			b[ttlOff] = byte(rcode >> 4) //nolint:gosec // rcodes are 12 bits
		}
	})
}

// ExtendedRcode returns a response's rcode with the OPT record's high
// bits put back, so a log line says 23 where the wire says 7 and 1.
func ExtendedRcode(b []byte) int {
	h, err := ParseHeader(b)
	if err != nil {
		return -1
	}
	_, qEnd, err := ParseQuestion(b)
	if err != nil {
		return h.Rcode()
	}
	rcode := h.Rcode()
	_ = rrWalk(b, qEnd, h, func(ttlOff int, typ uint16, _ uint32) {
		if typ == TypeOPT {
			rcode |= int(b[ttlOff]) << 4
		}
	})
	return rcode
}

// AddCookie puts the cookie option into a response's OPT record,
// creating the record when the response has none and replacing any
// cookie already there.
//
// The message is repacked rather than edited in place: changing the
// length of one record's rdata moves every record after it, and a
// compression pointer in one of those names an absolute offset that
// would then be a few bytes off the name it meant.
func AddCookie(resp []byte, cookie []byte) []byte {
	m, err := ParseMessage(resp)
	if err != nil {
		return resp
	}
	rdata := make([]byte, 0, 4+len(cookie))
	rdata = binary.BigEndian.AppendUint16(rdata, ednsCookie)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(cookie))) //nolint:gosec // at most 40
	rdata = append(rdata, cookie...)

	found := false
	for i, rr := range m.Additional {
		if rr.Type != TypeOPT {
			continue
		}
		kept, _ := dropOption(rr.Data, ednsCookie)
		merged := make([]byte, 0, len(kept)+len(rdata))
		merged = append(merged, kept...)
		merged = append(merged, rdata...)
		m.Additional[i].Data = merged
		found = true
		break
	}
	if !found {
		// A response to a query with an OPT record must carry one
		// (RFC 6891), and the class is the payload size this proxy will
		// accept -- not the client's, which is what it advertised.
		m.Additional = append(m.Additional, RR{Type: TypeOPT, Class: maxEDNSUDP, Data: rdata})
	}
	out, ok := m.Pack()
	if !ok {
		return resp
	}
	return out
}
