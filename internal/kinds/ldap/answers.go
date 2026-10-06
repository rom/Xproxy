package ldap

import (
	"errors"
	"net/netip"
	"strconv"
	"time"

	wire "github.com/rom/xproxy/internal/ldap"
)

// The directory's side: the answers, and what the relay does to them.

// fromDirectory reads responses, applies the attribute policy and the entry
// bound to the ones that belong to a search, and forwards them.
func (se *session) fromDirectory() string {
	t := se.t
	s := t.host
	rd := wire.NewReader(se.up, t.maxMessage())
	for {
		_ = se.up.SetReadDeadline(time.Now().Add(t.idleTimeout()))
		raw, err := rd.Next()
		if err != nil {
			if reason := t.readError(err, se.ip, "directory"); reason != "" {
				return reason
			}
			return "closed"
		}
		m, perr := wire.Parse(raw)
		if perr != nil {
			// A directory this relay cannot read is one it cannot decide
			// about, and the client behind it would read those octets
			// somehow.
			s.Counters().LDAPMalformed.Add(1)
			s.Counters().Refuse("ldap", "malformed_response")
			t.deny(se.ip, "ldap_malformed_response", perr.Error())
			return "ldap_malformed_response"
		}
		if m.Op.Request() {
			// The directory answers; it does not ask. A request from that
			// side is a datagram sent in the wrong direction at best.
			s.Counters().Refuse("ldap", "wrong_direction_response")
			t.deny(se.ip, "ldap_wrong_direction_response", m.Op.String())
			return "ldap_wrong_direction_response"
		}
		out, drop := se.filter(m, raw)
		if drop {
			continue
		}
		if err := se.writeClient(out); err != nil {
			return "closed"
		}
	}
}

// filter is what the relay does to one answer: adopts an identity a bind
// established, removes the attributes the policy refuses, and cuts a search
// that has returned enough. It returns the octets to forward, and whether
// this answer is dropped.
func (se *session) filter(m *wire.Message, raw []byte) ([]byte, bool) {
	t := se.t
	s := t.host
	switch m.Op {
	case wire.OpBindResponse:
		se.settle(m)
		se.finish(m.ID)
		return raw, false
	case wire.OpSearchResultEntry:
		return se.entry(m, raw)
	case wire.OpSearchResultDone:
		se.mu.Lock()
		e := se.outstanding[m.ID]
		cut := e != nil && e.cut
		_, held := se.outstanding[m.ID]
		delete(se.outstanding, m.ID)
		se.mu.Unlock()
		if held {
			s.Counters().LDAPOutstanding.Add(-1)
		}
		if cut {
			// The search was already completed with sizeLimitExceeded when
			// the bound was reached. Forwarding the directory's own Done as
			// well would give the client two answers to one request.
			return nil, true
		}
		return raw, false
	default:
		// Every other response completes its request: a modify, an add, a
		// compare, an extended operation. A search reference does not, which
		// is why it is not in this set -- more of the search follows it.
		if m.Op != wire.OpSearchResultReference && m.Op != wire.OpIntermediateResponse {
			se.finish(m.ID)
		}
		return raw, false
	}
}

// finish drops an outstanding request and republishes the count. A request
// that has been answered is not outstanding, and a table that kept answered
// requests would refuse new ones on a connection that is doing nothing wrong.
func (se *session) finish(id int) {
	se.mu.Lock()
	_, held := se.outstanding[id]
	delete(se.outstanding, id)
	se.mu.Unlock()
	if held {
		se.t.host.Counters().LDAPOutstanding.Add(-1)
	}
}

// settle adopts the identity a bind established, or counts the failure.
//
// The directory decides whether the credential was right, so the relay waits
// for its answer: believing the request would let anyone be anybody by
// binding with the wrong password.
func (se *session) settle(m *wire.Message) {
	t := se.t
	se.mu.Lock()
	name, dn, method := se.pendingBindName, se.pendingBind, se.pendingMethod
	se.pendingBindName, se.pendingBind = "", nil
	success := m.Result != nil && m.Result.Code == wire.ResultSuccess
	if success {
		se.bound, se.boundName, se.method = dn, name, method
		se.tap.User(name)
	} else {
		se.failures++
	}
	se.mu.Unlock()
	if success {
		t.logBind(se, name, method, wire.ResultSuccess)
		return
	}
	code := wire.ResultInvalidCredentials
	if m.Result != nil {
		code = m.Result.Code
	}
	t.host.Counters().LDAPBindFailures.Add(1)
	t.logBind(se, name, method, code)
	if code == wire.ResultInvalidCredentials {
		// A wrong password is what a ban trigger counts on this protocol:
		// one is a typo, and forty from one address in five minutes is a
		// password list.
		t.host.Counters().Refuse("ldap", "bind_failed")
		t.deny(se.ip, "ldap_bind_failed", name)
	}
}

// entry applies the attribute policy to one search result and counts it
// against the search's bound.
func (se *session) entry(m *wire.Message, raw []byte) ([]byte, bool) {
	t := se.t
	s := t.host
	s.Counters().LDAPEntries.Add(1)
	se.mu.Lock()
	e := se.outstanding[m.ID]
	if e == nil {
		se.mu.Unlock()
		// An entry for a search nobody made, or one this relay refused. It
		// is not forwarded: the client is not waiting for it, and a client
		// that received entries for a search it did not make would be
		// reading somebody else's answer.
		s.Counters().Refuse("ldap", "unsolicited_entry")
		t.deny(se.ip, "ldap_unsolicited_entry", strconv.Itoa(m.ID))
		return nil, true
	}
	if e.cut {
		se.mu.Unlock()
		return nil, true
	}
	e.seen++
	over := e.entries > 0 && e.seen > e.entries
	if over {
		e.cut = true
	}
	strip, allowOnly := e.strip, e.allowOnly
	se.mu.Unlock()
	if over {
		// The bound is this protocol's amplification bound, and it is
		// reached rather than refused: the client gets the entries it has
		// plus the directory's own sizeLimitExceeded, which is exactly what
		// it would get from a directory with an administrative limit. A drop
		// would look like a hang.
		s.Counters().LDAPTruncated.Add(1)
		s.Counters().Refuse("ldap", "max_entries")
		t.deny(se.ip, "ldap_max_entries", strconv.Itoa(e.entries))
		if out := wire.Answer(m.ID, wire.OpSearchRequest, wire.ResultSizeLimitExceeded,
			"the relay's entry bound was reached"); out != nil {
			_ = se.writeClient(out)
		}
		return nil, true
	}
	if strip.Empty() && allowOnly.Empty() {
		return raw, false
	}
	keep := func(attr string) bool {
		if !allowOnly.Empty() {
			return allowOnly.Has(attr)
		}
		return !strip.Has(attr)
	}
	out, removed, err := wire.StripEntry(m, keep)
	if err != nil {
		s.Counters().LDAPMalformed.Add(1)
		s.Counters().Refuse("ldap", "malformed_response")
		t.deny(se.ip, "ldap_malformed_response", err.Error())
		return nil, true
	}
	if removed > 0 {
		s.Counters().LDAPStripped.Add(uint64(removed))
		t.stripped(se, m, removed)
	}
	return out, false
}

// readError turns a reader failure into a reason, or the empty string for an
// ordinary end of connection.
func (t *server) readError(err error, ip netip.Addr, from string) string {
	switch {
	case errors.Is(err, wire.ErrTooLong):
		t.host.Counters().LDAPMalformed.Add(1)
		t.host.Counters().Refuse("ldap", "message_too_large")
		t.deny(ip, "ldap_message_too_large", from)
		return "ldap_message_too_large"
	case errors.Is(err, wire.ErrFraming):
		t.host.Counters().LDAPMalformed.Add(1)
		t.host.Counters().Refuse("ldap", "framing")
		t.deny(ip, "ldap_framing", from)
		return "ldap_framing"
	}
	return ""
}
