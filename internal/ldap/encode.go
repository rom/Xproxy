package ldap

// The messages the relay sends on its own behalf, and the one rewrite it
// makes to a message it forwards.
//
// A refusal is the directory's own vocabulary: an LDAPResult with a result
// code every client already knows how to display. Dropping the request
// instead would leave the client waiting on a connection that will never
// answer, and a hang is indistinguishable from a directory that died.

// ResponseOp is the response an operation is answered with. A relay that
// answered a search with a bind response would be a relay whose refusals
// hang the client.
func ResponseOp(op Op) (Op, bool) {
	switch op {
	case OpBindRequest:
		return OpBindResponse, true
	case OpSearchRequest:
		// A search is completed by its Done message, which is what a client
		// waits for whether or not any entry came first.
		return OpSearchResultDone, true
	case OpModifyRequest:
		return OpModifyResponse, true
	case OpAddRequest:
		return OpAddResponse, true
	case OpDelRequest:
		return OpDelResponse, true
	case OpModifyDNRequest:
		return OpModifyDNResponse, true
	case OpCompareRequest:
		return OpCompareResponse, true
	case OpExtendedRequest:
		return OpExtendedResponse, true
	}
	// Unbind and abandon are the two operations with no response at all: the
	// client is not waiting.
	return 0, false
}

// Answer builds an LDAPResult response for a request.
//
// diagnostic is the server-side message, which a client displays. It says
// what was refused and never why in detail: a refusal that named the rule and
// the subtree would be telling whoever is probing where the edges are.
func Answer(id int, op Op, code ResultCode, diagnostic string) []byte {
	return AnswerFor(id, op, "", code, diagnostic)
}

// AnswerFor is Answer with the extended operation's own name, which an
// extended response must carry: a client that pipelined two cannot otherwise
// tell which one answered.
func AnswerFor(id int, op Op, oid string, code ResultCode, diagnostic string) []byte {
	resp, ok := ResponseOp(op)
	if !ok {
		return nil
	}
	body := node(classApplication, byte(resp),
		enumerated(int(code)), str(""), str(diagnostic))
	if resp == OpExtendedResponse && oid != "" {
		body.add(leaf(classContext, 10, []byte(oid)))
	}
	return seqOf(integer(id), body)
}

// StartTLSRequest is the extended operation that asks for TLS, which this
// relay sends to a directory on a client's behalf.
func StartTLSRequest(id int) []byte {
	return seqOf(integer(id), node(classApplication, byte(OpExtendedRequest),
		leaf(classContext, 0, []byte(OIDStartTLS))))
}

// StartTLSResponse is the answer this relay gives a client that asked for
// TLS: success, after which the next octet from the client is a TLS record.
func StartTLSResponse(id int, code ResultCode, diagnostic string) []byte {
	return seqOf(integer(id), node(classApplication, byte(OpExtendedResponse),
		enumerated(int(code)), str(""), str(diagnostic),
		leaf(classContext, 10, []byte(OIDStartTLS))))
}

// NoticeOfDisconnection is the one unsolicited message the protocol has: the
// server saying it is about to close, with message identifier 0. A relay that
// closed without it would leave a client guessing whether it was refused or
// the network broke.
func NoticeOfDisconnection(code ResultCode, diagnostic string) []byte {
	return seqOf(integer(0), node(classApplication, byte(OpExtendedResponse),
		enumerated(int(code)), str(""), str(diagnostic),
		leaf(classContext, 10, []byte(OIDNoticeOfDisconnection))))
}

// seqOf wraps fields in the message SEQUENCE.
func seqOf(kids ...*packet) []byte {
	return node(classUniversal, tagSequence, kids...).encode(nil)
}

// StripEntry rebuilds a SearchResultEntry without the attributes keep
// refuses, and says how many it removed.
//
// This is the half of an attribute policy that a request-side access list
// cannot do: a search that asked for "*" named no password hash and the
// directory sent one. Removing it here means the application that asked for
// everything still works and no longer receives it.
//
// An entry left with no attributes at all is still forwarded. The entry's
// *existence* is the answer to the filter, and dropping it would change what
// the search found -- which is a different thing from changing what it
// returned, and not the relay's to do.
func StripEntry(m *Message, keep func(attr string) bool) ([]byte, int, error) {
	if m == nil || m.Op != OpSearchResultEntry || m.pkt == nil {
		return nil, 0, ErrShape
	}
	body := m.pkt.kids[1]
	if len(body.kids) < 2 {
		return nil, 0, ErrShape
	}
	attrs := body.kids[1]
	kept := make([]*packet, 0, len(attrs.kids))
	removed := 0
	for _, attr := range attrs.kids {
		if len(attr.kids) == 0 {
			return nil, 0, ErrShape
		}
		if keep(string(attr.kids[0].data)) {
			kept = append(kept, attr)
			continue
		}
		removed++
	}
	if removed == 0 {
		return m.Raw, 0, nil
	}
	rebuilt := node(classApplication, byte(OpSearchResultEntry),
		body.kids[0], node(classUniversal, tagSequence, kept...))
	out := seqOf(append([]*packet{m.pkt.kids[0], rebuilt}, m.pkt.kids[2:]...)...)
	return out, removed, nil
}
