package mms

import (
	"time"

	wire "github.com/rom/xproxy/internal/mms"
)

// Deciding about one frame, layer by layer.
//
// A frame has to be walked down to the MMS PDU before anything can be decided about
// it, and every layer on the way is a place a peer can say something this relay
// cannot read. The rule throughout is the same: a layer that does not parse is
// refused rather than forwarded, because forwarding it would be forwarding something
// with no policy applied to a substation.
//
// The one exception is a presentation data value on a context the association never
// agreed. That is not necessarily an attack -- it is what a stack this relay has not
// seen looks like -- but it is still something no service rule decided about, so it
// is counted and refused rather than passed as though it had been.

// decide reads one client frame and says whether to forward it and whether the
// association is over.
func (t *server) decide(c *conn, f *wire.Frame) (forward, fatal bool) {
	cotp, err := wire.ParseCOTP(f.Body)
	if err != nil {
		t.refuseConn(c, hard("unreadable_transport", err.Error(),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	switch cotp.Type {
	case wire.CR:
		// The connection request. Its selectors are a convention on IEC 61850, so
		// there is nothing here to decide; it is recorded for the log.
		c.update(func(a *Association) { a.Called, a.Calling = cotp.Called, cotp.Calling })
		if t.mc.LogRequests {
			t.logTransport(c, cotp)
		}
		return true, false
	case wire.DR, wire.DC:
		// The association ending. Forwarded, and the connection then ends of its
		// own accord when the peer closes.
		return true, false
	case wire.DT:
		return t.decideData(c, cotp.Data)
	}
	// An expedited data PDU, a reject, an error, an acknowledgement. Class 0 uses
	// none of them, and one arriving is a peer using a transport feature the
	// negotiated class does not have.
	t.refuseConn(c, hard("unexpected_transport", wire.TypeName(cotp.Type),
		ErrClassService, ErrCodeServiceNotSupported), "")
	return false, true
}

// decideData walks the session, presentation and ACSE layers.
func (t *server) decideData(c *conn, payload []byte) (forward, fatal bool) {
	s, err := wire.ParseSession(payload)
	if err != nil {
		t.refuseConn(c, hard("unreadable_session", err.Error(),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	if len(s.UserData) == 0 {
		// A session unit carrying nothing: a token exchange or a bare disconnect.
		return true, false
	}
	switch s.Kind {
	case wire.SPDUConnect:
		return t.decideConnect(c, s.UserData)
	case wire.SPDUFinish, wire.SPDUDisconnect, wire.SPDUAbort, wire.SPDUNotFinished:
		return true, false
	}
	return t.decidePDVs(c, s.UserData)
}

// decideConnect reads the presentation connect: the context definition list and the
// ACSE associate request inside it.
func (t *server) decideConnect(c *conn, b []byte) (forward, fatal bool) {
	ctxs, vals, err := wire.ParseCP(b)
	if err != nil {
		t.refuseConn(c, hard("unreadable_presentation", err.Error(),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	c.update(func(a *Association) { a.Contexts = ctxs })
	if len(vals) == 0 {
		t.refuseConn(c, hard("no_associate_request", "a presentation connect with no user data",
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	for _, v := range vals {
		if !v.IsACSE() {
			continue
		}
		return t.decideAssociate(c, v.Data)
	}
	// A connect whose user data is on no context this relay recognises as ACSE.
	// The association request is where the identity is, so one that cannot be read
	// is one whose identity is unknown.
	t.host.Counters().MMSOpaque.Add(1)
	t.refuseConn(c, hard("no_associate_request", "no ACSE context in the connect",
		ErrClassService, ErrCodeServiceNotSupported), "")
	return false, true
}

// decideAssociate decides about the ACSE associate request: the identity, and the
// password this protocol sends in the clear.
func (t *server) decideAssociate(c *conn, b []byte) (forward, fatal bool) {
	a, err := wire.ParseAssociate(b)
	if err != nil {
		t.refuseConn(c, hard("unreadable_associate", err.Error(),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	if a.Tag != wire.AARQ {
		// A client sending anything else where the association request belongs.
		t.refuseConn(c, hard("unexpected_associate", wire.APDUName(a.Tag),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	c.update(func(s *Association) {
		s.APTitle = a.CallingAPTitle.String()
		s.AEQualifier, s.HasQualifier = int(a.CallingAEQualifier), a.HasCallingAEQualifier
		s.Auth, s.AuthLength = a.Auth, a.AuthLength
		s.Associated = true
	})
	assoc := c.assoc()
	// The counter and the alert first, because they are about what the traffic is
	// rather than about the decision: an estate that has not moved to IEC 62351-4
	// wants to know how many of its associations carry a password even on a
	// listener that carries them.
	if a.Auth == wire.AuthPassword {
		t.host.Counters().MMSPlaintextPasswords.Add(1)
		if t.mc.AlertOnPlaintextPassword == nil || *t.mc.AlertOnPlaintextPassword {
			t.alertPlaintext(c, a.AuthLength)
		}
	}
	t.logAssociate(c, a)
	d := t.policy.Associate(assoc)
	t.observeAssociate(c, d.Allow)
	if !d.Allow {
		if !t.enforcing() && !d.Hard {
			t.refusalOnly(c, d, assoc.Identity())
			return true, false
		}
		// An association-level refusal closes: an MMS error cannot answer it,
		// because there is no MMS association yet to carry one and the ACSE reject
		// this relay would have to compose is one the client's stack matches
		// against a request it has not finished sending.
		t.refuseConn(c, d, assoc.Identity())
		return false, true
	}
	t.host.Counters().MMSAssociations.Add(1)
	return true, false
}

// decidePDVs decides about an ordinary data frame's presentation data values.
func (t *server) decidePDVs(c *conn, b []byte) (forward, fatal bool) {
	assoc := c.assoc()
	vals, err := wire.ParsePDVs(b, assoc.Contexts)
	if err != nil {
		t.refuseConn(c, hard("unreadable_presentation", err.Error(),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	for _, v := range vals {
		switch {
		case v.IsACSE():
			// A release or an abort mid-association. Nothing in either is worth a
			// policy, and refusing a client's attempt to close cleanly would
			// leave the association open.
			return true, false
		case v.IsMMS():
			return t.decideMMS(c, v.Data)
		}
	}
	// A value on a context the association never agreed. It is not MMS as far as
	// this relay can tell, so no service rule has decided about it.
	t.host.Counters().MMSOpaque.Add(1)
	d := hard("unknown_context", "a data value on a context the association did not define",
		ErrClassService, ErrCodeServiceNotSupported)
	t.refuseConn(c, d, "")
	return false, true
}

// decideMMS decides about one MMS PDU.
func (t *server) decideMMS(c *conn, b []byte) (forward, fatal bool) {
	m, err := wire.ParsePDU(b)
	if err != nil {
		t.refuseConn(c, hard("unreadable_service", err.Error(),
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	switch m.PDU {
	case wire.InitiateRequest:
		c.update(func(a *Association) { a.Initiated = true })
		t.host.Counters().MMSSessions.Add(1)
		return true, false
	case wire.ConcludeRequest, wire.ConcludeResponse, wire.CancelRequest,
		wire.CancelResponse, wire.Reject:
		return true, false
	case wire.ConfirmedRequest:
		return t.decideRequest(c, m)
	}
	// An unconfirmed PDU or a response from the client's direction. A client does
	// not send those, and a relay that forwarded one would be forwarding something
	// the IED will read as a reply to a request it never made.
	t.refuseConn(c, hard("unexpected_pdu", m.PDU.String(),
		ErrClassService, ErrCodeServiceNotSupported), "")
	return false, true
}

// decideRequest is the service-level decision.
func (t *server) decideRequest(c *conn, m *wire.Message) (forward, fatal bool) {
	if n := c.count(); t.mc.MaxRequests > 0 && n > t.mc.MaxRequests {
		t.refuseConn(c, hard("too_many_requests", "past the association's bound",
			ErrClassResource, ErrCodeCapabilityUnavailable), "")
		return false, true
	}
	if t.limiter != nil && !t.limiter.Allow(c.ip.String()) {
		return t.refused(c, m, hard("rate_limited", c.ip.String(),
			ErrClassResource, ErrCodeCapabilityUnavailable), "")
	}
	if !m.HasService {
		t.refuseConn(c, hard("no_service", "a confirmed request naming no service",
			ErrClassService, ErrCodeServiceNotSupported), "")
		return false, true
	}
	assoc := c.assoc()
	svc := m.Service
	ops := operations(m)

	// The service, then the size, then the objects. In that order because a
	// refusal should name the coarsest thing that was wrong: "write is not allowed
	// here" is a better line in an operator's log than a refusal naming one of
	// forty objects.
	if d := t.policy.Request(assoc, svc); !d.Allow {
		t.observeRequest(c, assoc, m, ops, false, time.Now())
		return t.refused(c, m, d, svc.String())
	}
	if d := t.policy.Bounds(svc, ops, m.NamesTruncated); !d.Allow {
		t.observeRequest(c, assoc, m, ops, false, time.Now())
		return t.refused(c, m, d, svc.String())
	}
	d := t.decideTarget(assoc, m, ops)
	if !d.Allow && svc.Changes() {
		// Hard whatever the mode. A monitor-only or shadow listener records what it
		// would have refused and forwards it -- except for the services that change
		// the substation, because a Write forwarded so that it could be written
		// down is a moved breaker. That is the documented contract of monitor_only
		// and it has to be applied where the decision is, not where it is acted on:
		// the refusal the policy composed is about an object, and whether it stands
		// depends on what the service does.
		d.Hard = true
	}
	t.observeRequest(c, assoc, m, ops, d.Allow, time.Now())
	for _, r := range t.policy.ObserveRules(assoc, svc, ops) {
		t.logObserved(c, r, svc, ops)
	}
	if !d.Allow {
		return t.refused(c, m, d, describe(ops))
	}
	// Behavioural detection, after the policy and on the requests that are
	// going on to the IED: the models learn from what reached the device, and a
	// request the policy refused never got there.
	if reason := t.decideAnomaly(c, m, ops); reason != "" {
		c.refusal()
		return t.respond(c, m, Decision{Reason: reason, Rule: "anomaly",
			ErrorClass: ErrClassAccess, ErrorCode: ErrCodeObjectAccessDenied})
	}
	// Remembered after the decision, so that a refused request leaves nothing in
	// the table: its answer is this relay's own error and not the IED's.
	c.remember(m.InvokeID, svc, selecting(m, ops))
	c.recordSubjects(m.InvokeID, t.lastSubjects(c))
	t.logRequest(c, m, ops)
	return true, false
}

// decideTarget applies the policy to whatever the request addressed: objects, a
// domain, or a file.
func (t *server) decideTarget(assoc Association, m *wire.Message, ops []Operation) Decision {
	if len(ops) > 0 {
		if d := t.policy.Operations(assoc, m.Service, ops); !d.Allow {
			return d
		}
		// The select-before-operate check, last, because it is about this
		// association's history rather than about the request.
		for _, op := range ops {
			if !op.Write || !op.Name.Operates() {
				continue
			}
			if d := t.policy.Operate(assoc, op.Name, time.Now()); !d.Allow {
				return d
			}
		}
		return allowed()
	}
	if m.FileName != "" || m.Service.Class() == wire.ClassFile {
		return t.policy.File(assoc, m.Service, m.FileName)
	}
	if m.ListName != "" {
		// A Read or a Write through a named variable list. The list decides what is
		// reached and the client defined it earlier, so the name of the list is
		// what a rule can match -- which is why it is matched as an object.
		return t.policy.Operations(assoc, m.Service, []Operation{{
			Name:  wire.ParseItem(m.ListName),
			Write: m.Service.Changes(),
		}})
	}
	return t.policy.Domain(assoc, m.Service, m.Domain)
}

// operations turns a request's names into the policy's own terms.
func operations(m *wire.Message) []Operation {
	if len(m.Names) == 0 {
		return nil
	}
	write := m.Service.Changes()
	out := make([]Operation, 0, len(m.Names))
	for _, n := range m.Names {
		out = append(out, Operation{Name: n, Write: write})
	}
	return out
}

// selecting says which control object a request is selecting, if any.
//
// It is the *object* rather than the attribute, because the operate that follows
// names Oper on the same object. An empty string means the request is not a select.
func selecting(m *wire.Message, ops []Operation) string {
	if m.Service != wire.SvcWrite {
		return ""
	}
	for _, op := range ops {
		if op.Name.Selects() {
			return selectKey(op.Name)
		}
	}
	return ""
}

// readServer reads what the IED sent back: the association's answer, the context
// list it agreed, and whether a select was confirmed.
func (t *server) readServer(c *conn, f *wire.Frame) {
	cotp, err := wire.ParseCOTP(f.Body)
	if err != nil || cotp.Type != wire.DT || len(cotp.Data) == 0 {
		return
	}
	s, err := wire.ParseSession(cotp.Data)
	if err != nil || len(s.UserData) == 0 {
		return
	}
	if s.Kind == wire.SPDUAccept {
		t.readAccept(c, s.UserData)
		return
	}
	assoc := c.assoc()
	vals, err := wire.ParsePDVs(s.UserData, assoc.Contexts)
	if err != nil {
		return
	}
	for _, v := range vals {
		if !v.IsMMS() {
			continue
		}
		t.readAnswer(c, v.Data)
	}
}

// readAccept reads the presentation accept, which is where the IED confirms the
// context list -- and it is the *server's* list that later data values are read
// against, because the server is the end that chose.
func (t *server) readAccept(c *conn, b []byte) {
	ctxs, vals, err := wire.ParseCP(b)
	if err != nil {
		return
	}
	if len(ctxs) > 0 {
		c.update(func(a *Association) { a.Contexts = ctxs })
	}
	for _, v := range vals {
		if !v.IsACSE() {
			continue
		}
		a, err := wire.ParseAssociate(v.Data)
		if err != nil {
			return
		}
		t.logAssociateResult(c, a)
		if a.Tag == wire.AARE && !a.Accepted() {
			t.host.Counters().MMSServerRefusals.Add(1)
		}
	}
}

// readAnswer reads one MMS answer from the IED.
func (t *server) readAnswer(c *conn, b []byte) {
	m, err := wire.ParsePDU(b)
	if err != nil {
		return
	}
	if !m.HasInvokeID {
		return
	}
	f, ok := c.took(m.InvokeID)
	if !ok {
		return
	}
	switch m.PDU {
	case wire.ConfirmedResponse:
		if f.selecting != "" {
			// The IED said yes to the select, so the selection is now this
			// association's. Recording it on the *answer* rather than the request
			// is the point: a client that asked to select an object the IED
			// refused holds no selection, and the operate that follows is refused.
			c.selected(f.selecting, time.Now().Add(t.policy.SelectTimeout()))
			t.logSelected(c, f.selecting)
		}
	case wire.ConfirmedError, wire.Reject:
		t.host.Counters().MMSServerErrors.Add(1)
		t.serverRefused(c, f.svc, m)
		t.observeServerError(f.subjects)
	}
}
