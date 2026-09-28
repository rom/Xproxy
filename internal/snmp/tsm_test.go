package snmp

import (
	"errors"
	"testing"
)

// The transport security model, read and built.
//
// The model's whole content is what it does *not* carry: no user, no engine,
// no clock, no digest. So the tests are about the two places that absence
// shows up on the wire -- an empty security parameters field, and flags that
// claim authPriv over a payload that is in the clear -- because both are shapes
// a reader written for USM gets wrong.

// A TSM message whose flags say authPriv and whose scoped PDU is plain, which
// is every TSM message ever sent (RFC 5591 s3.1.1).
func TestATransportSecurityModelMessageIsReadWithoutKeys(t *testing.T) {
	get := pdu(TagGetRequest, 41, 0, 0, varbind(oid(1, 3, 6, 1, 2, 1, 1, 5, 0), tlv(TagNull)))
	raw := v3msg(12, 0x03, SecurityModelTSM, tlv(TagOctetStr), scopedPDU("switch-9", "", get))
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("a message with no security parameters was refused: %v", err)
	}
	if !m.IsTSM() {
		t.Fatalf("model %d level %s", m.V3.SecurityModel, m.V3.Level)
	}
	// The flags are read as they arrived: the transport said authPriv, so the
	// message says authPriv, and a policy asking for authPriv is satisfied by
	// a session that provided it.
	if m.V3.Level != AuthPriv {
		t.Errorf("level %s, want authPriv", m.V3.Level)
	}
	// And the payload was read anyway, which is the part a USM reader gets
	// wrong: the privacy bit here is a statement about the transport, not a
	// promise of ciphertext.
	if m.V3.ScopedPDUEncrypted {
		t.Error("a plain scoped PDU under TSM read as ciphertext")
	}
	if m.PDU == nil || m.PDU.Type != GetRequest || m.PDU.RequestID != 41 {
		t.Fatalf("pdu %+v", m.PDU)
	}
	// Nothing was invented for the fields the model does not have. A relay
	// that reported a user name here would let a rule written about a USM user
	// match a message that named none.
	if m.V3.User != "" || len(m.V3.EngineID) != 0 || m.V3.EngineBoots != 0 {
		t.Errorf("TSM reported user %q engine %q boots %d",
			m.V3.User, m.V3.EngineID, m.V3.EngineBoots)
	}
	if len(m.V3.AuthParams) != 0 || m.V3.AuthParamsAt != 0 {
		t.Errorf("TSM reported a digest at %d: %x", m.V3.AuthParamsAt, m.V3.AuthParams)
	}
	if m.Community != "" {
		t.Errorf("TSM reported community %q", m.Community)
	}
}

// Security parameters under a model that defines none. RFC 5591 s3.1.1 says
// zero-length, so octets there are either an implementation that is not this
// model or a sender using a field nothing reads.
func TestTransportSecurityModelParametersMustBeEmpty(t *testing.T) {
	raw := v3msg(13, 0x03, SecurityModelTSM, octets(TagOctetStr, "not nothing"),
		scopedPDU("e", "", pdu(TagGetRequest, 1, 0, 0)))
	_, err := Parse(raw)
	if !errors.Is(err, ErrTSMParams) {
		t.Fatalf("parsing gave %v, want ErrTSMParams", err)
	}
	// A USM message carrying the same octets is a different matter: the field
	// is that model's and is read as that model's.
	if _, err := Parse(v3msg(14, 0x01, SecurityModelUSM, usm("e", 1, 2, "u", "", ""),
		scopedPDU("e", "", pdu(TagGetRequest, 1, 0, 0)))); err != nil {
		t.Errorf("a USM message was refused: %v", err)
	}
}

// Building one. A response under this model needs no keys, which is what lets
// a relay answer a manager whose credential it does not hold.
func TestBuildingATransportSecurityModelMessage(t *testing.T) {
	inner := pdu(TagResponse, 41, 0, 0,
		varbind(oid(1, 3, 6, 1, 2, 1, 1, 5, 0), octets(TagOctetStr, "switch-9")))
	scoped, err := ScopedPDU([]byte("switch-9"), "", inner)
	if err != nil {
		t.Fatal(err)
	}
	out, err := BuildTSM(TSMBuild{MessageID: 12, MaxSize: 65507, Level: AuthPriv, Scoped: scoped})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatalf("what was built does not parse: %v", err)
	}
	if !m.IsTSM() || m.V3.MessageID != 12 || m.V3.MaxSize != 65507 {
		t.Fatalf("header %+v", m.V3)
	}
	if m.V3.Level != AuthPriv {
		t.Errorf("level %s", m.V3.Level)
	}
	// The message identifier is the field that matters most on a response:
	// it is what the manager's stack pairs with the request it sent, and a
	// relay that rebuilt the envelope and lost it would answer into a void.
	if m.PDU == nil || m.PDU.Type != Response || m.PDU.RequestID != 41 {
		t.Fatalf("pdu %+v", m.PDU)
	}
	if string(m.V3.ContextEngineID) != "switch-9" {
		t.Errorf("context engine %q", m.V3.ContextEngineID)
	}
	// Reportable is off by default, which is what RFC 3412 s6.4 says about a
	// response: a report about a report is a loop.
	if m.V3.Reportable {
		t.Error("a response was built reportable")
	}
	if got, err := BuildTSM(TSMBuild{MessageID: 1, Level: AuthPriv, Reportable: true,
		Scoped: scoped}); err != nil {
		t.Error(err)
	} else if m, err := Parse(got); err != nil || !m.V3.Reportable {
		t.Errorf("reportable was not carried: %v %+v", err, m.V3)
	}
	// The three levels the flags can carry, so a listener that decides on the
	// level decides on what the transport actually gave.
	for _, lvl := range []SecurityLevel{NoAuthNoPriv, AuthNoPriv, AuthPriv} {
		got, err := BuildTSM(TSMBuild{MessageID: 2, Level: lvl, Scoped: scoped})
		if err != nil {
			t.Fatalf("%s: %v", lvl, err)
		}
		m, err := Parse(got)
		if err != nil {
			t.Fatalf("%s: %v", lvl, err)
		}
		if m.V3.Level != lvl {
			t.Errorf("%s was built and read back as %s", lvl, m.V3.Level)
		}
	}
	// A build with nothing to say is refused rather than producing an
	// envelope around no PDU, which a manager would read as malformed.
	if _, err := BuildTSM(TSMBuild{MessageID: 3, Level: AuthPriv}); !errors.Is(err, ErrScoped) {
		t.Errorf("an empty build gave %v", err)
	}
}

// The model numbers and their names, which appear in counters and log lines
// an operator compares against a vendor's documentation.
func TestSecurityModelsAreNamedAsTheirStandardsName(t *testing.T) {
	for v, want := range map[int64]string{
		1: "snmpv1", 2: "snmpv2c", 3: "usm", 4: "tsm", 7: "model_7",
	} {
		if got := SecurityModelName(v); got != want {
			t.Errorf("model %d names itself %q, want %q", v, got, want)
		}
	}
	// IsTSM is asked of messages that are not v3 at all, so it answers about
	// them rather than dereferencing a header that is not there.
	var none *Message
	if none.IsTSM() {
		t.Error("a nil message reported itself TSM")
	}
	m, err := Parse(v2c("public", pdu(TagGetRequest, 1, 0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if m.IsTSM() {
		t.Error("a v2c message reported itself TSM")
	}
}

// A refusal, which is the thing a USM message cannot have.
//
// wire.Refusal returns nothing for a version 3 message because a refusal would
// have to be signed with the manager's own key. Under the transport security
// model there is no key and no digest, so the refusal is an ordinary message
// written into the session -- which is the difference between a manager seeing
// noAccess in its own monitoring system and a manager seeing a timeout.
func TestATransportSecurityModelRequestCanBeRefusedInWords(t *testing.T) {
	get := pdu(TagGetRequest, 71, 0, 0, varbind(oid(1, 3, 6, 1, 2, 1, 1, 5, 0), tlv(TagNull)))
	raw := v3msg(31, 0x03, SecurityModelTSM, tlv(TagOctetStr), scopedPDU("switch-3", "vlan-9", get))
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := Refusal(m)
	if out == nil {
		t.Fatal("a transport security model request could not be refused")
	}
	answer, err := Parse(out)
	if err != nil {
		t.Fatalf("the refusal does not parse: %v", err)
	}
	if !answer.IsTSM() {
		t.Fatalf("the refusal was %s model %+v", answer.Version, answer.V3)
	}
	// The envelope is the request's, echoed. The message identifier is what the
	// manager's stack pairs the refusal with, and a refusal it cannot pair is a
	// timeout with extra steps.
	if answer.V3.MessageID != 31 {
		t.Errorf("message id %d, want 31", answer.V3.MessageID)
	}
	if string(answer.V3.ContextEngineID) != "switch-3" || answer.V3.ContextName != "vlan-9" {
		t.Errorf("context %q %q, want the request's", answer.V3.ContextEngineID, answer.V3.ContextName)
	}
	if answer.V3.Level != AuthPriv {
		t.Errorf("level %s: the transport's, not this relay's choice", answer.V3.Level)
	}
	// And the refusal itself: the word version 2c and 3 have for "you may not",
	// with the request identifier and the bindings the request carried.
	if answer.PDU == nil || answer.PDU.Type != Response {
		t.Fatalf("pdu %+v", answer.PDU)
	}
	if answer.PDU.RequestID != 71 || answer.PDU.ErrorStatus != StatusNoAccess {
		t.Errorf("request %d status %d", answer.PDU.RequestID, answer.PDU.ErrorStatus)
	}
	if len(answer.PDU.VarBinds) != 1 || answer.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.5.0" {
		t.Errorf("bindings %+v: an agent answers with the ones it was asked about", answer.PDU.VarBinds)
	}

	// A USM message is still unanswerable, which is the rule this is the
	// exception to rather than a rule that has gone away.
	usmMsg, err := Parse(v3msg(32, 0x01, SecurityModelUSM, usm("e", 1, 2, "u", "0123456789ab", ""),
		scopedPDU("e", "", get)))
	if err != nil {
		t.Fatal(err)
	}
	if Refusal(usmMsg) != nil {
		t.Error("a USM message was answered with a refusal this relay cannot sign")
	}
}
