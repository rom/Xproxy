package iec104

import "fmt"

// Type is an IEC 60870-5-101/104 type identification: what an ASDU is.
//
// The numbering is the standard's, and the important thing about it is
// that it is *sorted by direction and by danger*. Types 1 to 40 are
// monitoring information travelling up from the station. Types 45 to 51
// are the process commands travelling down. Types 100 to 107 are system
// commands, and two of them -- reset process and clock synchronisation --
// are the ones that stop a substation or move its time. Types 110 onwards
// are parameters and file transfer.
//
// A policy written in these numbers is therefore a policy about what the
// control centre may *do*, which is why this relay reads them.
type Type byte

// The monitoring directions: information travelling up from the controlled
// station. A relay almost never refuses these -- refusing telemetry blinds
// the control room, which is its own kind of incident -- but it does
// recognise them, so that "allow only monitoring" is a thing an operator
// can write.
const (
	MSpNA1 Type = 1  // single point
	MSpTA1 Type = 2  // single point with time tag
	MDpNA1 Type = 3  // double point
	MDpTA1 Type = 4  // double point with time tag
	MStNA1 Type = 5  // step position
	MStTA1 Type = 6  // step position with time tag
	MBoNA1 Type = 7  // bitstring of 32 bits
	MBoTA1 Type = 8  // bitstring with time tag
	MMeNA1 Type = 9  // measured value, normalised
	MMeTA1 Type = 10 // measured value, normalised, with time tag
	MMeNB1 Type = 11 // measured value, scaled
	MMeTB1 Type = 12 // measured value, scaled, with time tag
	MMeNC1 Type = 13 // measured value, short floating point
	MMeTC1 Type = 14 // measured value, float, with time tag
	MItNA1 Type = 15 // integrated totals
	MItTA1 Type = 16 // integrated totals with time tag
	MEpTA1 Type = 17 // protection equipment event
	MEpTB1 Type = 18 // packed start events of protection equipment
	MEpTC1 Type = 19 // packed output circuit information
	MPsNA1 Type = 20 // packed single point with change detection
	MMeND1 Type = 21 // measured value, normalised, without quality
	MSpTB1 Type = 30 // single point with CP56Time2a
	MDpTB1 Type = 31 // double point with CP56Time2a
	MStTB1 Type = 32 // step position with CP56Time2a
	MBoTB1 Type = 33 // bitstring with CP56Time2a
	MMeTD1 Type = 34 // measured value, normalised, CP56Time2a
	MMeTE1 Type = 35 // measured value, scaled, CP56Time2a
	MMeTF1 Type = 36 // measured value, float, CP56Time2a
	MItTB1 Type = 37 // integrated totals with CP56Time2a
	MEpTD1 Type = 38 // protection event with CP56Time2a
	MEpTE1 Type = 39 // packed start events with CP56Time2a
	MEpTF1 Type = 40 // packed output circuit with CP56Time2a
)

// MEiNA1 is the end of initialisation: a station says it has restarted
// and with what cause. A control centre uses it to know that everything
// it believed about the station's state is stale, which is why it is the
// first thing a station sends once data transfer is up.
const MEiNA1 Type = 70

// The control directions: process commands travelling down to the
// controlled station. These are the reason this relay exists.
const (
	CScNA1 Type = 45 // single command: open or close one thing
	CDcNA1 Type = 46 // double command
	CRcNA1 Type = 47 // regulating step command: raise or lower a tap
	CSeNA1 Type = 48 // setpoint command, normalised
	CSeNB1 Type = 49 // setpoint command, scaled
	CSeNC1 Type = 50 // setpoint command, short float
	CBoNA1 Type = 51 // bitstring of 32 bits command
	CScTA1 Type = 58 // single command with CP56Time2a
	CDcTA1 Type = 59 // double command with CP56Time2a
	CRcTA1 Type = 60 // regulating step with CP56Time2a
	CSeTA1 Type = 61 // setpoint, normalised, with CP56Time2a
	CSeTB1 Type = 62 // setpoint, scaled, with CP56Time2a
	CSeTC1 Type = 63 // setpoint, float, with CP56Time2a
	CBoTA1 Type = 64 // bitstring command with CP56Time2a
)

// The system commands. Two of these are the ones that matter most: a
// reset process command reboots a station, and a clock synchronisation
// command moves its time -- which changes the meaning of every timestamp
// in the historian and of every protection function keyed to one.
const (
	CIcNA1 Type = 100 // interrogation command: send me everything
	CCiNA1 Type = 101 // counter interrogation command
	CRdNA1 Type = 102 // read command
	CCsNA1 Type = 103 // clock synchronisation command
	CTsNA1 Type = 104 // test command
	CRpNA1 Type = 105 // reset process command
	CCdNA1 Type = 106 // delay acquisition command
	CTsTA1 Type = 107 // test command with CP56Time2a
)

// Parameters and file transfer.
const (
	PMeNA1 Type = 110 // parameter of measured value, normalised
	PMeNB1 Type = 111 // parameter of measured value, scaled
	PMeNC1 Type = 112 // parameter of measured value, float
	PAcNA1 Type = 113 // parameter activation
	FFrNA1 Type = 120 // file ready
	FSrNA1 Type = 121 // section ready
	FScNA1 Type = 122 // call directory, select file, call file, call section
	FLsNA1 Type = 123 // last section, last segment
	FAfNA1 Type = 124 // ack file, ack section
	FSgNA1 Type = 125 // segment
	FDrTA1 Type = 126 // directory
	FScNB1 Type = 127 // query log
)

// typeNames is every type identification the standard defines, as the
// names an operator writes in configuration. The names are the standard's
// own, which are ugly and which every engineer in this field reads
// fluently -- inventing friendlier ones would mean an operator translating
// from the substation documentation in their head.
var typeNames = map[string]Type{
	"M_SP_NA_1": MSpNA1, "M_SP_TA_1": MSpTA1, "M_DP_NA_1": MDpNA1, "M_DP_TA_1": MDpTA1,
	"M_ST_NA_1": MStNA1, "M_ST_TA_1": MStTA1, "M_BO_NA_1": MBoNA1, "M_BO_TA_1": MBoTA1,
	"M_ME_NA_1": MMeNA1, "M_ME_TA_1": MMeTA1, "M_ME_NB_1": MMeNB1, "M_ME_TB_1": MMeTB1,
	"M_ME_NC_1": MMeNC1, "M_ME_TC_1": MMeTC1, "M_IT_NA_1": MItNA1, "M_IT_TA_1": MItTA1,
	"M_EP_TA_1": MEpTA1, "M_EP_TB_1": MEpTB1, "M_EP_TC_1": MEpTC1, "M_PS_NA_1": MPsNA1,
	"M_ME_ND_1": MMeND1,
	"M_SP_TB_1": MSpTB1, "M_DP_TB_1": MDpTB1, "M_ST_TB_1": MStTB1, "M_BO_TB_1": MBoTB1,
	"M_ME_TD_1": MMeTD1, "M_ME_TE_1": MMeTE1, "M_ME_TF_1": MMeTF1, "M_IT_TB_1": MItTB1,
	"M_EP_TD_1": MEpTD1, "M_EP_TE_1": MEpTE1, "M_EP_TF_1": MEpTF1,

	"C_SC_NA_1": CScNA1, "C_DC_NA_1": CDcNA1, "C_RC_NA_1": CRcNA1, "C_SE_NA_1": CSeNA1,
	"C_SE_NB_1": CSeNB1, "C_SE_NC_1": CSeNC1, "C_BO_NA_1": CBoNA1,
	"C_SC_TA_1": CScTA1, "C_DC_TA_1": CDcTA1, "C_RC_TA_1": CRcTA1, "C_SE_TA_1": CSeTA1,
	"C_SE_TB_1": CSeTB1, "C_SE_TC_1": CSeTC1, "C_BO_TA_1": CBoTA1,

	"C_IC_NA_1": CIcNA1, "C_CI_NA_1": CCiNA1, "C_RD_NA_1": CRdNA1, "C_CS_NA_1": CCsNA1,
	"C_TS_NA_1": CTsNA1, "C_RP_NA_1": CRpNA1, "C_CD_NA_1": CCdNA1, "C_TS_TA_1": CTsTA1,

	"P_ME_NA_1": PMeNA1, "P_ME_NB_1": PMeNB1, "P_ME_NC_1": PMeNC1, "P_AC_NA_1": PAcNA1,
	"F_FR_NA_1": FFrNA1, "F_SR_NA_1": FSrNA1, "F_SC_NA_1": FScNA1, "F_LS_NA_1": FLsNA1,
	"F_AF_NA_1": FAfNA1, "F_SG_NA_1": FSgNA1, "F_DR_TA_1": FDrTA1, "F_SC_NB_1": FScNB1,
}

// typeByValue is the reverse, built once.
var typeByValue = func() map[Type]string {
	out := make(map[Type]string, len(typeNames))
	for n, t := range typeNames {
		out[t] = n
	}
	return out
}()

// TypeOf reads a type identification name as the configuration spells it,
// case insensitively, or a bare number for a type this list does not
// carry: a vendor's private range is still a thing an operator has to be
// able to name.
func TypeOf(s string) (Type, bool) {
	if t, ok := typeNames[upper(s)]; ok {
		return t, true
	}
	return 0, false
}

// String names a type identification, or reports its number when the
// standard does not define one.
func (t Type) String() string {
	if n, ok := typeByValue[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE_%d", byte(t))
}

// Known says whether this is a type identification the standard defines.
func (t Type) Known() bool { _, ok := typeByValue[t]; return ok }

// Monitoring says whether a type carries information up from the
// controlled station.
func (t Type) Monitoring() bool { return t >= 1 && t <= 40 }

// Command says whether a type is a process command to equipment: the set
// that opens a breaker, moves a tap changer or writes a setpoint.
func (t Type) Command() bool {
	return (t >= CScNA1 && t <= CBoNA1) || (t >= CScTA1 && t <= CBoTA1)
}

// System says whether a type is a system command, which includes the two
// that reset a station and move its clock.
func (t Type) System() bool { return t >= CIcNA1 && t <= CTsTA1 }

// SelectSupported says whether a type's command qualifier carries the
// select bit, which is what select-before-operate is built on. The
// bitstring commands do not: a 32-bit output has no two-step form in the
// standard.
func (t Type) SelectSupported() bool {
	switch t {
	case CScNA1, CDcNA1, CRcNA1, CSeNA1, CSeNB1, CSeNC1,
		CScTA1, CDcTA1, CRcTA1, CSeTA1, CSeTB1, CSeTC1:
		return true
	}
	return false
}

// commandType says whether the first information object of this type
// carries a command qualifier worth keeping.
func commandType(t Type) bool { return t.Command() }

// qualifierOffset is where the select/execute bit lives inside a command's
// information element, and whether it lives there at all.
//
// It is not always the first octet, and reading it as though it were is a
// select-before-execute bypass. A single, double or regulating step command is
// one qualifier octet, so there S/E really is bit 8 of the element's first byte.
// A setpoint is its *value* first and the qualifier of setpoint command after
// it: two octets of normalised or scaled value, or four of short float, and then
// the QOS. Reading bit 8 of the value's low byte instead means half of all
// setpoint values are read as selections -- and a selection is forwarded, so the
// station executes a command the relay recorded as a mere selection. The other
// half makes a genuine selection look like an execute, which is refused.
//
// A 32-bit bitstring command has no qualifier octet at all and so no two-step
// form, which is why SelectSupported leaves it out.
func qualifierOffset(t Type) (int, bool) {
	switch t {
	case CScNA1, CDcNA1, CRcNA1, CScTA1, CDcTA1, CRcTA1:
		return 0, true
	case CSeNA1, CSeNB1, CSeTA1, CSeTB1:
		// Two octets of value, then the QOS.
		return 2, true
	case CSeNC1, CSeTC1:
		// Four octets of IEEE 754 short float, then the QOS.
		return 4, true
	}
	return 0, false
}

// objectSize is the size of one information object's *element*, after its
// three-octet address, for the types this reads. A type that is not here
// is forwarded with its addresses unread rather than guessed at.
func objectSize(t Type) (int, bool) {
	switch t {
	case MSpNA1, MDpNA1:
		return 1, true
	case MStNA1, MMeND1:
		return 2, true
	// A normalised or scaled measurement is its two value octets *and* a
	// quality descriptor. The type without one exists separately -- that
	// is what the D in M_ME_ND_1 is for -- so a size that left the
	// quality out of NA and NB would make the two indistinguishable, and
	// would read every address after the first from one octet short.
	case MMeNA1, MMeNB1:
		return 3, true
	case MSpTA1, MDpTA1:
		return 4, true
	case MStTA1, MMeNC1, MBoNA1:
		return 5, true
	case MMeTA1, MMeTB1:
		// The same, plus a three-octet CP24Time2a.
		return 6, true
	case MItNA1:
		return 5, true
	case MBoTA1, MMeTC1, MItTA1:
		return 8, true
	case MSpTB1, MDpTB1:
		return 8, true
	case MStTB1:
		return 9, true
	case MMeTD1, MMeTE1:
		return 10, true
	case MMeTF1, MBoTB1, MItTB1:
		return 12, true
	// The commands. A single, double or regulating step command is one
	// qualifier octet; a setpoint is its value and a qualifier; the
	// timed forms add a seven-octet CP56Time2a.
	case CScNA1, CDcNA1, CRcNA1:
		return 1, true
	case CSeNA1, CSeNB1:
		return 3, true
	case CSeNC1:
		return 5, true
	case CBoNA1:
		return 4, true
	case CScTA1, CDcTA1, CRcTA1:
		return 8, true
	case CSeTA1, CSeTB1:
		return 10, true
	case CSeTC1:
		return 12, true
	case CBoTA1:
		return 11, true
	// The system commands carry one qualifier octet, except the two that
	// carry a time and the test command's fixed pattern.
	case CIcNA1, CCiNA1:
		return 1, true
	case CCdNA1:
		// A delay acquisition command carries a CP16Time2a, which is two
		// octets and not the one a qualifier would be.
		return 2, true
	case CRdNA1:
		return 0, true
	case CRpNA1:
		return 1, true
	case CTsNA1:
		return 2, true
	case CCsNA1:
		return 7, true
	case CTsTA1:
		// The test sequence counter and a CP56Time2a.
		return 9, true
	}
	return 0, false
}

// upper folds an ASCII name to upper case without a strings import in the
// hot path of a config load, and without touching anything but a to z.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// SetpointKind is how a setpoint command encodes the value it carries, which is
// the same vocabulary the monitoring direction uses for the same three
// encodings: an alias rather than a second set of names, because a bound written
// against a scaled setpoint and a bound written against a scaled measurement are
// the same arithmetic. See ValueKind in element.go.
type SetpointKind = ValueKind

// NotASetpoint is every type that carries no setpoint value: the single, double
// and regulating step commands, the bitstring command, and everything in the
// monitoring direction.
const NotASetpoint = NoValue

// SetpointEncoding says how a type carries its value, and where in the
// information element that value starts. The offset is always zero -- the value
// comes first and the qualifier after it, which is the layout that made the
// select bit easy to read from the wrong octet -- but it is returned rather
// than assumed so that a type with a different shape cannot be added silently.
func SetpointEncoding(t Type) (kind SetpointKind, at int) {
	switch t {
	case CSeNA1, CSeTA1:
		return Normalised, 0
	case CSeNB1, CSeTB1:
		return Scaled, 0
	case CSeNC1, CSeTC1:
		return ShortFloat, 0
	}
	return NotASetpoint, 0
}
