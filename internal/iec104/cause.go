package iec104

import "fmt"

// Cause is a cause of transmission: *why* this ASDU was sent.
//
// It is the field that makes an IEC 104 policy possible at all, because
// the same type identification means different things under different
// causes. A C_SC_NA_1 with cause `act` is a control centre telling a
// breaker to open. The same type with cause `actcon` is the station
// confirming it. The same type with cause `deact` is the centre
// withdrawing a selection. A relay that looked only at the type would
// refuse the station's own confirmations, and one that looked only at the
// direction would miss that an activation arriving *from* a station is a
// station trying to command its own control centre.
type Cause byte

// The causes of transmission the standard defines.
const (
	CausePeriodic     Cause = 1
	CauseBackground   Cause = 2
	CauseSpontaneous  Cause = 3
	CauseInitialised  Cause = 4
	CauseRequest      Cause = 5
	CauseActivation   Cause = 6
	CauseActCon       Cause = 7
	CauseDeactivation Cause = 8
	CauseDeactCon     Cause = 9
	CauseActTerm      Cause = 10
	CauseRetRem       Cause = 11
	CauseRetLoc       Cause = 12
	CauseFile         Cause = 13
	CauseIntroGeneral Cause = 20
	// CauseReqCounter is "requested by general counter interrogation": the
	// answer to a counter interrogation, which the standard keeps separate
	// from the general one because totals are read differently from
	// measurements.
	CauseReqCounter     Cause = 37
	CauseUnknownType    Cause = 44
	CauseUnknownCause   Cause = 45
	CauseUnknownCommon  Cause = 46
	CauseUnknownAddress Cause = 47
)

var causeNames = map[string]Cause{
	"per/cyc": CausePeriodic, "periodic": CausePeriodic,
	"back": CauseBackground, "background": CauseBackground,
	"spont": CauseSpontaneous, "spontaneous": CauseSpontaneous,
	"init": CauseInitialised, "initialised": CauseInitialised,
	"req": CauseRequest, "request": CauseRequest,
	"act": CauseActivation, "activation": CauseActivation,
	"actcon": CauseActCon, "deact": CauseDeactivation, "deactcon": CauseDeactCon,
	"actterm": CauseActTerm, "retrem": CauseRetRem, "retloc": CauseRetLoc,
	"file":         CauseFile,
	"introgen":     CauseIntroGeneral,
	"unknown_type": CauseUnknownType, "unknown_cause": CauseUnknownCause,
	"unknown_common": CauseUnknownCommon, "unknown_address": CauseUnknownAddress,
	"reqcogen": CauseReqCounter, "req_counter": CauseReqCounter,
}

var causeByValue = func() map[Cause]string {
	// The canonical name per value, chosen as the short form the standard
	// prints, so that a log line reads like the substation documentation.
	out := map[Cause]string{
		CausePeriodic: "per/cyc", CauseBackground: "back", CauseSpontaneous: "spont",
		CauseInitialised: "init", CauseRequest: "req", CauseActivation: "act",
		CauseActCon: "actcon", CauseDeactivation: "deact", CauseDeactCon: "deactcon",
		CauseActTerm: "actterm", CauseRetRem: "retrem", CauseRetLoc: "retloc",
		CauseFile: "file", CauseIntroGeneral: "introgen",
		CauseUnknownType: "unknown_type", CauseUnknownCause: "unknown_cause",
		CauseUnknownCommon: "unknown_common", CauseUnknownAddress: "unknown_address",
		CauseReqCounter: "reqcogen",
	}
	// Interrogation causes 21 to 36 are "interrogated by group n", and a
	// policy may well name one.
	for g := 1; g <= 16; g++ {
		out[Cause(20+g)] = fmt.Sprintf("introgroup%d", g)
	}
	return out
}()

func init() {
	for g := 1; g <= 16; g++ {
		causeNames[fmt.Sprintf("introgroup%d", g)] = Cause(20 + g)
	}
}

// CauseOf reads a cause of transmission as the configuration spells it.
func CauseOf(s string) (Cause, bool) {
	c, ok := causeNames[lower(s)]
	return c, ok
}

// String names a cause of transmission, or reports its number.
func (c Cause) String() string {
	if n, ok := causeByValue[c]; ok {
		return n
	}
	return fmt.Sprintf("COT_%d", byte(c))
}

// Known says whether the standard defines this cause.
func (c Cause) Known() bool { _, ok := causeByValue[c]; return ok }

// Commanding says whether this cause is one that asks a station to *do*
// something rather than to report: activation and deactivation, and no
// others. A confirmation or a termination carries the same type
// identification and is the station answering.
func (c Cause) Commanding() bool {
	return c == CauseActivation || c == CauseDeactivation
}

// lower folds an ASCII name to lower case.
func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
