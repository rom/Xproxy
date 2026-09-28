package mms

import (
	"fmt"
	"strings"
)

// IEC 61850 object names, which is where this protocol's security semantics live.
//
// MMS itself has no opinion about what a variable is: an ObjectName is a domain
// identifier and an item identifier, both opaque strings. IEC 61850-8-1 maps a
// substation's data model onto them, and the mapping is what makes a policy possible:
//
//	domain: AA1J1Q01A1LD0          the logical device
//	item:   XCBR1$CO$Pos$Oper      logical node, functional constraint, object,
//	                               attribute
//
// The **functional constraint** — the second segment — is the whole of it. The same
// service, a Write, means entirely different things depending on it:
//
//	ST, MX   status and measurands. Read every second by a control centre.
//	CO       control. `XCBR1$CO$Pos$Oper` operates a circuit breaker.
//	SP       a setpoint.
//	CF       configuration, which includes `ctlModel` -- the attribute that says
//	         whether a control needs select-before-operate at all.
//	SG, SE   setting groups: a protection relay's trip characteristics. Changing
//	         these is the most consequential write in a substation and the least
//	         likely to be noticed, because nothing moves until the fault that was
//	         meant to be cleared.
//	BR, RP   buffered and unbuffered report control blocks. Disabling one does not
//	         change the plant; it stops the control centre hearing about it.
//	GO, GS   GOOSE control blocks.
//	SV, MS   sampled-value control blocks.
//	LG       logs.
//	DC, EX   descriptions and extended definitions.
//
// And within `CO`, the attribute distinguishes a **select** from an **operate**:
// `SBO` and `SBOw` select, `Oper` operates, `Cancel` cancels a selection. A relay
// that allowed `SBOw` and refused `Oper` has let a client reserve a breaker without
// being able to move it, which is a real and useful distinction.

// FC is a functional constraint.
type FC string

// The functional constraints IEC 61850-7-2 defines.
const (
	FCStatus       FC = "ST"
	FCMeasurand    FC = "MX"
	FCSetpoint     FC = "SP"
	FCSubstitution FC = "SV"
	FCConfig       FC = "CF"
	FCDescription  FC = "DC"
	FCExtended     FC = "EX"
	FCSettingGroup FC = "SG"
	FCSettingEdit  FC = "SE"
	FCService      FC = "SR"
	FCOperate      FC = "OR"
	FCBlock        FC = "BL"
	FCControl      FC = "CO"
	FCBuffered     FC = "BR"
	FCUnbuffered   FC = "RP"
	FCLog          FC = "LG"
	FCGoose        FC = "GO"
	FCGooseStatus  FC = "GS"
	FCSampled      FC = "MS"
	FCUnicastSV    FC = "US"
	FCMulticastSV  FC = "MS2"
)

// fcInfo says what a constraint governs.
type fcInfo struct {
	// what is a phrase for a log line and a refusal detail.
	what string
	// operates says a write here reaches the primary plant: a breaker, a
	// disconnector, a tap changer.
	operates bool
	// protects says a write here changes what the device will do in a fault,
	// which is the class nothing else in this protocol distinguishes.
	protects bool
	// observability says a write here changes what the control centre is told
	// rather than what the plant does.
	observability bool
}

var fcs = map[FC]fcInfo{
	FCStatus:       {"status", false, false, false},
	FCMeasurand:    {"measurand", false, false, false},
	FCSetpoint:     {"setpoint", true, false, false},
	FCSubstitution: {"substituted value", true, false, false},
	FCConfig:       {"configuration", false, true, false},
	FCDescription:  {"description", false, false, false},
	FCExtended:     {"extended definition", false, false, false},
	FCSettingGroup: {"setting group", false, true, false},
	FCSettingEdit:  {"setting group being edited", false, true, false},
	FCService:      {"service tracking", false, false, false},
	FCOperate:      {"operate received", false, false, false},
	FCBlock:        {"blocking", true, false, false},
	FCControl:      {"control", true, false, false},
	FCBuffered:     {"buffered report control", false, false, true},
	FCUnbuffered:   {"unbuffered report control", false, false, true},
	FCLog:          {"log control", false, false, true},
	FCGoose:        {"GOOSE control", false, false, true},
	FCGooseStatus:  {"GOOSE status", false, false, false},
	FCSampled:      {"sampled value control", false, false, true},
	FCUnicastSV:    {"unicast sampled value control", false, false, true},
}

// Known says the constraint is one IEC 61850-7-2 defines.
func (f FC) Known() bool { _, ok := fcs[f]; return ok }

// What is a phrase for a log line.
func (f FC) What() string {
	if i, ok := fcs[f]; ok {
		return i.what
	}
	return fmt.Sprintf("functional constraint %q", string(f))
}

// Operates says a write to this constraint reaches the primary plant.
func (f FC) Operates() bool { return fcs[f].operates }

// Protects says a write to it changes what the device will do in a fault: a setting
// group, or the configuration that decides whether a control needs selecting first.
func (f FC) Protects() bool { return fcs[f].protects }

// Observability says a write to it changes what the control centre is told rather
// than what the plant does.
func (f FC) Observability() bool { return fcs[f].observability }

// FCs is every constraint a configuration may name, for the validator.
func FCs() []string {
	out := make([]string, 0, len(fcs))
	for f := range fcs {
		out = append(out, string(f))
	}
	return out
}

// The control attributes, which decide whether a request selects or operates.
const (
	AttrSelect       = "SBO"
	AttrSelectWith   = "SBOw"
	AttrOperate      = "Oper"
	AttrCancel       = "Cancel"
	AttrControlModel = "ctlModel"
)

// NameKind is which arm of the ObjectName choice a name arrived as.
type NameKind uint8

const (
	// NameVMD is vmd-specific: a name in the device's own namespace, which IEC
	// 61850 uses for a handful of well-known variables.
	NameVMD NameKind = iota
	// NameDomain is domain-specific, which is every 61850 data object.
	NameDomain
	// NameAA is aa-specific: a name scoped to the association, which is how a
	// client's own named variable lists are addressed.
	NameAA
)

// String names the kind.
func (k NameKind) String() string {
	switch k {
	case NameVMD:
		return "vmd"
	case NameDomain:
		return "domain"
	case NameAA:
		return "association"
	}
	return "unknown"
}

// Name is one MMS object name, with the 61850 structure read out of it where it is
// there.
type Name struct {
	Kind NameKind
	// Domain is the logical device, for a domain-specific name.
	Domain string
	// Item is the item identifier as it arrived, dollar signs and all. It is what
	// a `objects` pattern is matched against, because that is the form an engineer
	// reads in an SCL file and in a log.
	Item string
	// LogicalNode, FC, DataObject and Attribute are the item's segments, where it
	// had them. An item that is not in the 61850 form leaves them empty and Parsed
	// false, which is a fact a policy may decide about rather than one to guess
	// past.
	LogicalNode string
	FC          FC
	DataObject  string
	Attribute   string
	Parsed      bool
}

// Key is the name in one string, which is what a rule matches and a log line
// carries: `AA1J1Q01A1LD0/XCBR1$CO$Pos$Oper`.
func (n Name) Key() string {
	switch n.Kind {
	case NameDomain:
		return n.Domain + "/" + n.Item
	case NameAA:
		return "@" + n.Item
	}
	return n.Item
}

// String is the key, for a log line.
func (n Name) String() string { return n.Key() }

// Operates says this name is a control attribute that moves the plant: an Oper or a
// select-with-value on a control constraint.
//
// A select is deliberately not an operate. A client that may select and not operate
// has reserved a breaker without being able to move it, which is a distinction worth
// having on a protocol where both arrive as the same MMS Write.
func (n Name) Operates() bool {
	return n.FC == FCControl && (n.Attribute == AttrOperate || n.Attribute == "")
}

// Selects says it is a select rather than an operate.
func (n Name) Selects() bool {
	return n.FC == FCControl && (n.Attribute == AttrSelect || n.Attribute == AttrSelectWith)
}

// ParseItem reads the 61850 structure out of an item identifier.
//
// The form is LN$FC$DO[$DA...], and a name with fewer than two segments is not in
// that form: an IED's own well-known variables are not, and neither is a client's
// named variable list. Those come back unparsed rather than forced into segments,
// because a policy that treated `LastApplError` as a logical node called
// `LastApplError` with no constraint would be deciding about something that is not
// there.
func ParseItem(item string) Name {
	n := Name{Item: item}
	parts := strings.Split(item, "$")
	if len(parts) < 2 {
		return n
	}
	fc := FC(parts[1])
	if !fc.Known() {
		// A second segment that is not a functional constraint. The name is in
		// some other form, and saying so is better than inventing a constraint.
		return n
	}
	n.Parsed = true
	n.LogicalNode, n.FC = parts[0], fc
	if len(parts) > 2 {
		n.DataObject = parts[2]
	}
	if len(parts) > 3 {
		// The attribute may itself be a path -- `Oper$ctlVal` -- and what decides
		// the operation is the first segment of it: an Oper is an operate whether
		// the request names the whole structure or one member of it.
		n.Attribute = parts[3]
	}
	return n
}
