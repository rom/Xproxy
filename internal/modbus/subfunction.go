package modbus

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// A function code is not always the whole question.
//
// Three of them carry a second code that says what the frame actually
// does, and it is the second code a plant cares about. Function 8 is
// "diagnostic", which covers reading a bus message counter and forcing a
// device into listen-only mode: the first is a poll and the second is an
// outage, because a device in listen-only mode answers nobody until
// something restarts it. Function 43 is "encapsulated interface", which
// is either a device identification request or a CANopen tunnel carrying
// a second protocol. And function 90 is Schneider's UMAS, which is a
// protocol of its own: read a variable, stop the PLC, download a program
// block.
//
// A policy that can only say yes or no to "diagnostic" cannot say the one
// thing an engineer wants to say -- the counters, yes; listen-only mode,
// never -- so the sub-function is named here and classified by what it
// does to the device.

// FCUMAS is Schneider Electric's UMAS, the protocol every Unity and
// EcoStruxure engineering station speaks to a Modicon PLC. The
// specification does not have this function code: 90 is outside both
// user-defined ranges, so a relay that went by the specification alone
// would call it unknown and a relay that guessed would call it "vendor".
// It is neither. It is the code that carries a PLC stop and a program
// download, and what is known about it is published research rather than
// a standard -- which is why the table below says what it does not know,
// and why a read-only listener refuses every one of these frames.
const FCUMAS byte = 0x5A

// SubEffect is what a sub-function does. It is deliberately about the
// device rather than about the wire: "control" is the word a plant uses
// for stopping a PLC, and it is the same word whether the frame that did
// it was a diagnostic or a UMAS command. That is what makes a rule
// written about an effect outlive the code that carried it.
type SubEffect string

const (
	// SubRead reads a counter, a variable, an identity or a program, and
	// changes nothing.
	SubRead SubEffect = "read"
	// SubWrite changes process data: a variable, a register, a coil.
	SubWrite SubEffect = "write"
	// SubControl changes the device's own state rather than the process:
	// stop it, start it, restart its communications, force it into
	// listen-only mode.
	SubControl SubEffect = "control"
	// SubProgram carries a control program, in either direction. A block
	// written into a PLC is the change an attack that means to stay
	// makes; a block read out of one changes nothing and is the step
	// before a change tailored to what the plant actually runs. Both are
	// this effect, because a policy that permitted the read-out would be
	// permitting the reconnaissance for the write.
	SubProgram SubEffect = "program"
	// SubClear clears counters, a diagnostic register or the event log.
	// It touches neither the process nor the program, and it is how the
	// record of something that did goes away.
	SubClear SubEffect = "clear"
	// SubSession is the housekeeping a sub-protocol needs before it can
	// do anything: initialise, keep alive, take or release the
	// reservation UMAS uses to pair an engineering station with a PLC.
	// The reservation is a pairing step and not a safety boundary -- a
	// PLC hands it to whoever asks first -- so it is classified as what
	// it is.
	SubSession SubEffect = "session"
	// SubUnknown is a sub-function of a code that has them which this
	// package does not recognise, and the CANopen tunnel, which carries
	// whatever CANopen carries. It has a name because it is a thing a
	// rule can be written about: "the tunnel, from the one station that
	// needs it" is a policy, and silently passing every frame nobody
	// here can read is not.
	SubUnknown SubEffect = "unknown"
)

// SubEffects lists the effects, for the configuration reference, the
// validator and the policy, in the order the documentation uses them.
func SubEffects() []SubEffect {
	return []SubEffect{SubRead, SubWrite, SubControl, SubProgram, SubClear, SubSession, SubUnknown}
}

// ParseSubEffect reads an effect written as one of the names above.
func ParseSubEffect(s string) (SubEffect, bool) {
	for _, e := range SubEffects() {
		if string(e) == s {
			return e, true
		}
	}
	return "", false
}

// Unsafe says this effect stops a device, changes what it runs, clears
// the record of either, or is one nothing here can read.
//
// It is what a listener refuses by default to an allow rule that did not
// name the sub-function, because a rule written about "diagnostic" was
// written by somebody thinking of counters. The four are together for one
// reason: none of them is what an operator has in mind when they permit a
// function code, and each of them is what an intruder has in mind when
// they send one.
func (e SubEffect) Unsafe() bool {
	switch e {
	case SubControl, SubProgram, SubClear, SubUnknown:
		return true
	}
	return false
}

// SubFunction is what this package knows about one sub-function.
type SubFunction struct {
	Name   string
	Effect SubEffect
}

// diagnosticSubs are the sub-functions of function code 8 (MODBUS
// Application Protocol v1.1b3 section 6.8.1).
//
// Sub-function 4 is the one this whole file exists for: Force Listen Only
// Mode is a four-byte frame that takes a device off the bus until
// somebody restarts it, and it arrives under the same function code as
// the counter polls a maintenance tool makes all day.
var diagnosticSubs = map[uint16]SubFunction{
	0:  {"return_query_data", SubRead},
	1:  {"restart_communications", SubControl},
	2:  {"return_diagnostic_register", SubRead},
	3:  {"change_ascii_delimiter", SubControl},
	4:  {"force_listen_only", SubControl},
	10: {"clear_counters", SubClear},
	11: {"return_bus_message_count", SubRead},
	12: {"return_bus_comm_error_count", SubRead},
	13: {"return_bus_exception_error_count", SubRead},
	14: {"return_server_message_count", SubRead},
	15: {"return_server_no_response_count", SubRead},
	16: {"return_server_nak_count", SubRead},
	17: {"return_server_busy_count", SubRead},
	18: {"return_bus_character_overrun_count", SubRead},
	20: {"clear_overrun_counter", SubClear},
	// Get/Clear Modbus Plus Statistics is a get or a clear depending on
	// an operation field inside it, so it is classified as the one of
	// the two a policy has to decide about.
	21: {"get_clear_plus_statistics", SubClear},
}

// encapsulatedSubs are the MEI types of function code 43 (section 6.21).
// The specification defines two, and they are not the same kind of thing:
// one asks the device what it is, and the other is a tunnel.
var encapsulatedSubs = map[uint16]SubFunction{
	13: {"canopen", SubUnknown},
	14: {"read_device_identification", SubRead},
}

// umasSubs are the UMAS commands of function code 90.
//
// UMAS is not published by Schneider. This table is what the public
// research on the protocol says the commands are, and it is recorded here
// with that provenance because the difference matters to how it is used:
// a command absent from it is "unknown", not "harmless", and the listener
// treats it accordingly.
//
// Two groups earn the classification they have. 0x40 and 0x41 start and
// stop the PLC -- one frame, no authentication, and the plant is down.
// 0x30 to 0x35 are the strategy transfers: the blocks that are the
// control program, going into the PLC or coming out of it.
var umasSubs = map[uint16]SubFunction{
	0x01: {"init_comm", SubSession},
	0x02: {"read_id", SubRead},
	0x03: {"read_project_info", SubRead},
	0x04: {"read_plc_info", SubRead},
	0x06: {"read_card_info", SubRead},
	0x0A: {"repeat", SubRead},
	0x10: {"take_plc_reservation", SubSession},
	0x11: {"release_plc_reservation", SubSession},
	0x12: {"keep_alive", SubSession},
	0x20: {"read_memory_block", SubRead},
	0x22: {"read_variables", SubRead},
	0x23: {"write_variables", SubWrite},
	0x24: {"read_coils_registers", SubRead},
	0x25: {"write_coils_registers", SubWrite},
	0x30: {"initialize_upload", SubProgram},
	0x31: {"upload_block", SubProgram},
	0x32: {"end_upload", SubProgram},
	0x33: {"initialize_download", SubProgram},
	0x34: {"download_block", SubProgram},
	0x35: {"end_download", SubProgram},
	0x39: {"read_eth_master_data", SubRead},
	0x40: {"start_plc", SubControl},
	0x41: {"stop_plc", SubControl},
	0x50: {"monitor_plc", SubRead},
	0x58: {"check_plc", SubRead},
	0x70: {"read_io_object", SubRead},
	0x71: {"write_io_object", SubProgram},
	0x73: {"get_status_module", SubRead},
}

// subFunctions is the sub-function table of each function code that has
// one. A function code absent from it has no sub-function, which is a
// different thing from having one nobody here recognises: the first is
// nothing to write a rule about and the second is.
var subFunctions = map[byte]map[uint16]SubFunction{
	FCDiagnostic:            diagnosticSubs,
	FCEncapsulatedInterface: encapsulatedSubs,
	FCUMAS:                  umasSubs,
}

// SubMax is the largest sub-function number a function code can carry,
// or -1 for a code that has none. Function 8's sub-function is a 16-bit
// word; the MEI type and the UMAS command are a single byte.
func SubMax(fc byte) int {
	switch fc {
	case FCDiagnostic:
		return 0xFFFF
	case FCEncapsulatedInterface, FCUMAS:
		return 0xFF
	}
	return -1
}

// SubName is the name of a sub-function, for logs, traces and policy.
//
// One this package does not know is named by its number inside the
// namespace of the function code that carried it, because sub-function 4
// of a diagnostic and UMAS command 4 are not the same thing and a log
// that called them both "sub_4" would be inviting exactly that mistake.
func SubName(fc byte, sub uint16) string {
	if t, ok := subFunctions[fc][sub]; ok {
		return t.Name
	}
	return fmt.Sprintf("%s%d", subPrefix(fc), sub)
}

// subPrefix is the namespace a sub-function number is written in when this
// package has no name for it.
func subPrefix(fc byte) string {
	switch fc {
	case FCUMAS:
		return "umas_"
	case FCEncapsulatedInterface:
		return "mei_"
	}
	return "sub_"
}

// SubCode reads a sub-function of fc written as one of the names above or
// as a number, which is how a policy names one. A number outside what the
// code can carry is refused here rather than compiled into a rule that
// can never match.
func SubCode(fc byte, s string) (uint16, bool) {
	s = strings.TrimSpace(s)
	max := SubMax(fc)
	if max < 0 {
		return 0, false
	}
	for sub, t := range subFunctions[fc] {
		if t.Name == s {
			return sub, true
		}
	}
	// The generated names round-trip. A trace that says sub_37 is what an
	// operator writes the rule from, and the learning report puts one of
	// these names into a rule itself -- so a name this package produced
	// has to be a name it reads back, in the namespace of the function
	// code that produced it and not another one.
	n, err := strconv.ParseUint(strings.TrimPrefix(s, subPrefix(fc)), 0, 16)
	if err != nil || n > uint64(max) {
		return 0, false
	}
	return uint16(n), true //nolint:gosec // parsed at 16 bits and bounded by max above
}

// SubNames lists the names of a function code's known sub-functions, in
// numerical order, for the configuration reference and the error a
// validator gives.
func SubNames(fc byte) []string {
	subs := subFunctions[fc]
	nums := make([]int, 0, len(subs))
	for n := range subs {
		nums = append(nums, int(n))
	}
	sort.Ints(nums)
	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, subs[uint16(n)].Name) //nolint:gosec // a key of the map it came from
	}
	return out
}

// SubEffectOf is what a sub-function does, and whether the function code
// has sub-functions at all.
//
// A sub-function of a code that has them which this package does not
// recognise is SubUnknown with ok true: "a diagnostic nobody here can
// read" is something a rule can be written about, and "this function code
// has no sub-function" is not.
func SubEffectOf(fc byte, sub uint16) (SubEffect, bool) {
	subs, ok := subFunctions[fc]
	if !ok {
		return "", false
	}
	if t, ok := subs[sub]; ok {
		return t.Effect, true
	}
	return SubUnknown, true
}

// SubName is this request's sub-function by name, or "" for a function
// code that carries none.
func (p *PDU) SubName() string {
	if !p.HasSubFunction {
		return ""
	}
	return SubName(p.Function, p.SubFunction)
}

// SubEffect is what this request's sub-function does, and whether it has
// one at all.
func (p *PDU) SubEffect() (SubEffect, bool) {
	if !p.HasSubFunction {
		return "", false
	}
	return SubEffectOf(p.Function, p.SubFunction)
}
