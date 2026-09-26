package s7

import "fmt"

// The user-data protocol, which is a second protocol inside the first.
//
// Everything a PLC does that is not reading or writing memory arrives here:
// reading the diagnostic buffer, listing the blocks, reading and *setting*
// the clock, the password functions, and the programmer commands that set
// breakpoints and force variables. None of it is a function code; each is a
// function group and a subfunction, and a relay that only read function
// codes would see one operation called "userdata" where there are thirty.
//
// The group is the half that matters most, and two of them are the reason
// this package reads the layer at all. **Security** (group 5) is where a
// password is supplied and where the protection level is read: a client
// working through it is either unlocking a CPU or finding out how locked it
// is. **Programmer commands** (group 1) are the debugger: forcing a
// variable, setting a breakpoint, stepping the program. Neither is
// something an application does, and both are indistinguishable from a read
// to a relay that stopped at the function code.

// The function groups. The high nibble of the type-and-group octet is the
// type -- 4 for a request, 8 for a response -- and the low nibble is the
// group.
const (
	GroupMode       uint8 = 0x0
	GroupProgrammer uint8 = 0x1
	GroupCyclic     uint8 = 0x2
	GroupBlock      uint8 = 0x3
	GroupCPU        uint8 = 0x4
	GroupSecurity   uint8 = 0x5
	GroupPBC        uint8 = 0x6
	GroupTime       uint8 = 0x7
	GroupNC         uint8 = 0xF
)

var groupNames = map[uint8]string{
	GroupMode:       "mode_transition",
	GroupProgrammer: "programmer",
	GroupCyclic:     "cyclic",
	GroupBlock:      "block",
	GroupCPU:        "cpu",
	GroupSecurity:   "security",
	GroupPBC:        "pbc",
	GroupTime:       "time",
	GroupNC:         "nc",
}

// The request and response types of the type-and-group octet.
const (
	UserRequest  uint8 = 0x4
	UserResponse uint8 = 0x8
)

// UserData is a user-data PDU's parameter, read.
type UserData struct {
	// Method is 0x11 for a request and 0x12 for a response, which is the
	// protocol saying the same thing twice; both are kept because equipment
	// exists whose two fields disagree.
	Method uint8
	Type   uint8
	Group  uint8
	Sub    uint8
	// Sequence is the sequence number an answer echoes.
	Sequence uint8
	// LastUnit and ErrCode are a response's own fields: whether more data
	// follows, and the error the PLC reports.
	LastUnit bool
	ErrCode  uint16
	HasError bool
}

// UserData reads the user-data parameter.
//
// The parameter begins with the three octets 0x00 0x01 0x12, which is the
// protocol's own marker for this layer. A PDU whose parameter does not
// begin with them is not user data this package reads, and it says so:
// everything after the marker is at an offset that depends on it.
func (p *PDU) UserData() (*UserData, bool) {
	if p.Type != Userdata || len(p.Param) < 8 {
		return nil, false
	}
	if p.Param[0] != 0x00 || p.Param[1] != 0x01 || p.Param[2] != 0x12 {
		return nil, false
	}
	plen := int(p.Param[3])
	if plen < 4 || 4+plen > len(p.Param) {
		return nil, false
	}
	u := &UserData{
		Method:   p.Param[4],
		Type:     p.Param[5] >> 4,
		Group:    p.Param[5] & 0x0f,
		Sub:      p.Param[6],
		Sequence: p.Param[7],
	}
	if plen >= 8 {
		// A response carries a data-unit reference, a last-data-unit flag
		// and a two-octet error code.
		u.LastUnit = p.Param[9] != 0
		u.ErrCode = uint16(p.Param[10])<<8 | uint16(p.Param[11])
		u.HasError = true
	}
	return u, true
}

// GroupName names a function group.
func GroupName(g uint8) string {
	if n, ok := groupNames[g]; ok {
		return n
	}
	return fmt.Sprintf("%#x", g)
}

// The subfunctions worth naming, by group. The list is not exhaustive --
// this protocol has no specification to be exhaustive against -- and that is
// why `SubName` gives the number for anything else rather than a guess.
var subNames = map[uint16]string{
	key16(GroupMode, 0x01):       "stop",
	key16(GroupMode, 0x02):       "warm_restart",
	key16(GroupMode, 0x03):       "cold_restart",
	key16(GroupProgrammer, 0x01): "request_diag_data_1",
	key16(GroupProgrammer, 0x02): "variable_table",
	key16(GroupProgrammer, 0x03): "read_variable",
	key16(GroupProgrammer, 0x04): "write_variable",
	key16(GroupProgrammer, 0x05): "erase",
	key16(GroupProgrammer, 0x06): "read_diag_data",
	key16(GroupProgrammer, 0x07): "remove_diag_data",
	key16(GroupProgrammer, 0x08): "force",
	key16(GroupProgrammer, 0x0b): "request_diag_data_2",
	key16(GroupProgrammer, 0x0c): "breakpoint",
	key16(GroupProgrammer, 0x0d): "exit_hold",
	key16(GroupProgrammer, 0x0e): "memory_reset",
	key16(GroupProgrammer, 0x0f): "disable_job",
	key16(GroupProgrammer, 0x10): "enable_job",
	key16(GroupProgrammer, 0x11): "delete_job",
	key16(GroupProgrammer, 0x13): "read_job_list",
	key16(GroupCyclic, 0x01):     "subscribe",
	key16(GroupCyclic, 0x04):     "unsubscribe",
	key16(GroupCyclic, 0x05):     "change_driven",
	key16(GroupBlock, 0x01):      "list_blocks",
	key16(GroupBlock, 0x02):      "list_blocks_of_type",
	key16(GroupBlock, 0x03):      "block_info",
	key16(GroupCPU, 0x01):        "read_szl",
	key16(GroupCPU, 0x02):        "message_service",
	key16(GroupCPU, 0x03):        "diagnostic_message",
	key16(GroupCPU, 0x05):        "alarm_s_indication",
	key16(GroupCPU, 0x0b):        "alarm_ack",
	key16(GroupCPU, 0x13):        "alarm_query",
	key16(GroupSecurity, 0x01):   "set_password",
	key16(GroupSecurity, 0x02):   "clear_password",
	key16(GroupTime, 0x01):       "read_clock",
	key16(GroupTime, 0x02):       "set_clock",
	key16(GroupTime, 0x03):       "read_clock_following",
	key16(GroupTime, 0x04):       "set_clock_2",
}

func key16(group, sub uint8) uint16 { return uint16(group)<<8 | uint16(sub) }

// SubName names a subfunction within its group.
func SubName(group, sub uint8) string {
	if n, ok := subNames[key16(group, sub)]; ok {
		return n
	}
	return fmt.Sprintf("%#x", sub)
}

// Name is the whole operation as one string, `time.set_clock`, which is
// what a log line carries and what a rule names.
func (u *UserData) Name() string {
	return GroupName(u.Group) + "." + SubName(u.Group, u.Sub)
}

// Request says whether this is a request rather than an answer.
func (u *UserData) Request() bool { return u.Type == UserRequest }

// GroupNames is every group name, for the configuration's validation.
func GroupNames() []string {
	out := make([]string, 0, len(groupNames))
	for _, n := range groupNames {
		out = append(out, n)
	}
	return out
}

// GroupOf reads a group name as the configuration spells it.
func GroupOf(s string) (uint8, bool) {
	for code, name := range groupNames {
		if name == s {
			return code, true
		}
	}
	return 0, false
}
