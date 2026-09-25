package s7

// What an operation *is*, in the words a policy is written in.
//
// This protocol spreads its operations across two layers: a function code
// for the ones that read and write memory and set the connection up, and a
// user-data group and subfunction for everything else -- the diagnostic
// buffer, the block list, the clock, the password, the debugger. A policy
// written against function codes alone would have one name for thirty
// operations, and a policy written against groups and subfunctions would
// have thirty names for the two an application uses.
//
// So both are mapped onto one vocabulary, and the vocabulary is what an
// operator thinks in: this client may **read**, and it may not **write**,
// **download** a program, **stop** the CPU or use the **programmer**
// functions. Fourteen names cover the protocol, each of them something
// somebody would say out loud.
type Op string

// The operations.
const (
	// OpRead is reading memory: a data block, the process image, a timer.
	OpRead Op = "read"
	// OpWrite is writing it, which on a plant is the operation that moves
	// something physical.
	OpWrite Op = "write"
	// OpSetup is the connection negotiation, without which there is no
	// session at all.
	OpSetup Op = "setup"
	// OpUpload is reading a block *out* of the PLC: the program, as source
	// an engineering tool can open. It is a read, and it is how a plant's
	// control logic leaves the plant.
	OpUpload Op = "upload"
	// OpDownload is writing one in, which is changing the program the
	// machine runs.
	OpDownload Op = "download"
	// OpControl is the control service: a warm restart, inserting or
	// deleting a block, compressing the memory.
	OpControl Op = "control"
	// OpStop stops the CPU. On an unprotected S7-300 it is one PDU from
	// anybody who can open a socket.
	OpStop Op = "stop"
	// OpCPUServices is function code 0, which the families in the field
	// answer in ways nobody has documented.
	OpCPUServices Op = "cpu_services"
	// OpSZL is reading a system status list: the CPU's type, its firmware,
	// its diagnostic buffer. It is the read an inventory is built from.
	OpSZL Op = "szl"
	// OpDiagnostics is the rest of the CPU function group: the message
	// service and the alarm machinery.
	OpDiagnostics Op = "diagnostics"
	// OpBlocks is listing the blocks and reading their headers.
	OpBlocks Op = "blocks"
	// OpCyclic is subscribing to cyclic data, which is how an HMI reads a
	// screenful of values without asking for each one.
	OpCyclic Op = "cyclic"
	// OpTimeRead reads the CPU clock.
	OpTimeRead Op = "time_read"
	// OpTimeWrite sets it. On a plant the clock is what every log line and
	// every batch record is stamped with.
	OpTimeWrite Op = "time_write"
	// OpSecurity is the password functions: supplying one, clearing one,
	// and finding out how protected the CPU is.
	OpSecurity Op = "security"
	// OpProgrammer is the debugger: forcing a variable, setting a
	// breakpoint, stepping the program. Nothing an application does.
	OpProgrammer Op = "programmer"
	// OpMode is the mode transitions: stop, warm restart, cold restart,
	// requested through the user-data layer rather than the control
	// service.
	OpMode Op = "mode"
	// OpPBC is the programmable block communication a pair of PLCs uses
	// between themselves.
	OpPBC Op = "pbc"
	// OpNC is the numerical control layer of a machine tool.
	OpNC Op = "nc"
)

// ops is every operation, in the order the documentation lists them.
var ops = []Op{OpRead, OpWrite, OpSetup, OpUpload, OpDownload, OpControl, OpStop,
	OpCPUServices, OpSZL, OpDiagnostics, OpBlocks, OpCyclic, OpTimeRead, OpTimeWrite,
	OpSecurity, OpProgrammer, OpMode, OpPBC, OpNC}

// Ops is every operation name, for the configuration's validation and for
// the documentation to be checked against.
func Ops() []string {
	out := make([]string, 0, len(ops))
	for _, o := range ops {
		out = append(out, string(o))
	}
	return out
}

// OpOf reads an operation name as the configuration spells it.
func OpOf(s string) (Op, bool) {
	for _, o := range ops {
		if string(o) == s {
			return o, true
		}
	}
	return "", false
}

// Op says what a PDU asks for.
//
// The second return is the one that matters: a PDU whose operation this
// package cannot name is not an operation it should guess about. A function
// code nobody has documented, or a user-data group outside the nine, is
// reported as unknown -- and a listener refuses that, because forwarding an
// operation with no name is forwarding one with no policy.
func (p *PDU) Op() (Op, bool) {
	if p.Type == Userdata {
		u, ok := p.UserData()
		if !ok {
			return "", false
		}
		return opOfUserData(u)
	}
	if !p.HasFunction {
		return "", false
	}
	switch p.Function {
	case FnReadVar:
		return OpRead, true
	case FnWriteVar:
		return OpWrite, true
	case FnSetupComm:
		return OpSetup, true
	case FnStartUpload, FnUpload, FnEndUpload:
		return OpUpload, true
	case FnRequestDownload, FnDownloadBlock, FnDownloadEnded:
		return OpDownload, true
	case FnPLCControl:
		return OpControl, true
	case FnPLCStop:
		return OpStop, true
	case FnCPUServices:
		return OpCPUServices, true
	}
	return "", false
}

// opOfUserData maps a group and subfunction onto the vocabulary.
func opOfUserData(u *UserData) (Op, bool) {
	switch u.Group {
	case GroupMode:
		return OpMode, true
	case GroupProgrammer:
		return OpProgrammer, true
	case GroupCyclic:
		return OpCyclic, true
	case GroupBlock:
		return OpBlocks, true
	case GroupCPU:
		if u.Sub == 0x01 {
			return OpSZL, true
		}
		return OpDiagnostics, true
	case GroupSecurity:
		return OpSecurity, true
	case GroupTime:
		switch u.Sub {
		case 0x02, 0x04:
			return OpTimeWrite, true
		case 0x01, 0x03:
			return OpTimeRead, true
		}
		// A time subfunction this package does not know. It is in the
		// group that can set a clock, so it is not reported as a read.
		return "", false
	case GroupPBC:
		return OpPBC, true
	case GroupNC:
		return OpNC, true
	}
	return "", false
}

// Writes says whether an operation changes the PLC.
//
// The list is wider than "writes memory" on purpose. Downloading a block
// changes the program, a control service deletes one, a mode transition
// stops the machine, setting the clock changes what every record after it is
// stamped with, and the password functions change what the CPU will allow.
// An operator who writes "this client does not change the plant" means all
// of them.
func Writes(o Op) bool {
	switch o {
	case OpWrite, OpDownload, OpControl, OpStop, OpMode, OpTimeWrite,
		OpSecurity, OpProgrammer:
		return true
	}
	return false
}

// Dangerous says whether a refusal must stand even in monitor mode.
//
// It is the writing set, and the reason is the same one the modbus kind
// gives: a write forwarded so that it could be written down is a write. On
// this protocol the consequences are a stopped CPU, a changed program and a
// forced variable, none of which a report afterwards undoes.
func Dangerous(o Op) bool { return Writes(o) }

// DefaultOps is what a listener allows when the configuration names none:
// what an HMI, a historian and an inventory do, and nothing that changes
// anything.
//
// The absences are the policy. No write, no download, no upload -- a block
// upload is how a plant's control logic leaves the plant -- no control
// service, no stop, no mode transition, no clock setting, no password
// function and no programmer command. An engineering station needs several
// of those, and saying so in the file is a line a reviewer can see.
func DefaultOps() []Op {
	return []Op{OpSetup, OpRead, OpSZL, OpBlocks, OpCyclic, OpTimeRead, OpDiagnostics}
}
