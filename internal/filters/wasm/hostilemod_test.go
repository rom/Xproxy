package wasm

// A builder for guests that misbehave. testModule is the well-behaved
// guest; this one takes the body of xproxy_on_request from the test, so
// a case can call a host function with whatever arguments it likes —
// pointers outside the sandbox, lengths past the bounds, a header name
// with a newline in it, a flood of operations, or nothing at all before
// it traps.

// guestSpec describes one hostile guest.
type guestSpec struct {
	// strs are the strings placed in the data segment at offset 0
	// onwards; code addresses them through the o and l helpers.
	strs []string
	// locals declares the locals of xproxy_on_request, in the encoded
	// form (count, then each group).
	locals []byte
	// code builds the body of xproxy_on_request. o gives the offset of a
	// string and l its length, both as i32 constants.
	code func(o, l func(string) []byte) []byte
	// pages is the module's minimum memory size; 1 unless a case needs
	// room past the 64 KiB string bound.
	pages byte
	// allocPtr, when non-zero, makes xproxy_alloc ignore its argument
	// and return this pointer, which is how a guest lies about where the
	// host may write.
	allocPtr int64
	// allocTraps makes xproxy_alloc trap instead of returning.
	allocTraps bool
	// respCode, when set, is the body of xproxy_on_response, with
	// respLocals declaring its locals.
	respCode   func(o, l func(string) []byte) []byte
	respLocals []byte
}

// opUnreachable traps the guest; opMemGrow and opI32Store reach for
// memory the host may not have given it.
var (
	opUnreachable = []byte{0x00}
	opI32Store    = []byte{0x36, 0x02, 0x00} // align 2, offset 0
	opI32Eqz      = []byte{0x45}
	opSub         = []byte{0x6b}
	opLocalTee0   = []byte{0x22, 0x00}
)

// buildGuest encodes a module to the spec.
func buildGuest(s guestSpec) []byte {
	off := map[string]int64{}
	var data []byte
	for _, str := range s.strs {
		off[str] = int64(len(data))
		data = append(data, str...)
	}
	o := func(x string) []byte { return i32c(off[x]) }
	l := func(x string) []byte { return i32c(int64(len(x))) }
	pages := s.pages
	if pages == 0 {
		pages = 1
	}

	types := vec([][]byte{
		funcType(nil, []byte{i32}),                     // 0: () -> i32
		funcType([]byte{i32}, []byte{i32}),             // 1: (i32) -> i32
		funcType([]byte{i32, i32, i32}, []byte{i64}),   // 2: get
		funcType([]byte{i32, i32, i32, i32, i32}, nil), // 3: set_header, deny
		funcType([]byte{i32, i32, i32}, nil),           // 4: remove_header, log, set_body
		funcType([]byte{i32, i32, i32, i32}, nil),      // 5: log_attr
	})
	imp := func(name string, typ byte) []byte { return cat(str("xproxy"), str(name), []byte{0x00, typ}) }
	imports := vec([][]byte{imp("get", 2), imp("set_header", 3), imp("remove_header", 4), imp("deny", 3),
		imp("log", 4), imp("log_attr", 5), imp("set_body", 4)})
	funcs := [][]byte{{0}, {1}, {0}}
	if s.respCode != nil {
		funcs = append(funcs, []byte{1})
	}
	functions := vec(funcs)
	memory := vec([][]byte{{0x00, pages}})
	globals := vec([][]byte{cat([]byte{i32, 0x01}, i32c(4096), opEnd)})
	exps := [][]byte{
		cat(str("memory"), []byte{0x02, 0x00}),
		cat(str("xproxy_abi_version"), []byte{0x00}, uleb(7)),
		cat(str("xproxy_alloc"), []byte{0x00}, uleb(8)),
		cat(str("xproxy_on_request"), []byte{0x00}, uleb(9)),
	}
	if s.respCode != nil {
		exps = append(exps, cat(str("xproxy_on_response"), []byte{0x00}, uleb(10)))
	}
	exports := vec(exps)

	abiVersion := body(uleb(0), cat(i32c(1), opEnd))
	var alloc []byte
	switch {
	case s.allocTraps:
		alloc = body(uleb(0), cat(opUnreachable, opEnd))
	case s.allocPtr != 0:
		alloc = body(uleb(0), cat(i32c(s.allocPtr), opEnd))
	default:
		alloc = body(uleb(0), cat(opGGet0, opGGet0, opLocal0, opAdd, opGSet0, opEnd))
	}
	locals := s.locals
	if locals == nil {
		locals = uleb(0)
	}
	onRequest := body(locals, cat(s.code(o, l), opEnd))
	bodies := [][]byte{abiVersion, alloc, onRequest}
	if s.respCode != nil {
		rl := s.respLocals
		if rl == nil {
			rl = uleb(0)
		}
		bodies = append(bodies, body(rl, cat(s.respCode(o, l), opEnd)))
	}
	code := vec(bodies)
	dataSec := vec([][]byte{cat([]byte{0x00}, i32c(0), opEnd, uleb(uint64(len(data))), data)})

	mod := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	mod = append(mod, section(1, types)...)
	mod = append(mod, section(2, imports)...)
	mod = append(mod, section(3, functions)...)
	mod = append(mod, section(5, memory)...)
	mod = append(mod, section(6, globals)...)
	mod = append(mod, section(7, exports)...)
	mod = append(mod, section(10, code)...)
	mod = append(mod, section(11, dataSec)...)
	return mod
}

// countedLoop runs n iterations of code, counting down in local 0,
// which must be an i32 local the caller declared.
func countedLoop(n int64, code []byte) []byte {
	return cat(
		i32c(n), opLocalSet0,
		opBlock,
		opLoop,
		code,
		opLocalGet0, i32c(1), opSub, opLocalTee0,
		opI32Eqz, opBrIf1, // the counter reached zero: leave the block
		opBr0, // otherwise go round again
		opEnd, // end loop
		opEnd, // end block
	)
}

var (
	// Local 1 of xproxy_on_response: local 0 is the status parameter.
	opLocalGet1 = []byte{0x20, 0x01}
	opLocalSet1 = []byte{0x21, 0x01}

	opBlock = []byte{0x02, 0x40}
	opBrIf1 = []byte{0x0d, 0x01}
)

// oneI32Local is the local declaration a counted loop needs.
var oneI32Local = cat(uleb(1), uleb(1), []byte{i32})
