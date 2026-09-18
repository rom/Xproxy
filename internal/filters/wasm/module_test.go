package wasm

import "encoding/binary"

// A tiny WebAssembly binary encoder for the test guest, so the ABI is
// exercised against a real module without a toolchain in the test.

func uleb(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

func sleb(v int64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		done := (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0)
		if !done {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

func section(id byte, body []byte) []byte {
	return append(append([]byte{id}, uleb(uint64(len(body)))...), body...)
}

func vec(items [][]byte) []byte {
	out := uleb(uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func str(s string) []byte { return append(uleb(uint64(len(s))), s...) }

func funcType(params, results []byte) []byte {
	out := []byte{0x60}
	out = append(out, uleb(uint64(len(params)))...)
	out = append(out, params...)
	out = append(out, uleb(uint64(len(results)))...)
	return append(out, results...)
}

const (
	i32 = 0x7f
	i64 = 0x7e
)

// ops
func i32c(v int64) []byte { return append([]byte{0x41}, sleb(v)...) }
func i64c(v int64) []byte { return append([]byte{0x42}, sleb(v)...) }
func callOp(i int) []byte { return append([]byte{0x10}, uleb(uint64(i))...) }

var (
	opEnd       = []byte{0x0b}
	opIf        = []byte{0x04, 0x40}
	opLoop      = []byte{0x03, 0x40}
	opBr0       = []byte{0x0c, 0x00}
	opReturn    = []byte{0x0f}
	opLocal0    = []byte{0x20, 0x00}
	opGGet0     = []byte{0x23, 0x00}
	opGSet0     = []byte{0x24, 0x00}
	opAdd       = []byte{0x6a}
	opEq        = []byte{0x46}
	opI64And    = []byte{0x83}
	opWrap      = []byte{0xa7}
	opDrop      = []byte{0x1a}
	opI64ShrU   = []byte{0x88}
	opLocalGet0 = []byte{0x20, 0x00}
	opLocalSet0 = []byte{0x21, 0x00}
)

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func body(locals []byte, code []byte) []byte {
	b := append(append([]byte{}, locals...), code...)
	return append(uleb(uint64(len(b))), b...)
}

// lenOf extracts the length from a packed get result on the stack.
var lenOf = cat(i64c(0xffffffff), opI64And, opWrap)

// testModule builds the guest. Strings live in a data segment; offsets
// are returned so tests know them. abi is the version the module
// reports.
func testModule(abi int64, withResponse bool) []byte {
	strs := []string{"x-block", "x-wasm", "1", "wasm_block", "header", "x-hide", "wasm_seen", "x-slow", "hello", "wasm_resp", "x-cfg",
		"x-body", "x-body-seen", "x-swap", "swapped", "x-resp-swap", "resp-swapped", "x-body-state"}
	off := map[string]int64{}
	var data []byte
	for _, s := range strs {
		off[s] = int64(len(data))
		data = append(data, s...)
	}
	o := func(s string) []byte { return i32c(off[s]) }
	l := func(s string) []byte { return i32c(int64(len(s))) }

	types := vec([][]byte{
		funcType(nil, []byte{i32}),                     // 0: () -> i32
		funcType([]byte{i32}, []byte{i32}),             // 1: (i32) -> i32
		funcType([]byte{i32, i32, i32}, []byte{i64}),   // 2: get
		funcType([]byte{i32, i32, i32, i32, i32}, nil), // 3: set_header, deny
		funcType([]byte{i32, i32, i32}, nil),           // 4: remove_header, log
		funcType([]byte{i32, i32, i32, i32}, nil),      // 5: log_attr
	})
	imp := func(name string, typ byte) []byte { return cat(str("xproxy"), str(name), []byte{0x00, typ}) }
	imports := vec([][]byte{imp("get", 2), imp("set_header", 3), imp("remove_header", 4), imp("deny", 3), imp("log", 4), imp("log_attr", 5), imp("set_body", 4)})
	// Defined functions: 7 abi_version(t0), 8 alloc(t1), 9 on_request(t0), 10 on_response(t1)
	funcs := [][]byte{{0}, {1}, {0}}
	if withResponse {
		funcs = append(funcs, []byte{1})
	}
	functions := vec(funcs)
	memory := vec([][]byte{{0x00, 0x01}}) // min 1 page, no max
	globals := vec([][]byte{cat([]byte{i32, 0x01}, i32c(4096), opEnd)})
	exps := [][]byte{
		cat(str("memory"), []byte{0x02, 0x00}),
		cat(str("xproxy_abi_version"), []byte{0x00}, uleb(7)),
		cat(str("xproxy_alloc"), []byte{0x00}, uleb(8)),
		cat(str("xproxy_on_request"), []byte{0x00}, uleb(9)),
	}
	if withResponse {
		exps = append(exps, cat(str("xproxy_on_response"), []byte{0x00}, uleb(10)))
	}
	exports := vec(exps)

	abiVersion := body(uleb(0), cat(i32c(abi), opEnd))
	alloc := body(uleb(0), cat(opGGet0, opGGet0, opLocal0, opAdd, opGSet0, opEnd))
	onRequest := body(cat(uleb(1), uleb(1), []byte{i64}), cat( // one i64 local
		// x-body header: r = get(request body); if len(r) != 0 { set_body(0, ptr(r), len(r)); set_header("x-body-seen", "1") }
		// and publish the body state in a header either way
		i32c(getRequestHeader), o("x-body"), l("x-body"), callOp(0), lenOf,
		opIf,
		i32c(getRequestBody), i32c(0), i32c(0), callOp(0), opLocalSet0,
		opLocalGet0, lenOf,
		opIf,
		i32c(0), opLocalGet0, i64c(32), opI64ShrU, opWrap, opLocalGet0, lenOf, callOp(6),
		i32c(0), o("x-body-seen"), l("x-body-seen"), o("1"), l("1"), callOp(1),
		opEnd,
		i32c(getBodyState), i32c(0), i32c(0), callOp(0), opLocalSet0,
		i32c(0), o("x-body-state"), l("x-body-state"), opLocalGet0, i64c(32), opI64ShrU, opWrap, opLocalGet0, lenOf, callOp(1),
		opEnd,
		// x-swap header: set_body(0, "swapped")
		i32c(getRequestHeader), o("x-swap"), l("x-swap"), callOp(0), lenOf,
		opIf, i32c(0), o("swapped"), l("swapped"), callOp(6), opEnd,
		// x-block header present -> deny(451, "wasm_block", "header"); return 1
		i32c(getRequestHeader), o("x-block"), l("x-block"), callOp(0), lenOf,
		opIf, i32c(451), o("wasm_block"), l("wasm_block"), o("header"), l("header"), callOp(3), i32c(1), opReturn, opEnd,
		// x-slow header present -> spin forever
		i32c(getRequestHeader), o("x-slow"), l("x-slow"), callOp(0), lenOf,
		opIf, opLoop, opBr0, opEnd, opEnd,
		// set_header(request, "x-wasm", "1"); echo config into x-cfg
		i32c(0), o("x-wasm"), l("x-wasm"), o("1"), l("1"), callOp(1),
		i32c(getConfig), i32c(0), i32c(0), callOp(0), opDrop, // exercised, value unused by the guest
		i32c(0), o("x-cfg"), l("x-cfg"), o("hello"), l("hello"), callOp(1),
		// log_attr("wasm_seen", "1"); log(1, "hello")
		o("wasm_seen"), l("wasm_seen"), o("1"), l("1"), callOp(5),
		i32c(1), o("hello"), l("hello"), callOp(4),
		i32c(0), opEnd,
	))
	onResponse := body(uleb(0), cat(
		// x-resp-swap request header: set_body(1, "resp-swapped")
		i32c(getRequestHeader), o("x-resp-swap"), l("x-resp-swap"), callOp(0), lenOf,
		opIf, i32c(1), o("resp-swapped"), l("resp-swapped"), callOp(6), opEnd,
		// x-hide response header present -> remove it
		i32c(getResponseHeader), o("x-hide"), l("x-hide"), callOp(0), lenOf,
		opIf, i32c(1), o("x-hide"), l("x-hide"), callOp(2), opEnd,
		// status 500 -> deny(502, "wasm_resp", ""); return 1
		opLocal0, i32c(500), opEq,
		opIf, i32c(502), o("wasm_resp"), l("wasm_resp"), i32c(0), i32c(0), callOp(3), i32c(1), opReturn, opEnd,
		i32c(0), opEnd,
	))
	bodies := [][]byte{abiVersion, alloc, onRequest}
	if withResponse {
		bodies = append(bodies, onResponse)
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
	_ = binary.BigEndian
	return mod
}
