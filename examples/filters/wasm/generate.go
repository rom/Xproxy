//go:build ignore

// generate.go assembles policy.wasm from the program described in
// policy.wat without a WebAssembly toolchain:
//
//	go run generate.go
package main

import (
	"os"
)

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

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func section(id byte, body []byte) []byte { return cat([]byte{id}, uleb(uint64(len(body))), body) }

func vec(items ...[]byte) []byte {
	out := uleb(uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func str(s string) []byte { return append(uleb(uint64(len(s))), s...) }

const i32, i64 = 0x7f, 0x7e

func funcType(params, results []byte) []byte {
	return cat([]byte{0x60}, uleb(uint64(len(params))), params, uleb(uint64(len(results))), results)
}

func i32c(v int64) []byte { return append([]byte{0x41}, sleb(v)...) }
func i64c(v int64) []byte { return append([]byte{0x42}, sleb(v)...) }
func call(i int) []byte   { return append([]byte{0x10}, uleb(uint64(i))...) }

func body(code []byte) []byte { return cat(uleb(uint64(len(code)+1)), []byte{0x00}, code) } // no locals

func main() {
	data := "x-debug" + "debug_header" + "x-policy" + "v1" + "policy" + "checked"
	const (
		offDebug, lenDebug   = 0, 7
		offReason, lenReason = 7, 12
		offHdr, lenHdr       = 19, 8
		offVal, lenVal       = 27, 2
		offKey, lenKey       = 29, 6
		offAttr, lenAttr     = 35, 7
	)
	const (
		end, ifOp, ret, globalGet, globalSet, localGet, i32Add, i64And, wrap = 0x0b, 0x04, 0x0f, 0x23, 0x24, 0x20, 0x6a, 0x83, 0xa7
	)
	types := vec(
		funcType(nil, []byte{i32}),                     // 0: () -> i32
		funcType([]byte{i32}, []byte{i32}),             // 1: (i32) -> i32
		funcType([]byte{i32, i32, i32}, []byte{i64}),   // 2: get
		funcType([]byte{i32, i32, i32, i32, i32}, nil), // 3: deny, set_header
		funcType([]byte{i32, i32, i32, i32}, nil),      // 4: log_attr
	)
	imp := func(name string, typ byte) []byte { return cat(str("xproxy"), str(name), []byte{0x00, typ}) }
	imports := vec(imp("get", 2), imp("deny", 3), imp("set_header", 3), imp("log_attr", 4)) // functions 0..3
	functions := vec([]byte{0}, []byte{1}, []byte{0}, []byte{1})                            // 4 abi, 5 alloc, 6 on_request, 7 on_response
	memory := vec([]byte{0x00, 0x01})
	globals := vec(cat([]byte{i32, 0x01}, i32c(4096), []byte{end}))
	exports := vec(
		cat(str("memory"), []byte{0x02, 0x00}),
		cat(str("xproxy_abi_version"), []byte{0x00}, uleb(4)),
		cat(str("xproxy_alloc"), []byte{0x00}, uleb(5)),
		cat(str("xproxy_on_request"), []byte{0x00}, uleb(6)),
		cat(str("xproxy_on_response"), []byte{0x00}, uleb(7)),
	)
	abi := body(cat(i32c(1), []byte{end}))
	alloc := body(cat([]byte{globalGet, 0, globalGet, 0, localGet, 0, i32Add, globalSet, 0, end}))
	onRequest := body(cat(
		i32c(4), i32c(offDebug), i32c(lenDebug), call(0),
		i64c(0xffffffff), []byte{i64And, wrap},
		[]byte{ifOp, 0x40},
		i32c(403), i32c(offReason), i32c(lenReason), i32c(0), i32c(0), call(1),
		i32c(1), []byte{ret},
		[]byte{end},
		i32c(offKey), i32c(lenKey), i32c(offAttr), i32c(lenAttr), call(3),
		i32c(0), []byte{end},
	))
	onResponse := body(cat(
		i32c(1), i32c(offHdr), i32c(lenHdr), i32c(offVal), i32c(lenVal), call(2),
		i32c(0), []byte{end},
	))
	code := vec(abi, alloc, onRequest, onResponse)
	dataSeg := vec(cat([]byte{0x00}, i32c(0), []byte{end}, uleb(uint64(len(data))), []byte(data)))
	mod := cat([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00},
		section(1, types), section(2, imports), section(3, functions), section(5, memory),
		section(6, globals), section(7, exports), section(10, code), section(11, dataSeg))
	if err := os.WriteFile("policy.wasm", mod, 0o644); err != nil {
		panic(err)
	}
}
