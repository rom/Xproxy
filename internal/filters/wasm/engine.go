package wasm

import (
	"context"
	"sync"

	"github.com/tetratelabs/wazero"
)

// probeModule is the smallest module with a function body: one function
// returning i32 42. Compiling it makes the compiler back end allocate and
// protect executable memory, which is where a W^X policy refuses.
var probeModule = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
	0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type: () -> i32
	0x03, 0x02, 0x01, 0x00, // function: one of type 0
	0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b, // code: i32.const 42
}

// compilerUsable reports whether the wazero compiler works in this
// process: the architecture is supported and executable memory can be
// mapped. The probe runs once; the answer cannot change while the process
// lives because the memory policy is set before the first filter loads.
var compilerUsable = sync.OnceValue(func() bool {
	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	defer func() { _ = rt.Close(ctx) }()
	compiled, err := rt.CompileModule(ctx, probeModule)
	if err != nil {
		return false
	}
	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("probe"))
	if err != nil {
		return false
	}
	_ = mod.Close(ctx)
	return true
})
