// Package wasm is a built-in filter kind that runs a WebAssembly module
// per request in a sandbox (wazero, no cgo). The module implements the
// Xproxy WebAssembly ABI version 1 (docs/EXTENDING.md): it exports
// xproxy_abi_version, xproxy_alloc and xproxy_on_request (optionally
// xproxy_on_response) and imports host functions from module "xproxy"
// to read the request, set headers, log and deny.
//
//	filters:
//	  - name: policy
//	    kind: wasm
//	    options:
//	      module: /etc/xproxy/filters/policy.wasm
//	      config: "tenant=acme"          # free text the module reads with get(config)
//	      timeout: 50ms                  # per call; a trap or timeout fails closed
//	      memory_limit_pages: 256        # 16 MiB per instance
//	      instances: 16                  # pooled instances
//	      on_error: deny                 # or allow
//	      body_limit: 65536              # bytes of body a module may read or set; 0 disables
package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/rom/xproxy/internal/filter"
)

// ABIVersion is the guest contract this package implements.
const ABIVersion = 1

// Bounds on what crosses the sandbox boundary.
const (
	maxString    = 64 << 10
	maxModule    = 64 << 20
	maxLogAttrs  = 32
	maxHeaderOps = 64
)

// Config is the options schema.
type Config struct {
	Module           string `json:"module"`
	ConfigText       string `json:"config"`
	Timeout          string `json:"timeout"`
	MemoryLimitPages int    `json:"memory_limit_pages"`
	Instances        int    `json:"instances"`
	OnError          string `json:"on_error"`
	BodyLimit        *int64 `json:"body_limit"`
	// Engine is compiler, interpreter or auto (default). The compiler
	// emits machine code into executable memory, which a process under
	// MemoryDenyWriteExecute (the shipped systemd unit) or the macOS
	// hardened runtime cannot map; auto probes once and falls back to
	// the interpreter, which never needs executable pages.
	Engine    string `json:"engine"`
	timeout   time.Duration
	bodyLimit int64
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.Module == "" {
		errs = append(errs, errors.New("module is required"))
	} else if !strings.HasPrefix(c.Module, "/") {
		errs = append(errs, errors.New("module must be an absolute path"))
	} else if st, err := os.Stat(c.Module); err != nil {
		errs = append(errs, fmt.Errorf("module: %w", err))
	} else if st.Size() > maxModule {
		errs = append(errs, errors.New("module larger than 64 MiB"))
	}
	if len(c.ConfigText) > maxString {
		errs = append(errs, errors.New("config exceeds 64 KiB"))
	}
	c.timeout = 50 * time.Millisecond
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d < time.Millisecond || d > 10*time.Second {
			errs = append(errs, errors.New("timeout: must be a duration between 1ms and 10s"))
		} else {
			c.timeout = d
		}
	}
	if c.MemoryLimitPages == 0 {
		c.MemoryLimitPages = 256
	}
	if c.MemoryLimitPages < 1 || c.MemoryLimitPages > 16384 {
		errs = append(errs, errors.New("memory_limit_pages: must be between 1 and 16384 (64 KiB pages)"))
	}
	if c.Instances == 0 {
		c.Instances = 16
	}
	if c.Instances < 1 || c.Instances > 1024 {
		errs = append(errs, errors.New("instances: must be between 1 and 1024"))
	}
	switch c.Engine {
	case "":
		c.Engine = "auto"
	case "auto", "compiler", "interpreter":
	default:
		errs = append(errs, errors.New("engine: must be auto, compiler or interpreter"))
	}
	switch c.OnError {
	case "":
		c.OnError = "deny"
	case "deny", "allow":
	default:
		errs = append(errs, errors.New("on_error: must be deny or allow"))
	}
	c.bodyLimit = 64 << 10
	if c.BodyLimit != nil {
		if *c.BodyLimit < 0 || *c.BodyLimit > 16<<20 {
			errs = append(errs, errors.New("body_limit: must be between 0 and 16 MiB"))
		} else {
			c.bodyLimit = *c.BodyLimit
		}
	}
	return &c, errors.Join(errs...)
}

// wasmFilter owns the runtime, the compiled module and an instance pool.
type wasmFilter struct {
	name     string
	cfg      *Config
	log      *slog.Logger
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	hasResp  bool
	pool     chan api.Module
	slots    chan struct{} // one per allowed concurrent call (cfg.Instances)
	closed   atomic.Bool

	Calls, Denies, Errors, Timeouts atomic.Uint64
}

// call is the per request state host functions act on.
type call struct {
	f       *wasmFilter
	info    *filter.Info
	req     *http.Request
	resp    *http.Response
	verdict filter.Verdict
	attrs   []any
	ops     int
	hostErr error // failure while copying a host value into guest memory
	// bodies are buffered on first access, once per phase.
	reqBody  *bodyState
	respBody *bodyState
}

// bodyState is a buffered body: data when it fit the limit, tooLarge
// when it did not (the original stream then continues untouched).
type bodyState struct {
	data     []byte
	tooLarge bool
}

// bufferBody reads at most limit bytes of body; over the limit the
// stream is restored with what was read in front of the rest.
func bufferBody(rc io.ReadCloser, limit int64) (*bodyState, io.ReadCloser) {
	if rc == nil || rc == http.NoBody {
		return &bodyState{}, rc
	}
	buf, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return &bodyState{tooLarge: true}, io.NopCloser(io.MultiReader(bytes.NewReader(buf), &errReader{err}))
	}
	if int64(len(buf)) > limit {
		return &bodyState{tooLarge: true}, &restoredBody{Reader: io.MultiReader(bytes.NewReader(buf), rc), Closer: rc}
	}
	_ = rc.Close()
	return &bodyState{data: buf}, io.NopCloser(bytes.NewReader(buf))
}

type restoredBody struct {
	io.Reader
	io.Closer
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

func (c *call) requestBody() *bodyState {
	if c.reqBody == nil {
		c.reqBody, c.req.Body = bufferBody(c.req.Body, c.f.cfg.bodyLimit)
	}
	return c.reqBody
}

func (c *call) responseBody() *bodyState {
	if c.respBody == nil && c.resp != nil {
		c.respBody, c.resp.Body = bufferBody(c.resp.Body, c.f.cfg.bodyLimit)
	}
	if c.respBody == nil {
		return &bodyState{}
	}
	return c.respBody
}

type callKey struct{}

func callOf(ctx context.Context) *call {
	c, _ := ctx.Value(callKey{}).(*call)
	return c
}

func newFilter(ctx context.Context, name string, c *Config, log *slog.Logger) (*wasmFilter, error) {
	code, err := os.ReadFile(c.Module) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	engine := c.Engine
	if engine == "auto" {
		engine = "compiler"
		if !compilerUsable() {
			engine = "interpreter"
		}
	}
	rc := wazero.NewRuntimeConfigCompiler()
	if engine == "interpreter" {
		rc = wazero.NewRuntimeConfigInterpreter()
	}
	rc = rc.WithMemoryLimitPages(uint32(c.MemoryLimitPages)).WithCloseOnContextDone(true) //nolint:gosec // validated range
	rt := wazero.NewRuntimeWithConfig(ctx, rc)
	log.Info("wasm engine", "engine", engine, "module", c.Module)
	f := &wasmFilter{name: name, cfg: c, log: log, rt: rt, pool: make(chan api.Module, c.Instances), slots: make(chan struct{}, c.Instances)}
	if err := f.hostModule(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	compiled, err := rt.CompileModule(ctx, code)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("compile %s: %w", c.Module, err)
	}
	f.compiled = compiled
	exports := compiled.ExportedFunctions()
	for _, need := range []string{"xproxy_abi_version", "xproxy_alloc", "xproxy_on_request"} {
		if _, ok := exports[need]; !ok {
			_ = rt.Close(ctx)
			return nil, fmt.Errorf("module %s does not export %s", c.Module, need)
		}
	}
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("module %s does not export memory", c.Module)
	}
	_, f.hasResp = exports["xproxy_on_response"]
	// Instantiate once to check the ABI version, then keep the instance.
	m, err := f.instantiate(ctx)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	res, err := m.ExportedFunction("xproxy_abi_version").Call(ctx)
	if err != nil || len(res) != 1 || int32(res[0]) != ABIVersion { //nolint:gosec // guest value
		_ = m.Close(ctx)
		_ = rt.Close(ctx)
		if err != nil {
			return nil, fmt.Errorf("module %s: xproxy_abi_version: %w", c.Module, err)
		}
		return nil, fmt.Errorf("module %s implements ABI version %d, this proxy speaks %d", c.Module, int32(res[0]), ABIVersion) //nolint:gosec // guest value
	}
	f.pool <- m
	return f, nil
}

func (f *wasmFilter) instantiate(ctx context.Context) (api.Module, error) {
	mc := wazero.NewModuleConfig().WithName("").WithStartFunctions()
	if _, ok := f.compiled.ExportedFunctions()["_initialize"]; ok {
		mc = mc.WithStartFunctions("_initialize")
	}
	m, err := f.rt.InstantiateModule(ctx, f.compiled, mc)
	if err != nil {
		return nil, fmt.Errorf("instantiate %s: %w", f.cfg.Module, err)
	}
	return m, nil
}

// acquire takes a pooled instance or builds one.
func (f *wasmFilter) acquire(ctx context.Context) (api.Module, error) {
	select {
	case m := <-f.pool:
		return m, nil
	default:
		return f.instantiate(ctx)
	}
}

// release returns a healthy instance to the pool or closes it.
func (f *wasmFilter) release(ctx context.Context, m api.Module, healthy bool) {
	if healthy && !f.closed.Load() {
		select {
		case f.pool <- m:
			return
		default:
		}
	}
	_ = m.Close(ctx)
}

// hostModule exports the "xproxy" imports.
func (f *wasmFilter) hostModule(ctx context.Context) error {
	b := f.rt.NewHostModuleBuilder("xproxy")
	b.NewFunctionBuilder().WithFunc(hostGet).Export("get")
	b.NewFunctionBuilder().WithFunc(hostSetHeader).Export("set_header")
	b.NewFunctionBuilder().WithFunc(hostRemoveHeader).Export("remove_header")
	b.NewFunctionBuilder().WithFunc(hostDeny).Export("deny")
	b.NewFunctionBuilder().WithFunc(hostLog).Export("log")
	b.NewFunctionBuilder().WithFunc(hostLogAttr).Export("log_attr")
	b.NewFunctionBuilder().WithFunc(hostSetBody).Export("set_body")
	_, err := b.Instantiate(ctx)
	return err
}

// readString copies a bounded guest string.
func readString(m api.Module, ptr, n uint32) (string, bool) {
	if n > maxString {
		return "", false
	}
	b, ok := m.Memory().Read(ptr, n)
	if !ok {
		return "", false
	}
	return string(b), true
}

// writeString allocates in the guest and writes s; the result packs the
// pointer in the high 32 bits and the length in the low 32 bits, 0 for
// an absent value.
func writeString(ctx context.Context, m api.Module, s string) (uint64, error) {
	if s == "" || len(s) > maxString {
		return 0, nil
	}
	res, err := m.ExportedFunction("xproxy_alloc").Call(ctx, uint64(len(s)))
	if err != nil {
		return 0, fmt.Errorf("xproxy_alloc: %w", err)
	}
	if len(res) != 1 {
		return 0, errors.New("xproxy_alloc returned no result")
	}
	ptr := uint32(res[0]) //nolint:gosec // wasm32 pointer
	if !m.Memory().Write(ptr, []byte(s)) {
		return 0, errors.New("xproxy_alloc returned an out-of-bounds region")
	}
	return uint64(ptr)<<32 | uint64(len(s)), nil
}

// Kinds of get.
const (
	getMethod = iota
	getPath
	getHost
	getQuery
	getRequestHeader
	getClientIP
	getRoute
	getRequestID
	getConfig
	getCountry
	getJA4
	getResponseHeader
	getResponseStatus
	getRequestBody
	getResponseBody
	getBodyState
)

func hostGet(ctx context.Context, m api.Module, kind, ptr, n uint32) uint64 {
	c := callOf(ctx)
	if c == nil {
		return 0
	}
	name := ""
	if kind == getRequestHeader || kind == getResponseHeader {
		var ok bool
		if name, ok = readString(m, ptr, n); !ok {
			return 0
		}
	}
	var v string
	switch kind {
	case getMethod:
		v = c.req.Method
	case getPath:
		v = c.req.URL.Path
	case getHost:
		v = c.req.Host
	case getQuery:
		v = c.req.URL.RawQuery
	case getRequestHeader:
		v = c.req.Header.Get(name)
	case getClientIP:
		v = c.info.ClientIP.String()
	case getRoute:
		v = c.info.Route
	case getRequestID:
		v = c.info.RequestID
	case getConfig:
		v = c.f.cfg.ConfigText
	case getCountry:
		v = c.info.Country
	case getJA4:
		v = c.info.JA4
	case getResponseHeader:
		if c.resp != nil {
			v = c.resp.Header.Get(name)
		}
	case getResponseStatus:
		if c.resp != nil {
			v = strconv.Itoa(c.resp.StatusCode)
		}
	case getRequestBody:
		if c.f.cfg.bodyLimit > 0 {
			if b := c.requestBody(); !b.tooLarge {
				v, err := writeBytes(ctx, m, b.data)
				c.recordHostError(err)
				return v
			}
		}
	case getResponseBody:
		if c.f.cfg.bodyLimit > 0 && c.resp != nil {
			if b := c.responseBody(); !b.tooLarge {
				v, err := writeBytes(ctx, m, b.data)
				c.recordHostError(err)
				return v
			}
		}
	case getBodyState:
		switch {
		case c.f.cfg.bodyLimit == 0:
			v = "disabled"
		case c.resp != nil && c.responseBody().tooLarge, c.resp == nil && c.requestBody().tooLarge:
			v = "too_large"
		default:
			v = "ok"
		}
	}
	result, err := writeString(ctx, m, v)
	c.recordHostError(err)
	return result
}

func (c *call) recordHostError(err error) {
	if err != nil && c.hostErr == nil {
		c.hostErr = err
	}
}

// writeBytes is writeString for a body, bounded by the body limit
// instead of the string bound.
func writeBytes(ctx context.Context, m api.Module, b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, nil
	}
	res, err := m.ExportedFunction("xproxy_alloc").Call(ctx, uint64(len(b)))
	if err != nil {
		return 0, fmt.Errorf("xproxy_alloc: %w", err)
	}
	if len(res) != 1 {
		return 0, errors.New("xproxy_alloc returned no result")
	}
	ptr := uint32(res[0]) //nolint:gosec // wasm32 pointer
	if !m.Memory().Write(ptr, b) {
		return 0, errors.New("xproxy_alloc returned an out-of-bounds region")
	}
	return uint64(ptr)<<32 | uint64(len(b)), nil
}

// hostSetBody replaces the request (target 0) or response (target 1)
// body with guest bytes, bounded by body_limit, and fixes the length.
func hostSetBody(ctx context.Context, m api.Module, target, ptr, n uint32) {
	c := callOf(ctx)
	if c == nil || c.f.cfg.bodyLimit == 0 || int64(n) > c.f.cfg.bodyLimit {
		return
	}
	data, ok := m.Memory().Read(ptr, n)
	if !ok {
		return
	}
	body := append([]byte(nil), data...)
	switch {
	case target == 0:
		if c.req.Body != nil {
			_ = c.req.Body.Close()
		}
		c.req.Body = io.NopCloser(bytes.NewReader(body))
		c.req.ContentLength = int64(len(body))
		c.req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		c.reqBody = &bodyState{data: body}
	case target == 1 && c.resp != nil:
		if c.resp.Body != nil {
			_ = c.resp.Body.Close()
		}
		c.resp.Body = io.NopCloser(bytes.NewReader(body))
		c.resp.ContentLength = int64(len(body))
		c.resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		c.resp.Header.Del("Content-Encoding")
		c.respBody = &bodyState{data: body}
	}
}

func headerOK(name, value string) bool {
	return name != "" && !strings.ContainsAny(name, " :\r\n\x00") && !strings.ContainsAny(value, "\r\n\x00")
}

func hostSetHeader(ctx context.Context, m api.Module, target, np, nl, vp, vl uint32) {
	c := callOf(ctx)
	if c == nil || c.ops >= maxHeaderOps {
		return
	}
	name, ok1 := readString(m, np, nl)
	value, ok2 := readString(m, vp, vl)
	if !ok1 || !ok2 || !headerOK(name, value) {
		return
	}
	c.ops++
	switch {
	case target == 0:
		c.req.Header.Set(name, value)
	case target == 1 && c.resp != nil:
		c.resp.Header.Set(name, value)
	case target == 1:
		if c.verdict.Headers == nil {
			c.verdict.Headers = map[string]string{}
		}
		c.verdict.Headers[name] = value // on the deny response
	}
}

func hostRemoveHeader(ctx context.Context, m api.Module, target, np, nl uint32) {
	c := callOf(ctx)
	if c == nil || c.ops >= maxHeaderOps {
		return
	}
	name, ok := readString(m, np, nl)
	if !ok || !headerOK(name, "") {
		return
	}
	c.ops++
	if target == 0 {
		c.req.Header.Del(name)
	} else if c.resp != nil {
		c.resp.Header.Del(name)
	}
}

func hostDeny(ctx context.Context, m api.Module, status, rp, rl, dp, dl uint32) {
	c := callOf(ctx)
	if c == nil {
		return
	}
	reason, _ := readString(m, rp, rl)
	detail, _ := readString(m, dp, dl)
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	if reason == "" || len(reason) > 64 || strings.ContainsAny(reason, " \r\n") {
		reason = c.f.name
	}
	if len(detail) > 256 {
		detail = detail[:256]
	}
	c.verdict.Deny, c.verdict.Status, c.verdict.Reason, c.verdict.Detail = true, int(status), reason, detail
}

func hostLog(ctx context.Context, m api.Module, level, ptr, n uint32) {
	c := callOf(ctx)
	if c == nil {
		return
	}
	msg, ok := readString(m, ptr, n)
	if !ok {
		return
	}
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	attrs := []any{"request_id", c.info.RequestID, "route", c.info.Route}
	switch level {
	case 0:
		c.f.log.Debug(msg, attrs...)
	case 1:
		c.f.log.Info(msg, attrs...)
	case 2:
		c.f.log.Warn(msg, attrs...)
	default:
		c.f.log.Error(msg, attrs...)
	}
}

func hostLogAttr(ctx context.Context, m api.Module, kp, kl, vp, vl uint32) {
	c := callOf(ctx)
	if c == nil || len(c.attrs) >= 2*maxLogAttrs {
		return
	}
	key, ok1 := readString(m, kp, kl)
	value, ok2 := readString(m, vp, vl)
	if !ok1 || !ok2 || key == "" || len(key) > 64 || len(value) > 1024 || strings.ContainsAny(key, " =\"\r\n") {
		return
	}
	c.attrs = append(c.attrs, "wasm_"+key, value)
}

func (f *wasmFilter) Name() string { return f.name }

func (f *wasmFilter) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{c: &call{f: f, info: info}}
}

// Close drains the pool and closes the runtime.
func (f *wasmFilter) Close() error {
	f.closed.Store(true)
	ctx := context.Background()
	for {
		select {
		case m := <-f.pool:
			_ = m.Close(ctx)
			continue
		default:
		}
		break
	}
	return f.rt.Close(ctx)
}

// Status is the management view.
type Status struct {
	Module   string `json:"module"`
	Calls    uint64 `json:"calls"`
	Denies   uint64 `json:"denies"`
	Errors   uint64 `json:"errors"`
	Timeouts uint64 `json:"timeouts"`
	Pooled   int    `json:"pooled"`
}

// Status reports counters.
func (f *wasmFilter) Status() Status {
	return Status{Module: f.cfg.Module, Calls: f.Calls.Load(), Denies: f.Denies.Load(), Errors: f.Errors.Load(), Timeouts: f.Timeouts.Load(), Pooled: len(f.pool)}
}

type instance struct {
	c *call
}

// run calls one guest export with the per request state in the context
// and a deadline; a trap, a timeout or a bad result is an error.
func (f *wasmFilter) run(c *call, export string, args ...uint64) (int32, error) {
	f.Calls.Add(1)
	c.hostErr = nil
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), callKey{}, c), f.cfg.timeout)
	defer cancel()
	// instances is a concurrency bound, not only a pool size: a request
	// beyond it waits for a slot within the call timeout instead of
	// instantiating one more module (each with its own linear memory).
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	case <-ctx.Done():
		f.Timeouts.Add(1)
		return 0, fmt.Errorf("no instance free within %s", f.cfg.timeout)
	}
	m, err := f.acquire(ctx)
	if err != nil {
		f.Errors.Add(1)
		return 0, err
	}
	fn := m.ExportedFunction(export)
	if fn == nil {
		f.release(ctx, m, true)
		return 0, fmt.Errorf("module does not export %s", export)
	}
	res, err := fn.Call(ctx, args...)
	if err == nil && c.hostErr != nil {
		err = fmt.Errorf("host-to-guest copy failed: %w", c.hostErr)
	}
	if err != nil {
		f.release(context.Background(), m, false) // a trapped instance is not reused
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			f.Timeouts.Add(1)
		} else {
			f.Errors.Add(1)
		}
		return 0, err
	}
	if len(res) != 1 {
		f.release(context.Background(), m, false)
		f.Errors.Add(1)
		return 0, errors.New("guest returned no result")
	}
	f.release(ctx, m, true)
	return int32(res[0]), nil //nolint:gosec // guest value
}

func (in *instance) outcome(code int32, err error) filter.Verdict {
	c := in.c
	f := c.f
	if err != nil {
		f.log.Warn("wasm filter failed", "request_id", c.info.RequestID, "route", c.info.Route, "err", err.Error())
		if f.cfg.OnError == "allow" {
			c.attrs = append(c.attrs, "wasm_error", "allowed")
			return filter.Continue
		}
		return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: f.name, Detail: "guest_error"}
	}
	if code != 0 || c.verdict.Deny {
		f.Denies.Add(1)
		v := c.verdict
		v.Deny = true
		if v.Status == 0 {
			v.Status = http.StatusForbidden
		}
		if v.Reason == "" {
			v.Reason = f.name
		}
		return v
	}
	return filter.Continue
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	in.c.req = r
	in.c.verdict = filter.Verdict{}
	in.c.reqBody = nil
	code, err := in.c.f.run(in.c, "xproxy_on_request")
	return in.outcome(code, err)
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	f := in.c.f
	if !f.hasResp {
		return filter.Continue
	}
	in.c.resp = resp
	in.c.verdict = filter.Verdict{}
	in.c.respBody = nil
	code, err := f.run(in.c, "xproxy_on_response", uint64(resp.StatusCode)) //nolint:gosec // status
	v := in.outcome(code, err)
	if v.Deny && v.Headers != nil {
		// Headers set with target 1 during a response deny go on the
		// replacement response.
		for k, val := range v.Headers {
			resp.Header.Set(k, val)
		}
	}
	return v
}

func (in *instance) End() []any { return in.c.attrs }

func init() {
	filter.Register(filter.Kind{
		Name:        "wasm",
		Description: "WebAssembly module (ABI v1) run per request in a wazero sandbox.",
		BuffersBody: true,
		Validate: func(opts filter.Options) error {
			c, err := parse(opts)
			if err != nil {
				return err
			}
			// Compile once to catch a broken or mismatched module at load.
			f, err := newFilter(context.Background(), "validate", c, slog.New(slog.DiscardHandler))
			if err != nil {
				return err
			}
			return f.Close()
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return newFilter(context.Background(), name, c, env.Log)
		},
	})
}
