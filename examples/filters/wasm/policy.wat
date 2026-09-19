;; Example xproxy WebAssembly filter (ABI version 1), see docs/EXTENDING.md.
;;
;; Policy: a request carrying an X-Debug header is refused with 403 and
;; the reason "debug_header"; every other request continues and the
;; access log line carries wasm_policy=checked. In the response phase
;; the header X-Policy: v1 is added (a response header set during the
;; request phase would apply to a deny response only).
;;
;; policy.wasm next to this file is the same program assembled by
;; generate.go (go run generate.go); a WebAssembly toolchain such as wabt
;; (wat2wasm policy.wat) produces an equivalent binary from this text.
(module
  (import "xproxy" "get"        (func $get        (param i32 i32 i32) (result i64)))
  (import "xproxy" "deny"       (func $deny       (param i32 i32 i32 i32 i32)))
  (import "xproxy" "set_header" (func $set_header (param i32 i32 i32 i32 i32)))
  (import "xproxy" "log_attr"   (func $log_attr   (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  ;; offsets: x-debug 0..7, debug_header 7..19, x-policy 19..27, v1 27..29,
  ;;          policy 29..35, checked 35..42
  (data (i32.const 0) "x-debugdebug_headerx-policyv1policychecked")
  (global $heap (mut i32) (i32.const 4096))
  (func (export "xproxy_abi_version") (result i32) (i32.const 1))
  (func (export "xproxy_alloc") (param $n i32) (result i32)
    global.get $heap
    global.get $heap local.get $n i32.add global.set $heap)
  (func (export "xproxy_on_request") (result i32)
    ;; get(4 = request header, "x-debug"): length in the low 32 bits
    (i64.and (call $get (i32.const 4) (i32.const 0) (i32.const 7)) (i64.const 0xffffffff))
    i32.wrap_i64
    (if (then
      (call $deny (i32.const 403) (i32.const 7) (i32.const 12) (i32.const 0) (i32.const 0))
      (return (i32.const 1))))
    ;; log_attr("policy", "checked")
    (call $log_attr (i32.const 29) (i32.const 6) (i32.const 35) (i32.const 7))
    (i32.const 0))
  (func (export "xproxy_on_response") (param $status i32) (result i32)
    ;; set_header(1 = response, "x-policy", "v1")
    (call $set_header (i32.const 1) (i32.const 19) (i32.const 8) (i32.const 27) (i32.const 2))
    (i32.const 0)))
