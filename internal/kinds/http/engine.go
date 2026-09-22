// Package http is the HTTP data plane: the listener kind that takes a
// request apart, decides about it and forwards it.
//
// It is the largest kind by far and the one the engine grew out of, so
// it is also the one whose separation says the most: what an http
// listener needs from the engine is the same narrow Host every other
// kind uses, plus a generation of compiled policy that all http
// listeners of a process share. That shared generation is what the
// proxy.Plane interface exists for.
package http

import (
	"sync/atomic"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/bodybudget"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/challenge"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/shed"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/waf"
)

// engine is everything the http listeners of one process share: the
// compiled generation, and the state that has to survive a reload
// because it is a measurement rather than a setting.
//
// There is one per proxy.Server, built through proxy.RegisterPlane
// before any listener is bound.
type engine struct {
	host proxy.Host
	rt   atomic.Pointer[runtime]

	// logs, stats, fingerprints and acme are the engine's, read once
	// here because they are settled before the first listener binds and
	// the request path reads them on every request. Everything that a
	// reload can change is asked of host each time instead.
	logs         *logging.Logs
	stats        *proxy.Stats
	fingerprints *tlsconf.FingerprintTable

	// maintenance is the runtime toggle, over the configured window.
	maintenance atomic.Bool
	concurrency *limits.Concurrency
	// tarpits bounds the requests held in a tarpit at once.
	tarpits *limits.Concurrency
	// bodyBudget is the process-wide ceiling on request bodies held in
	// memory at once; see server.limits.max_buffered_body_bytes.
	bodyBudget bodybudget.Budget
	// marks are the clients that hit a honeypot.
	marks *marks
	// cache is the response cache, kept across reloads; nil when the
	// configuration has no cache section.
	cache      atomic.Pointer[cache.Cache]
	shedder    atomic.Pointer[shed.Shedder]
	challenger atomic.Pointer[challenge.Challenger]
	tracer     atomic.Pointer[tracing.Tracer]
	// traceRedactIP runs a span's client.address through the log
	// redactor; see config.Tracing.RedactClientAddress.
	traceRedactIP atomic.Bool
	// wafStats keeps per rule counters and learning across reloads.
	wafStats *waf.Stats
	// patches keeps virtual patch hit counters across generations.
	patches patchCounters
	// honeytokenHits keeps honeytoken counters across generations: a
	// plant that has been found stays found across a reload.
	honeytokenHits honeytokenCounters
	// degradation serves suspect clients slowly. Swapped on reload; the
	// counters start again with the new levels.
	degradation atomic.Pointer[degradation]
	// inventory is the API inventory, kept across generations.
	inventory *apiinv.Table
}

// cfg is the configuration of the live generation.
func (s *engine) cfg() *config.Config { return s.rt.Load().cfg }
