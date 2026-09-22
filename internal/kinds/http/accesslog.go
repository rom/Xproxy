package http

import (
	"math/rand/v2"

	"github.com/rom/xproxy/internal/config"
)

// accessLogPolicy holds the access-log sampling and field-selection
// settings for a generation.
type accessLogPolicy struct {
	sample       float64 // percentage 0..100
	alwaysErrors bool
	fields       map[string]bool // empty means keep every attribute
}

func newAccessLogPolicy(l config.LogStream) accessLogPolicy {
	p := accessLogPolicy{sample: l.AccessSamplePercent(), alwaysErrors: l.AlwaysLogsErrors()}
	if len(l.Fields) > 0 {
		p.fields = make(map[string]bool, len(l.Fields))
		for _, f := range l.Fields {
			p.fields[f] = true
		}
	}
	return p
}

// keep reports whether an access line for a request with the given
// status and denial should be written under the sampling policy.
func (p accessLogPolicy) keep(status int, denied string) bool {
	if p.alwaysErrors && (status >= 400 || denied != "") {
		return true
	}
	if p.sample >= 100 {
		return true
	}
	if p.sample <= 0 {
		return false
	}
	return rand.Float64()*100 < p.sample //nolint:gosec // log sampling needs no cryptographic randomness
}

// selectFields returns attrs trimmed to the configured field allowlist,
// or attrs unchanged when no allowlist is set. attrs is a flat list of
// key, value pairs.
func (p accessLogPolicy) selectFields(attrs []any) []any {
	if len(p.fields) == 0 {
		return attrs
	}
	out := attrs[:0:0]
	for i := 0; i+1 < len(attrs); i += 2 {
		if k, ok := attrs[i].(string); ok && p.fields[k] {
			out = append(out, attrs[i], attrs[i+1])
		}
	}
	return out
}
