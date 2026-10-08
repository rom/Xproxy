package config

import (
	"reflect"
	"strings"
)

// Enforcement is why a listener enforces its policy, or why it does not.
//
// Three independent settings can switch enforcement off, and they belong to
// different layers: `policy.mode: shadow` is the estate's generic switch,
// `monitor_only` is a kind's own, and a `learn` run is observe-only unless it
// says otherwise. Folding them into one value gives every kind the same
// precedence and gives a status view one string to report, instead of the
// twenty-three hand-written enforcing() methods that each combined the sources
// their author remembered -- where "why is this listener not enforcing?" had
// three possible answers and nowhere to read them.
//
// The precedence is the one every kind already used: either explicit switch wins
// over a learning run, because an operator who wrote `shadow` meant the whole
// listener, and a learning run with `enforce: true` is still a listener that
// enforces.
//
// Note that `monitor_only` means this on thirteen kinds and something else on
// iec104, where it is the protocol's own monitor direction and refuses every
// command rather than permitting them. That listener's MonitorOnly deliberately
// does not come in here; see IEC104Listener.MonitorOnly.
type Enforcement struct {
	// Shadow is policy.mode: shadow on the listener.
	Shadow bool
	// MonitorOnly is the kind's own monitor_only, where it means "evaluate
	// and do not enforce".
	MonitorOnly bool
	// Learning says a learn run is in progress, and LearnEnforce that it
	// decides anyway.
	Learning     bool
	LearnEnforce bool
}

// Enforcing reports whether the policy decides or only records.
func (e Enforcement) Enforcing() bool {
	switch {
	case e.Shadow, e.MonitorOnly:
		return false
	case e.Learning:
		return e.LearnEnforce
	}
	return true
}

// Mode names the state for a status view and a log line: enforce, shadow,
// monitor or learn. It is the field an operator reads to answer "is this
// listener actually deciding anything", so it names the *reason* rather than
// collapsing three of them into "not enforcing".
func (e Enforcement) Mode() string {
	switch {
	case e.Shadow:
		return "shadow"
	case e.MonitorOnly:
		return "monitor"
	case e.Learning && !e.LearnEnforce:
		return "learn"
	}
	return "enforce"
}

// kindSectionValue is the listener's own kind section, found by matching the
// kind against the yaml key of each pointer field. It is reflective because the
// alternative is a thirty-seven-arm switch that a new kind is added without.
func kindSectionValue(ln *Listener) reflect.Value {
	kind := ln.Kind
	if kind == "" {
		kind = "http"
	}
	v := reflect.ValueOf(ln).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag != kind {
			continue
		}
		fv := v.Field(i)
		for fv.Kind() == reflect.Ptr {
			if fv.IsNil() {
				return reflect.Value{}
			}
			fv = fv.Elem()
		}
		return fv
	}
	return reflect.Value{}
}

// sectionBool reads a bool field of a kind section by its yaml key.
func sectionBool(sec reflect.Value, key string) bool {
	f, ok := fieldByYAMLKey(sec, key)
	if !ok {
		return false
	}
	return f.Kind() == reflect.Bool && f.Bool()
}

// sectionNestedBool reads a bool inside a nested section, as learn.enabled is.
func sectionNestedBool(sec reflect.Value, outer, key string) bool {
	f, ok := fieldByYAMLKey(sec, outer)
	if !ok {
		return false
	}
	for f.Kind() == reflect.Ptr {
		if f.IsNil() {
			return false
		}
		f = f.Elem()
	}
	if f.Kind() != reflect.Struct {
		return false
	}
	return sectionBool(f, key)
}

func fieldByYAMLKey(sec reflect.Value, key string) (reflect.Value, bool) {
	if !sec.IsValid() || sec.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}
	t := sec.Type()
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if tag == key {
			return sec.Field(i), true
		}
	}
	return reflect.Value{}, false
}
