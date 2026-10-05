package simulate

import (
	"reflect"

	"github.com/rom/xproxy/internal/config"
)

// A configuration a simulation may rewrite freely.
//
// Offline promises the caller's configuration is not modified, and the caller
// is usually holding the estate's real one. A struct copy does not give that
// promise: a config.Config is mostly pointers and slices, so `cfg := *in` hands
// back something that shares every listener's protocol section with the
// original, and writing a listener's recording directory through one of those
// pointers changes the caller's copy. The promise then holds only where somebody
// remembered to copy the struct they were about to write to, which is a promise
// that lasts until the next field.
//
// So the copy is real, by reflection, once, before anything is rewritten.
// Everything after it can write where it likes.

// clone returns a deep copy of a configuration.
func clone(in *config.Config) *config.Config {
	out := &config.Config{}
	// The shallow copy first, because assigning the whole struct carries the
	// unexported fields with it -- a field-by-field copy cannot touch those --
	// and then the pointers, slices and maps under it are replaced one by one.
	*out = *in
	deepen(reflect.ValueOf(out).Elem(), 0)
	return out
}

// deepen replaces every exported pointer, slice and map reachable from v with a
// copy of its own.
//
// Interfaces and unexported fields are left sharing what they pointed at. What
// hides there is parse output -- a compiled expression, a rule set -- which the
// engine reads and never writes, and which a simulation has no reason to
// rewrite. If that stops being true, this is the place it would have to change.
func deepen(v reflect.Value, depth int) {
	if depth > maxWalkDepth || !v.IsValid() || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		n := reflect.New(v.Type().Elem())
		n.Elem().Set(v.Elem())
		deepen(n.Elem(), depth+1)
		v.Set(n)
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		n := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(n, v)
		for i := range n.Len() {
			deepen(n.Index(i), depth+1)
		}
		v.Set(n)
	case reflect.Map:
		if v.IsNil() {
			return
		}
		n := reflect.MakeMapWithSize(v.Type(), v.Len())
		for _, k := range v.MapKeys() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(v.MapIndex(k))
			deepen(e, depth+1)
			n.SetMapIndex(k, e)
		}
		v.Set(n)
	case reflect.Struct:
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			deepen(v.Field(i), depth+1)
		}
	default:
	}
}
