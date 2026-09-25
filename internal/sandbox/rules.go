package sandbox

import (
	"reflect"
	"regexp"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// pathKey matches the YAML keys of configuration fields that name files
// or directories: cert_file, directive_files, state_dir, root, database,
// csv, module, ledger. Keys ending in path or paths are URL paths
// (routes[].paths, doh_path, rewrite_path, health check path) and are
// deliberately absent; the sockets the process connects to (journald) need
// no rule and the one it binds (management) is added explicitly.
//
// `ledger` is here rather than being spelt `ledger_file` because the access
// trail is a ledger rather than a setting that happens to be a file -- and a
// key that named a path and was not in this list would be a path the sandbox
// did not know about, which is why the list and the naming have to agree.
var pathKey = regexp.MustCompile(`(^|_)(file|files|dir|root|database|csv|module|ledger)$`)

// walk visits every string field of the configuration whose YAML key names
// a file or directory, including entries of string slices and the
// free-form options of filters, and reports the key and the value.
func walk(cfg *config.Config, visit func(key, value string)) {
	walkValue(reflect.ValueOf(cfg).Elem(), "", visit)
}

func walkValue(v reflect.Value, key string, visit func(key, value string)) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		walkValue(v.Elem(), key, visit)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = strings.ToLower(f.Name)
			}
			walkValue(v.Field(i), tag, visit)
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < v.Len(); i++ {
			walkValue(v.Index(i), key, visit)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			k := key
			if s, ok := iter.Key().Interface().(string); ok {
				k = s
			}
			walkValue(iter.Value(), k, visit)
		}
	case reflect.String:
		s := v.String()
		if key == "" || !strings.HasPrefix(s, "/") {
			return
		}
		if key == "options" || pathKey.MatchString(key) {
			visit(lastKey(key), s)
		}
	}
}

// lastKey normalises a key to its last underscore separated word group
// used by Derive's classification (state_dir stays state_dir; a filter
// option named module stays module).
func lastKey(k string) string { return k }
