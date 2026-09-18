package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Options are the `filters[].options` mapping as decoded from YAML: nested
// maps with string keys, lists, strings, numbers and booleans.
type Options map[string]any

// Decode fills dst (a pointer to a struct with json tags) from the
// options and rejects unknown keys, so a typo in the configuration is a
// load error rather than a silently ignored setting.
func (o Options) Decode(dst any) error {
	if o == nil {
		o = Options{}
	}
	b, err := json.Marshal(normalise(o))
	if err != nil {
		return fmt.Errorf("options: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("options: %w", err)
	}
	return nil
}

// normalise converts map[any]any (older YAML decoders) to map[string]any
// so the JSON encoder accepts it.
func normalise(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalise(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalise(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normalise(val)
		}
		return out
	case Options:
		return normalise(map[string]any(x))
	}
	return v
}
