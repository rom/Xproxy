package fleet

import (
	"strings"
	"testing"
)

// TestBundleFileModes: a staged file must be owner read/write and carry no
// write bit for group or other, so nothing lands group- or world-writable
// on every node; read bits are the operator's choice (rule files are
// commonly 0644).
func TestBundleFileModes(t *testing.T) {
	mk := func(mode uint32) *Bundle {
		return &Bundle{Files: []File{{Path: "rules/extra.conf", Mode: mode, Content: []byte("# ok")}}}
	}
	for _, mode := range []uint32{0o666, 0o660, 0o622, 0o777, 0o400, 0o1600} {
		if err := mk(mode).Validate(); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("mode %o accepted: %v", mode, err)
		}
	}
	for _, mode := range []uint32{0o600, 0o640, 0o644} {
		if err := mk(mode).Validate(); err != nil && strings.Contains(err.Error(), "mode") {
			t.Errorf("mode %o refused: %v", mode, err)
		}
	}
}
