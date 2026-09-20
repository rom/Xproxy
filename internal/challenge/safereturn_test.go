package challenge

import "testing"

// TestSafeReturnRejectsControlBytes: a return path with any control byte
// falls back to "/": browsers strip tab and newline before parsing a
// Location, so "/\t/evil.test" would otherwise become "//evil.test".
func TestSafeReturnRejectsControlBytes(t *testing.T) {
	for _, bad := range []string{"/\t/evil.test", "/\x00x", "/a\x7fb", "/\r\nLocation: x", "//evil.test", "/\\evil.test", "", "http://evil.test", VerifyPath + "?x"} {
		if got := safeReturn(bad); got != "/" {
			t.Errorf("safeReturn(%q) = %q, want /", bad, got)
		}
	}
	for _, ok := range []string{"/", "/account?tab=1", "/a/b%20c", "/über"} {
		if got := safeReturn(ok); got != ok {
			t.Errorf("safeReturn(%q) = %q", ok, got)
		}
	}
}
