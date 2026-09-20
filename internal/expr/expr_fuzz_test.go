package expr

import "testing"

// FuzzParse feeds arbitrary text to the routing expression parser.
// Expressions come from the configuration, so the attacker here is an
// operator's typo or a fleet push rather than a client; the parser must
// still refuse cleanly rather than panic or recurse until the stack
// gives out, because a panic at load time takes the process with it.
func FuzzParse(f *testing.F) {
	vars := map[string]bool{"path": true, "host": true, "method": true, "client_ip": true}
	f.Add(`path == "/a" && host != "b"`)
	f.Add(`method in ["GET", "POST"]`)
	f.Add(`client_ip in cidr("10.0.0.0/8")`)
	f.Add(``)
	f.Add(`((((((((((((((((((((a))))))))))))))))))))`)
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 4096 {
			return // the configuration bounds expression length elsewhere
		}
		e, err := Parse(src, vars)
		if err != nil {
			if e != nil {
				t.Fatalf("an error came with an expression for %q", src)
			}
			return
		}
		if e == nil {
			t.Fatalf("no error and no expression for %q", src)
		}
	})
}
