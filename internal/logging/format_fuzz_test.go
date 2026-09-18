package logging

import "testing"

// FuzzParseTemplate checks that the access log template parser never
// panics and that ValidTemplate and ParseTemplate agree.
func FuzzParseTemplate(f *testing.F) {
	f.Add(TemplateFor("common", ""))
	f.Add(TemplateFor("combined", ""))
	f.Add("{client_ip} {status} {bytes_out} {duration_ms}")
	f.Add("{unknown}")
	f.Add("{")
	f.Add("}{}{{}}")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		toks, err := ParseTemplate(s)
		verr := ValidTemplate(s)
		if (err == nil) != (verr == nil) {
			t.Fatalf("ParseTemplate err=%v ValidTemplate err=%v for %q", err, verr, s)
		}
		if err == nil && len(s) > 0 && len(toks) == 0 {
			t.Fatalf("non empty template produced no tokens: %q", s)
		}
	})
}
