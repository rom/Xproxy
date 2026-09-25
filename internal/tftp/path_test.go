package tftp

import (
	"strings"
	"testing"
)

// TestAPathIsClassifiedByItsShapeAndNotItsSpelling is the point of the
// classifier. Each line below is a spelling a deny list would have had to
// think of separately, and each collapses to one of a handful of shapes.
func TestAPathIsClassifiedByItsShapeAndNotItsSpelling(t *testing.T) {
	for _, c := range []struct {
		name string
		want Class
	}{
		{"boot.bin", ClassPlain},
		{"firmware/switch/boot.bin", ClassPlain},
		{"./boot.bin", ClassPlain},
		{"a//b", ClassPlain},

		{"", ClassEmpty},

		{"boot.bin\x00.txt", ClassNUL},
		{"\x00", ClassNUL},

		{"boot\r\n.bin", ClassControl},
		{"boot\x1b[2Jbin", ClassControl},
		{"boot\x7f", ClassControl},

		{"../../etc/shadow", ClassTraversal},
		{"firmware/../../etc/shadow", ClassTraversal},
		{"firmware/../firmware/boot.bin", ClassTraversal},
		{"..", ClassTraversal},

		{"/etc/shadow", ClassAbsolute},
		{"/", ClassAbsolute},

		// A backslash is a separator on the server this bug lives on, so
		// the traversal is seen over it and not hidden behind the class an
		// estate serving Windows hosts might well allow.
		{`..\..\etc\shadow`, ClassTraversal},
		{`firmware\boot.bin`, ClassBackslash},
		{`\etc\shadow`, ClassAbsolute},

		{`\\host\share\boot.bin`, ClassDrive},
		{`c:\config.txt`, ClassDrive},
		{"c:/config.txt", ClassDrive},
		{"C:config.txt", ClassDrive},

		{"secret.txt.", ClassTrailing},
		{"secret.txt ", ClassTrailing},
		{"a/secret.txt./b", ClassTrailing},

		{"bøt.bin", ClassNonASCII},
	} {
		got := Classify(c.name)
		if got.Class != c.want {
			t.Errorf("%q is %v, want %v (%s)", c.name, got.Class, c.want, got.Detail)
		}
		if c.want != ClassPlain && c.want != ClassEmpty && got.Detail == "" {
			t.Errorf("%q was refused with nothing to say about why", c.name)
		}
	}
}

// TestADetailNeverRepeatsTheNameItRefused holds the line that a refusal
// caused by a control sequence must not carry the control sequence into the
// log line reporting it.
func TestADetailNeverRepeatsTheNameItRefused(t *testing.T) {
	for _, name := range []string{"boot\x1b[2Jbin", "a\x00b", "boot\r\n.bin"} {
		p := Classify(name)
		if strings.Contains(p.Detail, name) {
			t.Errorf("the detail for %q carries the name: %q", name, p.Detail)
		}
		for i := 0; i < len(p.Detail); i++ {
			if c := p.Detail[i]; c < 0x20 || c == 0x7f {
				t.Errorf("the detail for %q carries octet %#02x", name, c)
			}
		}
	}
}

// TestTheHardClassesAreTheOnesTwoParsersDisagreeOn pins which classes a
// configuration may not allow. It is the shadow-mode line in this kind: a
// bound on what a policy can be told to permit, not a policy itself.
func TestTheHardClassesAreTheOnesTwoParsersDisagreeOn(t *testing.T) {
	hard := map[Class]bool{ClassEmpty: true, ClassNUL: true, ClassControl: true}
	for c := range classNames {
		if got := c.Hard(); got != hard[c] {
			t.Errorf("%v hard=%v, want %v", c, got, hard[c])
		}
	}
	if ClassPlain.Hard() {
		t.Fatal("an ordinary path cannot be refused unconditionally")
	}
}

func TestAClassIsNamedTheWayAConfigurationWritesIt(t *testing.T) {
	for c, name := range classNames {
		got, ok := ClassOf(strings.ToUpper(" " + name + " "))
		if !ok || got != c {
			t.Errorf("%q read as %v ok=%v", name, got, ok)
		}
	}
	if _, ok := ClassOf("dangerous"); ok {
		t.Fatal("a class nobody defines was named")
	}
	if !strings.Contains(Class(99).String(), "99") {
		t.Fatalf("an unknown class hides its number: %q", Class(99))
	}
}

// TestADirectoryIsComparedByElementAndNotByPrefix is the bug a string prefix
// always has: firmware-staging begins with firmware.
func TestADirectoryIsComparedByElementAndNotByPrefix(t *testing.T) {
	for _, c := range []struct {
		name, dir string
		want      bool
	}{
		{"firmware/boot.bin", "firmware", true},
		{"firmware/switch/boot.bin", "firmware/switch", true},
		{"firmware-staging/boot.bin", "firmware", false},
		{"firmwarex/boot.bin", "firmware", false},
		{"boot.bin", "firmware", false},
		{"firmware", "firmware", true},
		{"firmware/boot.bin", "", true},
		{"firmware/boot.bin", "/firmware/", true},
		{"firmware/./boot.bin", "firmware", true},
	} {
		if got := Classify(c.name).Under(c.dir); got != c.want {
			t.Errorf("%q under %q = %v, want %v", c.name, c.dir, got, c.want)
		}
	}
}

func TestACleanedPathKeepsItsDepth(t *testing.T) {
	for _, c := range []struct {
		name, clean string
		depth       int
	}{
		{"boot.bin", "boot.bin", 1},
		{"./boot.bin", "boot.bin", 1},
		{"a//b/c", "a/b/c", 3},
		{"a/./b", "a/b", 2},
	} {
		p := Classify(c.name)
		if p.Clean != c.clean || p.Depth != c.depth {
			t.Errorf("%q cleans to %q at depth %d, want %q at %d", c.name, p.Clean, p.Depth, c.clean, c.depth)
		}
	}
}

// FuzzClassify checks the one property the classifier owes its callers: it
// answers for every filename, because a filename arrives in one
// unauthenticated datagram and there is nothing upstream of it to refuse a
// shape first.
func FuzzClassify(f *testing.F) {
	f.Add("boot.bin")
	f.Add("../../etc/shadow")
	f.Add("a\x00b")
	f.Add(`c:\x`)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		p := Classify(s)
		if p.Name != s {
			t.Fatalf("the name was changed: %q became %q", s, p.Name)
		}
		if _, ok := classNames[p.Class]; !ok {
			t.Fatalf("%q was given no class", s)
		}
		if p.Class == ClassPlain {
			if p.Clean == "" {
				t.Fatalf("%q is a plain path that cleans to nothing", s)
			}
			// A plain path may be compared against a directory, so the
			// comparison must not conclude that a name is under a
			// directory the cleaning invented.
			if strings.Contains(p.Clean, "..") && !strings.Contains(s, "..") {
				t.Fatalf("%q cleaned to %q", s, p.Clean)
			}
		}
		for i := 0; i < len(p.Detail); i++ {
			if c := p.Detail[i]; c < 0x20 || c == 0x7f {
				t.Fatalf("the detail for %q carries octet %#02x", s, c)
			}
		}
	})
}
