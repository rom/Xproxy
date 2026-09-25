package tftp

import (
	"fmt"
	"path"
	"strings"
)

// Class is what a filename turns out to be when it is read as a path.
//
// A relay refuses classes rather than strings. A deny list of strings is a
// list of the spellings somebody thought of: it stops `../../etc/passwd` and
// not `..\..\etc\passwd`, stops that one and not `/etc/passwd`, stops that
// one and not the name with a NUL in the middle that one server truncates at
// and another does not. Each of those has been the bug somewhere. The class
// is the shape, and there are not many shapes.
type Class int

// The classes, in the order Classify prefers them: the ones that make a
// server's reading of the *rest* of the name differ from this relay's come
// first, because once two parsers disagree about where the name ends, nothing
// further either of them concludes about it means anything. After those, the
// more specific claim about the name wins: `c:\x` is a drive rather than
// merely a name with a backslash in it, and `..\..\etc` is a traversal
// rather than either, because a backslash is a separator on the server that
// matters here.
const (
	// ClassPlain is a relative path of ordinary characters, which is what
	// every legitimate transfer in an estate asks for.
	ClassPlain Class = iota
	// ClassEmpty is no filename at all. Parse already refuses it; the class
	// exists so a classification is total.
	ClassEmpty
	// ClassNUL is a NUL inside the name. It means the name ran past its own
	// field, and it is the oldest way of making two parsers disagree: the
	// one that stops at the NUL sees a permitted name and the one that does
	// not sees whatever follows it.
	ClassNUL
	// ClassControl is a control character in the name. A carriage return
	// writes a second line into a server's log, and an escape sequence goes
	// wherever that log is read.
	ClassControl
	// ClassTraversal is a `..` element anywhere in the name, over either
	// separator. Any of them, not just the ones that escape:
	// `firmware/../firmware/x` resolves inside the directory on a server
	// that normalises the name and somewhere else entirely on one that walks
	// it a symlink at a time. It is looked for before the backslash class
	// because an estate may well allow backslashes, and `..\..\etc\shadow`
	// is not made safe by that.
	ClassTraversal
	// ClassDrive is a Windows drive letter or a UNC prefix: `c:\config` or
	// `\\host\share\file`. The first is absolute on a drive of its own and
	// the second is a request the server makes to a third machine.
	ClassDrive
	// ClassAbsolute is a name rooted at the file system, by either
	// separator. A TFTP server is meant to serve one directory; a name that
	// starts at the root is a request for the server's own idea of where it
	// is.
	ClassAbsolute
	// ClassBackslash is a backslash elsewhere in the name. On a server
	// running on Windows it is a directory separator, so a name carrying one
	// means two different things to two servers -- which is why it is a
	// class at all, rather than an ordinary character.
	ClassBackslash
	// ClassTrailing is an element ending in a space or a dot. Windows strips
	// both when it opens a file, so `secret.txt.` and `secret.txt ` reach
	// the same file that `secret.txt` does while comparing equal to
	// neither.
	ClassTrailing
	// ClassNonASCII is a byte above 0x7f. RFC 1350 says the filename is a
	// netascii string, so this is outside the standard -- but estates
	// contain devices that send UTF-8 names, so it is a class a policy may
	// allow rather than one that is always wrong.
	ClassNonASCII
)

var classNames = map[Class]string{
	ClassPlain: "plain", ClassEmpty: "empty", ClassNUL: "nul",
	ClassControl: "control", ClassNonASCII: "non_ascii",
	ClassBackslash: "backslash", ClassDrive: "drive",
	ClassAbsolute: "absolute", ClassTraversal: "traversal",
	ClassTrailing: "trailing",
}

func (c Class) String() string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return fmt.Sprintf("class(%d)", int(c))
}

// ClassOf names a class the way a configuration file writes it.
func ClassOf(s string) (Class, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for c, n := range classNames {
		if n == s {
			return c, true
		}
	}
	return 0, false
}

// Hard says whether this class is one no configuration may allow.
//
// Three of them are not policy. An empty name, a NUL in the middle and a
// control character each mean this relay and the server behind it are
// reading different names -- and a decision taken about a name the server
// will not see is not a decision, whatever a rule says about it. The rest
// are refusable by default and allowable by configuration, because an estate
// that really does serve absolute paths or UTF-8 names exists and a relay
// that cannot be told so is a relay nobody deploys.
func (c Class) Hard() bool {
	switch c {
	case ClassEmpty, ClassNUL, ClassControl:
		return true
	}
	return false
}

// Path is a filename read as a path.
type Path struct {
	// Name is the filename exactly as it arrived.
	Name string
	// Class is what it turned out to be.
	Class Class
	// Detail says which part of the name earned the class, for the log line
	// an operator reads. It never contains the name itself: a name with a
	// control sequence in it is the reason for the refusal, so repeating it
	// raw is the same mistake one layer up.
	Detail string
	// Clean is the name with its redundant elements removed and its
	// backslashes written as slashes, for comparing against a directory and
	// for logging. It is meaningful only for a class
	// a policy can allow: there is nothing to clean about a name whose end
	// two parsers disagree on.
	Clean string
	// Depth is how many elements Clean has.
	Depth int
}

// Classify reads a filename as a path.
func Classify(name string) Path {
	p := Path{Name: name}
	if name == "" {
		p.Class, p.Detail = ClassEmpty, "no filename"
		return p
	}
	if i := strings.IndexByte(name, 0); i >= 0 {
		p.Class = ClassNUL
		p.Detail = fmt.Sprintf("a NUL at octet %d of %d", i, len(name))
		return p
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || c == 0x7f {
			p.Class = ClassControl
			p.Detail = fmt.Sprintf("octet %#02x at %d", c, i)
			return p
		}
	}
	// Both separators from here on. A backslash is a separator on the server
	// that this whole class of bug lives on, so a relay that only split on
	// slashes would be reading a different path from the one being served.
	slashed := strings.ReplaceAll(name, `\`, "/")
	p.Clean = path.Clean(slashed)
	p.Depth = len(strings.Split(strings.Trim(p.Clean, "/"), "/"))
	for _, el := range strings.Split(slashed, "/") {
		if el == ".." {
			p.Class, p.Detail = ClassTraversal, "a .. element"
			return p
		}
	}
	switch {
	case driveLetter(name):
		p.Class, p.Detail = ClassDrive, "a drive letter"
		return p
	case strings.HasPrefix(name, `\\`):
		p.Class, p.Detail = ClassDrive, "a UNC prefix"
		return p
	case slashed[0] == '/':
		p.Class, p.Detail = ClassAbsolute, "rooted at the top of the file system"
		return p
	case strings.ContainsRune(name, '\\'):
		p.Class, p.Detail = ClassBackslash, "a backslash separator"
		return p
	}
	for _, el := range strings.Split(slashed, "/") {
		if el == "." || el == "" {
			continue
		}
		if c := el[len(el)-1]; c == ' ' || c == '.' {
			p.Class = ClassTrailing
			p.Detail = fmt.Sprintf("an element ending in %q", string(c))
			return p
		}
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			p.Class = ClassNonASCII
			p.Detail = fmt.Sprintf("octet %#02x at %d", name[i], i)
			return p
		}
	}
	p.Class = ClassPlain
	return p
}

// driveLetter says whether the name begins with a Windows drive, which is a
// letter, a colon, and then either a separator or nothing: `c:\x`, `c:/x`
// and `c:x` are all read relative to that drive rather than to the server's
// own directory.
func driveLetter(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	c := name[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Under says whether the path lies inside a directory.
//
// The comparison is element by element, because a string prefix would let
// `firmware-staging/x` through a policy that named `firmware`. An empty
// directory is every path: a rule that names no directory does not narrow by
// one.
func (p Path) Under(dir string) bool {
	want := elements(dir)
	if len(want) == 0 {
		return true
	}
	got := elements(p.Clean)
	if len(got) < len(want) {
		return false
	}
	for i, el := range want {
		if got[i] != el {
			return false
		}
	}
	return true
}

// elements splits a path into its non-empty elements, over either separator.
func elements(s string) []string {
	var out []string
	for _, el := range strings.Split(path.Clean(strings.ReplaceAll(s, `\\`, "/")), "/") {
		if el != "" && el != "." {
			out = append(out, el)
		}
	}
	return out
}
