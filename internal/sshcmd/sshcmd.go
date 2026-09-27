// Package sshcmd reads an SSH exec command line as a shell would split
// it, and then reads the command families a gateway has to hold to a
// policy -- scp, rsync, the sftp server and git -- into what they
// actually ask for.
//
// It exists because a regular expression over a command line is a weak
// thing to hold a shell to. "^scp -t /srv/incoming$" is a pattern
// somebody wrote meaning "uploads into that directory only", and every
// one of these walks past it:
//
//	scp -t /srv/incoming/../../etc/ssh
//	scp -f /srv/incoming            (the same words; the other direction)
//	scp -rt /srv/incoming           (bundled, so the pattern misses)
//	/usr/bin/scp -t /srv/incoming   (a path, so the pattern misses)
//	scp  -t  /srv/incoming          (two spaces)
//
// A pattern can be tightened against any one of those and stays wrong
// about the next. What the policy wants to say is "this may put files
// into that directory and take none out", which is a statement about
// the command's *meaning*: its direction, whether it recurses, and the
// path it names after that path is resolved. So the line is split the
// way a shell splits it, the options are read the way the program reads
// them, and the policy decides on that.
//
// Two rules keep the reading honest:
//
// Anything this cannot read as one simple command is an error, never a
// guess. A substitution, an operator, an unbalanced quote, an option no
// version of the program takes: each is refused with the reason, because
// a gateway that guesses at a line it does not understand is a gateway
// whose policy holds only for the lines somebody thought of.
//
// Nothing here decides anything. It reports what the line says; the
// caller's policy decides whether that is allowed. That split is what
// makes the reading testable against the programs' own documented
// invocations rather than against a configuration.
package sshcmd

import (
	"fmt"
	"path"
	"strings"
)

// Bounds on what is read. A command line longer or wordier than this is
// refused rather than parsed: an exec request carries a command, and
// something this size is a program being delivered as an argument.
const (
	MaxLine  = 4096
	MaxWords = 256
)

// Reasons a line is refused. Each one names what could not be read,
// which is what a refusal has to say to be actionable.
const (
	ReasonEmpty        = "empty"
	ReasonTooLong      = "too_long"
	ReasonTooManyWords = "too_many_words"
	ReasonQuote        = "unterminated_quote"
	ReasonEscape       = "trailing_escape"
	ReasonOperator     = "operator"
	ReasonSubstitution = "substitution"
	ReasonControl      = "control_character"
	ReasonOption       = "option"
	ReasonArguments    = "arguments"
)

// Error is a line, or a family's invocation, that could not be read.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

// Kind is the command family a line was recognised as.
type Kind string

const (
	KindSCP        Kind = "scp"
	KindRsync      Kind = "rsync"
	KindSFTPServer Kind = "sftp_server"
	KindGit        Kind = "git"
	// KindOther is everything with no parser here. A caller holds those
	// to whatever it held every command to before: this package has
	// nothing to say about them, and says so rather than guessing.
	KindOther Kind = "other"
)

// Direction is which way files move, from the gateway's point of view:
// Upload puts them on the target, Download takes them off it. It is the
// file movement and not the program's own verb, because that is what a
// policy means to allow or refuse -- git calls a fetch "upload-pack",
// after all, since the sense is the server's.
type Direction string

const (
	Upload   Direction = "upload"
	Download Direction = "download"
	// Neither is a command that is not the peer of a client at all: an
	// scp with no -t or -f, an rsync with no --server. Those run
	// something else entirely on the target, so the direction of the
	// transfer is not what they are asking for.
	Neither Direction = ""
)

// Word is one shell word: its value with the quoting removed, and
// whether it carried a glob or a tilde that the target's shell, not
// this parser, decides the meaning of.
type Word struct {
	Text string
	Glob bool
}

// Command is what a line asked for.
type Command struct {
	// Line is the command line as it arrived.
	Line string
	// Env are the leading VAR=value assignments, in order. A family
	// parser does not look past them; a policy that cares refuses them,
	// since each is a way to change what the command does.
	Env []string
	// Words are the command and its arguments, assignments removed.
	Words []Word
	// Kind is the family, Name the command word with any directory part
	// and .exe suffix removed, Path the word as written.
	Kind Kind
	Name string
	Path string
	// Exactly one of these is set for a recognised family.
	SCP        *SCP
	Rsync      *Rsync
	Git        *Git
	SFTPServer *SFTPServer
}

// SCP is an scp invocation as its server side reads it: one direction,
// the flags it was given and the paths it names.
type SCP struct {
	Direction Direction
	Recursive bool // -r
	Directory bool // -d, the target must be a directory
	Preserve  bool // -p
	Flags     string
	Paths     []Word
}

// Rsync is an rsync invocation. In server mode the file list travels
// inside rsync's own protocol, so the paths here are the transfer root
// and nothing below it: a policy over individual files is sftp's job,
// not this one's, and saying so is more useful than implying otherwise.
type Rsync struct {
	Server    bool // --server, which is how a client invokes the far side
	Direction Direction
	Deletes   bool // an option that removes files at the far end
	Options   []string
	Paths     []Word
}

// Git is a git transport invocation: the verb, and the repository it
// names.
type Git struct {
	Verb      string // upload-pack, receive-pack, upload-archive
	Direction Direction
	Path      Word
	Options   []string
}

// SFTPServer is an exec of the sftp server binary, which is the sftp
// subsystem under another name: the same protocol on the same channel,
// asked for in a way a subsystem policy never sees.
type SFTPServer struct {
	ReadOnly bool // -R
	Options  []string
}

// fileTransferNames are the family names, keyed by the command name
// with its directory part removed.
var fileTransferNames = map[string]Kind{
	"scp": KindSCP, "rsync": KindRsync,
	"sftp-server": KindSFTPServer, "internal-sftp": KindSFTPServer,
	"git-upload-pack": KindGit, "git-receive-pack": KindGit,
	"git-upload-archive": KindGit, "git": KindGit,
}

// Split reads a line as a POSIX shell reads one simple command, and
// refuses everything that is not one.
//
// Quoting is handled as a shell does, because that is the only way the
// words a policy checks are the words the target will run: single
// quotes take everything literally, double quotes take everything but
// the escapes a shell honours inside them, and a backslash outside
// quotes escapes the next character. What is refused is anything that
// makes the line more than one command or makes a word depend on
// something the gateway cannot see: an operator, a substitution, an
// unbalanced quote, and every control character but tab.
//
// Tab is the one exception, because it is not really one of them: outside
// quotes it separates words as a space does, and inside them it is an
// ordinary byte a path on the far side may legitimately contain.
// Everything else below 0x20, and 0x7f, is refused wherever it appears --
// a newline inside a quoted word is a word no log line can hold and a
// careless reader may take for two.
func Split(line string) ([]Word, error) {
	if len(line) > MaxLine {
		return nil, &Error{Reason: ReasonTooLong, Detail: fmt.Sprintf("%d bytes", len(line))}
	}
	var (
		words   []Word
		cur     strings.Builder
		curGlob bool
		inWord  bool
	)
	flush := func() {
		if inWord {
			words = append(words, Word{Text: cur.String(), Glob: curGlob})
			cur.Reset()
			curGlob = false
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
			continue
		case c == '\'':
			inWord = true
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, &Error{Reason: ReasonQuote, Detail: "'"}
			}
			body := line[i+1 : i+1+j]
			if err := noControl(body); err != nil {
				return nil, err
			}
			cur.WriteString(body)
			i += j + 1
			continue
		case c == '"':
			rest, err := readDouble(line[i+1:], &cur)
			if err != nil {
				return nil, err
			}
			inWord = true
			i = len(line) - len(rest) - 1
			continue
		case c == '\\':
			if i == len(line)-1 {
				return nil, &Error{Reason: ReasonEscape}
			}
			i++
			if err := noControl(line[i : i+1]); err != nil {
				return nil, err
			}
			inWord = true
			cur.WriteByte(line[i])
			continue
		case strings.IndexByte("$`", c) >= 0:
			// A substitution is another command, or a variable whose
			// value the gateway cannot see. Either way the words it
			// would check are not the words that will run.
			return nil, &Error{Reason: ReasonSubstitution, Detail: string(c)}
		case strings.IndexByte(";&|<>()\n\r{}", c) >= 0:
			return nil, &Error{Reason: ReasonOperator, Detail: string(c)}
		case c < 0x20 || c == 0x7f:
			return nil, &Error{Reason: ReasonControl, Detail: fmt.Sprintf("%#02x", c)}
		}
		if strings.IndexByte("*?[]~", c) >= 0 {
			// Kept, not refused: what it expands to is the target
			// shell's decision, and the caller is the one that knows
			// whether a word it cannot resolve is admissible.
			curGlob = true
		}
		inWord = true
		cur.WriteByte(c)
	}
	flush()
	switch {
	case len(words) == 0:
		return nil, &Error{Reason: ReasonEmpty}
	case len(words) > MaxWords:
		return nil, &Error{Reason: ReasonTooManyWords, Detail: fmt.Sprintf("%d words", len(words))}
	}
	return words, nil
}

// readDouble consumes a double-quoted section, writing its value, and
// returns what is left of the line after the closing quote.
func readDouble(s string, out *strings.Builder) (string, error) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return s[i+1:], nil
		case '\\':
			if i == len(s)-1 {
				return "", &Error{Reason: ReasonEscape}
			}
			i++
			// Inside double quotes a backslash escapes only these; in
			// front of anything else it is a literal backslash, and
			// reading it otherwise would give a word the shell will not.
			if strings.IndexByte(`"\$`+"`", s[i]) < 0 {
				out.WriteByte('\\')
			}
			if err := noControl(s[i : i+1]); err != nil {
				return "", err
			}
			out.WriteByte(s[i])
		case '$', '`':
			return "", &Error{Reason: ReasonSubstitution, Detail: string(c)}
		default:
			if err := noControl(s[i : i+1]); err != nil {
				return "", err
			}
			out.WriteByte(c)
		}
	}
	return "", &Error{Reason: ReasonQuote, Detail: `"`}
}

// noControl refuses a control character wherever it appears, quoted or
// not. A command line carrying one is a line whose rendering, logging
// and parsing disagree about where it ends.
func noControl(s string) error {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return &Error{Reason: ReasonControl, Detail: fmt.Sprintf("%#02x", c)}
		}
	}
	return nil
}

// Parse splits a line and reads the family it names.
func Parse(line string) (*Command, error) {
	words, err := Split(line)
	if err != nil {
		return nil, err
	}
	c := &Command{Line: line, Kind: KindOther}
	// Leading assignments, which is how a shell is asked to run
	// something with an environment of its own.
	for len(words) > 0 && assignment(words[0].Text) {
		c.Env = append(c.Env, words[0].Text)
		words = words[1:]
	}
	if len(words) == 0 {
		return nil, &Error{Reason: ReasonEmpty, Detail: "assignments with no command"}
	}
	c.Words = words
	c.Path = words[0].Text
	c.Name = strings.TrimSuffix(path.Base(c.Path), ".exe")
	kind, ok := fileTransferNames[c.Name]
	if !ok {
		return c, nil
	}
	args := words[1:]
	switch kind {
	case KindSCP:
		s, err := parseSCP(args)
		if err != nil {
			return nil, err
		}
		c.Kind, c.SCP = KindSCP, s
	case KindRsync:
		r, err := parseRsync(args)
		if err != nil {
			return nil, err
		}
		c.Kind, c.Rsync = KindRsync, r
	case KindSFTPServer:
		s, err := parseSFTPServer(args)
		if err != nil {
			return nil, err
		}
		c.Kind, c.SFTPServer = KindSFTPServer, s
	case KindGit:
		g, err := parseGit(c.Name, args)
		if err != nil {
			return nil, err
		}
		c.Kind, c.Git = KindGit, g
	}
	return c, nil
}

// assignment reports whether a word is a VAR=value prefix rather than a
// command. A name with a slash or a dot in it is not one: "./x=y" is a
// program with an odd name, not an assignment.
func assignment(w string) bool {
	i := strings.IndexByte(w, '=')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := w[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && j > 0:
		default:
			return false
		}
	}
	return true
}

// scpServerFlags are the flags OpenSSH's scp takes when it is the far
// side of a copy. Anything else is a client-side flag or a flag no
// version has, and either way it is not a line this can read.
const scpServerFlags = "dfprtvOq"

func parseSCP(args []Word) (*SCP, error) {
	s := &SCP{}
	end := false
	for _, a := range args {
		if !end && a.Text == "--" {
			end = true
			continue
		}
		if !end && len(a.Text) > 1 && a.Text[0] == '-' && !a.Glob {
			for i := 1; i < len(a.Text); i++ {
				f := a.Text[i]
				if strings.IndexByte(scpServerFlags, f) < 0 {
					return nil, &Error{Reason: ReasonOption, Detail: "scp -" + string(f)}
				}
				s.Flags += string(f)
				switch f {
				case 't':
					if s.Direction == Download {
						return nil, &Error{Reason: ReasonOption, Detail: "scp -t and -f together"}
					}
					s.Direction = Upload
				case 'f':
					if s.Direction == Upload {
						return nil, &Error{Reason: ReasonOption, Detail: "scp -t and -f together"}
					}
					s.Direction = Download
				case 'r':
					s.Recursive = true
				case 'd':
					s.Directory = true
				case 'p':
					s.Preserve = true
				}
			}
			continue
		}
		s.Paths = append(s.Paths, a)
	}
	if len(s.Paths) == 0 {
		return nil, &Error{Reason: ReasonArguments, Detail: "scp names no path"}
	}
	return s, nil
}

// rsyncRefused are the options that make an rsync invocation something
// other than the far side of one client's transfer: a daemon, a shell
// of its own, or options the client chose for the server to apply.
var rsyncRefused = map[string]bool{
	"--daemon": true, "--config": true, "--no-detach": true,
	"--rsh": true, "--remote-option": true,
}

// rsyncDeletes are the options that remove files at the far end.
var rsyncDeletes = map[string]bool{
	"--delete": true, "--delete-before": true, "--delete-during": true,
	"--delete-delay": true, "--delete-after": true, "--delete-excluded": true,
	"--delete-missing-args": true, "--remove-source-files": true,
	"--remove-sent-files": true, "--force": true,
}

func parseRsync(args []Word) (*Rsync, error) {
	r := &Rsync{Direction: Upload}
	for _, a := range args {
		w := a.Text
		switch {
		case strings.HasPrefix(w, "--"):
			name := w
			if i := strings.IndexByte(w, '='); i > 0 {
				name = w[:i]
			}
			if rsyncRefused[name] {
				return nil, &Error{Reason: ReasonOption, Detail: "rsync " + name}
			}
			switch name {
			case "--server":
				r.Server = true
			case "--sender":
				// The server sends, so files leave the target.
				r.Direction = Download
			}
			if rsyncDeletes[name] {
				r.Deletes = true
			}
			r.Options = append(r.Options, w)
		case len(w) > 1 && w[0] == '-' && !a.Glob:
			// A short bundle, as a client sends it: "-vlogDtpre.iLsfxC".
			// The letters after an "e" are rsync's compatibility string
			// and not options at all, which is why this stops there
			// rather than reading them as flags.
			for i := 1; i < len(w); i++ {
				if w[i] == 'e' {
					break
				}
				if w[i] == 'M' {
					// -M is --remote-option: the client choosing what
					// the server applies, which is the one short flag
					// that can carry anything refused above.
					return nil, &Error{Reason: ReasonOption, Detail: "rsync -M"}
				}
			}
			r.Options = append(r.Options, w)
		default:
			r.Paths = append(r.Paths, a)
		}
	}
	if len(r.Paths) == 0 {
		return nil, &Error{Reason: ReasonArguments, Detail: "rsync names no path"}
	}
	return r, nil
}

// sftpServerValue are the sftp server options that take a value, and
// sftpServerFlags the ones that do not. What is left out is left out on
// purpose: -d moves the server's start directory, so a path the policy
// checks would no longer mean what it says, and -p and -P change which
// requests the server answers, which is this gateway's decision.
var (
	sftpServerValue = map[string]bool{"-l": true, "-f": true, "-u": true}
	sftpServerFlags = map[string]bool{"-e": true, "-R": true, "-h": true}
)

func parseSFTPServer(args []Word) (*SFTPServer, error) {
	s := &SFTPServer{}
	for i := 0; i < len(args); i++ {
		w := args[i].Text
		switch {
		case sftpServerFlags[w]:
			if w == "-R" {
				s.ReadOnly = true
			}
			s.Options = append(s.Options, w)
		case sftpServerValue[w]:
			if i+1 >= len(args) {
				return nil, &Error{Reason: ReasonArguments, Detail: "sftp server " + w + " with no value"}
			}
			s.Options = append(s.Options, w, args[i+1].Text)
			i++
		case len(w) > 2 && sftpServerValue[w[:2]]:
			s.Options = append(s.Options, w)
		default:
			return nil, &Error{Reason: ReasonOption, Detail: "sftp server " + w}
		}
	}
	return s, nil
}

// gitVerbs are the transport commands, and which way files move when
// one runs. The names are the server's point of view -- a fetch is
// "upload-pack" -- so they are mapped rather than read.
var gitVerbs = map[string]Direction{
	"upload-pack": Download, "upload-archive": Download, "receive-pack": Upload,
}

// gitOptions are the options a transport command takes that say nothing
// about which repository is reached.
var gitOptions = map[string]bool{"--strict": true, "--advertise-refs": true}

func parseGit(name string, args []Word) (*Git, error) {
	g := &Git{}
	verb := strings.TrimPrefix(name, "git-")
	if verb == "git" {
		// The two-word form, "git upload-pack /srv/repo".
		if len(args) == 0 {
			return nil, &Error{Reason: ReasonArguments, Detail: "git names no command"}
		}
		verb = args[0].Text
		args = args[1:]
	}
	dir, ok := gitVerbs[verb]
	if !ok {
		return nil, &Error{Reason: ReasonOption, Detail: "git " + verb}
	}
	g.Verb, g.Direction = verb, dir
	for _, a := range args {
		w := a.Text
		if strings.HasPrefix(w, "-") && !a.Glob {
			name := w
			if i := strings.IndexByte(w, '='); i > 0 {
				name = w[:i]
			}
			if !gitOptions[name] && name != "--timeout" {
				return nil, &Error{Reason: ReasonOption, Detail: "git " + name}
			}
			g.Options = append(g.Options, w)
			continue
		}
		if g.Path.Text != "" {
			return nil, &Error{Reason: ReasonArguments, Detail: "git names more than one repository"}
		}
		g.Path = a
	}
	if g.Path.Text == "" {
		return nil, &Error{Reason: ReasonArguments, Detail: "git names no repository"}
	}
	return g, nil
}
