package sshcmd

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// The splitter, on arbitrary lines.
//
// This package decides what an SSH exec request means, and a policy above it
// refuses or allows on the words it returns. So a mis-split is not a crash but a
// bypass: if the words a rule is checked against are not the words the target's
// shell will run, the rule was checked against something that never happens.
// That makes this the one parser here where the interesting failure is a wrong
// answer rather than a panic, and the assertions below are written for that.
//
// What is asserted:
//
//   - every refusal names one of the reasons this package documents, because a
//     caller switches on them and an unnamed one falls through to a default that
//     was written for something else;
//   - an accepted line's words are within the bounds the doc comment promises;
//   - no word carries a control character *other than tab*, which is the
//     guarantee noControl gives: a word with a newline in it is one a log line
//     cannot hold and a shell may read as two. Tab is exempt on purpose -- it is
//     whitespace outside quotes and a legitimate byte in a path inside them --
//     and the fuzzer found that exemption within two seconds of starting, which
//     is a good sign about the fuzzer and the reason the seed below is explicit;
//   - and the round trip. Quoting the words a line produced and splitting that
//     again must give back the same words. This is the closest a test can get to
//     "the words the policy checks are the words the target will run" without a
//     shell to ask: a splitter that loses a quote, eats an escape or joins two
//     words fails it.
func FuzzSplit(f *testing.F) {
	for _, seed := range []string{
		`ls -la /srv`,
		`scp -t /srv/incoming`,
		`scp -f -- '/srv/a b/c'`,
		`rsync --server -vlogDtpre.iLsfxC . /data/`,
		`git-upload-pack '/srv/git/repo.git'`,
		`internal-sftp -R`,
		`FOO=bar BAZ=qux /usr/bin/scp -t /tmp`,
		`echo "a b\"c"`,
		`echo 'a;b|c&d'`,
		`echo a\ b`,
		// A tab inside single quotes: accepted, because noControl exempts tab.
		"'\t'",
		// And one outside them, where it is whitespace and separates words.
		"a\tb",
		`ls *.conf`,
		`ls ~/x`,
		`ls "$HOME"`,
		`a; b`,
		`a && b`,
		"a\nb",
		`a "unterminated`,
		`a 'unterminated`,
		`trailing\`,
		``,
		`   `,
		strings.Repeat("a ", 300),
		strings.Repeat("x", MaxLine+1),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, line string) {
		words, err := Split(line)
		if err != nil {
			expectedReason(t, err)
			if words != nil {
				t.Fatalf("Split(%q) returned words with an error", line)
			}
			return
		}
		if len(words) == 0 {
			t.Fatalf("Split(%q) accepted a line and returned no words; the caller "+
				"reads words[0] as the program", line)
		}
		if len(words) > MaxWords {
			t.Fatalf("Split(%q) returned %d words, past MaxWords", line, len(words))
		}
		if len(line) > MaxLine {
			t.Fatalf("Split accepted a line of %d bytes, past MaxLine", len(line))
		}
		for i, w := range words {
			for _, r := range w.Text {
				if (r < 0x20 && r != '\t') || r == 0x7f {
					t.Fatalf("Split(%q) word %d = %q carries control %#02x", line, i, w.Text, r)
				}
			}
		}

		// The round trip. Every word is requoted in single quotes, which a shell
		// reads literally, so splitting the result must give the same text back.
		// Glob-ness is deliberately not preserved: quoting is what takes a glob's
		// meaning away, so the requoted words must all report Glob false.
		quoted := make([]string, 0, len(words))
		for _, w := range words {
			quoted = append(quoted, "'"+strings.ReplaceAll(w.Text, "'", `'\''`)+"'")
		}
		again, err := Split(strings.Join(quoted, " "))
		if err != nil {
			// The one legitimate reason: quoting adds two bytes per word, so a
			// line near the bound can cross it.
			var e *Error
			if errors.As(err, &e) && (e.Reason == ReasonTooLong || e.Reason == ReasonEmpty) {
				return
			}
			t.Fatalf("Split(%q) gave %d words that do not split again: %v", line, len(words), err)
		}
		if len(again) != len(words) {
			t.Fatalf("Split(%q) gave %d words; requoted they split into %d",
				line, len(words), len(again))
		}
		for i := range words {
			if again[i].Text != words[i].Text {
				t.Fatalf("Split(%q) word %d = %q; requoted it came back %q",
					line, i, words[i].Text, again[i].Text)
			}
			if again[i].Glob {
				t.Fatalf("word %d = %q reported a glob after being quoted", i, again[i].Text)
			}
		}
	})
}

// Parse, on arbitrary lines: the family recognition above the splitter.
//
// A wrong family is the same class of failure as a wrong split. If an scp is read
// as KindOther, the policy that bounds file transfers never runs on it; if
// something that is not an scp is read as one, a rule about paths is applied to
// words that are not paths.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`scp -t /srv`,
		`scp -f /srv/x`,
		`scp`,
		`/usr/libexec/openssh/sftp-server`,
		`rsync --server --sender -e.iLsfxC . /data`,
		`rsync --server --delete . /data`,
		`git-receive-pack 'repo.git'`,
		`git upload-pack repo.git`,
		`scp.exe -t /srv`,
		`FOO=1 scp -t /srv`,
		`FOO=1`,
		`not-a-transfer --server`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, line string) {
		c, err := Parse(line)
		if err != nil {
			expectedReason(t, err)
			return
		}
		if c == nil {
			t.Fatal("Parse returned no command and no error")
		}
		if c.Line != line {
			t.Fatalf("Parse(%q) recorded the line as %q", line, c.Line)
		}
		switch c.Kind {
		case KindSCP, KindRsync, KindSFTPServer, KindGit, KindOther:
		default:
			t.Fatalf("Parse(%q) returned kind %q, which no caller handles", line, c.Kind)
		}
		if len(c.Words) == 0 {
			t.Fatalf("Parse(%q) returned no words", line)
		}
		if c.Path != c.Words[0].Text {
			t.Fatalf("Parse(%q): Path %q is not the first word %q", line, c.Path, c.Words[0].Text)
		}
		if !utf8.ValidString(c.Name) && utf8.ValidString(line) {
			t.Fatalf("Parse(%q) produced an invalid name %q from valid input", line, c.Name)
		}
		// Every assignment recorded is one a shell would read as one.
		for _, e := range c.Env {
			if !assignment(e) {
				t.Fatalf("Parse(%q) recorded %q as an assignment", line, e)
			}
		}
		// A direction is only ever one of the three, and only a family that
		// carries files has one.
		dir := direction(c)
		switch dir {
		case Upload, Download, Neither:
		default:
			t.Fatalf("Parse(%q) returned direction %q", line, dir)
		}
		if c.Kind == KindOther && dir != Neither {
			t.Fatalf("Parse(%q) gave an unrecognised command the direction %q", line, dir)
		}
		// Paths a family parser reports are words from the line, not values it
		// invented: a policy checks them against patterns, so one that came from
		// nowhere is a rule applied to something nobody sent.
		for _, p := range paths(c) {
			if !fromWords(c.Words, p) {
				t.Fatalf("Parse(%q) reported path %q, which is not one of its words", line, p.Text)
			}
		}
	})
}

// expectedReason fails on any refusal that is not one this package documents.
func expectedReason(t *testing.T, err error) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an *Error, so a caller cannot read its reason", err)
	}
	switch e.Reason {
	case ReasonEmpty, ReasonTooLong, ReasonTooManyWords, ReasonQuote, ReasonEscape,
		ReasonOperator, ReasonSubstitution, ReasonControl, ReasonOption, ReasonArguments:
		return
	}
	t.Fatalf("refusal reason %q is not one of the documented ones", e.Reason)
}

// direction and paths read whichever family is set, so the assertions above do
// not have to repeat the switch.
func direction(c *Command) Direction {
	switch {
	case c.SCP != nil:
		return c.SCP.Direction
	case c.Rsync != nil:
		return c.Rsync.Direction
	case c.Git != nil:
		return c.Git.Direction
	}
	return Neither
}

func paths(c *Command) []Word {
	switch {
	case c.SCP != nil:
		return c.SCP.Paths
	case c.Rsync != nil:
		return c.Rsync.Paths
	case c.Git != nil:
		if c.Git.Path.Text == "" {
			return nil
		}
		return []Word{c.Git.Path}
	}
	return nil
}

func fromWords(words []Word, p Word) bool {
	for _, w := range words {
		if w.Text == p.Text {
			return true
		}
	}
	return false
}
