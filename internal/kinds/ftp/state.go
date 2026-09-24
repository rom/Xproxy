package ftp

import (
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	wire "github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/textsafe"
)

// The two commands that are only meaningful as half of a pair, and the
// canonicalisation every path argument goes through.
//
// A proxy that reads FTP one command at a time can hold a policy over
// each command and still miss what a pair of them does. REST followed by
// STOR is not an upload of the bytes that arrive: it is an edit of a file
// at an offset, and the bytes that arrive are a fragment. RNFR followed
// by RNTO is not two path decisions: it is one move, and a proxy that
// forgot the first has nothing to match the second against.

// restartBound is the largest offset this proxy will relay. RFC 3659
// makes the marker a decimal number with no stated bound; a file offset
// past a terabyte is not a resumed upload.
const restartBound = 1 << 40

// restartKeeps are the commands a restart marker survives: the ones a
// client sends between REST and the transfer that uses it.
//
// RFC 3659 section 5 says the marker is reset by anything that is not the
// restarted transfer, which read strictly would reset it on the PASV
// every client sends next. So the set is the transfer setup -- the data
// connection, the type, the protection -- and everything else clears it,
// which is both what a server does in practice and what stops a marker
// from outliving the exchange it was for.
var restartKeeps = map[string]bool{
	"REST": true,
	"PASV": true, "EPSV": true, "PORT": true, "EPRT": true,
	"TYPE": true, "MODE": true, "STRU": true,
	"PBSZ": true, "PROT": true,
}

// restart reads a REST command. The offset is kept rather than
// forwarded blind, because the commands that follow mean something
// different once it is set.
func (se *session) restartCmd(c wire.Command) (bool, string) {
	arg := strings.TrimSpace(c.Arg)
	n, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || n < 0 || n > restartBound || arg != strconv.FormatInt(n, 10) {
		// Anything but a plain non-negative decimal. RFC 3659 allows a
		// marker a server defines itself, which is a value this proxy
		// cannot reason about and so will not carry.
		if !se.refuse(501, "the restart marker must be a byte offset", "rest_invalid", textsafe.Clip64(arg)) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	se.pendingRestart = n
	return se.relay(c)
}

// restartAllowed decides a transfer that follows a REST. It returns the
// reason to refuse, or empty.
//
// The offset is where a resumed transfer is a hole in two policies at
// once, and neither is obvious from one command:
//
//   - A scanner sees the bytes that cross the proxy. With an offset,
//     those are a fragment of the file, so a rule set that would match
//     the whole never sees it: upload the first half, then REST to the
//     middle and upload the second, and each half passes. Refusing is
//     the only honest answer -- the proxy cannot scan bytes it will
//     never be shown.
//   - max_file_bytes counts what crosses the proxy, and the file ends up
//     the offset plus that. Here the offset is counted towards the
//     bound, which is what makes the bound about the file rather than
//     about one transfer.
func (se *session) restartAllowed(c wire.Command) string {
	if se.restart == 0 {
		return ""
	}
	upload := wire.Uploads[c.Verb]
	scanned := upload && se.policy.yara != nil
	if se.t.icapFor(upload) != nil && wire.Uploads[c.Verb] == upload {
		scanned = true
	}
	if scanned {
		return "rest_unscannable"
	}
	return ""
}

// renameTo decides an RNTO, which is only meaningful after an RNFR the
// server accepted. Without one there is no rename to complete, and a
// proxy that relayed it would be forwarding half a decision.
func (se *session) renameTo(c wire.Command) (bool, string) {
	if se.renameFrom == "" {
		if !se.refuse(503, "send RNFR first", "rename_out_of_order", c.Verb) {
			return true, "too_many_errors"
		}
		return false, ""
	}
	return se.relay(c)
}

// pathShape rejects the argument shapes a proxy and a server would read
// differently. It returns the reason to refuse, or empty.
//
// Each of these is a way for the path the policy matched and the path the
// server opened to be two different files:
//
//   - A backslash is a separator on a Windows server and an ordinary
//     character in a pattern here, so "/srv/exports\..\..\etc" is inside
//     the allowed tree as far as this proxy can tell and outside it as
//     far as the server is concerned. There is no escaping that works for
//     both, so it is refused.
//   - A control character is not part of a name anybody needs, and a
//     carriage return in particular is the first half of a command the
//     server reads and the proxy did not.
//   - Bytes that are not valid UTF-8 cannot be compared against a
//     pattern with any confidence about what the server will make of
//     them -- an overlong or truncated sequence is a different string on
//     each side. A server that has agreed OPTS UTF8 ON is sending UTF-8;
//     one that has not is sending bytes this proxy will not guess the
//     encoding of.
func pathShape(arg string) string {
	if strings.ContainsRune(arg, '\\') {
		return "path_separator"
	}
	for _, r := range arg {
		if r < 0x20 || r == 0x7f {
			return "path_control"
		}
	}
	if !utf8.ValidString(arg) {
		return "path_encoding"
	}
	return ""
}

// cleanArg is the absolute path a command's argument names, as the proxy
// follows it. It is here rather than inline so the rename pair and the
// path policy resolve a name the same way.
func (se *session) cleanArg(arg string) string { return path.Clean(se.resolve(arg)) }
