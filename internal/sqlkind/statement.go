// Package sqlkind classifies a SQL statement by its shape, for the database
// relay kinds.
//
// The TFTP kind learned that a deny list of strings is a list of the spellings
// somebody thought of: it stops `../../etc/shadow` and not `..\..\etc\shadow`,
// stops that and not `/etc/shadow`. On SQL the same problem is worse, because
// the language has several kinds of quoting, comments with dialect-specific
// rules, and a hundred ways to write whitespace. A relay that searched a
// statement for "DROP" would be beaten by `DR/**/OP`, by `"DROP"`, and by a
// statement that mentions the word in a string literal and is perfectly
// innocent.
//
// So this package does the opposite. It reads the leading keyword of every
// statement in a message, having first skipped comments and quoted regions
// *properly*, and names the kind. The policy is then an allow list of kinds, and
// a statement whose kind this code cannot name is `Unknown`, which the policy
// refuses. That turns "did anybody think of this spelling" into "is this
// statement one of the shapes we allow" -- and the failure mode of a spelling
// nobody thought of becomes a refusal rather than a pass.
//
// Three things it deliberately gets conservative rather than right:
//
// A `WITH` statement may be a write. `WITH x AS (...) DELETE FROM y` is a
// DELETE wearing a SELECT's hat, and both dialects allow a data-modifying
// statement inside or after a common table expression. Rather than parse the CTE
// list, this scans the whole statement at top level for a writing keyword and,
// if it finds one, classifies the statement as that write. That can classify a
// read as a write, and it can never classify a write as a read. When a
// classifier has to be wrong, it must be wrong towards the more restricted
// answer.
//
// `EXPLAIN ANALYZE` executes the statement it explains. Plain EXPLAIN does not.
// So `EXPLAIN ANALYZE INSERT ...` is classified as the insert.
//
// `COPY` (PostgreSQL) and `LOAD DATA` (MySQL) are several operations wearing one
// keyword. `COPY t TO STDOUT` is bulk egress; `COPY t FROM PROGRAM 'curl ...'`
// runs a shell command as the server's operating-system user, which is remote
// code execution with a SQL keyword in front of it. The kind carries which, so a
// policy can allow the data ones and refuse the program one without an operator
// having to know that they share a verb.
//
// What it does not attempt at all is table names. Knowing which relations a
// statement touches means parsing SQL, including every alias, subquery, CTE and
// search-path interaction, and a relay that got that 95% right would be a relay
// whose policy has a 5% hole in exactly the place somebody is looking.
// Restricting a role's tables is the database's own job, done properly, with
// GRANT.
//
// # Dialects
//
// The lexical rules differ between the two dialects in ways that decide whether
// a keyword is visible at all, so the dialect is a parameter rather than an
// assumption:
//
//   - PostgreSQL nests block comments: `/* /* */ */` is one comment. MySQL does
//     not. A reader that got this backwards would either think a statement
//     resumed inside a comment, or think it ended inside one.
//   - PostgreSQL has dollar-quoted strings (`$tag$ ... $tag$`) with no escaping
//     inside at all, which is how a function body is written and the most
//     effective place to hide text from a naive reader.
//   - MySQL has `#` line comments and backtick-quoted identifiers.
//   - **MySQL has executable comments.** `/*! SELECT 1 */` and
//     `/*!80000 SELECT 1 */` are *code*, not comments: the server runs the
//     contents when the version matches. A lexer that treated them as comments
//     would miss every keyword inside one, which is exactly what they are used
//     for. They are therefore unwrapped and lexed as the statement they are.
//   - MySQL honours backslash escapes inside string literals by default;
//     PostgreSQL has not since standard_conforming_strings became the default in
//     9.1, so there `'\'` is a complete string containing one backslash.
package sqlkind

import "strings"

type Dialect int

// The dialects.
const (
	// PostgreSQL is the PostgreSQL lexical dialect.
	PostgreSQL Dialect = iota
	// MySQL is the MySQL and MariaDB dialect, which is also close enough to
	// TDS's for the keywords that matter; TDS uses its own value so the
	// difference can be made later without touching a policy.
	MySQL
	// TSQL is Microsoft's dialect: `--` and `/* */` comments that nest, and
	// bracket-quoted identifiers.
	TSQL
)

func (d Dialect) hashComments() bool     { return d == MySQL }
func (d Dialect) nestsComments() bool    { return d == PostgreSQL || d == TSQL }
func (d Dialect) dollarQuotes() bool     { return d == PostgreSQL }
func (d Dialect) backticks() bool        { return d == MySQL }
func (d Dialect) brackets() bool         { return d == TSQL }
func (d Dialect) execComments() bool     { return d == MySQL }
func (d Dialect) backslashEscapes() bool { return d == MySQL }

// Kind is what a statement does, as far as its leading keyword says.
type Kind string

// The statement kinds. The names are the ones a configuration writes.
const (
	// KindUnknown is a statement this classifier cannot name. The policy
	// refuses it, which is the whole point of classifying rather than
	// pattern-matching.
	KindUnknown Kind = "unknown"
	// The data statements.
	KindSelect Kind = "select"
	KindInsert Kind = "insert"
	KindUpdate Kind = "update"
	KindDelete Kind = "delete"
	KindMerge  Kind = "merge"
	// KindCopy moves bulk data, or runs a program. CopyTarget says which.
	KindCopy Kind = "copy"
	// The procedural ones. CALL and DO both run code the database holds, and
	// DO runs a block supplied in the statement -- in plpgsql by default,
	// which can do anything the role can.
	KindCall Kind = "call"
	KindDo   Kind = "do"
	// Session and transaction control.
	KindSet       Kind = "set"
	KindShow      Kind = "show"
	KindReset     Kind = "reset"
	KindBegin     Kind = "begin"
	KindCommit    Kind = "commit"
	KindRollback  Kind = "rollback"
	KindSavepoint Kind = "savepoint"
	KindLock      Kind = "lock"
	// The extended-protocol statements a client can also send as text.
	KindPrepare    Kind = "prepare"
	KindExecute    Kind = "execute"
	KindDeallocate Kind = "deallocate"
	KindDeclare    Kind = "declare"
	KindFetch      Kind = "fetch"
	KindMove       Kind = "move"
	KindCloseC     Kind = "close_cursor"
	KindExplain    Kind = "explain"
	// Asynchronous notification, which is a side channel between sessions.
	KindListen   Kind = "listen"
	KindNotify   Kind = "notify"
	KindUnlisten Kind = "unlisten"
	// KindDDL is every statement that changes the schema: CREATE, ALTER,
	// DROP, TRUNCATE, COMMENT, REINDEX, CLUSTER, REFRESH. They are one kind
	// because a policy that allows any of them on a production database has
	// already made the decision the others turn on.
	KindDDL Kind = "ddl"
	// KindGrant is GRANT, REVOKE and the role statements. Separate from DDL
	// because changing who may do what is a different decision from changing
	// what there is.
	KindGrant Kind = "grant"
	// KindMaintenance is VACUUM, ANALYZE, CHECKPOINT and friends.
	KindMaintenance Kind = "maintenance"
	// KindTransactionAdmin is the two-phase commit statements.
	KindTransactionAdmin Kind = "two_phase"
	// KindEmpty is a statement with nothing in it, which the protocol allows
	// and the server answers with EmptyQueryResponse.
	KindEmpty Kind = "empty"
)

// CopyTarget says which of the three COPY operations a COPY statement is.
type CopyTarget string

// The COPY targets.
const (
	// CopyNone is not a COPY.
	CopyNone CopyTarget = ""
	// CopyIn is COPY ... FROM STDIN: bulk ingest over the protocol.
	CopyIn CopyTarget = "in"
	// CopyOut is COPY ... TO STDOUT: bulk egress over the protocol.
	CopyOut CopyTarget = "out"
	// CopyFile is COPY ... TO or FROM a server-side path, which needs
	// superuser or pg_write_server_files and reads or writes the server's
	// own filesystem.
	CopyFile CopyTarget = "file"
	// CopyLocal is MySQL's LOAD DATA LOCAL INFILE: the *client* reads a path
	// and sends it, at the server's request. A compromised or hostile server
	// asks for /etc/passwd or a private key and the client obeys.
	CopyLocal CopyTarget = "local"
	// CopyProgram is COPY ... FROM PROGRAM or TO PROGRAM: the server runs a
	// shell command. This is remote code execution as the postgres user, and
	// it is the reason COPY is classified in this much detail.
	CopyProgram CopyTarget = "program"
)

// Statement is one statement out of a message.
type Statement struct {
	Kind Kind
	// Copy says which COPY this is, when Kind is KindCopy.
	Copy CopyTarget
	// Verb is the leading keyword as it was written, upper-cased, for the log
	// line. It is clipped, because it came off the network.
	Verb string
	// Writes says the statement can change data. It is derived from the kind
	// and is what `read_only` is checked against, so that a rule does not
	// have to list every writing kind.
	Writes bool
}

// Statements splits a message's text into statements and classifies each.
//
// The simple query protocol allows several statements in one message separated
// by semicolons, and runs them in one implicit transaction. That is also the
// delivery mechanism for every SQL injection that ends in `; DROP TABLE`, so
// every statement is classified and the caller applies its policy to all of
// them -- a relay that classified only the first would be a relay whose policy
// is bypassed by a semicolon.
//
// ok is false when the text cannot be lexed: an unterminated quote, an
// unterminated block comment, an unterminated dollar quote. Those are refused
// rather than classified, because the relay and the server would disagree about
// where the statement ends, and disagreeing about that is how a statement gets
// past a relay that read a different one.
func Statements(d Dialect, text string, max int) (out []Statement, ok bool) {
	parts, ok := split(d, text, max)
	if !ok {
		return nil, false
	}
	for _, p := range parts {
		out = append(out, classify(d, p))
	}
	if len(out) == 0 {
		out = append(out, Statement{Kind: KindEmpty})
	}
	return out, true
}

// split cuts text at top-level semicolons, skipping comments and every kind of
// quoted region. The returned parts keep their original text, because the
// classifier needs to look inside them.
func split(d Dialect, text string, max int) ([]string, bool) {
	var out []string
	start := 0
	i := 0
	for i < len(text) {
		switch {
		case text[i] == '-' && i+1 < len(text) && text[i+1] == '-',
			d.hashComments() && text[i] == '#':
			// Line comment to the end of the line, or the end of the text.
			j := strings.IndexByte(text[i:], '\n')
			if j < 0 {
				i = len(text)
			} else {
				i += j + 1
			}
		case text[i] == '/' && i+1 < len(text) && text[i+1] == '*':
			if d.execComments() && execComment(text, i) {
				// MySQL runs the contents of /*! ... */ and
				// /*!nnnnn ... */. Skipping it as a comment would hide
				// every keyword inside one, which is exactly what it is
				// used for: `/*!50000 DROP TABLE t */` is a DROP.
				i = skipExecOpen(text, i)
				continue
			}
			n, ok := blockComment(d, text, i)
			if !ok {
				return nil, false
			}
			i = n
		case text[i] == '\'':
			n, ok := quoted(d, text, i, '\'')
			if !ok {
				return nil, false
			}
			i = n
		case text[i] == '"',
			d.backticks() && text[i] == '`':
			n, ok := quoted(d, text, i, text[i])
			if !ok {
				return nil, false
			}
			i = n
		case d.brackets() && text[i] == '[':
			// T-SQL quotes an identifier in brackets, and doubles the closer
			// to escape it.
			n, ok := quoted(d, text, i, ']')
			if !ok {
				return nil, false
			}
			i = n
		case d.dollarQuotes() && text[i] == '$':
			n, ok, isQuote := dollarQuote(text, i)
			if !ok {
				return nil, false
			}
			if !isQuote {
				// A dollar sign that is not a quote: a positional parameter
				// like $1.
				i++
				continue
			}
			i = n
		case text[i] == ';':
			out = append(out, text[start:i])
			if max > 0 && len(out) > max {
				return nil, false
			}
			i++
			start = i
		default:
			i++
		}
	}
	if tail := text[start:]; strings.TrimSpace(strip(d, tail)) != "" {
		out = append(out, tail)
	}
	if max > 0 && len(out) > max {
		return nil, false
	}
	// Drop the empty parts a trailing or doubled semicolon leaves, but keep at
	// least nothing: a message of only semicolons is an empty query.
	kept := out[:0]
	for _, p := range out {
		if strings.TrimSpace(strip(d, p)) != "" {
			kept = append(kept, p)
		}
	}
	return kept, true
}

// blockComment returns the index just past a /* */ comment.
//
// PostgreSQL nests them, unlike the SQL standard: `/* /* */ */` is one comment
// and `/* /* */` is unterminated. A reader that stopped at the first `*/` would
// think the statement resumed inside a comment, which is a place to hide a
// keyword from exactly this classifier.
func blockComment(d Dialect, text string, i int) (int, bool) {
	depth := 0
	for i < len(text) {
		switch {
		case text[i] == '/' && i+1 < len(text) && text[i+1] == '*':
			depth++
			i += 2
		case text[i] == '*' && i+1 < len(text) && text[i+1] == '/':
			depth--
			i += 2
			// MySQL does not nest: the first close ends the comment however
			// many opens preceded it.
			if depth == 0 || !d.nestsComments() {
				return i, true
			}
		default:
			i++
		}
	}
	return 0, false
}

// quoted returns the index just past a single- or double-quoted region. A
// doubled quote inside is an escaped quote and does not end it.
//
// Backslash escapes are deliberately not honoured: standard_conforming_strings
// has been on by default since PostgreSQL 9.1, which means a backslash in an
// ordinary string literal is just a backslash, and `'\'` is a complete string
// containing one. A reader that treated it as an escape would think that string
// was unterminated and run on into the next one -- reading a different
// statement from the server's. E'...' strings *do* honour backslashes, and
// a relay cannot know which without tracking the session's setting, so an E
// string whose content ends in a backslash is the one case this reads
// differently from a server with escapes enabled; it is lexed as the standard
// says, and the statement is refused rather than guessed at if that leaves the
// text unterminated.
func quoted(d Dialect, text string, i int, q byte) (int, bool) {
	i++ // the opening quote
	for i < len(text) {
		// MySQL honours a backslash escape inside a string literal by default,
		// so a backslash-quote does not end the string. PostgreSQL has not
		// since 9.1, where the same two octets are a backslash then the
		// closing quote -- read the wrong way round, a reader runs on into the
		// next statement and decides about text the server never saw as one.
		if d.backslashEscapes() && text[i] == '\\' && q != '`' && q != ']' {
			i += 2
			continue
		}
		if text[i] != q {
			i++
			continue
		}
		if i+1 < len(text) && text[i+1] == q {
			i += 2
			continue
		}
		return i + 1, true
	}
	return 0, false
}

// dollarQuote returns the index just past a $tag$...$tag$ string.
//
// This is how a function body is written, and it is the most effective place to
// hide text from a naive reader, because the tag is chosen by whoever wrote the
// statement and there is no escaping inside at all. isQuote is false when the
// dollar sign was not opening one -- `$1` is a parameter placeholder.
func dollarQuote(text string, i int) (next int, ok, isQuote bool) {
	j := i + 1
	for j < len(text) && (text[j] == '_' || isAlpha(text[j]) || (j > i+1 && isDigit(text[j]))) {
		j++
	}
	if j >= len(text) || text[j] != '$' {
		return 0, true, false
	}
	tag := text[i : j+1]
	rest := text[j+1:]
	k := strings.Index(rest, tag)
	if k < 0 {
		return 0, false, true
	}
	return j + 1 + k + len(tag), true, true
}

// strip removes comments from a statement so the leading keyword can be read.
// It keeps quoted regions, because a quoted identifier is part of the
// statement.
func strip(d Dialect, text string) string {
	var b strings.Builder
	i := 0
	for i < len(text) {
		switch {
		case text[i] == '-' && i+1 < len(text) && text[i+1] == '-',
			d.hashComments() && text[i] == '#':
			j := strings.IndexByte(text[i:], '\n')
			if j < 0 {
				return b.String()
			}
			// A comment is whitespace, not nothing: `SEL--x\nECT` must not
			// become SELECT.
			b.WriteByte(' ')
			i += j + 1
		case text[i] == '/' && i+1 < len(text) && text[i+1] == '*':
			if d.execComments() && execComment(text, i) {
				// Unwrap it: the contents are code, so they are written out
				// and lexed as part of the statement.
				j := skipExecOpen(text, i)
				end, ok := blockComment(d, text, i)
				if !ok {
					b.WriteString(text[j:])
					return b.String()
				}
				b.WriteByte(' ')
				b.WriteString(text[j : end-2])
				b.WriteByte(' ')
				i = end
				continue
			}
			n, ok := blockComment(d, text, i)
			if !ok {
				return b.String()
			}
			b.WriteByte(' ')
			i = n
		case text[i] == '\'' || text[i] == '"' ||
			(d.backticks() && text[i] == '`'):
			n, ok := quoted(d, text, i, text[i])
			if !ok {
				b.WriteString(text[i:])
				return b.String()
			}
			b.WriteString(text[i:n])
			i = n
		case d.dollarQuotes() && text[i] == '$':
			n, ok, isQuote := dollarQuote(text, i)
			if !ok {
				b.WriteString(text[i:])
				return b.String()
			}
			if !isQuote {
				b.WriteByte(text[i])
				i++
				continue
			}
			b.WriteString(text[i:n])
			i = n
		default:
			b.WriteByte(text[i])
			i++
		}
	}
	return b.String()
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// words returns the upper-cased keywords of a stripped statement, outside
// quotes, up to a handful -- enough to recognise EXPLAIN ANALYZE and a data
// modifying CTE without walking a long statement twice.
func words(d Dialect, stripped string, max int) []string {
	var out []string
	i := 0
	for i < len(stripped) && len(out) < max {
		c := stripped[i]
		switch {
		case isAlpha(c) || c == '_':
			j := i
			for j < len(stripped) && (isAlpha(stripped[j]) || isDigit(stripped[j]) || stripped[j] == '_') {
				j++
			}
			out = append(out, strings.ToUpper(stripped[i:j]))
			i = j
		case c == '\'' || c == '"' || (d.backticks() && c == '`'):
			n, ok := quoted(d, stripped, i, c)
			if !ok {
				return out
			}
			i = n
		case d.dollarQuotes() && c == '$':
			n, ok, isQuote := dollarQuote(stripped, i)
			if !ok || !isQuote {
				i++
				continue
			}
			i = n
		default:
			i++
		}
	}
	return out
}

// leadingKinds maps a statement's first keyword to its kind, for the keywords
// both dialects share.
//
// The dialect-specific tables are separate rather than merged, and that matters:
// `FLUSH PRIVILEGES` is a MySQL statement and a PostgreSQL syntax error, so a
// shared table would make the PostgreSQL relay classify it as an ordinary
// maintenance statement -- which a policy might allow -- instead of `unknown`,
// which a policy always refuses. Merging the tables would make each dialect's
// relay *less* strict by exactly the other dialect's vocabulary.
var leadingKinds = map[string]Kind{
	"SELECT": KindSelect, "TABLE": KindSelect, "VALUES": KindSelect,
	"INSERT": KindInsert, "UPDATE": KindUpdate, "DELETE": KindDelete,
	"MERGE": KindMerge, "CALL": KindCall, "DO": KindDo,
	"SET": KindSet, "SHOW": KindShow, "RESET": KindReset,
	"BEGIN": KindBegin, "START": KindBegin,
	"COMMIT": KindCommit, "END": KindCommit,
	"ROLLBACK": KindRollback, "ABORT": KindRollback,
	"SAVEPOINT": KindSavepoint, "RELEASE": KindSavepoint, "LOCK": KindLock,
	"PREPARE": KindPrepare, "EXECUTE": KindExecute, "DEALLOCATE": KindDeallocate,
	"DECLARE": KindDeclare, "FETCH": KindFetch, "MOVE": KindMove,
	"CLOSE": KindCloseC, "EXPLAIN": KindExplain,
	"CREATE": KindDDL, "ALTER": KindDDL, "DROP": KindDDL, "TRUNCATE": KindDDL,
	"COMMENT": KindDDL, "REINDEX": KindDDL, "RENAME": KindDDL,
	"GRANT": KindGrant, "REVOKE": KindGrant,
	"ANALYZE": KindMaintenance, "ANALYSE": KindMaintenance,
}

// pgKinds are the keywords only PostgreSQL has.
var pgKinds = map[string]Kind{
	"COPY": KindCopy, "LISTEN": KindListen, "NOTIFY": KindNotify,
	"UNLISTEN": KindUnlisten, "CLUSTER": KindDDL, "REFRESH": KindDDL,
	"IMPORT": KindDDL, "SECURITY": KindDDL, "VACUUM": KindMaintenance,
	"CHECKPOINT": KindMaintenance, "DISCARD": KindMaintenance,
	"LOAD": KindMaintenance,
}

// myKinds are the keywords only MySQL and MariaDB have.
//
// LOAD is KindCopy rather than maintenance because `LOAD DATA [LOCAL] INFILE`
// is the bulk data path, and the LOCAL form asks the *client* to read a file
// and send it -- which is how a hostile or compromised server reads the
// filesystem of whatever connected to it.
var myKinds = map[string]Kind{
	"LOAD": KindCopy, "REPLACE": KindInsert, "HANDLER": KindSelect,
	"DESCRIBE": KindShow, "DESC": KindShow, "USE": KindSet,
	"FLUSH": KindMaintenance, "OPTIMIZE": KindMaintenance, "REPAIR": KindMaintenance,
	"CHECK": KindMaintenance, "CHECKSUM": KindMaintenance, "KILL": KindMaintenance,
	"PURGE": KindMaintenance, "BINLOG": KindMaintenance, "CACHE": KindMaintenance,
	"STOP": KindMaintenance, "SHUTDOWN": KindMaintenance, "RESTART": KindMaintenance,
	"INSTALL": KindDDL, "UNINSTALL": KindDDL, "CHANGE": KindDDL,
	"SIGNAL": KindCall, "RESIGNAL": KindCall, "XA": KindTransactionAdmin,
}

// tsqlKinds are the keywords only Microsoft's dialect has.
var tsqlKinds = map[string]Kind{
	"EXEC": KindExecute, "GO": KindEmpty, "USE": KindSet,
	"BULK": KindCopy, "PRINT": KindSelect, "RAISERROR": KindCall,
	"THROW": KindCall, "BACKUP": KindMaintenance, "RESTORE": KindMaintenance,
	"DBCC": KindMaintenance, "KILL": KindMaintenance, "SHUTDOWN": KindMaintenance,
	"DENY": KindGrant, "WAITFOR": KindMaintenance,
}

// kindOfWord resolves a keyword in one dialect.
func kindOfWord(d Dialect, w string) (Kind, bool) {
	var extra map[string]Kind
	switch d {
	case PostgreSQL:
		extra = pgKinds
	case MySQL:
		extra = myKinds
	case TSQL:
		extra = tsqlKinds
	}
	if k, ok := extra[w]; ok {
		return k, true
	}
	k, ok := leadingKinds[w]
	return k, ok
}

// writingKinds are the kinds that can change data. CALL and DO are here because
// a procedure and an anonymous block can do anything the role can, and a relay
// that called them reads is a relay whose read_only setting is decorative.
var writingKinds = map[Kind]bool{
	KindInsert: true, KindUpdate: true, KindDelete: true, KindMerge: true,
	KindCopy: true, KindCall: true, KindDo: true, KindDDL: true,
	KindGrant: true, KindMaintenance: true, KindTransactionAdmin: true,
	KindUnknown: true,
}

// classify names one statement.
func classify(d Dialect, text string) Statement {
	stripped := strip(d, text)
	w := words(d, stripped, 24)
	if len(w) == 0 {
		return Statement{Kind: KindEmpty}
	}
	st := Statement{Verb: Clip(w[0])}
	switch w[0] {
	case "WITH":
		// A common table expression may end in a write. Look at top level for
		// a writing keyword rather than parsing the CTE list: wrong towards
		// the restricted answer is the only direction a classifier may be
		// wrong in.
		st.Kind = KindSelect
		for _, k := range w[1:] {
			if kd, ok := kindOfWord(d, k); ok && writingKinds[kd] {
				st.Kind = kd
				break
			}
		}
	case "EXPLAIN":
		// ANALYZE runs the statement. Without it, nothing is executed.
		st.Kind = KindExplain
		if hasWord(w[1:], "ANALYZE") || hasWord(w[1:], "ANALYSE") {
			for _, k := range w[1:] {
				// ANALYZE is itself a maintenance statement, so the word that
				// told us the statement executes must not be the word we
				// classify it as.
				if k == "ANALYZE" || k == "ANALYSE" {
					continue
				}
				if kd, ok := kindOfWord(d, k); ok && writingKinds[kd] {
					st.Kind = kd
					break
				}
			}
		}
	case "PREPARE":
		// PREPARE TRANSACTION is two-phase commit, not a prepared statement.
		st.Kind = KindPrepare
		if hasWord(w[1:], "TRANSACTION") {
			st.Kind = KindTransactionAdmin
		}
	case "COMMIT", "ROLLBACK":
		st.Kind = leadingKinds[w[0]]
		if hasWord(w[1:], "PREPARED") {
			st.Kind = KindTransactionAdmin
		}
	default:
		kd, ok := kindOfWord(d, w[0])
		if !ok {
			return Statement{Kind: KindUnknown, Verb: st.Verb, Writes: true}
		}
		st.Kind = kd
	}
	if st.Kind == KindCopy {
		st.Copy = copyTarget(w)
	}
	st.Writes = writingKinds[st.Kind]
	return st
}

// copyTarget says which COPY this is.
//
// PROGRAM is checked first and regardless of direction, because both `FROM
// PROGRAM` and `TO PROGRAM` run a command and the difference between them is
// only which way the output goes.
func copyTarget(w []string) CopyTarget {
	if hasWord(w, "PROGRAM") {
		return CopyProgram
	}
	// MySQL's LOAD DATA LOCAL INFILE is its own hazard and its own target.
	// The server sends a packet asking the *client* to open a path and send
	// it, and the client obeys if local_infile is on -- which it is by
	// default in several drivers. That is a server reading the filesystem of
	// whatever connected to it, and it is the reason `local` is a target a
	// policy can name and refuse.
	if hasWord(w, "LOAD") {
		switch {
		case hasWord(w, "LOCAL"):
			return CopyLocal
		case hasWord(w, "INFILE"):
			return CopyFile
		}
		return CopyFile
	}
	switch {
	case hasWord(w, "STDIN"):
		return CopyIn
	case hasWord(w, "STDOUT"):
		return CopyOut
	}
	// Neither STDIN nor STDOUT nor PROGRAM: the target is a path on the
	// server, which needs a privileged role and touches the server's own
	// filesystem.
	return CopyFile
}

func hasWord(w []string, want string) bool {
	for _, s := range w {
		if s == want {
			return true
		}
	}
	return false
}

// KindOf reads a kind the way a configuration writes it.
func KindOf(s string) (Kind, bool) {
	k := Kind(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := writingKinds[k]; ok {
		return k, k != KindUnknown
	}
	switch k {
	case KindSelect, KindExplain, KindShow, KindSet, KindReset, KindBegin,
		KindCommit, KindRollback, KindSavepoint, KindLock, KindPrepare,
		KindExecute, KindDeallocate, KindDeclare, KindFetch, KindMove,
		KindCloseC, KindListen, KindNotify, KindUnlisten, KindEmpty:
		return k, true
	}
	return "", false
}

// Kinds is every kind a configuration may name, in a useful order.
func Kinds() []Kind {
	return []Kind{KindSelect, KindInsert, KindUpdate, KindDelete, KindMerge,
		KindCopy, KindCall, KindDo, KindExplain, KindShow, KindSet, KindReset,
		KindBegin, KindCommit, KindRollback, KindSavepoint, KindLock,
		KindPrepare, KindExecute, KindDeallocate, KindDeclare, KindFetch,
		KindMove, KindCloseC, KindListen, KindNotify, KindUnlisten,
		KindDDL, KindGrant, KindMaintenance, KindTransactionAdmin, KindEmpty}
}

// KindNames is Kinds as a configuration spells them.
func KindNames() []string {
	ks := Kinds()
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, string(k))
	}
	return out
}

// MaxVerb bounds the leading keyword kept for a log line. It came off the
// network, so it is clipped here rather than at each reader.
const MaxVerb = 64

// Clip bounds a peer-chosen string.
func Clip(s string) string {
	if len(s) <= MaxVerb {
		return s
	}
	return s[:MaxVerb] + "..."
}

// execComment says whether a /* at i opens a MySQL executable comment.
//
// `/*!` and `/*!nnnnn` are not comments: the server executes what is inside
// when the version matches, and `/*!` with no number executes unconditionally.
// They exist so that a dump can carry MySQL-only syntax past other servers, and
// they are the single most effective way to hide a keyword from a reader that
// skips comments. `/*+ hint */` is an optimiser hint and *is* skipped, because
// it cannot carry a statement.
func execComment(text string, i int) bool {
	return i+2 < len(text) && text[i+2] == '!'
}

// skipExecOpen returns the index just past `/*!` and any version digits.
func skipExecOpen(text string, i int) int {
	j := i + 3 // past the /*!
	for j < len(text) && isDigit(text[j]) {
		j++
	}
	return j
}
