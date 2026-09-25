package pgwire

import "github.com/rom/xproxy/internal/sqlkind"

// The statement classifier lives in internal/sqlkind, because MySQL and TDS need
// the same vocabulary with different lexical rules and two copies of a
// six-hundred-line lexer would drift. These aliases keep the names this
// package's callers already use.
type (
	// Kind is what a statement does.
	Kind = sqlkind.Kind
	// CopyTarget says which bulk-data operation a statement is.
	CopyTarget = sqlkind.CopyTarget
	// Statement is one classified statement.
	Statement = sqlkind.Statement
)

// The statement kinds.
const (
	KindUnknown          = sqlkind.KindUnknown
	KindSelect           = sqlkind.KindSelect
	KindInsert           = sqlkind.KindInsert
	KindUpdate           = sqlkind.KindUpdate
	KindDelete           = sqlkind.KindDelete
	KindMerge            = sqlkind.KindMerge
	KindCopy             = sqlkind.KindCopy
	KindCall             = sqlkind.KindCall
	KindDo               = sqlkind.KindDo
	KindSet              = sqlkind.KindSet
	KindShow             = sqlkind.KindShow
	KindReset            = sqlkind.KindReset
	KindBegin            = sqlkind.KindBegin
	KindCommit           = sqlkind.KindCommit
	KindRollback         = sqlkind.KindRollback
	KindSavepoint        = sqlkind.KindSavepoint
	KindLock             = sqlkind.KindLock
	KindPrepare          = sqlkind.KindPrepare
	KindExecute          = sqlkind.KindExecute
	KindDeallocate       = sqlkind.KindDeallocate
	KindDeclare          = sqlkind.KindDeclare
	KindFetch            = sqlkind.KindFetch
	KindMove             = sqlkind.KindMove
	KindCloseC           = sqlkind.KindCloseC
	KindExplain          = sqlkind.KindExplain
	KindListen           = sqlkind.KindListen
	KindNotify           = sqlkind.KindNotify
	KindUnlisten         = sqlkind.KindUnlisten
	KindDDL              = sqlkind.KindDDL
	KindGrant            = sqlkind.KindGrant
	KindMaintenance      = sqlkind.KindMaintenance
	KindTransactionAdmin = sqlkind.KindTransactionAdmin
	KindEmpty            = sqlkind.KindEmpty
)

// The COPY targets.
const (
	CopyNone    = sqlkind.CopyNone
	CopyIn      = sqlkind.CopyIn
	CopyOut     = sqlkind.CopyOut
	CopyFile    = sqlkind.CopyFile
	CopyLocal   = sqlkind.CopyLocal
	CopyProgram = sqlkind.CopyProgram
)

// Statements classifies the statements in a message, in PostgreSQL's dialect.
func Statements(text string, max int) ([]Statement, bool) {
	return sqlkind.Statements(sqlkind.PostgreSQL, text, max)
}

// KindOf reads a kind the way a configuration writes it.
func KindOf(s string) (Kind, bool) { return sqlkind.KindOf(s) }

// Kinds is every kind a configuration may name.
func Kinds() []Kind { return sqlkind.Kinds() }

// KindNames is Kinds as a configuration spells them.
func KindNames() []string { return sqlkind.KindNames() }
