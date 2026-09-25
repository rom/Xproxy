package sqlkind

import "testing"

// The classifier runs on a string the client chose, on every statement, and its
// output decides whether that statement crosses. So the invariant the fuzzer
// checks is not a shape but the safety direction: whatever comes back must never
// be *less* restricted than the truth.
//
// Every dialect is fuzzed with the same corpus, because the lexical rules differ
// and a string that is a comment in one is code in another -- which is the whole
// reason the dialect is a parameter.
func FuzzStatements(f *testing.F) {
	f.Add("SELECT 1")
	f.Add("SELECT 1; DROP TABLE t")
	f.Add("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x")
	f.Add("COPY t FROM PROGRAM 'id'")
	f.Add("LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t")
	f.Add("DO $$ BEGIN PERFORM 1; END $$")
	f.Add("/* /* nested */ */ SELECT 1")
	f.Add("/*!50000 DROP TABLE t */")
	f.Add("# a comment\nSELECT `DROP`")
	f.Add(`SELECT 'a\'; DROP TABLE t'`)
	f.Add("SELECT [DROP]")
	f.Fuzz(func(t *testing.T, sql string) {
		for _, d := range []Dialect{PostgreSQL, MySQL, TSQL} {
			got, ok := Statements(d, sql, 64)
			if !ok {
				continue
			}
			if len(got) == 0 {
				t.Fatalf("dialect %d: a lexed statement list is empty: %q", d, sql)
			}
			for _, st := range got {
				// Every statement gets a kind, and unknown is the one that
				// means "this code could not read it". It must count as a
				// write, because that is what makes an allow list of kinds and
				// read_only both refuse it without an operator having to think
				// about the unknown case at all.
				if st.Kind == "" {
					t.Fatalf("dialect %d: a statement with no kind: %q", d, sql)
				}
				if st.Kind == KindUnknown && !st.Writes {
					t.Fatalf("dialect %d: an unreadable statement that does not count as a write: %q", d, sql)
				}
				// A bulk-data statement always says which operation it is, and
				// nothing else ever claims to be one.
				if (st.Kind == KindCopy) != (st.Copy != CopyNone) {
					t.Fatalf("dialect %d: copy target %q on kind %s: %q", d, st.Copy, st.Kind, sql)
				}
				// The verb goes in a log line, so it is bounded.
				if len(st.Verb) > MaxVerb+3 {
					t.Fatalf("dialect %d: an unclipped verb: %d octets", d, len(st.Verb))
				}
			}
			// A kind the classifier produced must be one a configuration can
			// name, or `unknown`. Otherwise a policy could never allow
			// something the classifier emits, and the kind would be
			// unreachable rather than refused.
			for _, st := range got {
				if st.Kind == KindUnknown {
					continue
				}
				if _, ok := KindOf(string(st.Kind)); !ok {
					t.Fatalf("dialect %d: %s is emitted but not nameable: %q", d, st.Kind, sql)
				}
			}
		}
	})
}
