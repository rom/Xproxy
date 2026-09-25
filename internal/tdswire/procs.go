package tdswire

import "sort"

// Which procedures a relay lets through, and which it refuses whatever the mode.
//
// SQL Server's real hazards are not statements. They are procedures, and they are
// the reason a T-SQL relay needs a procedure policy as well as a statement one:
// `xp_cmdshell 'whoami'` is a shell command running as the service account, and
// to a statement classifier it is an EXECUTE. The statement policy would have to
// refuse every EXECUTE to catch it, which would refuse every stored procedure in
// the estate.
//
// So this is an allow list of procedures, the same inversion the statement
// classifier makes: a procedure nobody thought of is refused, rather than a
// procedure somebody remembered to write down. The default list is what a client
// library calls -- the dynamic-SQL family, the cursor family, and the metadata
// calls JDBC and ODBC make to describe a result set -- and nothing else.

// DefaultProcedures is the allow list a listener uses when the configuration
// names none.
//
// Everything here is something a driver calls on its own behalf. The absences are
// the point: every `xp_`, every `sp_oa`, sp_configure, sp_addlinkedserver and
// sp_send_dbmail are off until an operator names them.
func DefaultProcedures() []string {
	return []string{
		// Dynamic SQL and prepared statements: what a parameterised query is.
		"sp_executesql", "sp_prepare", "sp_prepexec", "sp_execute", "sp_unprepare",
		// Cursors.
		"sp_cursor", "sp_cursoropen", "sp_cursorprepare", "sp_cursorexecute",
		"sp_cursorprepexec", "sp_cursorfetch", "sp_cursoroption",
		"sp_cursorclose", "sp_cursorunprepare",
		// What a connection pool calls when it hands a connection on.
		"sp_reset_connection",
		// The metadata calls a driver makes to describe parameters and results.
		// A relay that refused these would break every JDBC and ODBC
		// application while allowing the queries they then run, which is the
		// wrong way round.
		"sp_describe_first_result_set", "sp_describe_undeclared_parameters",
		"sp_datatype_info", "sp_tables", "sp_columns", "sp_sproc_columns",
		"sp_pkeys", "sp_fkeys", "sp_statistics", "sp_special_columns",
		"sp_server_info", "sp_stored_procedures", "sp_table_privileges",
		"sp_column_privileges",
	}
}

// dangerous is the set whose refusal is never shadowed.
//
// Each one of these is a way out of the database. `xp_cmdshell` runs a shell
// command as the service account; the `sp_oa` family instantiates arbitrary COM
// objects, which is the same thing with more steps; the registry procedures read
// and write the host's configuration; `sp_addlinkedserver` turns one compromised
// database into a route to another; `sp_configure` is how `xp_cmdshell` gets
// turned back on after somebody disabled it; `xp_servicecontrol` stops and starts
// services.
//
// Refusing these in monitor mode too is the same judgement the MySQL kind makes
// about the replication commands. Forwarding a shell command and writing down
// that it was noticed is not a trial of a policy; it is a shell command.
var dangerous = map[string]bool{
	"xp_cmdshell":          true,
	"xp_regread":           true,
	"xp_regwrite":          true,
	"xp_regdeletekey":      true,
	"xp_regdeletevalue":    true,
	"xp_regaddmultistring": true,
	"xp_regenumvalues":     true,
	"xp_regenumkeys":       true,
	"xp_instance_regread":  true,
	"xp_instance_regwrite": true,
	"sp_oacreate":          true,
	"sp_oamethod":          true,
	"sp_oagetproperty":     true,
	"sp_oasetproperty":     true,
	"sp_oadestroy":         true,
	"sp_oageterrorinfo":    true,
	"sp_addextendedproc":   true,
	"sp_dropextendedproc":  true,
	"sp_addlinkedserver":   true,
	"sp_addlinkedsrvlogin": true,
	"sp_serveroption":      true,
	"sp_configure":         true,
	"xp_servicecontrol":    true,
	"xp_availablemedia":    true,
	"xp_makecab":           true,
	"xp_unpackcab":         true,
	"xp_ntsec_enumdomains": true,
	"xp_loginconfig":       true,
	"xp_enumgroups":        true,
	"sp_send_dbmail":       true,
	"xp_sendmail":          true,
	"xp_startmail":         true,
	"xp_dirtree":           true,
	"xp_subdirs":           true,
	"xp_fileexist":         true,
	"xp_fixeddrives":       true,
	"xp_create_subdir":     true,
	"xp_delete_file":       true,
	"sp_add_job":           true,
	"sp_add_jobstep":       true,
	"sp_start_job":         true,
	"sp_addsrvrolemember":  true,
	"sp_addrolemember":     true,
}

// Dangerous says whether refusing this procedure is a decision monitor mode must
// not shadow. The name is expected lower-cased, as Procedure returns it.
func Dangerous(proc string) bool { return dangerous[proc] }

// DangerousProcedures is the set, sorted, for a document and a warning.
func DangerousProcedures() []string {
	out := make([]string, 0, len(dangerous))
	for p := range dangerous {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
